package thehive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/datadog/threatest/pkg/threatest/matchers/internal/httpclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAPIKey = "test-api-key-do-not-log"

// fakeTheHive serves /api/v1/query from an in-memory list of alerts, honouring
// the trailing page step, and records the requests it receives.
type fakeTheHive struct {
	t        *testing.T
	alerts   []map[string]any
	pages    [][2]int
	patches  map[string]map[string]any
	lastOrg  string
	lastAuth string
}

func (f *fakeTheHive) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.lastAuth = r.Header.Get("Authorization")
	f.lastOrg = r.Header.Get("X-Organisation")
	if f.lastAuth != "Bearer "+testAPIKey {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"type":"AuthenticationError","message":"Authentication failure"}`)
		return
	}

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/query":
		var body struct {
			Query []map[string]any `json:"query"`
		}
		require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))
		last := body.Query[len(body.Query)-1]
		require.Equal(f.t, "page", last["_name"])
		from, to := int(last["from"].(float64)), int(last["to"].(float64))
		f.pages = append(f.pages, [2]int{from, to})
		from, to = min(from, len(f.alerts)), min(to, len(f.alerts))
		require.NoError(f.t, json.NewEncoder(w).Encode(f.alerts[from:to]))
	case r.Method == http.MethodPatch:
		var body map[string]any
		require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))
		f.patches[r.URL.Path] = body
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newFake(t *testing.T, numAlerts int) (*fakeTheHive, *TheHiveAlertsAPIImpl) {
	fake := &fakeTheHive{t: t, patches: map[string]map[string]any{}}
	for i := range numAlerts {
		fake.alerts = append(fake.alerts, map[string]any{"_id": fmt.Sprintf("~%d", i), "title": "t", "_createdAt": 1761562800000})
	}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	api := newAlertsAPI(server.URL, testAPIKey, "", httpclient.TLSOptions{}).(*TheHiveAlertsAPIImpl)
	return fake, api
}

func TestFindAlertsPaginates(t *testing.T) {
	fake, api := newFake(t, 2*pageSize+5)

	alerts, err := api.FindAlerts(context.Background(), map[string]any{"_and": []any{}})
	require.NoError(t, err)
	assert.Len(t, alerts, 2*pageSize+5)
	assert.Equal(t, [][2]int{{0, pageSize}, {pageSize, 2 * pageSize}, {2 * pageSize, 3 * pageSize}}, fake.pages)
	assert.Equal(t, "~0", alerts[0].ID)
	assert.Equal(t, int64(1761562800000), alerts[0].CreatedAt)
	assert.JSONEq(t, `{"_id":"~0","title":"t","_createdAt":1761562800000}`, string(alerts[0].Raw))
}

func TestFindAlertsStopsAtExactPageBoundary(t *testing.T) {
	fake, api := newFake(t, pageSize)

	alerts, err := api.FindAlerts(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, alerts, pageSize)
	assert.Len(t, fake.pages, 2, "a full page requires one more request to detect the end")
}

func TestFindAlertsCapsAtMaxAlerts(t *testing.T) {
	_, api := newFake(t, maxAlerts+pageSize)

	alerts, err := api.FindAlerts(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, alerts, maxAlerts)
}

func TestAuthFailure(t *testing.T) {
	_, api := newFake(t, 1)
	bad := newAlertsAPI(api.baseURL, "wrong-key", "", httpclient.TLSOptions{})

	_, err := bad.FindAlerts(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status code 401")
	assert.Contains(t, err.Error(), "Authentication failure")
	assert.NotContains(t, err.Error(), "wrong-key")
}

func TestMissingCredentials(t *testing.T) {
	api := newAlertsAPI("", "", "", httpclient.TLSOptions{})
	_, err := api.FindAlerts(context.Background(), nil)
	assert.ErrorContains(t, err, "THEHIVE_URL")
}

func TestOrganisationHeader(t *testing.T) {
	fake, api := newFake(t, 0)
	api.organisation = "dacs"

	_, err := api.FindAlerts(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "dacs", fake.lastOrg)
}

func TestUpdateAlertSendsStatusAndAddTags(t *testing.T) {
	fake, api := newFake(t, 0)

	err := api.UpdateAlert(context.Background(), "~42", AlertUpdate{Status: "Other", AddTags: []string{"Control Validation"}})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"status": "Other", "addTags": []any{"Control Validation"}}, fake.patches["/api/v1/alert/~42"])
}

func TestBuildAlertFilter(t *testing.T) {
	m := &TheHiveAlertGeneratedAssertion{AlertFilter: &TheHiveAlertFilter{Title: "My Rule", Source: "splunk"}}

	t.Run("includes title, source and window", func(t *testing.T) {
		buf, _ := json.Marshal(m.buildAlertFilter(true, false))
		assert.Contains(t, string(buf), `{"_eq":{"_field":"title","_value":"My Rule"}}`)
		assert.Contains(t, string(buf), `{"_eq":{"_field":"source","_value":"splunk"}}`)
		assert.Contains(t, string(buf), `"_field":"_createdAt"`)
		assert.NotContains(t, string(buf), "_not")
	})

	t.Run("cleanup filter drops title and excludes closed alerts", func(t *testing.T) {
		buf, _ := json.Marshal(m.buildAlertFilter(false, true))
		assert.NotContains(t, string(buf), "My Rule")
		assert.Contains(t, string(buf), `{"_not":{"_eq":{"_field":"stage","_value":"Closed"}}}`)
	})
}
