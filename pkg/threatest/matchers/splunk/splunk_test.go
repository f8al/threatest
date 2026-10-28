package splunk

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/datadog/threatest/pkg/threatest/matchers"
	"github.com/datadog/threatest/pkg/threatest/matchers/internal/httpclient"
	"github.com/datadog/threatest/pkg/threatest/matchers/splunk/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testToken = "test-token-do-not-log"
const detonationUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"

func sampleRow(cd string) map[string]any {
	return map[string]any{
		"_bkt":       "aws_cloudtrail~12~ABC",
		"_cd":        cd,
		"_time":      "2026-10-27T10:30:00.123+00:00",
		"_raw":       `{"userAgent":"stratus-red-team_` + detonationUID + `"}`,
		"sourcetype": "aws:cloudtrail",
		"source":     "s3://bucket/key",
		"host":       "aws",
	}
}

func TestConvertResult(t *testing.T) {
	id, event := convertResult(sampleRow("12:345"))
	assert.Equal(t, "aws_cloudtrail~12~ABC:12:345", id)
	assert.Equal(t, "aws:cloudtrail", event.EventName)
	assert.Equal(t, time.Date(2026, 10, 27, 10, 30, 0, 123e6, time.UTC), event.Time.UTC())
	assert.Equal(t, "aws", event.Attributes["host"])
	assert.Contains(t, event.Attributes["message"], detonationUID)
	assert.Contains(t, string(event.Body), "sourcetype")
}

func TestConvertResultWithoutBucketUsesHash(t *testing.T) {
	row := map[string]any{"source": "/var/log/auth.log", "count": "3"}
	id, event := convertResult(row)
	id2, _ := convertResult(map[string]any{"source": "/var/log/auth.log", "count": "3"})
	assert.Len(t, id, 64)
	assert.Equal(t, id, id2, "hash must be stable for identical rows")
	assert.Equal(t, "/var/log/auth.log", event.EventName)
	assert.True(t, event.Time.IsZero())
}

func TestConvertResultMultivalueField(t *testing.T) {
	row := sampleRow("1:1")
	row["dest"] = []any{"10.0.0.1", "10.0.0.2"}
	_, event := convertResult(row)
	assert.Equal(t, []any{"10.0.0.1", "10.0.0.2"}, event.Attributes["dest"])
}

func TestParseTimeEpoch(t *testing.T) {
	assert.Equal(t, int64(1761561000), parseTime("1761561000.000").Unix())
}

func TestDefaultCorrelationQuery(t *testing.T) {
	m := &Matcher{Filter: &Filter{}}
	assert.Equal(t, `search index=* "my-uuid"`, m.defaultCorrelationQuery("my-uuid"))

	m.Filter.Indexes = []string{"aws_cloudtrail", "linux"}
	assert.Equal(t, `search (index="aws_cloudtrail" OR index="linux") "my-uuid"`, m.defaultCorrelationQuery("my-uuid"))

	m.Filter.Query = `index=aws_cloudtrail "<% .CorrelationID %>"`
	assert.Equal(t, `index=aws_cloudtrail "<% .CorrelationID %>"`, m.defaultCorrelationQuery("my-uuid"))
}

func TestNormalizeQuery(t *testing.T) {
	assert.Equal(t, "search index=main foo", normalizeQuery("index=main foo"))
	assert.Equal(t, "search index=main foo", normalizeQuery("  search index=main foo"))
	assert.Equal(t, "| tstats count where index=main", normalizeQuery("| tstats count where index=main"))
}

func TestHasExpected(t *testing.T) {
	tests := []struct {
		name        string
		rows        []map[string]any
		expectMatch bool
	}{
		{name: "telemetry missing", rows: nil, expectMatch: false},
		{name: "telemetry found", rows: []map[string]any{sampleRow("1:1"), sampleRow("1:2")}, expectMatch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := mocks.NewSearchAPI(t)
			expectedQuery := `search index=aws_cloudtrail "` + detonationUID + `"`
			mockAPI.On("Search", mock.Anything, expectedQuery, mock.Anything, mock.Anything).Return(tt.rows, nil)

			m := &Matcher{SearchAPI: mockAPI, Filter: &Filter{Query: `index=aws_cloudtrail "<% .CorrelationID %>"`}}
			found, err := m.HasExpected(context.Background(), detonationUID)
			require.NoError(t, err)
			assert.Equal(t, tt.expectMatch, found)
		})
	}
}

func TestSearchHonoursTimeRange(t *testing.T) {
	from := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	to := from.Add(30 * time.Minute)

	mockAPI := mocks.NewSearchAPI(t)
	mockAPI.On("Search", mock.Anything, "search index=main", from, to).Return([]map[string]any{sampleRow("1:1")}, nil)

	m := &Matcher{SearchAPI: mockAPI, Filter: &Filter{}}
	events, err := m.Search(context.Background(), "index=main", matchers.WithTimeRange(from, to))
	require.NoError(t, err)
	assert.Len(t, events, 1)
}

func TestSearchDefaultWindow(t *testing.T) {
	inWindow := func(ts time.Time) bool {
		return time.Since(ts) > lookbackWindow-time.Minute && time.Since(ts) < lookbackWindow+time.Minute
	}
	mockAPI := mocks.NewSearchAPI(t)
	mockAPI.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(inWindow), mock.Anything).Return(nil, nil)

	m := &Matcher{SearchAPI: mockAPI, Filter: &Filter{}}
	_, err := m.Search(context.Background(), "index=main")
	require.NoError(t, err)
}

func TestSearchAPIRequest(t *testing.T) {
	var form map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, searchPath, r.URL.Path)
		require.Equal(t, "Bearer "+testToken, r.Header.Get("Authorization"))
		require.NoError(t, r.ParseForm())
		form = map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		fmt.Fprint(w, `{"preview":false,"init_offset":0,"messages":[],"results":[{"_raw":"hello","_cd":"1:1","_bkt":"main~1~X"}]}`)
	}))
	defer server.Close()

	api := newSearchAPI(server.URL+"/", testToken, httpclient.TLSOptions{})
	earliest := time.Unix(1761561000, 0)
	rows, err := api.Search(context.Background(), "search index=main", earliest, earliest.Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "hello", rows[0]["_raw"])
	assert.Equal(t, map[string]string{
		"search":        "search index=main",
		"exec_mode":     "oneshot",
		"output_mode":   "json",
		"earliest_time": "1761561000",
		"latest_time":   "1761564600",
	}, form)
}

func TestSearchAPIAuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"messages":[{"type":"WARN","text":"call not properly authenticated"}]}`)
	}))
	defer server.Close()

	api := newSearchAPI(server.URL, "wrong-token", httpclient.TLSOptions{})
	_, err := api.Search(context.Background(), "search *", time.Now(), time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status code 401")
	assert.Contains(t, err.Error(), "call not properly authenticated")
	assert.NotContains(t, err.Error(), "wrong-token")
}

func TestSearchAPINonJSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `<response><messages><msg type="WARN">call not properly authenticated</msg></messages></response>`)
	}))
	defer server.Close()

	_, err := newSearchAPI(server.URL, testToken, httpclient.TLSOptions{}).Search(context.Background(), "search *", time.Now(), time.Now())
	assert.ErrorContains(t, err, "status code 401")
}

func TestSearchAPIFatalMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"messages":[{"type":"FATAL","text":"Unknown search command 'foo'."}],"results":[]}`)
	}))
	defer server.Close()

	_, err := newSearchAPI(server.URL, testToken, httpclient.TLSOptions{}).Search(context.Background(), "| foo", time.Now(), time.Now())
	assert.ErrorContains(t, err, "Unknown search command")
}

func TestSearchAPIMissingCredentials(t *testing.T) {
	_, err := newSearchAPI("", "", httpclient.TLSOptions{}).Search(context.Background(), "search *", time.Now(), time.Now())
	assert.ErrorContains(t, err, "SPLUNK_URL")
}

func TestSearchAPIBadCACertFile(t *testing.T) {
	api := newSearchAPI("https://splunk:8089", testToken, httpclient.TLSOptions{CACertFile: "/nonexistent/ca.pem"})
	_, err := api.Search(context.Background(), "search *", time.Now(), time.Now())
	assert.ErrorContains(t, err, "unable to read CA certificate file")
}
