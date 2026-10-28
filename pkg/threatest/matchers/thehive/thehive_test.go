package thehive_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/datadog/threatest/pkg/threatest/matchers/thehive"
	"github.com/datadog/threatest/pkg/threatest/matchers/thehive/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testTitle = "AWS Defense Evasion Stop Logging Cloudtrail"
const detonationUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
const closedStatus = thehive.DefaultClosedStatus
const cleanupTag = thehive.DefaultCleanupTag

func sampleAlert(id string) thehive.Alert {
	return thehive.Alert{ID: id, Title: testTitle, Source: "splunk", Stage: "New"}
}

// userAgent embeds the UUID the way Stratus Red Team does.
func userAgent(uid string) thehive.Observable {
	return thehive.Observable{
		DataType: "user-agent",
		Data:     "aws-cli/2.15.0 stratus-red-team_" + uid,
		Tags:     []string{"field:userAgent"},
	}
}

func newMatcher(api thehive.TheHiveAlertsAPI, filter thehive.TheHiveAlertFilter) *thehive.TheHiveAlertGeneratedAssertion {
	return &thehive.TheHiveAlertGeneratedAssertion{
		AlertsAPI:    api,
		AlertFilter:  &filter,
		ClosedStatus: closedStatus,
		CleanupTag:   cleanupTag,
	}
}

func stringify(v any) string {
	buf, _ := json.Marshal(v)
	return string(buf)
}

func filterHas(field string, value any) func(map[string]any) bool {
	return func(filter map[string]any) bool {
		for _, clause := range filter["_and"].([]map[string]any) {
			eq, ok := clause["_eq"].(map[string]any)
			if ok && eq["_field"] == field && eq["_value"] == value {
				return true
			}
		}
		return false
	}
}

func TestHasExpected(t *testing.T) {
	tests := []struct {
		name            string
		observableField string
		alerts          []thehive.Alert
		observables     map[string][]thehive.Observable
		expectMatch     bool
	}{
		{
			name:        "no alerts",
			expectMatch: false,
		},
		{
			name:        "alert without the UUID",
			alerts:      []thehive.Alert{sampleAlert("~1")},
			observables: map[string][]thehive.Observable{"~1": {userAgent("other-uuid")}},
			expectMatch: false,
		},
		{
			name:        "UUID embedded in a longer observable value",
			alerts:      []thehive.Alert{sampleAlert("~1")},
			observables: map[string][]thehive.Observable{"~1": {userAgent(detonationUID)}},
			expectMatch: true,
		},
		{
			name:   "second alert matches",
			alerts: []thehive.Alert{sampleAlert("~1"), sampleAlert("~2")},
			observables: map[string][]thehive.Observable{
				"~1": {{DataType: "ip", Data: "10.0.0.1"}},
				"~2": {userAgent(detonationUID)},
			},
			expectMatch: true,
		},
		{
			name:            "UUID in an observable with another field tag",
			observableField: "commandLine",
			alerts:          []thehive.Alert{sampleAlert("~1")},
			observables:     map[string][]thehive.Observable{"~1": {userAgent(detonationUID)}},
			expectMatch:     false,
		},
		{
			name:            "UUID in an observable with the expected field tag",
			observableField: "userAgent",
			alerts:          []thehive.Alert{sampleAlert("~1")},
			observables:     map[string][]thehive.Observable{"~1": {userAgent(detonationUID)}},
			expectMatch:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := mocks.NewTheHiveAlertsAPI(t)
			mockAPI.On("FindAlerts", mock.Anything, mock.MatchedBy(filterHas("title", testTitle))).Return(tt.alerts, nil)
			for id, observables := range tt.observables {
				mockAPI.On("FindObservables", mock.Anything, id).Return(observables, nil).Maybe()
			}

			matcher := newMatcher(mockAPI, thehive.TheHiveAlertFilter{Title: testTitle, ObservableField: tt.observableField})
			matches, err := matcher.HasExpected(context.Background(), detonationUID)
			require.NoError(t, err)
			assert.Equal(t, tt.expectMatch, matches)
		})
	}
}

func TestHasExpectedMatchesDescriptionWithoutFetchingObservables(t *testing.T) {
	alert := sampleAlert("~1")
	alert.Description = "| userAgent |\n| stratus-red-team_" + detonationUID + " |"

	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("FindAlerts", mock.Anything, mock.Anything).Return([]thehive.Alert{alert}, nil)

	matches, err := newMatcher(mockAPI, thehive.TheHiveAlertFilter{Title: testTitle}).HasExpected(context.Background(), detonationUID)
	require.NoError(t, err)
	assert.True(t, matches)
	mockAPI.AssertNotCalled(t, "FindObservables", mock.Anything, mock.Anything)
}

func TestHasExpectedCachesObservablesAcrossPolls(t *testing.T) {
	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("FindAlerts", mock.Anything, mock.Anything).Return([]thehive.Alert{sampleAlert("~1")}, nil)
	mockAPI.On("FindObservables", mock.Anything, "~1").Return([]thehive.Observable{userAgent("other-uuid")}, nil).Once()

	matcher := newMatcher(mockAPI, thehive.TheHiveAlertFilter{Title: testTitle})
	for range 3 {
		matches, err := matcher.HasExpected(context.Background(), detonationUID)
		require.NoError(t, err)
		assert.False(t, matches)
	}
}

func TestHasExpectedSearchError(t *testing.T) {
	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("FindAlerts", mock.Anything, mock.Anything).Return(nil, assert.AnError)

	_, err := newMatcher(mockAPI, thehive.TheHiveAlertFilter{Title: testTitle}).HasExpected(context.Background(), detonationUID)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestRelated(t *testing.T) {
	matching := sampleAlert("~1")
	matching.CreatedAt = 1761562800000

	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("FindAlerts", mock.Anything, mock.Anything).Return([]thehive.Alert{matching, sampleAlert("~2")}, nil)
	mockAPI.On("FindObservables", mock.Anything, "~1").Return([]thehive.Observable{userAgent(detonationUID)}, nil)
	mockAPI.On("FindObservables", mock.Anything, "~2").Return(nil, nil)

	events, err := newMatcher(mockAPI, thehive.TheHiveAlertFilter{Title: testTitle}).Related(context.Background(), detonationUID)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, testTitle, events["~1"].EventName)
	assert.Equal(t, int64(1761562800000), events["~1"].Time.UnixMilli())
}

func TestCleanup(t *testing.T) {
	// Cleanup looks at every open alert in the window, not only those with the
	// expected title, and never filters by title.
	isOpenAlertsFilter := func(filter map[string]any) bool {
		return !filterHas("title", testTitle)(filter) && strings.Contains(stringify(filter), "_not")
	}

	matching := sampleAlert("~1")
	otherTitle := sampleAlert("~2")
	otherTitle.Title = "Another rule"
	unrelated := sampleAlert("~3")

	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("ListAlertStatuses", mock.Anything).Return([]thehive.AlertStatus{
		{Value: "New", Stage: "New"},
		{Value: closedStatus, Stage: "Closed"},
	}, nil)
	mockAPI.On("FindAlerts", mock.Anything, mock.MatchedBy(isOpenAlertsFilter)).Return([]thehive.Alert{matching, otherTitle, unrelated}, nil)
	mockAPI.On("FindObservables", mock.Anything, "~1").Return([]thehive.Observable{userAgent(detonationUID)}, nil)
	mockAPI.On("FindObservables", mock.Anything, "~2").Return([]thehive.Observable{userAgent(detonationUID)}, nil)
	mockAPI.On("FindObservables", mock.Anything, "~3").Return([]thehive.Observable{userAgent("other-uuid")}, nil)

	expectedUpdate := thehive.AlertUpdate{Status: closedStatus, AddTags: []string{cleanupTag}}
	mockAPI.On("UpdateAlert", mock.Anything, "~1", expectedUpdate).Return(nil)
	mockAPI.On("UpdateAlert", mock.Anything, "~2", expectedUpdate).Return(nil)

	require.NoError(t, newMatcher(mockAPI, thehive.TheHiveAlertFilter{Title: testTitle}).Cleanup(context.Background(), detonationUID))

	mockAPI.AssertCalled(t, "UpdateAlert", mock.Anything, "~1", expectedUpdate)
	mockAPI.AssertCalled(t, "UpdateAlert", mock.Anything, "~2", expectedUpdate)
	mockAPI.AssertNotCalled(t, "UpdateAlert", mock.Anything, "~3", mock.Anything)
}

func TestCleanupRejectsBadClosedStatus(t *testing.T) {
	tests := []struct {
		name         string
		closedStatus string
		statuses     []thehive.AlertStatus
		expectError  string
	}{
		{name: "unset", closedStatus: "", expectError: "set THEHIVE_CLOSED_STATUS"},
		{name: "not in Closed stage", closedStatus: "New", statuses: []thehive.AlertStatus{{Value: "New", Stage: "New"}}, expectError: "is in stage 'New'"},
		{name: "unknown", closedStatus: "Nope", statuses: []thehive.AlertStatus{{Value: "New", Stage: "New"}}, expectError: "does not exist"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := mocks.NewTheHiveAlertsAPI(t)
			if tt.statuses != nil {
				mockAPI.On("ListAlertStatuses", mock.Anything).Return(tt.statuses, nil)
			}
			matcher := newMatcher(mockAPI, thehive.TheHiveAlertFilter{Title: testTitle})
			matcher.ClosedStatus = tt.closedStatus

			err := matcher.Cleanup(context.Background(), detonationUID)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
			mockAPI.AssertNotCalled(t, "FindAlerts", mock.Anything, mock.Anything)
			mockAPI.AssertNotCalled(t, "UpdateAlert", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestCleanupProceedsWhenStatusesCannotBeListed(t *testing.T) {
	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("ListAlertStatuses", mock.Anything).Return(nil, assert.AnError)
	mockAPI.On("FindAlerts", mock.Anything, mock.Anything).Return(nil, nil)

	require.NoError(t, newMatcher(mockAPI, thehive.TheHiveAlertFilter{Title: testTitle}).Cleanup(context.Background(), detonationUID))
}

func TestCleanupWithoutTag(t *testing.T) {
	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("ListAlertStatuses", mock.Anything).Return([]thehive.AlertStatus{{Value: closedStatus, Stage: "Closed"}}, nil)
	mockAPI.On("FindAlerts", mock.Anything, mock.Anything).Return([]thehive.Alert{sampleAlert("~1")}, nil)
	mockAPI.On("FindObservables", mock.Anything, "~1").Return([]thehive.Observable{userAgent(detonationUID)}, nil)
	mockAPI.On("UpdateAlert", mock.Anything, "~1", thehive.AlertUpdate{Status: closedStatus}).Return(nil)

	matcher := newMatcher(mockAPI, thehive.TheHiveAlertFilter{Title: testTitle})
	matcher.CleanupTag = ""
	require.NoError(t, matcher.Cleanup(context.Background(), detonationUID))
}

func TestBuilderDefaultsAndEnvOverrides(t *testing.T) {
	t.Setenv("THEHIVE_URL", "https://thehive.example.com")
	b := thehive.TheHiveAlert(testTitle)
	assert.Equal(t, "Other", b.ClosedStatus)
	assert.Equal(t, "Control Validation", b.CleanupTag)

	t.Setenv("THEHIVE_CLOSED_STATUS", "Duplicated")
	t.Setenv("THEHIVE_CLEANUP_TAG", "")
	b = thehive.TheHiveAlert(testTitle)
	assert.Equal(t, "Duplicated", b.ClosedStatus)
	assert.Equal(t, "", b.CleanupTag, "an explicitly empty tag disables tagging")

	b = thehive.TheHiveAlert(testTitle, thehive.WithClosedStatus("Ignored"), thehive.WithCleanupTag("lab"))
	assert.Equal(t, "Ignored", b.ClosedStatus)
	assert.Equal(t, "lab", b.CleanupTag)
}

func hostMatcher(api thehive.TheHiveAlertsAPI, field string, hosts ...string) *thehive.TheHiveAlertGeneratedAssertion {
	m := newMatcher(api, thehive.TheHiveAlertFilter{
		Title:           testTitle,
		ObservableField: field,
		Correlation:     thehive.CorrelationHost,
		Hosts:           hosts,
	})
	m.NotBefore = time.UnixMilli(1761562800000)
	return m
}

func ipObservable(ip, field string) thehive.Observable {
	return thehive.Observable{DataType: "ip", Data: ip, Tags: []string{"field:" + field}}
}

func TestHasExpectedHostCorrelation(t *testing.T) {
	tests := []struct {
		name        string
		field       string
		observables []thehive.Observable
		expectMatch bool
	}{
		{name: "exact address", observables: []thehive.Observable{ipObservable("10.0.0.5", "src_ip")}, expectMatch: true},
		{name: "hostname, case-insensitive", observables: []thehive.Observable{{DataType: "hostname", Data: "EGRESS-01"}}, expectMatch: true},
		{name: "address prefix does not match", observables: []thehive.Observable{ipObservable("10.0.0.50", "src_ip")}, expectMatch: false},
		{name: "UUID is irrelevant", observables: []thehive.Observable{userAgent(detonationUID)}, expectMatch: false},
		{name: "field tag required", field: "src_ip", observables: []thehive.Observable{ipObservable("10.0.0.5", "dest_ip")}, expectMatch: false},
		{name: "field tag matches", field: "src_ip", observables: []thehive.Observable{ipObservable("10.0.0.5", "src_ip")}, expectMatch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := mocks.NewTheHiveAlertsAPI(t)
			mockAPI.On("FindAlerts", mock.Anything, mock.MatchedBy(filterHas("title", testTitle))).Return([]thehive.Alert{sampleAlert("~1")}, nil)
			mockAPI.On("FindObservables", mock.Anything, "~1").Return(tt.observables, nil)

			matches, err := hostMatcher(mockAPI, tt.field, "10.0.0.5", "egress-01").HasExpected(context.Background(), detonationUID)
			require.NoError(t, err)
			assert.Equal(t, tt.expectMatch, matches)
		})
	}
}

func TestHostCorrelationIgnoresDescription(t *testing.T) {
	alert := sampleAlert("~1")
	alert.Description = "src 10.0.0.5"
	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("FindAlerts", mock.Anything, mock.Anything).Return([]thehive.Alert{alert}, nil)
	mockAPI.On("FindObservables", mock.Anything, "~1").Return(nil, nil)

	matches, err := hostMatcher(mockAPI, "", "10.0.0.5").HasExpected(context.Background(), detonationUID)
	require.NoError(t, err)
	assert.False(t, matches)
}

func TestHostCorrelationWindowStartsAtNotBefore(t *testing.T) {
	createdSince := func(filter map[string]any) bool {
		return strings.Contains(stringify(filter), `{"_gte":{"_field":"_createdAt","_value":1761562800000}}`)
	}
	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("FindAlerts", mock.Anything, mock.MatchedBy(createdSince)).Return(nil, nil)

	_, err := hostMatcher(mockAPI, "", "10.0.0.5").HasExpected(context.Background(), detonationUID)
	require.NoError(t, err)
}

func TestHostCorrelationWithoutHosts(t *testing.T) {
	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("FindAlerts", mock.Anything, mock.Anything).Return([]thehive.Alert{sampleAlert("~1")}, nil)

	_, err := hostMatcher(mockAPI, "").HasExpected(context.Background(), detonationUID)
	assert.ErrorContains(t, err, "THEHIVE_DETONATION_HOSTS")
}

func TestCleanupHostCorrelationOnlyClosesExpectedTitle(t *testing.T) {
	// Unlike UUID correlation, other rules firing on the same host are real
	// detections and must stay open, so cleanup filters on title.
	isTitledOpenFilter := func(filter map[string]any) bool {
		return filterHas("title", testTitle)(filter) && strings.Contains(stringify(filter), "_not")
	}
	mockAPI := mocks.NewTheHiveAlertsAPI(t)
	mockAPI.On("ListAlertStatuses", mock.Anything).Return([]thehive.AlertStatus{{Value: closedStatus, Stage: "Closed"}}, nil)
	mockAPI.On("FindAlerts", mock.Anything, mock.MatchedBy(isTitledOpenFilter)).Return([]thehive.Alert{sampleAlert("~1")}, nil)
	mockAPI.On("FindObservables", mock.Anything, "~1").Return([]thehive.Observable{ipObservable("10.0.0.5", "src_ip")}, nil)
	mockAPI.On("UpdateAlert", mock.Anything, "~1", thehive.AlertUpdate{Status: closedStatus, AddTags: []string{cleanupTag}}).Return(nil)

	require.NoError(t, hostMatcher(mockAPI, "", "10.0.0.5").Cleanup(context.Background(), detonationUID))
}

func TestBuilderHostCorrelation(t *testing.T) {
	t.Setenv("THEHIVE_DETONATION_HOSTS", " 10.0.0.5, egress-01 ,")
	before := time.Now()
	b := thehive.TheHiveAlert(testTitle)
	assert.Equal(t, thehive.CorrelationUUID, b.AlertFilter.Correlation)
	assert.Equal(t, []string{"10.0.0.5", "egress-01"}, b.AlertFilter.Hosts)
	assert.False(t, b.NotBefore.Before(before))

	b = thehive.TheHiveAlert(testTitle, thehive.WithHostCorrelation())
	assert.Equal(t, thehive.CorrelationHost, b.AlertFilter.Correlation)
	assert.Equal(t, []string{"10.0.0.5", "egress-01"}, b.AlertFilter.Hosts)

	b = thehive.TheHiveAlert(testTitle, thehive.WithHostCorrelation("192.0.2.1"))
	assert.Equal(t, []string{"192.0.2.1"}, b.AlertFilter.Hosts)
}
