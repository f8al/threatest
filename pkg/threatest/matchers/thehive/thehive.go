// Package thehive matches expected TheHive alerts, such as those created by
// the TA-thehive-cortex Splunk alert action.
package thehive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/datadog/threatest/pkg/threatest/matchers"
	"github.com/datadog/threatest/pkg/threatest/secret"
	log "github.com/sirupsen/logrus"
)

// AlertLookbackWindow bounds how far back alerts are searched, mirroring the
// Elastic matcher.
const AlertLookbackWindow = 1 * time.Hour

// DefaultClosedStatus is the alert status set during cleanup when
// THEHIVE_CLOSED_STATUS is unset. It must belong to the Closed stage.
const DefaultClosedStatus = "Other"

// DefaultCleanupTag is added to every alert closed by cleanup when
// THEHIVE_CLEANUP_TAG is unset, so notifications and responders can exclude
// control validation alerts.
const DefaultCleanupTag = "Control Validation"

const closedStage = "Closed"

// Correlation modes. CorrelationUUID looks for the detonation UUID in the
// alert. CorrelationHost is for detonations whose telemetry cannot carry the
// UUID, such as network traffic from flightsim: it matches alerts with an
// observable equal to one of the detonation host's addresses, created after
// the matcher was built.
const (
	CorrelationUUID = "uuid"
	CorrelationHost = "host"
)

const requestTimeout = 30 * time.Second

// pageSize is the number of entities requested per page; maxAlerts bounds the
// total number of alerts fetched by a single search.
const pageSize = 100
const maxAlerts = 1000

// Alert is a TheHive alert. Raw holds the full JSON document.
type Alert struct {
	ID          string   `json:"_id"`
	CreatedAt   int64    `json:"_createdAt"`
	Title       string   `json:"title"`
	Source      string   `json:"source"`
	SourceRef   string   `json:"sourceRef"`
	Status      string   `json:"status"`
	Stage       string   `json:"stage"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`

	Raw json.RawMessage `json:"-"`
}

// Observable is a TheHive observable. Data is empty for attachments.
type Observable struct {
	DataType string   `json:"dataType"`
	Data     string   `json:"data"`
	Tags     []string `json:"tags"`
}

// AlertStatus is an entry returned by the listAlertStatus query.
type AlertStatus struct {
	Value string `json:"value"`
	Stage string `json:"stage"`
}

// AlertUpdate is the body of an alert PATCH. Only set fields are sent.
type AlertUpdate struct {
	Status  string   `json:"status,omitempty"`
	AddTags []string `json:"addTags,omitempty"`
}

type TheHiveAlertsAPI interface {
	// FindAlerts runs listAlert with the given filter, newest first.
	FindAlerts(ctx context.Context, filter map[string]any) ([]Alert, error)
	FindObservables(ctx context.Context, alertID string) ([]Observable, error)
	ListAlertStatuses(ctx context.Context) ([]AlertStatus, error)
	UpdateAlert(ctx context.Context, alertID string, update AlertUpdate) error
}

type TheHiveAlertsAPIImpl struct {
	baseURL      string
	apiKey       secret.Secret
	organisation string
	client       *http.Client
	clientErr    error
}

func (m *TheHiveAlertsAPIImpl) FindAlerts(ctx context.Context, filter map[string]any) ([]Alert, error) {
	steps := []map[string]any{{"_name": "listAlert"}}
	if len(filter) > 0 {
		steps = append(steps, withName("filter", filter))
	}
	steps = append(steps, map[string]any{"_name": "sort", "_fields": []map[string]string{{"_createdAt": "desc"}}})

	raws, err := m.queryPaginated(ctx, steps, maxAlerts)
	if err != nil {
		return nil, err
	}
	if len(raws) >= maxAlerts {
		log.Warnf("at least %d TheHive alerts returned, checking first %d", maxAlerts, maxAlerts)
	}

	alerts := make([]Alert, 0, len(raws))
	for _, raw := range raws {
		var alert Alert
		if err := json.Unmarshal(raw, &alert); err != nil {
			return nil, fmt.Errorf("error parsing alert: %w", err)
		}
		alert.Raw = raw
		alerts = append(alerts, alert)
	}
	return alerts, nil
}

func (m *TheHiveAlertsAPIImpl) FindObservables(ctx context.Context, alertID string) ([]Observable, error) {
	steps := []map[string]any{
		{"_name": "getAlert", "idOrName": alertID},
		{"_name": "observables"},
	}
	raws, err := m.queryPaginated(ctx, steps, 0)
	if err != nil {
		return nil, err
	}
	observables := make([]Observable, 0, len(raws))
	for _, raw := range raws {
		var observable Observable
		if err := json.Unmarshal(raw, &observable); err != nil {
			return nil, fmt.Errorf("error parsing observable: %w", err)
		}
		observables = append(observables, observable)
	}
	return observables, nil
}

func (m *TheHiveAlertsAPIImpl) ListAlertStatuses(ctx context.Context) ([]AlertStatus, error) {
	var statuses []AlertStatus
	if err := m.query(ctx, []map[string]any{{"_name": "listAlertStatus"}}, &statuses); err != nil {
		return nil, err
	}
	return statuses, nil
}

func (m *TheHiveAlertsAPIImpl) UpdateAlert(ctx context.Context, alertID string, update AlertUpdate) error {
	payload, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("error marshaling alert update: %w", err)
	}
	resp, err := m.doRequest(ctx, http.MethodPatch, "/api/v1/alert/"+alertID, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("update alert request failed: %w", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

// queryPaginated runs a query chain with a trailing page step until a short
// page is returned. limit caps the number of entities; 0 means no cap.
func (m *TheHiveAlertsAPIImpl) queryPaginated(ctx context.Context, steps []map[string]any, limit int) ([]json.RawMessage, error) {
	var all []json.RawMessage
	for from := 0; limit == 0 || from < limit; from += pageSize {
		paged := append(slices.Clone(steps), map[string]any{"_name": "page", "from": from, "to": from + pageSize})
		var page []json.RawMessage
		if err := m.query(ctx, paged, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < pageSize {
			break
		}
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func (m *TheHiveAlertsAPIImpl) query(ctx context.Context, steps []map[string]any, out any) error {
	payload, err := json.Marshal(map[string]any{"query": steps})
	if err != nil {
		return fmt.Errorf("error marshaling query: %w", err)
	}
	resp, err := m.doRequest(ctx, http.MethodPost, "/api/v1/query", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("query request failed: %w", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("error parsing query response: %w", err)
	}
	return nil
}

// doRequest validates credentials, sends the request with the API key and
// optional organisation header, and checks for non-2xx status codes.
func (m *TheHiveAlertsAPIImpl) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	if m.baseURL == "" || m.apiKey.Value() == "" {
		return nil, errors.New("missing TheHive credentials: set the THEHIVE_URL and THEHIVE_API_KEY env vars")
	}
	if m.clientErr != nil {
		return nil, m.clientErr
	}

	req, err := http.NewRequestWithContext(ctx, method, m.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.apiKey.Value())
	req.Header.Set("Content-Type", "application/json")
	if m.organisation != "" {
		req.Header.Set("X-Organisation", m.organisation)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing request: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		// TheHive errors are {"type": ..., "message": ...}; neither echoes the key.
		var apiErr struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		detail := ""
		if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&apiErr) == nil && apiErr.Message != "" {
			detail = fmt.Sprintf(": %s: %s", apiErr.Type, apiErr.Message)
		}
		return nil, fmt.Errorf("request to %s failed with status code %d%s", path, resp.StatusCode, detail)
	}

	return resp, nil
}

func (m *TheHiveAlertGeneratedAssertion) HasExpected(ctx context.Context, correlationID string) (bool, error) {
	alerts, err := m.AlertsAPI.FindAlerts(ctx, m.buildAlertFilter(true, false))
	if err != nil {
		return false, fmt.Errorf("unable to search for TheHive alert: %w", err)
	}

	for i := range alerts {
		matches, err := m.alertMatchesExecution(ctx, alerts[i], correlationID)
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}

	return false, nil
}

func (m *TheHiveAlertGeneratedAssertion) String() string {
	if m.AlertFilter.Correlation == CorrelationHost {
		return fmt.Sprintf("TheHive alert '%s' from detonation host", m.AlertFilter.Title)
	}
	return fmt.Sprintf("TheHive alert '%s'", m.AlertFilter.Title)
}

// Related returns the alerts correlated to the detonation, filtered by title
// and source when set.
func (m *TheHiveAlertGeneratedAssertion) Related(ctx context.Context, correlationID string) (map[string]matchers.ThreatestEvent, error) {
	alerts, err := m.AlertsAPI.FindAlerts(ctx, m.buildAlertFilter(true, false))
	if err != nil {
		return nil, fmt.Errorf("unable to search for TheHive alerts: %w", err)
	}

	result := make(map[string]matchers.ThreatestEvent)
	for i := range alerts {
		matches, err := m.alertMatchesExecution(ctx, alerts[i], correlationID)
		if err != nil {
			return nil, err
		}
		if matches {
			result[alerts[i].ID] = convertAlert(alerts[i])
		}
	}
	return result, nil
}

func (m *TheHiveAlertGeneratedAssertion) Search(ctx context.Context, query string, _ ...matchers.SearchOption) (map[string]matchers.ThreatestEvent, error) {
	return nil, errors.New("Search is not implemented for TheHive")
}

// Cleanup moves every open alert correlated to the detonation to the
// configured Closed-stage status and adds CleanupTag. With UUID correlation
// this covers alerts of any title; with host correlation, only the expected
// title, because other rules can legitimately fire on the same host.
func (m *TheHiveAlertGeneratedAssertion) Cleanup(ctx context.Context, correlationID string) error {
	if err := m.validateClosedStatus(ctx); err != nil {
		return err
	}

	alerts, err := m.AlertsAPI.FindAlerts(ctx, m.buildAlertFilter(m.AlertFilter.Correlation == CorrelationHost, true))
	if err != nil {
		return fmt.Errorf("unable to search for TheHive alerts: %w", err)
	}

	for i := range alerts {
		matches, err := m.alertMatchesExecution(ctx, alerts[i], correlationID)
		if err != nil {
			return err
		}
		if !matches {
			continue
		}
		update := AlertUpdate{Status: m.ClosedStatus}
		if m.CleanupTag != "" {
			update.AddTags = []string{m.CleanupTag}
		}
		if err := m.AlertsAPI.UpdateAlert(ctx, alerts[i].ID, update); err != nil {
			return fmt.Errorf("unable to close alert %s: %w", alerts[i].ID, err)
		}
	}

	return nil
}

// validateClosedStatus checks that ClosedStatus is set and, when the status
// list can be read, that it belongs to the Closed stage.
func (m *TheHiveAlertGeneratedAssertion) validateClosedStatus(ctx context.Context) error {
	if m.ClosedStatus == "" {
		return errors.New("TheHive cleanup needs a Closed-stage alert status: set THEHIVE_CLOSED_STATUS")
	}
	statuses, err := m.AlertsAPI.ListAlertStatuses(ctx)
	if err != nil {
		// TheHive rejects unknown statuses on update anyway.
		log.Warnf("unable to list TheHive alert statuses, not validating '%s': %v", m.ClosedStatus, err)
		return nil
	}
	for _, status := range statuses {
		if status.Value == m.ClosedStatus {
			if status.Stage != closedStage {
				return fmt.Errorf("TheHive alert status '%s' is in stage '%s', not '%s'", m.ClosedStatus, status.Stage, closedStage)
			}
			return nil
		}
	}
	return fmt.Errorf("TheHive alert status '%s' does not exist", m.ClosedStatus)
}

// buildAlertFilter builds a listAlert filter over the lookback window, or
// from NotBefore with host correlation. The title is included when withTitle
// is set; openOnly excludes Closed-stage alerts.
func (m *TheHiveAlertGeneratedAssertion) buildAlertFilter(withTitle, openOnly bool) map[string]any {
	since := sinceValue()
	if m.AlertFilter.Correlation == CorrelationHost && !m.NotBefore.IsZero() {
		since = m.NotBefore.UnixMilli()
	}
	clauses := []map[string]any{
		{"_gte": map[string]any{"_field": "_createdAt", "_value": since}},
	}
	if withTitle && m.AlertFilter.Title != "" {
		clauses = append(clauses, eq("title", m.AlertFilter.Title))
	}
	if m.AlertFilter.Source != "" {
		clauses = append(clauses, eq("source", m.AlertFilter.Source))
	}
	if openOnly {
		clauses = append(clauses, map[string]any{"_not": eq("stage", closedStage)})
	}
	return map[string]any{"_and": clauses}
}

func eq(field string, value any) map[string]any {
	return map[string]any{"_eq": map[string]any{"_field": field, "_value": value}}
}

func withName(name string, step map[string]any) map[string]any {
	named := map[string]any{"_name": name}
	for k, v := range step {
		named[k] = v
	}
	return named
}

// sinceValue returns the lower bound of the alert search window, in epoch
// milliseconds.
func sinceValue() int64 {
	return time.Now().Add(-AlertLookbackWindow).UnixMilli()
}

// alertMatchesExecution reports whether the alert references the detonation
// UUID. The UUID is usually embedded in a longer value (a user agent or a
// command line), so this is a substring match. Without ObservableField, the
// alert description is checked before fetching observables.
func (m *TheHiveAlertGeneratedAssertion) alertMatchesExecution(ctx context.Context, alert Alert, uid string) (bool, error) {
	if m.AlertFilter.Correlation == CorrelationHost {
		return m.alertMatchesHost(ctx, alert)
	}
	field := m.AlertFilter.ObservableField
	if field == "" && strings.Contains(alert.Description, uid) {
		return true, nil
	}

	observables, err := m.getObservables(ctx, alert.ID)
	if err != nil {
		return false, fmt.Errorf("unable to fetch observables of alert %s: %w", alert.ID, err)
	}
	for _, observable := range observables {
		if field != "" && !slices.Contains(observable.Tags, "field:"+field) {
			continue
		}
		if strings.Contains(observable.Data, uid) {
			return true, nil
		}
	}
	return false, nil
}

// alertMatchesHost reports whether the alert has an observable equal to one
// of the detonation host's addresses. The comparison is exact (ignoring case
// and surrounding whitespace) so 10.0.0.5 does not match 10.0.0.50.
func (m *TheHiveAlertGeneratedAssertion) alertMatchesHost(ctx context.Context, alert Alert) (bool, error) {
	if len(m.AlertFilter.Hosts) == 0 {
		return false, errors.New("TheHive host correlation needs the detonation host's addresses: set THEHIVE_DETONATION_HOSTS")
	}
	observables, err := m.getObservables(ctx, alert.ID)
	if err != nil {
		return false, fmt.Errorf("unable to fetch observables of alert %s: %w", alert.ID, err)
	}
	field := m.AlertFilter.ObservableField
	for _, observable := range observables {
		if field != "" && !slices.Contains(observable.Tags, "field:"+field) {
			continue
		}
		data := strings.TrimSpace(observable.Data)
		for _, host := range m.AlertFilter.Hosts {
			if strings.EqualFold(data, host) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (m *TheHiveAlertGeneratedAssertion) getObservables(ctx context.Context, alertID string) ([]Observable, error) {
	m.mu.Lock()
	cached, ok := m.observables[alertID]
	m.mu.Unlock()
	if ok {
		return cached, nil
	}

	observables, err := m.AlertsAPI.FindObservables(ctx, alertID)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	if m.observables == nil {
		m.observables = make(map[string][]Observable)
	}
	m.observables[alertID] = observables
	m.mu.Unlock()
	return observables, nil
}

func convertAlert(alert Alert) matchers.ThreatestEvent {
	return matchers.ThreatestEvent{
		EventName: alert.Title,
		Time:      time.UnixMilli(alert.CreatedAt).UTC(),
		Attributes: map[string]any{
			"id":        alert.ID,
			"title":     alert.Title,
			"source":    alert.Source,
			"sourceRef": alert.SourceRef,
			"status":    alert.Status,
			"stage":     alert.Stage,
			"tags":      alert.Tags,
		},
		Body: alert.Raw,
	}
}
