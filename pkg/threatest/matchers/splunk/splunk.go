// Package splunk matches expected events in Splunk Enterprise.
package splunk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/datadog/threatest/pkg/threatest/matchers"
	"github.com/datadog/threatest/pkg/threatest/matchers/internal/httpclient"
	"github.com/datadog/threatest/pkg/threatest/querybuilder"
	"github.com/datadog/threatest/pkg/threatest/secret"
)

// lookbackWindow bounds how far back events are searched when no time range
// is given. It is wider than the Datadog logs matcher because Splunk
// timestamps are event times, which can trail the detonation by the ingest lag.
const lookbackWindow = 1 * time.Hour

const requestTimeout = 60 * time.Second

const searchPath = "/services/search/jobs"

// SearchAPI runs a blocking SPL search and returns its result rows.
type SearchAPI interface {
	Search(ctx context.Context, spl string, earliest, latest time.Time) ([]map[string]any, error)
}

type SearchAPIImpl struct {
	baseURL   string
	token     secret.Secret
	client    *http.Client
	clientErr error
}

type searchResponse struct {
	Results  []map[string]any `json:"results"`
	Messages []searchMessage  `json:"messages"`
}

type searchMessage struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Search runs spl as a oneshot search job, which blocks until the search
// completes and returns the results in the response body. Oneshot returns a
// capped number of rows, which is enough for a presence assertion; use a
// transforming query (e.g. stats) when discovering high-volume telemetry.
func (m *SearchAPIImpl) Search(ctx context.Context, spl string, earliest, latest time.Time) ([]map[string]any, error) {
	if m.baseURL == "" || m.token.Value() == "" {
		return nil, errors.New("missing Splunk credentials: set the SPLUNK_URL and SPLUNK_TOKEN env vars")
	}
	if m.clientErr != nil {
		return nil, m.clientErr
	}

	form := url.Values{}
	form.Set("search", spl)
	form.Set("exec_mode", "oneshot")
	form.Set("output_mode", "json")
	form.Set("earliest_time", strconv.FormatInt(earliest.Unix(), 10))
	form.Set("latest_time", strconv.FormatInt(latest.Unix(), 10))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL+searchPath, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.token.Value())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading search response: %w", err)
	}

	var searchResp searchResponse
	// Error responses also carry a messages list, so a decode failure here is
	// only fatal when the request succeeded.
	decodeErr := json.Unmarshal(body, &searchResp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request to %s failed with status code %d%s", searchPath, resp.StatusCode, formatMessages(searchResp.Messages))
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("error parsing search response: %w", decodeErr)
	}
	for _, msg := range searchResp.Messages {
		if msg.Type == "FATAL" || msg.Type == "ERROR" {
			return nil, fmt.Errorf("search failed:%s", formatMessages(searchResp.Messages))
		}
	}
	return searchResp.Results, nil
}

func formatMessages(msgs []searchMessage) string {
	var b strings.Builder
	for _, msg := range msgs {
		fmt.Fprintf(&b, " [%s] %s", msg.Type, msg.Text)
	}
	return b.String()
}

type Filter struct {
	Query   string
	Indexes []string
}

type Matcher struct {
	SearchAPI SearchAPI
	Filter    *Filter
}

type Builder struct {
	Matcher
}

type Option func(*Builder)

// WithCredentials overrides the default environment-variable-based
// credentials (SPLUNK_URL, SPLUNK_TOKEN, SPLUNK_CA_CERT,
// SPLUNK_INSECURE_SKIP_VERIFY).
func WithCredentials(baseURL, token string, tlsOpts httpclient.TLSOptions) Option {
	return func(b *Builder) {
		b.SearchAPI = newSearchAPI(baseURL, token, tlsOpts)
	}
}

// WithQuery sets the SPL query used to find related events. It supports the
// <% .CorrelationID %> marker.
func WithQuery(query string) Option {
	return func(b *Builder) {
		b.Filter.Query = query
	}
}

// WithIndexes restricts the default correlation query to the given indexes.
func WithIndexes(indexes ...string) Option {
	return func(b *Builder) {
		b.Filter.Indexes = indexes
	}
}

func newSearchAPI(baseURL, token string, tlsOpts httpclient.TLSOptions) SearchAPI {
	client, err := httpclient.New(requestTimeout, tlsOpts)
	return &SearchAPIImpl{
		baseURL:   strings.TrimRight(baseURL, "/"),
		token:     secret.New(token),
		client:    client,
		clientErr: err,
	}
}

// SplunkLog creates a builder for matching Splunk events. By default,
// credentials are read from the SPLUNK_URL (e.g. https://splunk:8089) and
// SPLUNK_TOKEN environment variables. SPLUNK_CA_CERT points to a PEM bundle
// for a private CA; SPLUNK_INSECURE_SKIP_VERIFY=true disables verification.
func SplunkLog(opts ...Option) *Builder {
	insecure, _ := strconv.ParseBool(os.Getenv("SPLUNK_INSECURE_SKIP_VERIFY"))
	builder := &Builder{}
	builder.SearchAPI = newSearchAPI(os.Getenv("SPLUNK_URL"), os.Getenv("SPLUNK_TOKEN"), httpclient.TLSOptions{
		CACertFile:         os.Getenv("SPLUNK_CA_CERT"),
		InsecureSkipVerify: insecure,
	})
	builder.Filter = &Filter{}
	for _, opt := range opts {
		opt(builder)
	}
	return builder
}

func (m *Matcher) HasExpected(ctx context.Context, correlationID string) (bool, error) {
	events, err := m.Related(ctx, correlationID)
	if err != nil {
		return false, err
	}
	return len(events) > 0, nil
}

func (m *Matcher) Related(ctx context.Context, correlationID string) (map[string]matchers.ThreatestEvent, error) {
	query := querybuilder.SubstituteQuery(m.defaultCorrelationQuery(correlationID), querybuilder.CorrelationVars{CorrelationID: correlationID})
	return m.Search(ctx, query)
}

func (m *Matcher) Search(ctx context.Context, query string, opts ...matchers.SearchOption) (map[string]matchers.ThreatestEvent, error) {
	o := matchers.ResolveOpts(opts)
	earliest := time.Now().Add(-lookbackWindow)
	latest := time.Now()
	if !o.From.IsZero() {
		earliest = o.From
	}
	if !o.To.IsZero() {
		latest = o.To
	}

	rows, err := m.SearchAPI.Search(ctx, normalizeQuery(query), earliest, latest)
	if err != nil {
		return nil, fmt.Errorf("unable to search Splunk: %w", err)
	}
	result := make(map[string]matchers.ThreatestEvent, len(rows))
	for i := range rows {
		id, event := convertResult(rows[i])
		result[id] = event
	}
	return result, nil
}

func (m *Matcher) String() string {
	query := m.Filter.Query
	if query == "" {
		query = "default correlation"
	}
	return fmt.Sprintf("Splunk events matching '%s'", query)
}

func (m *Matcher) Cleanup(ctx context.Context, correlationID string) error {
	return nil
}

func (m *Matcher) defaultCorrelationQuery(correlationID string) string {
	if m.Filter.Query != "" {
		return m.Filter.Query
	}
	indexes := "index=*"
	if len(m.Filter.Indexes) > 0 {
		terms := make([]string, len(m.Filter.Indexes))
		for i, index := range m.Filter.Indexes {
			terms[i] = "index=" + strconv.Quote(index)
		}
		indexes = "(" + strings.Join(terms, " OR ") + ")"
	}
	// A quoted phrase rather than a wildcard term: Splunk documents wildcards
	// around strings containing minor breakers (- and _) as unreliable.
	return fmt.Sprintf(`search %s "%s"`, indexes, correlationID)
}

// normalizeQuery prepends the search command, which the REST API requires
// for queries that don't start with a generating command.
func normalizeQuery(query string) string {
	trimmed := strings.TrimSpace(query)
	if strings.HasPrefix(trimmed, "|") || strings.HasPrefix(trimmed, "search ") {
		return trimmed
	}
	return "search " + trimmed
}

// convertResult maps a Splunk result row to a ThreatestEvent, keyed by the
// event's bucket and offset when present, else by a hash of the row.
func convertResult(row map[string]any) (string, matchers.ThreatestEvent) {
	raw, _ := json.Marshal(row)

	attrs := make(map[string]any, len(row))
	for k, v := range row {
		attrs[k] = v
	}
	if msg, ok := row["_raw"]; ok {
		attrs["message"] = msg
	}

	eventName := "splunk_event"
	if st, ok := row["sourcetype"].(string); ok && st != "" {
		eventName = st
	} else if src, ok := row["source"].(string); ok && src != "" {
		eventName = src
	}

	var ts time.Time
	if rawTime, ok := row["_time"].(string); ok {
		ts = parseTime(rawTime)
	}

	bkt, _ := row["_bkt"].(string)
	cd, _ := row["_cd"].(string)
	id := bkt + ":" + cd
	if bkt == "" || cd == "" {
		sum := sha256.Sum256(raw)
		id = hex.EncodeToString(sum[:])
	}

	return id, matchers.ThreatestEvent{
		EventName:  eventName,
		Time:       ts,
		Attributes: attrs,
		Body:       raw,
	}
}

// parseTime parses Splunk's _time, which is ISO 8601 with a numeric offset
// in JSON output, falling back to epoch seconds.
func parseTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC()
	}
	return time.Time{}
}
