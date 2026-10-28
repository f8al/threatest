package thehive

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/datadog/threatest/pkg/threatest/matchers/internal/httpclient"
	"github.com/datadog/threatest/pkg/threatest/secret"
)

// TheHiveAlertFilter holds filtering criteria for TheHive alerts.
type TheHiveAlertFilter struct {
	Title  string
	Source string
	// ObservableField restricts UUID matching to observables tagged
	// "field:<ObservableField>", the tag TA-thehive-cortex sets from the
	// Splunk field name.
	ObservableField string
	// Correlation is CorrelationUUID (default) or CorrelationHost.
	Correlation string
	// Hosts are the detonation host's addresses (IPs, hostnames) matched
	// against observables with host correlation.
	Hosts []string
}

// TheHiveAlertGeneratedAssertion verifies that an expected TheHive alert was
// generated.
type TheHiveAlertGeneratedAssertion struct {
	AlertsAPI   TheHiveAlertsAPI
	AlertFilter *TheHiveAlertFilter
	// ClosedStatus is the alert status set during cleanup. It must belong to
	// the Closed stage.
	ClosedStatus string
	// CleanupTag is added to alerts closed during cleanup. Empty adds no tag.
	CleanupTag string
	// NotBefore excludes alerts created earlier with host correlation. The
	// builder sets it to its creation time, which precedes the detonation.
	NotBefore time.Time

	// observables caches each alert's observables across polls. The alert
	// action creates an alert and its observables in one request.
	mu          sync.Mutex
	observables map[string][]Observable
}

// TheHiveAlertGeneratedAssertionBuilder constructs a
// TheHiveAlertGeneratedAssertion using the builder pattern.
type TheHiveAlertGeneratedAssertionBuilder struct {
	TheHiveAlertGeneratedAssertion
}

// Option configures a TheHiveAlertGeneratedAssertionBuilder.
type Option func(*TheHiveAlertGeneratedAssertionBuilder)

// WithCredentials overrides the default environment-variable-based
// credentials (THEHIVE_URL, THEHIVE_API_KEY, THEHIVE_ORGANISATION,
// THEHIVE_CA_CERT, THEHIVE_INSECURE_SKIP_VERIFY).
func WithCredentials(baseURL, apiKey, organisation string, tlsOpts httpclient.TLSOptions) Option {
	return func(b *TheHiveAlertGeneratedAssertionBuilder) {
		b.AlertsAPI = newAlertsAPI(baseURL, apiKey, organisation, tlsOpts)
	}
}

// WithSource filters alerts by source (e.g. "splunk").
func WithSource(source string) Option {
	return func(b *TheHiveAlertGeneratedAssertionBuilder) {
		b.AlertFilter.Source = source
	}
}

// WithObservableField restricts UUID matching to observables tagged
// "field:<name>".
func WithObservableField(name string) Option {
	return func(b *TheHiveAlertGeneratedAssertionBuilder) {
		b.AlertFilter.ObservableField = name
	}
}

// WithHostCorrelation matches alerts on the detonation host's addresses
// instead of the detonation UUID. With no hosts, the addresses are read from
// THEHIVE_DETONATION_HOSTS (comma-separated).
func WithHostCorrelation(hosts ...string) Option {
	return func(b *TheHiveAlertGeneratedAssertionBuilder) {
		b.AlertFilter.Correlation = CorrelationHost
		if len(hosts) > 0 {
			b.AlertFilter.Hosts = hosts
		}
	}
}

// WithCleanupTag sets the tag added to matched alerts during cleanup,
// overriding THEHIVE_CLEANUP_TAG.
func WithCleanupTag(tag string) Option {
	return func(b *TheHiveAlertGeneratedAssertionBuilder) {
		b.CleanupTag = tag
	}
}

// WithClosedStatus sets the status applied to matched alerts during cleanup,
// overriding THEHIVE_CLOSED_STATUS.
func WithClosedStatus(status string) Option {
	return func(b *TheHiveAlertGeneratedAssertionBuilder) {
		b.ClosedStatus = status
	}
}

// newAlertsAPI creates a TheHiveAlertsAPI with explicit credentials.
func newAlertsAPI(baseURL, apiKey, organisation string, tlsOpts httpclient.TLSOptions) TheHiveAlertsAPI {
	client, err := httpclient.New(requestTimeout, tlsOpts)
	return &TheHiveAlertsAPIImpl{
		baseURL:      strings.TrimRight(baseURL, "/"),
		apiKey:       secret.New(apiKey),
		organisation: organisation,
		client:       client,
		clientErr:    err,
	}
}

// TheHiveAlert creates a builder for matching TheHive alerts by title. By
// default, credentials are read from the THEHIVE_URL and THEHIVE_API_KEY
// environment variables. THEHIVE_ORGANISATION selects an organisation,
// THEHIVE_CLOSED_STATUS (default "Other") sets the cleanup status,
// THEHIVE_CLEANUP_TAG (default "Control Validation") sets the cleanup tag,
// THEHIVE_CA_CERT points to a
// PEM bundle for a private CA and THEHIVE_INSECURE_SKIP_VERIFY=true disables
// certificate verification.
func TheHiveAlert(title string, opts ...Option) *TheHiveAlertGeneratedAssertionBuilder {
	insecure, _ := strconv.ParseBool(os.Getenv("THEHIVE_INSECURE_SKIP_VERIFY"))
	builder := &TheHiveAlertGeneratedAssertionBuilder{}
	builder.AlertsAPI = newAlertsAPI(
		os.Getenv("THEHIVE_URL"),
		os.Getenv("THEHIVE_API_KEY"),
		os.Getenv("THEHIVE_ORGANISATION"),
		httpclient.TLSOptions{
			CACertFile:         os.Getenv("THEHIVE_CA_CERT"),
			InsecureSkipVerify: insecure,
		},
	)
	builder.AlertFilter = &TheHiveAlertFilter{
		Title:       title,
		Correlation: CorrelationUUID,
		Hosts:       splitList(os.Getenv("THEHIVE_DETONATION_HOSTS")),
	}
	builder.NotBefore = time.Now()
	builder.ClosedStatus = envOrDefault("THEHIVE_CLOSED_STATUS", DefaultClosedStatus)
	builder.CleanupTag = envOrDefault("THEHIVE_CLEANUP_TAG", DefaultCleanupTag)

	for _, opt := range opts {
		opt(builder)
	}

	return builder
}

func envOrDefault(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
