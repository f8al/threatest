//go:build integration

// Package integration checks the Splunk and TheHive matchers against live
// instances. Run with:
//
//	go test -tags integration ./pkg/threatest/matchers/integration/ -v
//
// Each test is skipped unless its credentials are set in the environment.
// The tests only read: they never create, update or close anything.
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/datadog/threatest/pkg/threatest/matchers"
	"github.com/datadog/threatest/pkg/threatest/matchers/splunk"
	"github.com/datadog/threatest/pkg/threatest/matchers/thehive"
	"github.com/stretchr/testify/require"
)

func requireEnv(t *testing.T, names ...string) {
	for _, name := range names {
		if os.Getenv(name) == "" {
			t.Skipf("%s not set", name)
		}
	}
}

func TestSplunkSearch(t *testing.T) {
	requireEnv(t, "SPLUNK_URL", "SPLUNK_TOKEN")

	m := splunk.SplunkLog()
	events, err := m.Search(context.Background(), "| makeresults count=3 | eval marker=\"threatest\"",
		matchers.WithTimeRange(time.Now().Add(-time.Minute), time.Now()))
	require.NoError(t, err)
	require.Len(t, events, 3)
}

func TestSplunkRelatedNoMatch(t *testing.T) {
	requireEnv(t, "SPLUNK_URL", "SPLUNK_TOKEN")

	found, err := splunk.SplunkLog().HasExpected(context.Background(), "00000000-0000-0000-0000-000000000000")
	require.NoError(t, err)
	require.False(t, found)
}

func TestTheHiveRelated(t *testing.T) {
	requireEnv(t, "THEHIVE_URL", "THEHIVE_API_KEY")

	// An unused UUID: this exercises auth, the query chain and pagination over
	// the past hour of alerts without matching any of them.
	m := thehive.TheHiveAlert("", thehive.WithSource(os.Getenv("THEHIVE_TEST_SOURCE")))
	events, err := m.Related(context.Background(), "00000000-0000-0000-0000-000000000000")
	require.NoError(t, err)
	require.Empty(t, events)
}
