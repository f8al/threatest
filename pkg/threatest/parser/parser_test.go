package parser

import (
	"fmt"
	"github.com/datadog/threatest/pkg/threatest/matchers/splunk"
	"github.com/datadog/threatest/pkg/threatest/matchers/thehive"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

// TestParserRejectsDetonatorWithMissingRequiredField ensures the parser returns
// an error (instead of panicking with a nil pointer dereference) when a
// detonator block is present in the YAML but its required inner field is
// omitted.
func TestParserRejectsDetonatorWithMissingRequiredField(t *testing.T) {
	cases := []struct {
		name          string
		yamlInput     string
		expectedError string
	}{
		{
			name: "awsCliDetonator without script",
			yamlInput: `
scenarios:
  - name: A
    detonate:
      awsCliDetonator: {}
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: foo
`,
			expectedError: "scenario 'A' has an AWS CLI detonator with no script defined",
		},
		{
			name: "stratusRedTeamDetonator without attackTechnique",
			yamlInput: `
scenarios:
  - name: B
    detonate:
      stratusRedTeamDetonator: {}
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: foo
`,
			expectedError: "scenario 'B' has a Stratus Red Team detonator with no attackTechnique defined",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scenarios, err := Parse([]byte(tc.yamlInput), "", "", "")
			assert.Nil(t, scenarios)
			assert.EqualError(t, err, tc.expectedError)
		})
	}
}

func TestParserCorrectlyParsesValidInput(t *testing.T) {
	validYaml := `
scenarios:
  # Example 1: Remote detonation over SSH
  # Note: SSH configuration is provided using the --ssh-host, --ssh-username and --ssh-keyfile CLI arguments
  - name: curl metadata service
    detonate:
      remoteDetonator:
        commands: ["curl http://169.254.169.254 --connect-timeout 1"]
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: "Network utility accessed cloud metadata service"
          severity: medium

  # Example 2: Stratus Red Team detonation
  # Note: You must be authenticated to the relevant cloud provider before running it
  # The example below is equivalent to manually running "stratus detonate aws.exfiltration.ec2-security-group-open-port-22-ingress"
  - name: opening a security group to the Internet
    detonate:
      stratusRedTeamDetonator:
        attackTechnique: aws.exfiltration.ec2-security-group-open-port-22-ingress
    expectations:
      - timeout: 15m
        datadogSecuritySignal:
          name: "Potential administrative port open to the world via AWS security group"

  # Example 3: Elastic Security detection alert expectation
  - name: curl metadata service detected by Elastic
    detonate:
      remoteDetonator:
        commands: ["curl http://169.254.169.254 --connect-timeout 1"]
    expectations:
      - timeout: 1m
        elasticSecuritySignal:
          name: "Network utility accessed cloud metadata service"
          severity: medium
`
	scenarios, err := Parse([]byte(validYaml), "", "", "")
	assert.Nil(t, err, "parsing a valid YAML scenario file should not return an error")
	assert.Len(t, scenarios, 3)

	assert.Equal(t, scenarios[0].Name, "curl metadata service")
	assert.NotNil(t, scenarios[0].Detonator)
	assert.Len(t, scenarios[0].TelemetryAssertions, 1)

	assert.Equal(t, scenarios[1].Name, "opening a security group to the Internet")
	assert.NotNil(t, scenarios[1].Detonator)
	assert.Len(t, scenarios[1].TelemetryAssertions, 1)

	assert.Equal(t, scenarios[2].Name, "curl metadata service detected by Elastic")
	assert.NotNil(t, scenarios[2].Detonator)
	assert.Len(t, scenarios[2].TelemetryAssertions, 1)
	assert.Equal(t, "Elastic Security alert 'Network utility accessed cloud metadata service'", scenarios[2].TelemetryAssertions[0].Matcher.String())
}

func TestParserParsesNewTelemetryBlocksAndDiscoverFlag(t *testing.T) {
	yamlInput := `
scenarios:
  - name: discover logs and events
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 5m
        datadogLog:
          query: "<% .CorrelationID %>"
        discover: true
      - timeout: 5m
        datadogEvent:
          query: "stratus-red-team"
        discover: true
      - timeout: 5m
        datadogSecuritySignal:
          name: "some signal"
        discover: true
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, err, "parsing new telemetry blocks should not error")
	assert.Len(t, scenarios, 1)
	assert.Equal(t, "discover logs and events", scenarios[0].Name)
	assert.NotNil(t, scenarios[0].Detonator)
	assert.Len(t, scenarios[0].TelemetryAssertions, 3)
	assert.True(t, scenarios[0].TelemetryAssertions[0].Discover)
	assert.Equal(t, "<% .CorrelationID %>", scenarios[0].TelemetryAssertions[0].Query)
	assert.True(t, scenarios[0].TelemetryAssertions[1].Discover)
	assert.Equal(t, "stratus-red-team", scenarios[0].TelemetryAssertions[1].Query)
	assert.True(t, scenarios[0].TelemetryAssertions[2].Discover)
}

func TestParserParsesDiscoverDefaultFalse(t *testing.T) {
	yamlInput := `
scenarios:
  - name: assert only
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: foo
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, err)
	assert.Len(t, scenarios, 1)
	assert.Len(t, scenarios[0].TelemetryAssertions, 1)
	assert.False(t, scenarios[0].TelemetryAssertions[0].Discover)
}

func TestParserRejectsElasticDiscover(t *testing.T) {
	yamlInput := `
scenarios:
  - name: elastic discover
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        elasticSecuritySignal:
          name: foo
        discover: true
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, scenarios)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "discover mode is not supported for Elastic Security")
}

func TestParserRejectsAlertQueryWithoutDiscover(t *testing.T) {
	yamlInput := `
scenarios:
  - name: alert query without discover
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: foo
          query: "service:aws"
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, scenarios)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "query on datadogSecuritySignal is only supported with discover: true")
}

func TestParserRejectsMissingSignalName(t *testing.T) {
	yamlInput := `
scenarios:
  - name: missing name
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        datadogSecuritySignal: {}
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, scenarios)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "datadogSecuritySignal.name is required when discover is false")
}

func TestParserParsesSplunkAndTheHiveBlocks(t *testing.T) {
	yamlInput := `
scenarios:
  - name: aws cloudtrail stop logging
    detonate:
      stratusRedTeamDetonator:
        attackTechnique: aws.defense-evasion.cloudtrail-stop
    expectations:
      - timeout: 30m
        theHiveAlert:
          title: "AWS Defense Evasion Stop Logging Cloudtrail"
          source: splunk
          observableField: userAgent
      - timeout: 30m
        splunkLog:
          query: 'index=aws_cloudtrail "<% .CorrelationID %>"'
        discover: true
      - splunkLog:
          indexes: [aws_cloudtrail]
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	require.NoError(t, err)
	require.Len(t, scenarios, 1)

	assertions := scenarios[0].TelemetryAssertions
	require.Len(t, assertions, 3)

	alert := assertions[0].Matcher.(*thehive.TheHiveAlertGeneratedAssertionBuilder)
	assert.Equal(t, "AWS Defense Evasion Stop Logging Cloudtrail", alert.AlertFilter.Title)
	assert.Equal(t, "splunk", alert.AlertFilter.Source)
	assert.Equal(t, "userAgent", alert.AlertFilter.ObservableField)
	assert.False(t, assertions[0].Discover)

	discovery := assertions[1].Matcher.(*splunk.Builder)
	assert.True(t, assertions[1].Discover)
	assert.Equal(t, `index=aws_cloudtrail "<% .CorrelationID %>"`, assertions[1].Query)
	assert.Equal(t, `index=aws_cloudtrail "<% .CorrelationID %>"`, discovery.Filter.Query)

	presence := assertions[2].Matcher.(*splunk.Builder)
	assert.Equal(t, []string{"aws_cloudtrail"}, presence.Filter.Indexes)
}

func TestParserRejectsMissingTheHiveTitle(t *testing.T) {
	yamlInput := `
scenarios:
  - name: missing title
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        theHiveAlert:
          source: splunk
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, scenarios)
	assert.ErrorContains(t, err, "theHiveAlert.title is required when discover is false")
}

func TestParserAllowsTheHiveDiscoverWithoutTitle(t *testing.T) {
	yamlInput := `
scenarios:
  - name: discover alerts
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        theHiveAlert:
          source: splunk
        discover: true
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	require.NoError(t, err)
	assert.True(t, scenarios[0].TelemetryAssertions[0].Discover)
}

func TestParserTheHiveHostCorrelation(t *testing.T) {
	base := `
scenarios:
  - name: dns tunneling
    detonate:
      remoteDetonator:
        commands: ["flightsim run tunnel-dns -fast"]
    expectations:
      - timeout: 30m
        theHiveAlert:
          title: "DNS Tunneling via High Volume Unique Subdomains"
          correlation: %s
`
	scenarios, err := Parse([]byte(fmt.Sprintf(base, "host")), "host", "user", "")
	require.NoError(t, err)
	alert := scenarios[0].TelemetryAssertions[0].Matcher.(*thehive.TheHiveAlertGeneratedAssertionBuilder)
	assert.Equal(t, thehive.CorrelationHost, alert.AlertFilter.Correlation)

	scenarios, err = Parse([]byte(strings.Replace(fmt.Sprintf(base, "uuid"), "          correlation: uuid\n", "", 1)), "host", "user", "")
	require.NoError(t, err)
	alert = scenarios[0].TelemetryAssertions[0].Matcher.(*thehive.TheHiveAlertGeneratedAssertionBuilder)
	assert.Equal(t, thehive.CorrelationUUID, alert.AlertFilter.Correlation)

	_, err = Parse([]byte(fmt.Sprintf(base, "ip")), "host", "user", "")
	assert.Error(t, err)

	_, err = Parse([]byte(fmt.Sprintf(base, "host")+"        discover: true\n"), "host", "user", "")
	assert.ErrorContains(t, err, "host correlation is not supported with discover: true")
}
