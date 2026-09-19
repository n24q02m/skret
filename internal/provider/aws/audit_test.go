package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLookuper replays canned pages per LookupEvents call.
type fakeLookuper struct {
	pages []cloudtrailtypes.Event
	token bool // when true, every response carries a NextToken (never exhausted)
	calls int
	names []string // EventName of each call, in order
	err   error
}

func (f *fakeLookuper) LookupEvents(_ context.Context, params *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if len(params.LookupAttributes) == 1 {
		f.names = append(f.names, *params.LookupAttributes[0].AttributeValue)
	}
	out := &cloudtrail.LookupEventsOutput{Events: f.pages}
	if f.token {
		tok := "more"
		out.NextToken = &tok
	}
	return out, nil
}

// ctEvent builds one LookupEvents entry: an SSM parameter event envelope.
func ctEvent(id string, at time.Time, eventName, parameter, user, ip string) cloudtrailtypes.Event {
	ev := fmt.Sprintf(`{"eventSource":"ssm.amazonaws.com","eventName":%q,"awsRegion":"us-east-1",
		"sourceIPAddress":%q,"userName":%q,
		"requestParameters":{"name":%q}}`, eventName, ip, user, parameter)
	return cloudtrailtypes.Event{
		EventId:         &id,
		EventTime:       &at,
		CloudTrailEvent: &ev,
	}
}

func TestLookupParameterEvents_MergesDedupesAndSorts(t *testing.T) {
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	older := t0.Add(-time.Hour)
	lookuper := &fakeLookuper{
		pages: []cloudtrailtypes.Event{
			ctEvent("id-1", older, "GetParameter", "/app/prod/API_KEY", "alice", "1.2.3.4"),
			ctEvent("id-2", t0, "PutParameter", "/app/prod/API_KEY", "bob", "5.6.7.8"),
			ctEvent("id-1", older, "GetParameter", "/app/prod/API_KEY", "alice", "1.2.3.4"), // dup across lookups
		},
	}

	events, err := LookupParameterEvents(context.Background(), lookuper, AuditLookupOpts{})
	require.NoError(t, err)
	require.Len(t, events, 2, "duplicate event IDs collapse")

	assert.Equal(t, "PutParameter", events[0].Event, "newest first")
	assert.Equal(t, t0.Format(time.RFC3339), events[0].Time)
	assert.Equal(t, "/app/prod/API_KEY", events[0].Parameter)
	assert.Equal(t, "bob", events[0].Username)
	assert.Equal(t, "5.6.7.8", events[0].SourceIP)
	assert.Equal(t, "us-east-1", events[0].Region)
	assert.Equal(t, "id-2", events[0].EventID)

	assert.Equal(t, "GetParameter", events[1].Event)

	// Every SSM parameter event name was looked up, exactly once each.
	assert.Len(t, lookuper.names, len(ssmParameterEventNames))
	seen := map[string]bool{}
	for _, n := range lookuper.names {
		seen[n] = true
	}
	assert.Len(t, seen, len(ssmParameterEventNames), "one lookup per event name")
}

func TestLookupParameterEvents_SinceBound(t *testing.T) {
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	capt := &capturingLookuper{}
	_, err := LookupParameterEvents(context.Background(), capt, AuditLookupOpts{Since: since})
	require.NoError(t, err)
	require.NotEmpty(t, capt.inputs)
	for _, in := range capt.inputs {
		require.NotNil(t, in.StartTime)
		assert.True(t, in.StartTime.Equal(since), "lookup window start == --since")
		require.Len(t, in.LookupAttributes, 1, "LookupEvents accepts at most one lookup attribute")
		assert.Equal(t, cloudtrailtypes.LookupAttributeKeyEventName, in.LookupAttributes[0].AttributeKey)
	}
}

// capturingLookuper records every input for assertion.
type capturingLookuper struct {
	inputs []*cloudtrail.LookupEventsInput
}

func (c *capturingLookuper) LookupEvents(_ context.Context, params *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	c.inputs = append(c.inputs, params)
	return &cloudtrail.LookupEventsOutput{}, nil
}

func TestLookupParameterEvents_KeyFilter(t *testing.T) {
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	lookuper := &fakeLookuper{pages: []cloudtrailtypes.Event{
		ctEvent("id-1", t0, "GetParameter", "/app/prod/API_KEY", "alice", ""),
		ctEvent("id-2", t0, "GetParameter", "/app/prod/DB_PASS", "bob", ""),
	}}

	events, err := LookupParameterEvents(context.Background(), lookuper, AuditLookupOpts{Key: "/app/prod/DB_PASS"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "/app/prod/DB_PASS", events[0].Parameter)
}

func TestLookupParameterEvents_Limit(t *testing.T) {
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	var pages []cloudtrailtypes.Event
	for i := range 12 {
		pages = append(pages, ctEvent(fmt.Sprintf("id-%d", i), t0.Add(time.Duration(i)*time.Minute), "GetParameter", fmt.Sprintf("/p/K%d", i), "u", ""))
	}
	lookuper := &fakeLookuper{pages: pages}

	events, err := LookupParameterEvents(context.Background(), lookuper, AuditLookupOpts{Limit: 5})
	require.NoError(t, err)
	require.Len(t, events, 5)
	assert.Equal(t, "/p/K11", events[0].Parameter, "limit keeps the newest events")
}

func TestLookupParameterEvents_DropsNonSSMAndUnparseable(t *testing.T) {
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	bad := `{"eventSource":"s3.amazonaws.com","eventName":"GetObject","requestParameters":{}}`
	broken := `{not-json`
	noParam := `{"eventSource":"ssm.amazonaws.com","eventName":"ListDocuments","requestParameters":{}}`
	id := "id-x"
	lookuper := &fakeLookuper{pages: []cloudtrailtypes.Event{
		{EventId: &id, EventTime: &t0, CloudTrailEvent: &bad},
		{EventId: &id, EventTime: &t0, CloudTrailEvent: &broken},
		{EventId: &id, EventTime: &t0, CloudTrailEvent: &noParam},
	}}

	events, err := LookupParameterEvents(context.Background(), lookuper, AuditLookupOpts{})
	require.NoError(t, err)
	assert.Empty(t, events, "non-SSM, unparseable, and parameter-less events are dropped")
}

func TestLookupParameterEvents_ARNFallbackForParameterName(t *testing.T) {
	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	arn := "arn:aws:ssm:us-east-1:123456789012:parameter/app/prod/API_KEY"
	ev := `{"eventSource":"ssm.amazonaws.com","eventName":"GetParameter","requestParameters":{},"userIdentity":{"arn":"arn:aws:sts::123456789012:assumed-role/DeployRole/i-abc"}}`
	resName := arn
	id := "id-arn"
	lookuper := &fakeLookuper{pages: []cloudtrailtypes.Event{{
		EventId:         &id,
		EventTime:       &t0,
		CloudTrailEvent: &ev,
		Resources:       []cloudtrailtypes.Resource{{ResourceName: &resName}},
	}}}

	events, err := LookupParameterEvents(context.Background(), lookuper, AuditLookupOpts{})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "app/prod/API_KEY", events[0].Parameter, "name falls back to the resource ARN tail")
	assert.Equal(t, "i-abc", events[0].Username, "assumed-role session name becomes the actor")
}

func TestLookupParameterEvents_BoundedPagination(t *testing.T) {
	lookuper := &fakeLookuper{token: true}

	_, err := LookupParameterEvents(context.Background(), lookuper, AuditLookupOpts{})
	require.NoError(t, err)
	assert.LessOrEqual(t, lookuper.calls, auditPagesPerEvent*len(ssmParameterEventNames),
		"pagination stops at the per-name page budget even when the service keeps paging")
}

func TestLookupParameterEvents_LookupError(t *testing.T) {
	lookuper := &fakeLookuper{err: errors.New("AccessDeniedException: not authorized")}
	_, err := LookupParameterEvents(context.Background(), lookuper, AuditLookupOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloudtrail lookup")
	assert.Contains(t, err.Error(), "not authorized")
}
