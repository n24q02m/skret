package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/n24q02m/skret/internal/config"
)

// CloudTrailLookuper abstracts the CloudTrail LookupEvents API for testing.
type CloudTrailLookuper interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// ssmParameterEventNames is the closed set of SSM Parameter Store
// operations skret exports: the writes skret issues (Put/Delete) and the
// reads skret's own commands use (GetParameter via `get`, GetParameters via
// batch reads, GetParametersByPath via `env`/`list`, GetParameterHistory
// via `history`).
var ssmParameterEventNames = []string{
	"GetParameter",
	"GetParameters",
	"GetParametersByPath",
	"GetParameterHistory",
	"PutParameter",
	"DeleteParameter",
	"DeleteParameters",
}

// auditPagesPerEvent bounds pagination per event name. LookupEvents pages at
// 50 events, so the default scans at most 500 events per name (3.5k total)
// before rendering -- a bounded, predictable cost for a CLI call.
const auditPagesPerEvent = 10

// AuditEvent is the rendered form of one CloudTrail SSM parameter event.
// Only metadata is carried: CloudTrail never logs parameter values, and the
// parser below extracts fixed fields only.
type AuditEvent struct {
	Time      string `json:"time"` // RFC3339, UTC
	Event     string `json:"event"`
	Parameter string `json:"parameter"`
	Username  string `json:"username,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
	Region    string `json:"region,omitempty"`
	EventID   string `json:"event_id,omitempty"`
}

// AuditLookupOpts bound and filter a LookupEvents sweep.
type AuditLookupOpts struct {
	// Since is the lookup window start (zero = CloudTrail's default, the
	// last 90 days -- the service's lookup retention).
	Since time.Time
	// Limit caps rendered events (0 = unbounded within the page budget).
	Limit int
	// Key filters by exact SSM parameter name ("" = no filter).
	Key string
}

// NewCloudTrailLookuper builds a CloudTrail client with the exact credential
// resolution the SSM provider uses (skret-stored credential, then profile,
// then the standard SDK chain).
func NewCloudTrailLookuper(cfg *config.ResolvedConfig) (CloudTrailLookuper, error) {
	creds, storedProfile, _ := resolveStoredCredentials()

	profile := cfg.Profile
	if profile == "" {
		profile = storedProfile
	}

	awsCfg, err := loadAWSConfig(context.Background(), cfg.Region, profile, creds)
	if err != nil {
		return nil, fmt.Errorf("aws: load config for cloudtrail: %w", err)
	}
	return cloudtrail.NewFromConfig(awsCfg), nil
}

// cloudTrailEvent is the subset of the CloudTrailEvent JSON envelope the
// renderer needs (LookupEvents returns it as a JSON string).
type cloudTrailEvent struct {
	EventName       string `json:"eventName"`
	EventSource     string `json:"eventSource"`
	AWSRegion       string `json:"awsRegion"`
	SourceIPAddress string `json:"sourceIPAddress"`
	UserName        string `json:"userName"`
	// RequestIdentity carries identity when userName is absent (assumed
	// roles, federated users).
	RequestIdentity struct {
		Arn string `json:"arn"`
	} `json:"userIdentity"`
	RequestParameters struct {
		Name string `json:"name"`
		Path string `json:"path"`
	} `json:"requestParameters"`
}

// LookupParameterEvents sweeps LookupEvents once per parameter event name
// (the API accepts at most one lookup attribute per call), merges, dedupes
// by event ID, and returns events newest-first. Names are exact-filtered by
// opts.Key after the merge.
func LookupParameterEvents(ctx context.Context, ct CloudTrailLookuper, opts AuditLookupOpts) ([]AuditEvent, error) {
	byID := make(map[string]AuditEvent)

	for _, name := range ssmParameterEventNames {
		input := &cloudtrail.LookupEventsInput{
			LookupAttributes: []cloudtrailtypes.LookupAttribute{{
				AttributeKey:   cloudtrailtypes.LookupAttributeKeyEventName,
				AttributeValue: &name,
			}},
		}
		if !opts.Since.IsZero() {
			input.StartTime = &opts.Since
		}

		for page := 0; page < auditPagesPerEvent; page++ {
			out, err := ct.LookupEvents(ctx, input)
			if err != nil {
				return nil, fmt.Errorf("aws: cloudtrail lookup %s: %w", name, err)
			}
			for _, ev := range out.Events {
				if ev.EventId == nil || *ev.EventId == "" {
					continue
				}
				if _, seen := byID[*ev.EventId]; seen {
					continue
				}
				ae, ok := renderAuditEvent(ev)
				if !ok {
					continue
				}
				byID[*ev.EventId] = ae
			}
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			input.NextToken = out.NextToken
		}

		if opts.Limit > 0 && len(byID) >= opts.Limit {
			break
		}
	}

	events := make([]AuditEvent, 0, len(byID))
	for _, e := range byID {
		if opts.Key != "" && e.Parameter != opts.Key {
			continue
		}
		events = append(events, e)
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Time != events[j].Time {
			return events[i].Time > events[j].Time
		}
		return events[i].EventID < events[j].EventID
	})
	if opts.Limit > 0 && len(events) > opts.Limit {
		events = events[:opts.Limit]
	}
	return events, nil
}

// renderAuditEvent converts one LookupEvents entry. Entries that are not SSM
// parameter events, or whose envelope does not parse, are dropped (ok=false)
// rather than rendered with unknown fields.
func renderAuditEvent(ev cloudtrailtypes.Event) (AuditEvent, bool) {
	if ev.EventId == nil {
		return AuditEvent{}, false
	}
	var envelope cloudTrailEvent
	if ev.CloudTrailEvent == nil || json.Unmarshal([]byte(*ev.CloudTrailEvent), &envelope) != nil {
		return AuditEvent{}, false
	}
	if envelope.EventSource != "ssm.amazonaws.com" {
		return AuditEvent{}, false
	}

	parameter := envelope.RequestParameters.Name
	if parameter == "" {
		parameter = envelope.RequestParameters.Path
	}
	if parameter == "" {
		parameter = parameterFromARNs(ev.Resources)
	}
	if parameter == "" {
		return AuditEvent{}, false
	}

	actor := envelope.UserName
	if actor == "" {
		actor = actorFromARN(envelope.RequestIdentity.Arn)
	}

	out := AuditEvent{
		Event:     envelope.EventName,
		Parameter: parameter,
		Username:  actor,
		SourceIP:  envelope.SourceIPAddress,
		Region:    envelope.AWSRegion,
		EventID:   *ev.EventId,
	}
	if ev.EventTime != nil {
		out.Time = ev.EventTime.UTC().Format(time.RFC3339)
	}
	return out, true
}

// parameterFromARNs extracts the parameter name from resource ARNs
// (arn:aws:ssm:<region>:<account>:parameter/<name>) when requestParameters
// carries no name (older event shapes).
func parameterFromARNs(resources []cloudtrailtypes.Resource) string {
	for _, r := range resources {
		if r.ResourceName == nil {
			continue
		}
		const marker = ":parameter/"
		if idx := strings.Index(*r.ResourceName, marker); idx >= 0 {
			return (*r.ResourceName)[idx+len(marker):]
		}
	}
	return ""
}

// actorFromARN reduces an assumed-role / STS ARN to its usable tail
// (role/session name) for display.
func actorFromARN(arn string) string {
	if arn == "" {
		return ""
	}
	if idx := strings.LastIndex(arn, "/"); idx >= 0 {
		return arn[idx+1:]
	}
	if idx := strings.LastIndex(arn, ":"); idx >= 0 {
		return arn[idx+1:]
	}
	return arn
}
