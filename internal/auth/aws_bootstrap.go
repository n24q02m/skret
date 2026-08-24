package auth

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// IAMClient is the subset of IAM the bootstrap flow uses (seam for tests).
type IAMClient interface {
	GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error)
	GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	CreateUser(context.Context, *iam.CreateUserInput, ...func(*iam.Options)) (*iam.CreateUserOutput, error)
	PutUserPolicy(context.Context, *iam.PutUserPolicyInput, ...func(*iam.Options)) (*iam.PutUserPolicyOutput, error)
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	CreateAccessKey(context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
}

// STSClient confirms the bootstrap identity (and yields the account id).
type STSClient interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// BootstrapOpts configures a single provisioning run.
type BootstrapOpts struct {
	Project  string
	Path     string // SSM path prefix, e.g. /myapp/prod
	Region   string
	UserName string // default skret-<project>
}

// BootstrapResult is returned to the credential-store boundary. SecretKey
// MUST remain in memory and MUST NOT be logged or written to command output.
type BootstrapResult struct {
	Account           string
	UserName          string
	PolicyName        string
	PolicyFingerprint string
	AccessKeyID       string
	SecretKey         string
}

// PolicyConflictError means an existing IAM identity is bound to a different
// namespace policy. Bootstrap refuses to overwrite it.
type PolicyConflictError struct {
	UserName            string
	PolicyName          string
	ExpectedFingerprint string
	ExistingFingerprint string
}

func (e *PolicyConflictError) Error() string {
	return fmt.Sprintf(
		"BOOTSTRAP_POLICY_CONFLICT: policy %q on IAM user %q does not match the requested namespace (expected %s, existing %s); remediation: choose a unique --project/--user-name or reconcile the existing IAM policy before retrying",
		e.PolicyName, e.UserName, e.ExpectedFingerprint, e.ExistingFingerprint,
	)
}

// BootstrapFlow provisions a scoped, least-privilege IAM user + access key from
// a one-time admin/root identity.
type BootstrapFlow struct {
	IAM IAMClient
	STS STSClient
}

const maxAccessKeys = 2 // AWS hard cap per user

// Provision verifies the calling identity, ensures the dedicated IAM user
// exists, attaches the least-privilege inline policy, and mints a fresh access
// key. The returned BootstrapResult.SecretKey is the only secret value.
func (f *BootstrapFlow) Provision(ctx context.Context, o BootstrapOpts) (*BootstrapResult, error) {
	id, err := f.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: verify identity: %w", err)
	}
	account := aws.ToString(id.Account)

	user := o.UserName
	if user == "" {
		user = "skret-" + o.Project
	}

	if _, err := f.IAM.GetUser(ctx, &iam.GetUserInput{UserName: &user}); err != nil {
		var nse *iamtypes.NoSuchEntityException
		if !errors.As(err, &nse) {
			return nil, fmt.Errorf("bootstrap: get user %q: %w", user, err)
		}
		if _, err := f.IAM.CreateUser(ctx, &iam.CreateUserInput{UserName: &user}); err != nil {
			return nil, fmt.Errorf("bootstrap: create user %q: %w", user, err)
		}
	}

	policy, err := buildPolicy(o.Region, account, o.Path)
	if err != nil {
		return nil, err
	}
	policyName := "skret-" + o.Project
	expectedFingerprint, err := policyFingerprint(policy)
	if err != nil {
		return nil, err
	}
	existingPolicy, err := f.IAM.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
		UserName: &user, PolicyName: &policyName,
	})
	if err == nil && existingPolicy.PolicyDocument != nil {
		existingFingerprint, fingerprintErr := policyFingerprint(aws.ToString(existingPolicy.PolicyDocument))
		if fingerprintErr != nil {
			return nil, fingerprintErr
		}
		if existingFingerprint != expectedFingerprint {
			return nil, &PolicyConflictError{
				UserName: user, PolicyName: policyName,
				ExpectedFingerprint: expectedFingerprint,
				ExistingFingerprint: existingFingerprint,
			}
		}
	} else if err != nil {
		var nse *iamtypes.NoSuchEntityException
		if !errors.As(err, &nse) {
			return nil, fmt.Errorf("bootstrap: get policy %q: %w", policyName, err)
		}
	}
	if _, err := f.IAM.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		UserName: &user, PolicyName: &policyName, PolicyDocument: &policy,
	}); err != nil {
		return nil, fmt.Errorf("bootstrap: put policy: %w", err)
	}

	keys, err := f.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: &user})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: list access keys: %w", err)
	}
	if len(keys.AccessKeyMetadata) >= maxAccessKeys {
		return nil, fmt.Errorf("bootstrap: user %q already has %d access keys (AWS max); delete one first", user, len(keys.AccessKeyMetadata))
	}

	out, err := f.IAM.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: &user})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: create access key: %w", err)
	}
	return &BootstrapResult{
		Account:           account,
		UserName:          user,
		PolicyName:        policyName,
		PolicyFingerprint: expectedFingerprint,
		AccessKeyID:       aws.ToString(out.AccessKey.AccessKeyId),
		SecretKey:         aws.ToString(out.AccessKey.SecretAccessKey),
	}, nil
}

// BootstrapCredentials is an admin/root identity entered interactively for a
// single bootstrap run. It is used in-memory to call IAM/STS and is NEVER
// persisted by skret.
type BootstrapCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// PromptBootstrapCredentials interactively reads an admin/root AWS identity used
// transiently to provision the scoped skret key (Case 1). Mirrors the
// `skret auth login aws keys` paste flow, but these keys are discarded after the
// run rather than stored. Returns an error if the required fields are blank.
func PromptBootstrapCredentials(ctx context.Context, in io.Reader) (*BootstrapCredentials, error) {
	r := bufio.NewReader(in)
	fmt.Fprintln(ctxOut(ctx), "Paste an admin/root AWS identity to bootstrap from (used once, not stored):")
	akid := promptLine(ctx, r, "AWS Access Key ID: ")
	if akid == "" {
		return nil, fmt.Errorf("bootstrap: access key id required")
	}
	sak := promptLine(ctx, r, "AWS Secret Access Key: ")
	if sak == "" {
		return nil, fmt.Errorf("bootstrap: secret access key required")
	}
	sess := promptLine(ctx, r, "AWS Session Token (optional, blank = skip): ")
	return &BootstrapCredentials{AccessKeyID: akid, SecretAccessKey: sak, SessionToken: sess}, nil
}

func policyFingerprint(policyDocument string) (string, error) {
	decoded, err := url.QueryUnescape(policyDocument)
	if err != nil {
		return "", fmt.Errorf("bootstrap: decode policy document: %w", err)
	}

	var document any
	if err := json.Unmarshal([]byte(decoded), &document); err != nil {
		return "", fmt.Errorf("bootstrap: parse policy document: %w", err)
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("bootstrap: canonicalize policy document: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// buildPolicy returns the least-privilege inline policy JSON: the exact SSM
// actions skret calls, scoped to parameter/<path>/*, plus KMS constrained to
// SSM via kms:ViaService.
func buildPolicy(region, account, path string) (string, error) {
	p := strings.Trim(path, "/")
	resource := fmt.Sprintf("arn:aws:ssm:%s:%s:parameter/%s/*", region, account, p)
	doc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{
				"Sid":    "SkretSSM",
				"Effect": "Allow",
				"Action": []string{
					"ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
					"ssm:GetParameterHistory", "ssm:PutParameter", "ssm:DeleteParameter",
					"ssm:AddTagsToResource",
				},
				"Resource": resource,
			},
			map[string]any{
				"Sid":      "SkretKMSViaSSM",
				"Effect":   "Allow",
				"Action":   []string{"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"},
				"Resource": "*",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"kms:ViaService": "ssm." + region + ".amazonaws.com"},
				},
			},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("bootstrap: marshal policy: %w", err)
	}
	return string(b), nil
}
