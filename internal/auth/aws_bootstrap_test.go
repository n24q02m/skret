package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeIAM records call counts + captured inputs and returns configured results.
type fakeIAM struct {
	getUserFn         func(*iam.GetUserInput) (*iam.GetUserOutput, error)
	createUserFn      func(*iam.CreateUserInput) (*iam.CreateUserOutput, error)
	putUserPolicyFn   func(*iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error)
	listAccessKeysFn  func(*iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error)
	createAccessKeyFn func(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error)

	createUserCalls      int
	putPolicyCalls       int
	createAccessKeyCalls int
	capturedPolicyDoc    string
}

func (f *fakeIAM) GetUser(_ context.Context, in *iam.GetUserInput, _ ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	return f.getUserFn(in)
}

func (f *fakeIAM) CreateUser(_ context.Context, in *iam.CreateUserInput, _ ...func(*iam.Options)) (*iam.CreateUserOutput, error) {
	f.createUserCalls++
	if f.createUserFn != nil {
		return f.createUserFn(in)
	}
	return &iam.CreateUserOutput{}, nil
}

func (f *fakeIAM) PutUserPolicy(_ context.Context, in *iam.PutUserPolicyInput, _ ...func(*iam.Options)) (*iam.PutUserPolicyOutput, error) {
	f.putPolicyCalls++
	f.capturedPolicyDoc = aws.ToString(in.PolicyDocument)
	if f.putUserPolicyFn != nil {
		return f.putUserPolicyFn(in)
	}
	return &iam.PutUserPolicyOutput{}, nil
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if f.listAccessKeysFn != nil {
		return f.listAccessKeysFn(in)
	}
	return &iam.ListAccessKeysOutput{}, nil
}

func (f *fakeIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	f.createAccessKeyCalls++
	if f.createAccessKeyFn != nil {
		return f.createAccessKeyFn(in)
	}
	return &iam.CreateAccessKeyOutput{}, nil
}

// fakeSTS records the GetCallerIdentity behaviour.
type fakeSTS struct {
	fn    func() (*sts.GetCallerIdentityOutput, error)
	calls int
}

func (f *fakeSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	f.calls++
	return f.fn()
}

const (
	testSecret  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testKeyID   = "AKIAIOSFODNN7EXAMPLE"
	testAccount = "123456789012"
	testRegion  = "ap-southeast-1"
)

func okSTS() *fakeSTS {
	return &fakeSTS{fn: func() (*sts.GetCallerIdentityOutput, error) {
		return &sts.GetCallerIdentityOutput{Account: aws.String(testAccount)}, nil
	}}
}

func okCreateAccessKey() func(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	return func(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
		return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
			AccessKeyId:     aws.String(testKeyID),
			SecretAccessKey: aws.String(testSecret),
		}}, nil
	}
}

func TestProvision_HappyPath_CreatesUserAndScopedPolicy(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return nil, &iamtypes.NoSuchEntityException{}
		},
		createAccessKeyFn: okCreateAccessKey(),
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	res, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.NoError(t, err)

	// User did not exist -> CreateUser called exactly once.
	assert.Equal(t, 1, iamFake.createUserCalls)
	assert.Equal(t, 1, iamFake.putPolicyCalls)
	assert.Equal(t, 1, iamFake.createAccessKeyCalls)

	// Result fields.
	assert.Equal(t, testAccount, res.Account)
	assert.Equal(t, "skret-myapp", res.UserName)
	assert.Equal(t, "skret-myapp", res.PolicyName)
	assert.Equal(t, testKeyID, res.AccessKeyID)
	assert.Equal(t, testSecret, res.SecretKey)

	// Parse the captured policy document and assert structure.
	var doc struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid       string          `json:"Sid"`
			Effect    string          `json:"Effect"`
			Action    []string        `json:"Action"`
			Resource  string          `json:"Resource"`
			Condition json.RawMessage `json:"Condition"`
		} `json:"Statement"`
	}
	require.NoError(t, json.Unmarshal([]byte(iamFake.capturedPolicyDoc), &doc))
	assert.Equal(t, "2012-10-17", doc.Version)
	require.Len(t, doc.Statement, 2)

	ssmStmt := doc.Statement[0]
	assert.Equal(t, "SkretSSM", ssmStmt.Sid)
	assert.Equal(t, "Allow", ssmStmt.Effect)
	assert.ElementsMatch(t, []string{
		"ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
		"ssm:GetParameterHistory", "ssm:PutParameter", "ssm:DeleteParameter",
	}, ssmStmt.Action)
	assert.Len(t, ssmStmt.Action, 6)
	assert.Equal(
		t,
		fmt.Sprintf("arn:aws:ssm:%s:%s:parameter/myapp/prod/*", testRegion, testAccount),
		ssmStmt.Resource,
	)

	kmsStmt := doc.Statement[1]
	assert.Equal(t, "SkretKMSViaSSM", kmsStmt.Sid)
	assert.ElementsMatch(t, []string{"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"}, kmsStmt.Action)
	assert.Len(t, kmsStmt.Action, 3)

	var cond struct {
		StringEquals map[string]string `json:"StringEquals"`
	}
	require.NoError(t, json.Unmarshal(kmsStmt.Condition, &cond))
	assert.Equal(t, "ssm."+testRegion+".amazonaws.com", cond.StringEquals["kms:ViaService"])
}

func TestProvision_UserExists_SkipsCreateUser(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return &iam.GetUserOutput{}, nil
		},
		createAccessKeyFn: okCreateAccessKey(),
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	res, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.NoError(t, err)

	// User existed -> CreateUser NOT called; rest proceeds.
	assert.Equal(t, 0, iamFake.createUserCalls)
	assert.Equal(t, 1, iamFake.putPolicyCalls)
	assert.Equal(t, 1, iamFake.createAccessKeyCalls)
	assert.Equal(t, testKeyID, res.AccessKeyID)
}

func TestProvision_TwoKeyCap_Errors(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return &iam.GetUserOutput{}, nil
		},
		listAccessKeysFn: func(*iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
				{AccessKeyId: aws.String("AKIA000000000000000A")},
				{AccessKeyId: aws.String("AKIA000000000000000B")},
			}}, nil
		},
		createAccessKeyFn: okCreateAccessKey(),
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	res, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Equal(t, 0, iamFake.createAccessKeyCalls)
	assert.Contains(t, err.Error(), "already has 2 access keys")
}

func TestProvision_GetCallerIdentityError_StopsEarly(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			t.Fatal("GetUser must not be called when identity check fails")
			return nil, nil
		},
	}
	stsFake := &fakeSTS{fn: func() (*sts.GetCallerIdentityOutput, error) {
		return nil, errors.New("no credentials")
	}}
	flow := &BootstrapFlow{IAM: iamFake, STS: stsFake}

	res, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Equal(t, 1, stsFake.calls)
	assert.Contains(t, err.Error(), "verify identity")
}

func TestProvision_DefaultUserName(t *testing.T) {
	var capturedUser string
	iamFake := &fakeIAM{
		getUserFn: func(in *iam.GetUserInput) (*iam.GetUserOutput, error) {
			capturedUser = aws.ToString(in.UserName)
			return &iam.GetUserOutput{}, nil
		},
		createAccessKeyFn: okCreateAccessKey(),
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	res, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "demo", Path: "/demo/dev", Region: testRegion,
	})
	require.NoError(t, err)
	assert.Equal(t, "skret-demo", capturedUser)
	assert.Equal(t, "skret-demo", res.UserName)
}

func TestProvision_ExplicitUserName(t *testing.T) {
	var capturedUser string
	iamFake := &fakeIAM{
		getUserFn: func(in *iam.GetUserInput) (*iam.GetUserOutput, error) {
			capturedUser = aws.ToString(in.UserName)
			return &iam.GetUserOutput{}, nil
		},
		createAccessKeyFn: okCreateAccessKey(),
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	_, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "demo", Path: "/demo/dev", Region: testRegion, UserName: "custom-user",
	})
	require.NoError(t, err)
	assert.Equal(t, "custom-user", capturedUser)
}

func TestProvision_GetUserNonNSEError_Surfaced(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return nil, errors.New("access denied")
		},
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	res, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Equal(t, 0, iamFake.createUserCalls)
	assert.Contains(t, err.Error(), "get user")
}

func TestProvision_CreateUserError_Surfaced(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return nil, &iamtypes.NoSuchEntityException{}
		},
		createUserFn: func(*iam.CreateUserInput) (*iam.CreateUserOutput, error) {
			return nil, errors.New("limit exceeded")
		},
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	_, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create user")
}

func TestProvision_PutPolicyError_Surfaced(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return &iam.GetUserOutput{}, nil
		},
		putUserPolicyFn: func(*iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
			return nil, errors.New("malformed policy")
		},
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	_, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "put policy")
}

func TestProvision_ListAccessKeysError_Surfaced(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return &iam.GetUserOutput{}, nil
		},
		listAccessKeysFn: func(*iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
			return nil, errors.New("throttled")
		},
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	_, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list access keys")
}

func TestProvision_CreateAccessKeyError_Surfaced(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return &iam.GetUserOutput{}, nil
		},
		createAccessKeyFn: func(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
			return nil, errors.New("limit exceeded")
		},
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	_, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create access key")
}

func TestBuildPolicy_PathNormalization(t *testing.T) {
	want := fmt.Sprintf("arn:aws:ssm:%s:%s:parameter/myapp/prod/*", testRegion, testAccount)
	for _, path := range []string{"/myapp/prod/", "myapp/prod", "/myapp/prod"} {
		doc, err := buildPolicy(testRegion, testAccount, path)
		require.NoError(t, err)

		var parsed struct {
			Statement []struct {
				Resource string `json:"Resource"`
			} `json:"Statement"`
		}
		require.NoError(t, json.Unmarshal([]byte(doc), &parsed))
		require.NotEmpty(t, parsed.Statement)
		assert.Equal(t, want, parsed.Statement[0].Resource, "path %q must normalize", path)
	}
}

// TestProvision_ValueSafety asserts the secret appears ONLY in the dedicated
// result field, never in a fmt-rendered summary built from the result.
func TestProvision_ValueSafety(t *testing.T) {
	iamFake := &fakeIAM{
		getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return &iam.GetUserOutput{}, nil
		},
		createAccessKeyFn: okCreateAccessKey(),
	}
	flow := &BootstrapFlow{IAM: iamFake, STS: okSTS()}

	res, err := flow.Provision(context.Background(), BootstrapOpts{
		Project: "myapp", Path: "/myapp/prod", Region: testRegion,
	})
	require.NoError(t, err)

	// Secret lives in the dedicated field.
	assert.Equal(t, testSecret, res.SecretKey)

	// A summary that intentionally omits SecretKey must not leak it.
	summary := fmt.Sprintf("account=%s user=%s policy=%s access_key_id=%s",
		res.Account, res.UserName, res.PolicyName, res.AccessKeyID)
	assert.NotContains(t, summary, testSecret)

	// The non-secret fields carry no secret material.
	for _, field := range []string{res.Account, res.UserName, res.PolicyName, res.AccessKeyID} {
		assert.False(t, strings.Contains(field, testSecret))
	}
}

// TestProvision_ErrorsNeverLeakSecret runs every error branch and asserts the
// surfaced error string never contains the secret value.
func TestProvision_ErrorsNeverLeakSecret(t *testing.T) {
	cases := []struct {
		name string
		iam  *fakeIAM
		sts  *fakeSTS
	}{
		{
			name: "identity",
			iam:  &fakeIAM{},
			sts:  &fakeSTS{fn: func() (*sts.GetCallerIdentityOutput, error) { return nil, errors.New("boom " + testSecret[:4]) }},
		},
		{
			name: "create-access-key",
			iam: &fakeIAM{
				getUserFn: func(*iam.GetUserInput) (*iam.GetUserOutput, error) { return &iam.GetUserOutput{}, nil },
				createAccessKeyFn: func(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
					return nil, errors.New("denied")
				},
			},
			sts: okSTS(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flow := &BootstrapFlow{IAM: tc.iam, STS: tc.sts}
			_, err := flow.Provision(context.Background(), BootstrapOpts{
				Project: "myapp", Path: "/myapp/prod", Region: testRegion,
			})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), testSecret)
		})
	}
}

func TestPromptBootstrapCredentials(t *testing.T) {
	t.Run("full input incl session token", func(t *testing.T) {
		in := strings.NewReader("AKIAADMINEXAMPLE0001\nadmin-secret-value\nadmin-session-token\n")
		c, err := PromptBootstrapCredentials(context.Background(), in)
		require.NoError(t, err)
		assert.Equal(t, "AKIAADMINEXAMPLE0001", c.AccessKeyID)
		assert.Equal(t, "admin-secret-value", c.SecretAccessKey)
		assert.Equal(t, "admin-session-token", c.SessionToken)
	})

	t.Run("session token optional", func(t *testing.T) {
		in := strings.NewReader("AKIAADMINEXAMPLE0001\nadmin-secret-value\n\n")
		c, err := PromptBootstrapCredentials(context.Background(), in)
		require.NoError(t, err)
		assert.Empty(t, c.SessionToken)
	})

	t.Run("missing access key id errors", func(t *testing.T) {
		in := strings.NewReader("\n")
		_, err := PromptBootstrapCredentials(context.Background(), in)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access key id required")
	})

	t.Run("missing secret errors without leaking", func(t *testing.T) {
		in := strings.NewReader("AKIAADMINEXAMPLE0001\n\n")
		_, err := PromptBootstrapCredentials(context.Background(), in)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret access key required")
		assert.NotContains(t, err.Error(), "AKIAADMINEXAMPLE0001")
	})
}
