package auth

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

// AWSKeysFlow performs interactive paste of AWS access key credentials.
type AWSKeysFlow struct {
	in io.Reader
}

// NewAWSKeysFlow creates a paste flow that reads from the given reader.
func NewAWSKeysFlow(in io.Reader) *AWSKeysFlow {
	return &AWSKeysFlow{in: in}
}

// Login prompts for access key id, secret access key, and optional session
// token, returning a Credential on success.
func (f *AWSKeysFlow) Login(ctx context.Context, _ map[string]string) (*Credential, error) {
	r := bufio.NewReader(f.in)
	akid, err := promptLine(ctx, r, "AWS Access Key ID: ")
	if err != nil {
		return nil, err
	}
	if akid == "" {
		return nil, fmt.Errorf("aws keys: access key id required")
	}
	sak, err := promptLine(ctx, r, "AWS Secret Access Key: ")
	if err != nil {
		return nil, err
	}
	if sak == "" {
		return nil, fmt.Errorf("aws keys: secret access key required")
	}
	sess, _ := promptLine(ctx, r, "AWS Session Token (optional, blank = skip): ")

	return &Credential{
		Method: "access-key",
		Token:  sak,
		Metadata: map[string]string{
			"access_key_id": akid,
			"session_token": sess,
		},
	}, nil
}

// promptLine writes prompt to the context writer and reads one trimmed line
// from r. Returns empty string + nil on EOF with no input.
func promptLine(ctx context.Context, r *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(ctxOut(ctx), prompt)
	s, err := r.ReadString('\n')
	if err != nil && s == "" {
		return "", nil
	}
	return strings.TrimSpace(s), nil
}
