package auth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSKeysFlow_Paste(t *testing.T) {
	in := strings.NewReader("AKIAEXAMPLE\nSECRETEXAMPLE\n\n")
	flow := auth.NewAWSKeysFlow(in)
	cred, err := flow.Login(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "access-key", cred.Method)
	assert.Equal(t, "AKIAEXAMPLE", cred.Metadata["access_key_id"])
	assert.Equal(t, "SECRETEXAMPLE", cred.Token)
	assert.Empty(t, cred.Metadata["session_token"])
}

func TestAWSKeysFlow_MissingSecret(t *testing.T) {
	in := strings.NewReader("AKIAEXAMPLE\n")
	flow := auth.NewAWSKeysFlow(in)
	_, err := flow.Login(context.Background(), nil)
	require.Error(t, err)
}
