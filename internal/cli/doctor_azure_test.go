package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/pkg/skret"
)

// TestDoctorAzureReachCheck_ConfigError covers the construction-failure
// classification. The reachable/auth/network classes need a live vault or a
// credential chain, so they stay untested here (no network in unit tests).
func TestDoctorAzureReachCheck_ConfigError(t *testing.T) {
	probeCache := map[string]error{}
	checks := doctorAzureReachCheck(
		"prod",
		time.Second,
		probeCache,
		&config.ResolvedConfig{Provider: "azure"},
	)
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	c := checks[0]
	assert.Equal(t, "provider[prod]", c.Name)
	assert.Equal(t, doctorFail, c.Status)
	assert.Contains(t, c.Detail, "one of vault_url or vault_name is required")
	assert.Contains(t, c.Remediation, "vault_url")
	assert.Equal(t, skret.ExitConfigError, c.failClass)
}
