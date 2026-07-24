package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/n24q02m/skret/pkg/skret"
)

// errorEnvelope is the --format json shape for a failing command.
type errorEnvelope struct {
	Error       string `json:"error"`
	Code        int    `json:"code"`
	Remediation string `json:"remediation,omitempty"`
}

// RenderError writes err to w: a bare message for the table format (byte-
// identical to the fmt.Fprintln(os.Stderr, err) main.go used before this
// existed), or a parseable JSON envelope when format is "json" -- so a
// --format json caller gets a body it can unmarshal to match skret.ExitCode.
func RenderError(w io.Writer, err error, format string) {
	if err == nil {
		return
	}
	if format != "json" {
		fmt.Fprintln(w, err)
		return
	}
	env := errorEnvelope{
		Error:       err.Error(),
		Code:        skret.ExitCode(err),
		Remediation: skret.RemediationOf(err),
	}
	data, mErr := json.MarshalIndent(env, "", "  ")
	if mErr != nil {
		// Never swallow the original error just because rendering failed.
		fmt.Fprintln(w, err)
		return
	}
	fmt.Fprintln(w, string(data))
}
