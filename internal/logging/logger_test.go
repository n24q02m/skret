package logging_test

import (
	"testing"

	"github.com/n24q02m/skret/internal/logging"
)

func TestSetup(t *testing.T) {
	logging.Setup("debug", "text")
	logging.Setup("info", "json")
	logging.Setup("error", "")
}
