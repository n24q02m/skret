package version

import "fmt"

var (
	Version = "0.0.0-dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("skret %s (commit: %s, built: %s)", Version, Commit, Date)
}
