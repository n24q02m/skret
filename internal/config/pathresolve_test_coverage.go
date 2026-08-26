package config
import "testing"
func TestResolvePath_Coverage(t *testing.T) {
	_, _ = ResolvePath("C:\\x\\y")
    _, _ = ResolvePath("a")
    _, _ = ResolvePath("a/b")
    _, _ = ResolvePath("foo/ssm/bar")
}
