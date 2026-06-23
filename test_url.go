package main
import (
	"fmt"
	"net/url"
)
func main() {
	baseURL := "http://example.com/\x7f"
	path, err := url.JoinPath(baseURL, "repos")
	fmt.Printf("JoinPath err: %v, path: %q\n", err, path)

	u, err := url.Parse(path)
	fmt.Printf("Parse err: %v, u: %v\n", err, u)
}
