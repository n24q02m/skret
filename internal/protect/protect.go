// Package protect finds files and plaintext secrets that should not be
// committed: .env files and well-known credential formats. It needs no
// secret provider, so it can run in any repository as a pre-commit hook.
//
// A Finding names the file, the line and the rule; it never carries the
// matched text, so nothing protect prints can leak the secret it found.
package protect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/n24q02m/skret/internal/logging"
)

// EnvFileRule is the rule name for a .env file being committed.
const EnvFileRule = "env-file"

// AllowMarker on a line suppresses content findings on that line, for
// intentional fixtures such as documented example tokens.
const AllowMarker = "skret:allow"

// Finding is one problem in one file. Line is 1-based; 0 means the whole
// file (the env-file rule).
type Finding struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Rule string `json:"rule"`
}

// Options configures a Checker.
type Options struct {
	// Strict also applies the generic heuristics shared with the log
	// redactor (key=value assignments, long base64-like runs), which flag
	// hashes, lockfiles and placeholders as well as real secrets.
	Strict bool
	// Allow lists path patterns to skip entirely. A pattern without "/"
	// matches the file name at any depth ("*.pem"); a pattern ending in "/"
	// matches everything under a directory of that name at any depth
	// ("testdata/"); any other pattern matches the whole path ("docs/*.md").
	Allow []string
}

type rule struct {
	name string
	re   *regexp.Regexp
	// bounded rules only match at the start of a word, so a token prefix
	// inside a longer identifier ("task-..." for "sk-") does not count.
	bounded bool
}

// tokenRules are high-confidence credential formats not covered by the log
// redactor's patterns. Each has a fixed prefix and a fixed or minimum
// length, so ordinary code and prose do not match.
var tokenRules = []rule{
	{"github-token", regexp.MustCompile(`gh[ousr]_[A-Za-z0-9]{36,}`), true},
	{"github-fine-grained-pat", regexp.MustCompile(`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`), true},
	{"aws-temporary-access-key-id", regexp.MustCompile(`ASIA[A-Z0-9]{16}`), true},
	{"sk-scoped-api-key", regexp.MustCompile(`sk-[a-z]{2,10}-[A-Za-z0-9_-]{40,}`), true},
	{"slack-token", regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}`), true},
	{"slack-webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), true},
	{"stripe-live-key", regexp.MustCompile(`[rs]k_live_[A-Za-z0-9]{20,}`), true},
	{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), true},
	{"gitlab-pat", regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), true},
	{"npm-token", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), true},
	{"pypi-token", regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`), true},
	{"private-key", regexp.MustCompile(`-----BEGIN ((RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY( BLOCK)?-----`), true},
	{"age-secret-key", regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`), true},
}

// templateSuffixes mark committed templates of env files (".env.example"),
// which are expected in a repository. Their content is still scanned.
var templateSuffixes = []string{".example", ".sample", ".template", ".dist"}

// Checker applies the rules to files.
type Checker struct {
	rules []rule
	allow []string
}

// New returns a Checker for opts, or an error naming an invalid Allow
// pattern.
func New(opts Options) (*Checker, error) {
	for _, p := range opts.Allow {
		if _, err := path.Match(strings.TrimSuffix(p, "/"), ""); err != nil {
			return nil, fmt.Errorf("allow pattern %q: %w", p, err)
		}
	}
	var rules []rule
	for _, p := range logging.Patterns() {
		if p.Generic && !opts.Strict {
			continue
		}
		rules = append(rules, rule{name: p.Name, re: p.Regexp, bounded: !p.Generic})
	}
	rules = append(rules, tokenRules...)
	return &Checker{rules: rules, allow: opts.Allow}, nil
}

// RuleNames lists the rules this Checker applies.
func (c *Checker) RuleNames() []string {
	names := make([]string, 0, 1+len(c.rules))
	names = append(names, EnvFileRule)
	for _, r := range c.rules {
		names = append(names, r.name)
	}
	return names
}

// Check returns the findings for the file name with the given content,
// sorted by line and rule. Nil content (a binary, oversize or non-regular
// file) is checked by name only.
func (c *Checker) Check(name string, content []byte) []Finding {
	slashed := filepath.ToSlash(name)
	if c.allowed(slashed) {
		return nil
	}
	var out []Finding
	if isEnvFile(path.Base(slashed)) {
		out = append(out, Finding{File: name, Line: 0, Rule: EnvFileRule})
	}
	marker := []byte(AllowMarker)
	for i, line := range bytes.Split(content, []byte{'\n'}) {
		if bytes.Contains(line, marker) {
			continue
		}
		for _, r := range c.rules {
			if r.matches(line) {
				out = append(out, Finding{File: name, Line: i + 1, Rule: r.name})
			}
		}
	}
	Sort(out)
	return out
}

func (r rule) matches(line []byte) bool {
	if !r.bounded {
		return r.re.Match(line)
	}
	for _, loc := range r.re.FindAllIndex(line, -1) {
		if loc[0] == 0 || !isWordByte(line[loc[0]-1]) {
			return true
		}
	}
	return false
}

func isWordByte(b byte) bool {
	return b == '_' || ('0' <= b && b <= '9') || ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}

// Allowed reports whether name matches an Allow pattern, so Check skips it.
func (c *Checker) Allowed(name string) bool { return c.allowed(filepath.ToSlash(name)) }

func (c *Checker) allowed(slashed string) bool {
	base := path.Base(slashed)
	for _, p := range c.allow {
		switch {
		case strings.HasSuffix(p, "/"):
			dir := strings.TrimSuffix(p, "/")
			if strings.HasPrefix(slashed, dir+"/") || strings.Contains(slashed, "/"+dir+"/") {
				return true
			}
		case strings.Contains(p, "/"):
			if ok, _ := path.Match(p, slashed); ok {
				return true
			}
		default:
			if ok, _ := path.Match(p, base); ok {
				return true
			}
		}
	}
	return false
}

// binaryExtensions are file types that are binary by design: images, audio
// and video, fonts, PDF, and compiled code. Archives and databases are not
// listed, because they can hold text files or rows that protect cannot read.
var binaryExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true, ".ico": true,
	".webp": true, ".tif": true, ".tiff": true, ".psd": true, ".heic": true, ".avif": true,
	".mp3": true, ".wav": true, ".ogg": true, ".flac": true, ".m4a": true, ".aac": true,
	".mp4": true, ".mov": true, ".avi": true, ".mkv": true, ".webm": true,
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true, ".eot": true,
	".pdf": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".o": true, ".a": true,
	".lib": true, ".obj": true, ".class": true, ".pyc": true, ".wasm": true,
}

// KnownBinary reports whether name has the extension of a file type that is
// binary by design, so not reading its content as text is expected.
func KnownBinary(name string) bool {
	return binaryExtensions[strings.ToLower(path.Ext(filepath.ToSlash(name)))]
}

// isEnvFile reports whether a file name is a dotenv file: ".env",
// ".env.<name>", ".env-<name>", ".env_<name>" or "<name>.env", in any case,
// except committed templates such as ".env.example". ".envrc" is not one.
func isEnvFile(base string) bool {
	base = strings.ToLower(base)
	for _, s := range templateSuffixes {
		if strings.HasSuffix(base, s) {
			return false
		}
	}
	return base == ".env" ||
		strings.HasPrefix(base, ".env.") ||
		strings.HasPrefix(base, ".env-") ||
		strings.HasPrefix(base, ".env_") ||
		strings.HasSuffix(base, ".env")
}

// Sort orders findings by file, line, then rule.
func Sort(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
}

// RenderTable writes findings as a FILE/LINE/RULE table; a whole-file
// finding shows "-" as its line.
func RenderTable(w io.Writer, findings []Finding) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FILE\tLINE\tRULE")
	for _, f := range findings {
		line := "-"
		if f.Line > 0 {
			line = strconv.Itoa(f.Line)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", f.File, line, f.Rule)
	}
	return tw.Flush()
}

// RenderJSON writes findings as a JSON array of {file, line, rule}.
func RenderJSON(w io.Writer, findings []Finding) error {
	if findings == nil {
		findings = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}
