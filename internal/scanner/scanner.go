package scanner

import (
	"bytes"
	"io"
	"os"
	"sort"
)

// Finding is one managed secret value located in a file. It deliberately holds
// NO value — only the key name and location — so output can never leak a secret.
type Finding struct {
	Key  string `json:"key"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// Target is a managed secret to look for: its display key and the value to match.
// The value is used only in memory and never surfaced in a Finding.
type Target struct {
	Key   string
	Value string
}

// Opts controls scanning.
type Opts struct {
	MinLength int   // skip targets whose value is shorter than this (noise guard)
	MaxBytes  int64 // skip files larger than this (0 -> default 8 MiB)
}

const (
	defaultMaxBytes = 8 << 20
	binarySniff     = 8 << 10
)

// Scan returns every place a target value appears as a substring anywhere in the
// given files (matching is whole-file, so values spanning line boundaries are
// detected). Binary and oversize files are skipped. A target whose value is
// shorter than opts.MinLength is skipped.
func Scan(targets []Target, files []string, opts Opts) ([]Finding, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	active := make([]Target, 0, len(targets))
	for _, t := range targets {
		if len(t.Value) >= opts.MinLength {
			active = append(active, t)
		}
	}
	var findings []Finding
	for _, f := range files {
		fs, err := scanFile(f, active, maxBytes)
		if err != nil {
			continue // unreadable file: skip, do not fail the whole scan
		}
		findings = append(findings, fs...)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Key < findings[j].Key
	})
	return findings, nil
}

func scanFile(path string, targets []Target, maxBytes int64) ([]Finding, error) {
	content, err := loadFile(path, maxBytes)
	if err != nil || content == nil {
		return nil, err
	}
	return scanContent(path, content, targets), nil
}

func loadFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > maxBytes {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bin, err := isBinary(f)
	if err != nil || bin {
		return nil, err
	}

	return io.ReadAll(f)
}

var newline = []byte{'\n'} // hoisted for better performance

func isBinary(f *os.File) (bool, error) {
	head := make([]byte, binarySniff)
	n, _ := f.Read(head)
	if bytes.IndexByte(head[:n], 0) >= 0 {
		return true, nil
	}
	if _, err := f.Seek(0, 0); err != nil {
		return false, err
	}
	return false, nil
}

func scanContent(path string, content []byte, targets []Target) []Finding {
	var out []Finding
	for _, t := range targets {
		idx := bytes.Index(content, []byte(t.Value))
		if idx < 0 {
			continue
		}
		// Line number of the first match: 1 + newlines before it.
		line := 1 + bytes.Count(content[:idx], newline)
		out = append(out, Finding{Key: t.Key, File: path, Line: line})
	}
	return out
}

// trigger ci
