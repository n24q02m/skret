// Package differ compares two secret sets and reports drift without ever
// exposing secret values.
package differ

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// Source yields a point-in-time snapshot of one secret set.
type Source interface {
	Label() string
	Read(ctx context.Context) (Snapshot, error)
}

// Snapshot is one source's keys and (optionally readable) values.
type Snapshot struct {
	Secrets       map[string]string
	CanReadValues bool
}

// Opts controls diff computation.
type Opts struct {
	Hashes bool // compute sha256[:8] per side for changed/unknown keys
}

// Result holds the comparison outcome. It never stores plaintext values.
type Result struct {
	A, B      string
	OnlyA     []string
	OnlyB     []string
	Changed   []string
	Unknown   []string // value comparison impossible (a side is write-only)
	SameCount int
	Hashes    map[string][2]string // key -> {hashA, hashB}; "?" when a side is unreadable
}

// HasDrift reports whether the two sources differ in any compared dimension.
func (r Result) HasDrift() bool {
	return len(r.OnlyA) > 0 || len(r.OnlyB) > 0 || len(r.Changed) > 0
}

// hash8 returns the first 8 hex chars of sha256(s). One-way; safe to display.
func hash8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

// Diff compares two sources. Values are read into memory only to compute
// equality/hashes; they are never stored in Result.
func Diff(ctx context.Context, a, b Source, opts Opts) (Result, error) {
	sa, err := a.Read(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("diff %s vs %s: %w", a.Label(), b.Label(), err)
	}
	sb, err := b.Read(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("diff %s vs %s: %w", a.Label(), b.Label(), err)
	}

	res := Result{A: a.Label(), B: b.Label()}
	if opts.Hashes {
		res.Hashes = make(map[string][2]string)
	}
	canCompare := sa.CanReadValues && sb.CanReadValues

	hashSide := func(readable bool, v string) string {
		if !readable {
			return "?"
		}
		return hash8(v)
	}

	for k, va := range sa.Secrets {
		vb, ok := sb.Secrets[k]
		if !ok {
			res.OnlyA = append(res.OnlyA, k)
			continue
		}
		switch {
		case !canCompare:
			res.Unknown = append(res.Unknown, k)
			if opts.Hashes {
				res.Hashes[k] = [2]string{hashSide(sa.CanReadValues, va), hashSide(sb.CanReadValues, vb)}
			}
		case va != vb:
			res.Changed = append(res.Changed, k)
			if opts.Hashes {
				res.Hashes[k] = [2]string{hash8(va), hash8(vb)}
			}
		default:
			res.SameCount++
		}
	}
	for k := range sb.Secrets {
		if _, ok := sa.Secrets[k]; !ok {
			res.OnlyB = append(res.OnlyB, k)
		}
	}

	sort.Strings(res.OnlyA)
	sort.Strings(res.OnlyB)
	sort.Strings(res.Changed)
	sort.Strings(res.Unknown)
	return res, nil
}
