package differ

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TableOpts controls table rendering.
type TableOpts struct {
	ShowHash bool
}

// RenderTable produces the human-readable diff. Never includes secret values.
func RenderTable(r Result, opts TableOpts) string {
	var b strings.Builder
	fmt.Fprintf(&b, "diff %s vs %s\n\n", r.A, r.B)

	if len(r.OnlyA) > 0 {
		fmt.Fprintf(&b, "+ only in %s\n", r.A)
		for _, k := range r.OnlyA {
			fmt.Fprintf(&b, "    %s\n", k)
		}
	}
	if len(r.OnlyB) > 0 {
		fmt.Fprintf(&b, "- only in %s\n", r.B)
		for _, k := range r.OnlyB {
			fmt.Fprintf(&b, "    %s\n", k)
		}
	}
	if len(r.Changed) > 0 {
		fmt.Fprintln(&b, "~ differs")
		for _, k := range r.Changed {
			if opts.ShowHash {
				h := r.Hashes[k]
				fmt.Fprintf(&b, "    %s   %s → %s\n", k, h[0], h[1])
			} else {
				fmt.Fprintf(&b, "    %s\n", k)
			}
		}
	}
	if len(r.Unknown) > 0 {
		fmt.Fprintf(&b, "? cannot compare values (%s is write-only)\n", r.B)
		for _, k := range r.Unknown {
			fmt.Fprintf(&b, "    %s\n", k)
		}
	}

	if !r.HasDrift() && len(r.Unknown) == 0 {
		fmt.Fprintln(&b, "no drift")
	}
	fmt.Fprintf(&b, "\n%d same\n", r.SameCount)
	return b.String()
}

// jsonResult is the stable wire shape: keys only, never values.
type jsonResult struct {
	A         string               `json:"a"`
	B         string               `json:"b"`
	OnlyA     []string             `json:"only_a"`
	OnlyB     []string             `json:"only_b"`
	Changed   []string             `json:"changed"`
	Unknown   []string             `json:"unknown"`
	SameCount int                  `json:"same_count"`
	Hashes    map[string][2]string `json:"hashes,omitempty"`
}

// RenderJSON produces the machine-readable diff. Never includes secret values.
func RenderJSON(r Result) string {
	out := jsonResult{
		A: r.A, B: r.B,
		OnlyA: orEmpty(r.OnlyA), OnlyB: orEmpty(r.OnlyB),
		Changed: orEmpty(r.Changed), Unknown: orEmpty(r.Unknown),
		SameCount: r.SameCount, Hashes: r.Hashes,
	}
	// jsonResult is a fixed struct of strings/ints/maps; MarshalIndent cannot fail.
	buf, _ := json.MarshalIndent(out, "", "  ")
	return string(buf)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
