package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// RenderTable writes findings as a KEY/FILE/LINE table. It never prints values.
// When any finding carries a commit (history scan), a COMMIT column is appended.
func RenderTable(w io.Writer, findings []Finding) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	history := false
	for _, f := range findings {
		if f.Commit != "" {
			history = true
			break
		}
	}
	if history {
		fmt.Fprintln(tw, "KEY\tFILE\tLINE\tCOMMIT")
		for _, f := range findings {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", f.Key, f.File, f.Line, f.Commit)
		}
		return tw.Flush()
	}
	fmt.Fprintln(tw, "KEY\tFILE\tLINE")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%d\n", f.Key, f.File, f.Line)
	}
	return tw.Flush()
}

// RenderJSON writes findings as a JSON array (KEY/FILE/LINE only).
func RenderJSON(w io.Writer, findings []Finding) error {
	if findings == nil {
		findings = []Finding{}
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
