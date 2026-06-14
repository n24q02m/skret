package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestScanFindsValueOnLine(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "env.txt", "line1\nline2\nbefore sup3r-s3cret-value after\nline4\n")

	findings, err := Scan(
		[]Target{{Key: "API_KEY", Value: "sup3r-s3cret-value"}},
		[]string{f},
		Opts{},
	)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, Finding{Key: "API_KEY", File: f, Line: 3}, findings[0])
}

func TestScanValueAbsent(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "env.txt", "nothing to see here\n")

	findings, err := Scan(
		[]Target{{Key: "API_KEY", Value: "sup3r-s3cret-value"}},
		[]string{f},
		Opts{},
	)
	require.NoError(t, err)
	require.Empty(t, findings)
}

func TestScanSkipsBinaryFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	require.NoError(t, os.WriteFile(p, []byte("abc\x00sup3r-s3cret-value"), 0o600))

	findings, err := Scan(
		[]Target{{Key: "API_KEY", Value: "sup3r-s3cret-value"}},
		[]string{p},
		Opts{},
	)
	require.NoError(t, err)
	require.Empty(t, findings)
}

func TestScanSkipsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "big.txt", "sup3r-s3cret-value over here\n")

	findings, err := Scan(
		[]Target{{Key: "API_KEY", Value: "sup3r-s3cret-value"}},
		[]string{f},
		Opts{MaxBytes: 4},
	)
	require.NoError(t, err)
	require.Empty(t, findings)
}

func TestScanSkipsShortValue(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "env.txt", "the value ab is short\n")

	findings, err := Scan(
		[]Target{{Key: "SHORT", Value: "ab"}},
		[]string{f},
		Opts{MinLength: 6},
	)
	require.NoError(t, err)
	require.Empty(t, findings)
}

func TestScanTwoTargetsTwoLines(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "env.txt", "alpha-secret-one\nfiller\nbeta-secret-two\n")

	findings, err := Scan(
		[]Target{
			{Key: "BKEY", Value: "beta-secret-two"},
			{Key: "AKEY", Value: "alpha-secret-one"},
		},
		[]string{f},
		Opts{},
	)
	require.NoError(t, err)
	require.Len(t, findings, 2)
	// Sorted by file, then line, then key.
	require.Equal(t, Finding{Key: "AKEY", File: f, Line: 1}, findings[0])
	require.Equal(t, Finding{Key: "BKEY", File: f, Line: 3}, findings[1])
}

func TestScanSortsAcrossFilesAndKeys(t *testing.T) {
	dir := t.TempDir()
	fb := writeFile(t, dir, "b.txt", "shared-value\n")
	fa := writeFile(t, dir, "a.txt", "shared-value zzz-value\n")

	findings, err := Scan(
		[]Target{
			{Key: "ZKEY", Value: "zzz-value"},
			{Key: "SKEY", Value: "shared-value"},
		},
		[]string{fb, fa},
		Opts{},
	)
	require.NoError(t, err)
	require.Len(t, findings, 3)
	// a.txt before b.txt; within a.txt line 1 both keys, sorted by key.
	require.Equal(t, fa, findings[0].File)
	require.Equal(t, "SKEY", findings[0].Key)
	require.Equal(t, fa, findings[1].File)
	require.Equal(t, "ZKEY", findings[1].Key)
	require.Equal(t, fb, findings[2].File)
}

func TestScanSkipsDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	require.NoError(t, os.MkdirAll(sub, 0o700))

	findings, err := Scan(
		[]Target{{Key: "API_KEY", Value: "sup3r-s3cret-value"}},
		[]string{sub},
		Opts{},
	)
	require.NoError(t, err)
	require.Empty(t, findings)
}

func TestScanSkipsUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "ok.txt", "sup3r-s3cret-value\n")
	missing := filepath.Join(dir, "does-not-exist.txt")

	findings, err := Scan(
		[]Target{{Key: "API_KEY", Value: "sup3r-s3cret-value"}},
		[]string{missing, f},
		Opts{},
	)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, f, findings[0].File)
}

// TestScanFindsMultiLineValue is the regression for the leak-guard false-clean:
// a secret value spanning newlines (PEM/SSH key) must still be detected.
func TestScanFindsMultiLineValue(t *testing.T) {
	dir := t.TempDir()
	pem := "-----BEGIN KEY-----\nabcdef\nghijkl\n-----END KEY-----"
	f := writeFile(t, dir, "leak.txt", "noise\nprefix\n"+pem+"\nsuffix\n")

	findings, err := Scan(
		[]Target{{Key: "PRIVKEY", Value: pem}},
		[]string{f},
		Opts{},
	)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, "PRIVKEY", findings[0].Key)
	// First match begins on line 3 (after "noise", "prefix").
	require.Equal(t, 3, findings[0].Line)
}

// TestScanFindsCRLFValue ensures a value containing a CRLF pair is also matched.
func TestScanFindsCRLFValue(t *testing.T) {
	dir := t.TempDir()
	val := "tok-part1\r\ntok-part2"
	f := writeFile(t, dir, "crlf.txt", "head\n"+val+"\n")

	findings, err := Scan(
		[]Target{{Key: "TOK", Value: val}},
		[]string{f},
		Opts{},
	)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, 2, findings[0].Line)
}
