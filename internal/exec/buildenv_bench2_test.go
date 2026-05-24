package exec_test

import (
	"strings"
	"testing"
)

func BenchmarkStringsContains(b *testing.B) {
	b.ReportAllocs()
	s := "foo bar baz something something $VAR"
	for i := 0; i < b.N; i++ {
		_ = strings.Contains(s, "$")
	}
}

func BenchmarkStringsIndexByteDollar(b *testing.B) {
	b.ReportAllocs()
	s := "foo bar baz something something $VAR"
	for i := 0; i < b.N; i++ {
		_ = strings.IndexByte(s, '$') >= 0
	}
}
