package exec_test

import (
	"fmt"
	"testing"

	"github.com/n24q02m/skret/internal/exec"
	"github.com/n24q02m/skret/internal/provider"
)

func BenchmarkBuildEnv_NoExpansion(b *testing.B) {
	count := 100
	secrets := make([]*provider.Secret, count)
	for i := 0; i < count; i++ {
		secrets[i] = &provider.Secret{Key: fmt.Sprintf("VAR_%d", i), Value: "static_value"}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = exec.BuildEnv(secrets, nil, "", nil)
	}
}

func BenchmarkBuildEnv_DeepDependency(b *testing.B) {
	depth := 9
	secrets := make([]*provider.Secret, depth)
	secrets[0] = &provider.Secret{Key: "VAR_0", Value: "base"}
	for i := 1; i < depth; i++ {
		secrets[i] = &provider.Secret{Key: fmt.Sprintf("VAR_%d", i), Value: fmt.Sprintf("${VAR_%d}", i-1)}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = exec.BuildEnv(secrets, nil, "", nil)
	}
}

func BenchmarkBuildEnv_VeryDeepDependency(b *testing.B) {
	depth := 100
	secrets := make([]*provider.Secret, depth)
	secrets[0] = &provider.Secret{Key: "VAR_0", Value: "base"}
	for i := 1; i < depth; i++ {
		secrets[i] = &provider.Secret{Key: fmt.Sprintf("VAR_%d", i), Value: fmt.Sprintf("${VAR_%d}", i-1)}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = exec.BuildEnv(secrets, nil, "", nil)
	}
}

func BenchmarkBuildEnv_WideDependency(b *testing.B) {
	width := 100
	secrets := make([]*provider.Secret, width+1)
	secrets[0] = &provider.Secret{Key: "BASE", Value: "value"}
	for i := 1; i <= width; i++ {
		secrets[i] = &provider.Secret{Key: fmt.Sprintf("VAR_%d", i), Value: "${BASE}"}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = exec.BuildEnv(secrets, nil, "", nil)
	}
}
