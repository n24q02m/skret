package aws_test

import (
	"context"
	"testing"
	"time"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSSMClient struct {
	params map[string]ssmtypes.Parameter
}

func (m *mockSSMClient) GetParameter(_ context.Context, input *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	p, ok := m.params[*input.Name]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{Message: awslib.String("not found")}
	}
	return &ssm.GetParameterOutput{Parameter: &p}, nil
}

func (m *mockSSMClient) GetParametersByPath(_ context.Context, input *ssm.GetParametersByPathInput, _ ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	var params []ssmtypes.Parameter
	for _, p := range m.params {
		name := awslib.ToString(p.Name)
		path := awslib.ToString(input.Path)
		if len(name) > len(path) && name[:len(path)] == path {
			params = append(params, p)
		}
	}
	return &ssm.GetParametersByPathOutput{Parameters: params}, nil
}

func (m *mockSSMClient) PutParameter(_ context.Context, input *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	now := time.Now()
	m.params[*input.Name] = ssmtypes.Parameter{
		Name:             input.Name,
		Value:            input.Value,
		Version:          1,
		LastModifiedDate: &now,
	}
	return &ssm.PutParameterOutput{Version: 1}, nil
}

func (m *mockSSMClient) DeleteParameter(_ context.Context, input *ssm.DeleteParameterInput, _ ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error) {
	if _, ok := m.params[*input.Name]; !ok {
		return nil, &ssmtypes.ParameterNotFound{Message: awslib.String("not found")}
	}
	delete(m.params, *input.Name)
	return &ssm.DeleteParameterOutput{}, nil
}

func newTestProvider(params map[string]ssmtypes.Parameter) provider.SecretProvider {
	if params == nil {
		params = make(map[string]ssmtypes.Parameter)
	}
	mock := &mockSSMClient{params: params}
	return skaws.NewWithClient(mock, "/test/prod")
}

func TestAWS_Name(t *testing.T) {
	p := newTestProvider(nil)
	assert.Equal(t, "aws", p.Name())
}

func TestAWS_Capabilities(t *testing.T) {
	p := newTestProvider(nil)
	caps := p.Capabilities()
	assert.True(t, caps.Write)
	assert.True(t, caps.Versioning)
	assert.True(t, caps.Tagging)
}

func TestAWS_Get(t *testing.T) {
	p := newTestProvider(map[string]ssmtypes.Parameter{
		"/test/prod/DB_URL": {
			Name:    awslib.String("/test/prod/DB_URL"),
			Value:   awslib.String("postgres://prod"),
			Version: 3,
		},
	})
	defer p.Close()

	s, err := p.Get(context.Background(), "/test/prod/DB_URL")
	require.NoError(t, err)
	assert.Equal(t, "/test/prod/DB_URL", s.Key)
	assert.Equal(t, "postgres://prod", s.Value)
	assert.Equal(t, int64(3), s.Version)
}

func TestAWS_GetNotFound(t *testing.T) {
	p := newTestProvider(nil)
	defer p.Close()

	_, err := p.Get(context.Background(), "/test/prod/MISSING")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestAWS_List(t *testing.T) {
	p := newTestProvider(map[string]ssmtypes.Parameter{
		"/test/prod/A": {Name: awslib.String("/test/prod/A"), Value: awslib.String("a")},
		"/test/prod/B": {Name: awslib.String("/test/prod/B"), Value: awslib.String("b")},
	})
	defer p.Close()

	secrets, err := p.List(context.Background(), "/test/prod")
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
}

func TestAWS_Set(t *testing.T) {
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter)}
	p := skaws.NewWithClient(mock, "/test/prod")
	defer p.Close()

	err := p.Set(context.Background(), "/test/prod/NEW", "value", provider.SecretMeta{})
	require.NoError(t, err)

	s, err := p.Get(context.Background(), "/test/prod/NEW")
	require.NoError(t, err)
	assert.Equal(t, "value", s.Value)
}

func TestAWS_SetWithMeta(t *testing.T) {
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter)}
	p := skaws.NewWithClient(mock, "/test/prod")
	defer p.Close()

	meta := provider.SecretMeta{
		Description: "test desc",
		Tags:        map[string]string{"env": "prod"},
	}
	err := p.Set(context.Background(), "/test/prod/META", "val", meta)
	require.NoError(t, err)
}

func TestAWS_Delete(t *testing.T) {
	p := newTestProvider(map[string]ssmtypes.Parameter{
		"/test/prod/KEY": {Name: awslib.String("/test/prod/KEY"), Value: awslib.String("val")},
	})
	defer p.Close()

	err := p.Delete(context.Background(), "/test/prod/KEY")
	require.NoError(t, err)

	_, err = p.Get(context.Background(), "/test/prod/KEY")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestAWS_DeleteNotFound(t *testing.T) {
	p := newTestProvider(nil)
	defer p.Close()

	err := p.Delete(context.Background(), "/test/prod/MISSING")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}
