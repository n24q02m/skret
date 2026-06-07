package aws_test

import (
	"context"
	"errors"
	"testing"
	"time"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	skaws "github.com/n24q02m/skret/internal/provider/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSSMClient struct {
	params                  map[string]ssmtypes.Parameter
	errGet                  error
	errBatch                error
	errList                 error
	errPut                  error
	errDel                  error
	errHistory              error
	history                 map[string][]ssmtypes.ParameterHistory
	GetParametersByPathFunc func(ctx context.Context, input *ssm.GetParametersByPathInput) (*ssm.GetParametersByPathOutput, error)
	GetParameterHistoryFunc func(ctx context.Context, input *ssm.GetParameterHistoryInput) (*ssm.GetParameterHistoryOutput, error)
	PutParameterFunc        func(ctx context.Context, input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error)
}

func (m *mockSSMClient) GetParameter(_ context.Context, input *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if m.errGet != nil {
		return nil, m.errGet
	}
	p, ok := m.params[*input.Name]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{Message: awslib.String("not found")}
	}
	return &ssm.GetParameterOutput{Parameter: &p}, nil
}

func (m *mockSSMClient) GetParameters(_ context.Context, input *ssm.GetParametersInput, _ ...func(*ssm.Options)) (*ssm.GetParametersOutput, error) {
	if m.errBatch != nil {
		return nil, m.errBatch
	}
	var params []ssmtypes.Parameter
	for _, name := range input.Names {
		if p, ok := m.params[name]; ok {
			params = append(params, p)
		}
	}
	return &ssm.GetParametersOutput{Parameters: params}, nil
}

func (m *mockSSMClient) GetParametersByPath(ctx context.Context, input *ssm.GetParametersByPathInput, _ ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	if m.GetParametersByPathFunc != nil {
		return m.GetParametersByPathFunc(ctx, input)
	}
	if m.errList != nil {
		return nil, m.errList
	}
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

func (m *mockSSMClient) PutParameter(ctx context.Context, input *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	if m.PutParameterFunc != nil {
		return m.PutParameterFunc(ctx, input)
	}
	if m.errPut != nil {
		return nil, m.errPut
	}
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
	if m.errDel != nil {
		return nil, m.errDel
	}
	if _, ok := m.params[*input.Name]; !ok {
		return nil, &ssmtypes.ParameterNotFound{Message: awslib.String("not found")}
	}
	delete(m.params, *input.Name)
	return &ssm.DeleteParameterOutput{}, nil
}

func (m *mockSSMClient) GetParameterHistory(ctx context.Context, input *ssm.GetParameterHistoryInput, _ ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error) {
	if m.GetParameterHistoryFunc != nil {
		return m.GetParameterHistoryFunc(ctx, input)
	}
	if m.errHistory != nil {
		return nil, m.errHistory
	}
	h, ok := m.history[*input.Name]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{Message: awslib.String("not found")}
	}
	return &ssm.GetParameterHistoryOutput{Parameters: h}, nil
}

func newTestProvider(params map[string]ssmtypes.Parameter) provider.SecretProvider {
	if params == nil {
		params = make(map[string]ssmtypes.Parameter)
	}
	return skaws.NewWithClient(&mockSSMClient{params: params}, "/test/prod/")
}

func TestAWS_New_EnvVars(t *testing.T) {
	t.Setenv("AWS_REGION", "us-west-2")
	t.Setenv("AWS_PROFILE", "")

	cfg := &config.ResolvedConfig{Region: "us-east-1"}
	p, err := skaws.New(cfg)
	require.NoError(t, err)
	assert.Equal(t, "aws", p.Name())
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
}

func TestAWS_Get(t *testing.T) {
	p := newTestProvider(map[string]ssmtypes.Parameter{
		"/test/prod/API_KEY": {Name: awslib.String("/test/prod/API_KEY"), Value: awslib.String("secret")},
	})
	s, err := p.Get(context.Background(), "/test/prod/API_KEY")
	require.NoError(t, err)
	assert.Equal(t, "secret", s.Value)
}

func TestAWS_GetNotFound(t *testing.T) {
	p := newTestProvider(nil)
	_, err := p.Get(context.Background(), "/test/prod/MISSING")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestAWS_GetError(t *testing.T) {
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter), errGet: errors.New("network err")}
	p := skaws.NewWithClient(mock, "/test/prod")
	_, err := p.Get(context.Background(), "/test/prod/KEY")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network err")
}

func TestAWS_GetWithLastModifiedDate(t *testing.T) {
	now := time.Now()
	p := newTestProvider(map[string]ssmtypes.Parameter{
		"/test/prod/KEY": {Name: awslib.String("/test/prod/KEY"), Value: awslib.String("val"), LastModifiedDate: &now},
	})
	s, err := p.Get(context.Background(), "/test/prod/KEY")
	require.NoError(t, err)
	assert.Equal(t, now, s.Meta.UpdatedAt)
}

func TestAWS_GetNoLastModified(t *testing.T) {
	p := newTestProvider(map[string]ssmtypes.Parameter{
		"/test/prod/KEY": {Name: awslib.String("/test/prod/KEY"), Value: awslib.String("val")},
	})
	s, err := p.Get(context.Background(), "/test/prod/KEY")
	require.NoError(t, err)
	assert.True(t, s.Meta.UpdatedAt.IsZero())
}

func TestAWS_List(t *testing.T) {
	p := newTestProvider(map[string]ssmtypes.Parameter{
		"/test/prod/A": {Name: awslib.String("/test/prod/A"), Value: awslib.String("valA")},
		"/test/prod/B": {Name: awslib.String("/test/prod/B"), Value: awslib.String("valB")},
		"/other/X":     {Name: awslib.String("/other/X"), Value: awslib.String("valX")},
	})
	secrets, err := p.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
}

func TestAWS_ListWithExplicitPath(t *testing.T) {
	p := newTestProvider(map[string]ssmtypes.Parameter{
		"/test/prod/A": {Name: awslib.String("/test/prod/A"), Value: awslib.String("valA")},
	})
	secrets, err := p.List(context.Background(), "/test/")
	require.NoError(t, err)
	assert.Len(t, secrets, 1)
}

func TestAWS_ListError(t *testing.T) {
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter), errList: errors.New("network err")}
	p := skaws.NewWithClient(mock, "/test/prod")
	_, err := p.List(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network err")
}

func TestAWS_ListPagination_MultiplePages(t *testing.T) {
	calls := 0
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter)}
	mock.GetParametersByPathFunc = func(_ context.Context, input *ssm.GetParametersByPathInput) (*ssm.GetParametersByPathOutput, error) {
		calls++
		if calls == 1 {
			return &ssm.GetParametersByPathOutput{
				Parameters: []ssmtypes.Parameter{{Name: awslib.String("/test/prod/A"), Value: awslib.String("A")}},
				NextToken:  awslib.String("token1"),
			}, nil
		}
		return &ssm.GetParametersByPathOutput{
			Parameters: []ssmtypes.Parameter{{Name: awslib.String("/test/prod/B"), Value: awslib.String("B")}},
		}, nil
	}

	p := skaws.NewWithClient(mock, "/test/prod")
	secrets, err := p.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
	assert.Equal(t, 2, calls)
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

func TestAWS_SetVerifiesOverwriteAndSecureString(t *testing.T) {
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter)}

	var capturedInput *ssm.PutParameterInput
	mock.PutParameterFunc = func(_ context.Context, input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
		capturedInput = input
		return &ssm.PutParameterOutput{Version: 1}, nil
	}

	p := skaws.NewWithClient(mock, "/test/prod")
	err := p.Set(context.Background(), "/test/prod/KEY", "val", provider.SecretMeta{
		Description: "my description",
		Tags:        map[string]string{"team": "infra", "env": "staging"},
	})
	require.NoError(t, err)
	require.NotNil(t, capturedInput)

	// Verify overwrite is enabled
	assert.True(t, *capturedInput.Overwrite)
	// Verify SecureString type
	assert.Equal(t, ssmtypes.ParameterTypeSecureString, capturedInput.Type)
	// Verify description
	assert.Equal(t, "my description", *capturedInput.Description)
	// Verify tags
	assert.Len(t, capturedInput.Tags, 2)
}

func TestAWS_SetNoDescription(t *testing.T) {
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter)}

	var capturedInput *ssm.PutParameterInput
	mock.PutParameterFunc = func(_ context.Context, input *ssm.PutParameterInput) (*ssm.PutParameterOutput, error) {
		capturedInput = input
		return &ssm.PutParameterOutput{Version: 1}, nil
	}

	p := skaws.NewWithClient(mock, "/test/prod")
	err := p.Set(context.Background(), "/test/prod/KEY", "val", provider.SecretMeta{})
	require.NoError(t, err)
	require.NotNil(t, capturedInput)
	assert.Nil(t, capturedInput.Description)
	assert.Empty(t, capturedInput.Tags)
}

func TestAWS_SetError(t *testing.T) {
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter), errPut: errors.New("network err")}
	p := skaws.NewWithClient(mock, "/test/prod")
	err := p.Set(context.Background(), "/test/prod/META", "val", provider.SecretMeta{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network err")
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

func TestAWS_DeleteError(t *testing.T) {
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter), errDel: errors.New("network err")}
	p := skaws.NewWithClient(mock, "/test/prod")
	err := p.Delete(context.Background(), "/test/prod/MISSING")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network err")
}

func TestAWS_GetHistory(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	mock := &mockSSMClient{
		params: make(map[string]ssmtypes.Parameter),
		history: map[string][]ssmtypes.ParameterHistory{
			"/test/prod/KEY": {
				{
					Name:             awslib.String("/test/prod/KEY"),
					Value:            awslib.String("v1"),
					Version:          1,
					LastModifiedDate: &now,
				},
				{
					Name:    awslib.String("/test/prod/KEY"),
					Value:   awslib.String("v2"),
					Version: 2,
				},
			},
		},
	}
	p := skaws.NewWithClient(mock, "/test/prod")
	defer p.Close()

	history, err := p.GetHistory(context.Background(), "/test/prod/KEY")
	require.NoError(t, err)
	require.Len(t, history, 2)
	assert.Equal(t, "v1", history[0].Value)
	assert.Equal(t, int64(1), history[0].Version)
	assert.Equal(t, now, history[0].Meta.UpdatedAt)
	assert.Equal(t, "v2", history[1].Value)
	assert.Equal(t, int64(2), history[1].Version)
	assert.True(t, history[1].Meta.UpdatedAt.IsZero())
}

func TestAWS_GetHistory_Pagination(t *testing.T) {
	now := time.Now()
	calls := 0
	mock := &mockSSMClient{params: make(map[string]ssmtypes.Parameter)}
	mock.GetParameterHistoryFunc = func(_ context.Context, input *ssm.GetParameterHistoryInput) (*ssm.GetParameterHistoryOutput, error) {
		calls++
		if calls == 1 {
			return &ssm.GetParameterHistoryOutput{
				Parameters: []ssmtypes.ParameterHistory{
					{Name: awslib.String("/test/prod/KEY"), Value: awslib.String("v1"), Version: 1, LastModifiedDate: &now},
				},
				NextToken: awslib.String("history-token"),
			}, nil
		}
		return &ssm.GetParameterHistoryOutput{
			Parameters: []ssmtypes.ParameterHistory{
				{Name: awslib.String("/test/prod/KEY"), Value: awslib.String("v2"), Version: 2},
			},
		}, nil
	}

	p := skaws.NewWithClient(mock, "/test/prod")
	history, err := p.GetHistory(context.Background(), "/test/prod/KEY")
	require.NoError(t, err)
	assert.Len(t, history, 2)
	assert.Equal(t, 2, calls)
}

func TestAWS_GetHistory_Error(t *testing.T) {
	mock := &mockSSMClient{
		params:     make(map[string]ssmtypes.Parameter),
		errHistory: errors.New("access denied"),
	}
	p := skaws.NewWithClient(mock, "/test/prod")
	_, err := p.GetHistory(context.Background(), "/test/prod/KEY")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestAWS_GetHistory_NotFound(t *testing.T) {
	mock := &mockSSMClient{
		params:     make(map[string]ssmtypes.Parameter),
		errHistory: &ssmtypes.ParameterNotFound{Message: awslib.String("not found")},
	}
	p := skaws.NewWithClient(mock, "/test/prod")
	_, err := p.GetHistory(context.Background(), "/test/prod/MISSING")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestAWS_Rollback_Success(t *testing.T) {
	now := time.Now()
	mock := &mockSSMClient{
		params: make(map[string]ssmtypes.Parameter),
		history: map[string][]ssmtypes.ParameterHistory{
			"/test/prod/KEY": {
				{Name: awslib.String("/test/prod/KEY"), Value: awslib.String("original"), Version: 1, LastModifiedDate: &now},
				{Name: awslib.String("/test/prod/KEY"), Value: awslib.String("updated"), Version: 2},
			},
		},
	}
	p := skaws.NewWithClient(mock, "/test/prod")
	defer p.Close()

	err := p.Rollback(context.Background(), "/test/prod/KEY", 1)
	require.NoError(t, err)

	// Verify the value was set back to version 1's value
	s, err := p.Get(context.Background(), "/test/prod/KEY")
	require.NoError(t, err)
	assert.Equal(t, "original", s.Value)
}

func TestAWS_Rollback_VersionNotFound(t *testing.T) {
	mock := &mockSSMClient{
		params: make(map[string]ssmtypes.Parameter),
		history: map[string][]ssmtypes.ParameterHistory{
			"/test/prod/KEY": {
				{Name: awslib.String("/test/prod/KEY"), Value: awslib.String("v1"), Version: 1},
			},
		},
	}
	p := skaws.NewWithClient(mock, "/test/prod")

	err := p.Rollback(context.Background(), "/test/prod/KEY", 99)
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestAWS_Rollback_HistoryError(t *testing.T) {
	mock := &mockSSMClient{
		params:     make(map[string]ssmtypes.Parameter),
		errHistory: errors.New("history fetch failed"),
	}
	p := skaws.NewWithClient(mock, "/test/prod")

	err := p.Rollback(context.Background(), "/test/prod/KEY", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "history fetch failed")
}

func TestAWS_Rollback_SetError(t *testing.T) {
	now := time.Now()
	mock := &mockSSMClient{
		params: make(map[string]ssmtypes.Parameter),
		history: map[string][]ssmtypes.ParameterHistory{
			"/test/prod/KEY": {
				{Name: awslib.String("/test/prod/KEY"), Value: awslib.String("v1"), Version: 1, LastModifiedDate: &now},
			},
		},
		errPut: errors.New("write denied"),
	}
	p := skaws.NewWithClient(mock, "/test/prod")

	err := p.Rollback(context.Background(), "/test/prod/KEY", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "write denied")
}

func TestAWS_Close(t *testing.T) {
	p := newTestProvider(nil)
	err := p.Close()
	assert.NoError(t, err)
}

func TestAWS_PaginationFallback(t *testing.T) {
	type pageMock struct {
		mockSSMClient
		calls int
	}
	pm := &pageMock{}
	pm.params = make(map[string]ssmtypes.Parameter)
	pm.GetParametersByPathFunc = func(_ context.Context, input *ssm.GetParametersByPathInput) (*ssm.GetParametersByPathOutput, error) {
		pm.calls++
		if pm.calls == 1 {
			return &ssm.GetParametersByPathOutput{
				Parameters: []ssmtypes.Parameter{
					{Name: awslib.String("/test/prod/A"), Value: awslib.String("A"), Version: 1},
				},
				NextToken: awslib.String("token1"),
			}, nil
		}
		return &ssm.GetParametersByPathOutput{
			Parameters: []ssmtypes.Parameter{
				{Name: awslib.String("/test/prod/B"), Value: awslib.String("B"), Version: 1},
			},
			NextToken: nil,
		}, nil
	}

	p := skaws.NewWithClient(pm, "/test/prod")
	secrets, err := p.List(context.Background(), "/test/prod")
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
}

func TestAWS_New_EmptyRegionProfile(t *testing.T) {
	cfg := &config.ResolvedConfig{Region: "", Profile: ""}
	_, err := skaws.New(cfg)
	_ = err
}

func TestAWS_GetBatch(t *testing.T) {
	mock := &mockSSMClient{
		params: map[string]ssmtypes.Parameter{
			"K1": {Name: awslib.String("K1"), Value: awslib.String("V1")},
			"K2": {Name: awslib.String("K2"), Value: awslib.String("V2")},
		},
	}
	p := skaws.NewWithClient(mock, "/test/")
	secrets, err := p.GetBatch(context.Background(), []string{"K1", "K2", "K3"})
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
}

func TestAWS_GetBatch_Error(t *testing.T) {
	mock := &mockSSMClient{
		params: make(map[string]ssmtypes.Parameter),
		errBatch: errors.New("get_batch failure"),
	}
	p := skaws.NewWithClient(mock, "/test/")
	_, err := p.GetBatch(context.Background(), []string{"K1"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get_batch failure")
}
