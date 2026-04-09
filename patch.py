import re

def rep(f, o, n):
    with open(f, 'r', encoding='utf-8') as file:
        t = file.read()
    if o in t:
        t = t.replace(o, n)
        with open(f, 'w', encoding='utf-8') as file:
            file.write(t)
    else:
        print(f'Failed to find {repr(o)[:30]} in {f}')

rep('internal/provider/provider.go',
    '\tSet(ctx context.Context, key string, value string, meta SecretMeta) error\n\tDelete(ctx context.Context, key string) error',
    '\tSet(ctx context.Context, key string, value string, meta SecretMeta) error\n\tDelete(ctx context.Context, key string) error\n\tGetHistory(ctx context.Context, key string) ([]*Secret, error)\n\tRollback(ctx context.Context, key string, version int64) error'
)

rep('internal/provider/local/local.go',
    'func (p *Provider) Close() error { return nil }',
    'func (p *Provider) GetHistory(_ context.Context, key string) ([]*provider.Secret, error) {\n\treturn nil, provider.ErrCapabilityNotSupported\n}\n\nfunc (p *Provider) Rollback(_ context.Context, key string, version int64) error {\n\treturn provider.ErrCapabilityNotSupported\n}\n\nfunc (p *Provider) Close() error { return nil }'
)

rep('internal/provider/aws/aws.go',
    '\tDeleteParameter(ctx context.Context, params *ssm.DeleteParameterInput, optFns ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error)\n}',
    '\tDeleteParameter(ctx context.Context, params *ssm.DeleteParameterInput, optFns ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error)\n\tGetParameterHistory(ctx context.Context, params *ssm.GetParameterHistoryInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error)\n}'
)

hist_str = '''func (p *Provider) GetHistory(ctx context.Context, key string) ([]*provider.Secret, error) {
\tvar secrets []*provider.Secret
\tvar nextToken *string

\tfor {
\t\toutput, err := p.client.GetParameterHistory(ctx, &ssm.GetParameterHistoryInput{
\t\t\tName:           awslib.String(key),
\t\t\tWithDecryption: awslib.Bool(true),
\t\t\tNextToken:      nextToken,
\t\t})
\t\tif err != nil {
\t\t\treturn nil, mapError("history", key, err)
\t\t}

\t\tfor i := range output.Parameters {
\t\t\tparam := output.Parameters[i]
\t\t\ts := &provider.Secret{
\t\t\t\tKey:     awslib.ToString(param.Name),
\t\t\t\tValue:   awslib.ToString(param.Value),
\t\t\t\tVersion: param.Version,
\t\t\t}
\t\t\tif param.LastModifiedDate != nil {
\t\t\t\ts.Meta.UpdatedAt = *param.LastModifiedDate
\t\t\t}
\t\t\tsecrets = append(secrets, s)
\t\t}

\t\tif output.NextToken == nil {
\t\t\tbreak
\t\t}
\t\tnextToken = output.NextToken
\t}
\treturn secrets, nil
}

func (p *Provider) Rollback(ctx context.Context, key string, version int64) error {
\thistory, err := p.GetHistory(ctx, key)
\tif err != nil {
\t\treturn err
\t}
\tvar found *provider.Secret
\tfor _, s := range history {
\t\tif s.Version == version {
\t\t\tfound = s
\t\t\tbreak
\t\t}
\t}
\tif found == nil {
\t\treturn provider.ErrNotFound
\t}
\treturn p.Set(ctx, key, found.Value, found.Meta)
}

func (p *Provider) Close() error { return nil }'''

rep('internal/provider/aws/aws.go', 'func (p *Provider) Close() error { return nil }', hist_str)

rep('internal/exec/exec.go',
    'import (\n\t"strings"\n\n\t"github.com/n24q02m/skret/internal/provider"\n)',
    'import (\n\t"os"\n\t"strings"\n\n\t"github.com/n24q02m/skret/internal/provider"\n)'
)

old_for = '''\t\tfor _, s := range secrets {
\t\t\tname := KeyToEnvName(s.Key, pathPrefix)
\t\t\tif excludeSet[name] || existingKeys[name] {
\t\t\t\tcontinue
\t\t\t}
\t\t\tenv = append(env, name+"="+s.Value)
\t\t}'''

new_for = '''\t\tfor _, s := range secrets {
\t\t\tname := KeyToEnvName(s.Key, pathPrefix)
\t\t\tif excludeSet[name] || existingKeys[name] {
\t\t\t\tcontinue
\t\t\t}
\t\t\tval := os.Expand(s.Value, func(k string) string {
\t\t\t\tfor _, e := range existing {
\t\t\t\t\tif strings.HasPrefix(e, k+"=") {
\t\t\t\t\t\treturn e[len(k)+1:]
\t\t\t\t\t}
\t\t\t\t}
\t\t\t\treturn os.Getenv(k)
\t\t\t})
\t\t\tenv = append(env, name+"="+val)
\t\t}'''
rep('internal/exec/exec.go', old_for, new_for)

old_cfg = '''\t\t\tenvName := "prod"
\t\t\tif provider == "local" {
\t\t\t\tenvName = "dev"
\t\t\t}

\t\t\tenv := config.Environment{
\t\t\t\tProvider: provider,
\t\t\t\tPath:     path,
\t\t\t\tRegion:   region,
\t\t\t\tFile:     file,
\t\t\t}

\t\t\tcfg := config.Config{
\t\t\t\tVersion:      "1",
\t\t\t\tDefaultEnv:   envName,
\t\t\t\tEnvironments: map[string]config.Environment{envName: env},
\t\t\t}'''

new_cfg = '''\t\t\tcfg := config.Config{
\t\t\t\tVersion:      "1",
\t\t\t\tDefaultEnv:   "dev",
\t\t\t\tEnvironments: map[string]config.Environment{
\t\t\t\t\t"dev": {
\t\t\t\t\t\tProvider: "local",
\t\t\t\t\t\tFile:     ".secrets.dev.yaml",
\t\t\t\t\t},
\t\t\t\t\t"prod": {
\t\t\t\t\t\tProvider: "aws",
\t\t\t\t\t\tPath:     "/my-app/prod/",
\t\t\t\t\t\tRegion:   "us-east-1",
\t\t\t\t\t},
\t\t\t\t},
\t\t\t}'''
rep('internal/cli/init.go', old_cfg, new_cfg)
