$content = Get-Content -Raw C:\Users\n24q02m-wlap\projects\skret\internal\provider\aws\aws.go
$content = $content -replace '(?s)type SSMClient interface \{.*?\}(\r?\n)?/ Provider wraps AWS SSM Parameter Store\.', "type SSMClient interface {
        GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
        GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
        GetParameterHistory(ctx context.Context, params *ssm.GetParameterHistoryInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error)
        PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
        DeleteParameter(ctx context.Context, params *ssm.DeleteParameterInput, optFns ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error)
}

// Provider wraps AWS SSM Parameter Store.""

Set-Content C:\Users\n24q02m-wlap\projects\skret\internal\provider\aws\aws.go $content
