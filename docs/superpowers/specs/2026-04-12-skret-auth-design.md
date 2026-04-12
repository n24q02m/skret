# skret auth — Native Authentication Design

**Status:** Approved
**Date:** 2026-04-12
**Author:** n24q02m + Claude

---

## 1. Overview

### Problem

skret currently requires users to install and authenticate with external CLIs (`aws-cli`, `doppler`, `infisical`) before using skret. This adds friction: users must know which CLI to install, how to authenticate, and manage credentials across multiple tools.

### Solution

Add `skret auth <provider>` as a unified authentication entry point that supports ALL auth methods for each provider natively — no external CLI dependencies. When credentials are missing or expired, skret auto-detects and prompts login (in interactive terminals) or fails fast with instructions (in CI/pipes).

### Goals

1. Zero external CLI dependencies for authentication.
2. Every auth method per provider supported (SSO, static tokens, machine identity).
3. Auto-detect missing/expired credentials and prompt inline (interactive) or fail fast (non-interactive).
4. Credentials stored in standard locations compatible with existing tools.
5. `skret auth status` shows auth state for all providers at a glance.

---

## 2. Auth methods per provider

### AWS

| Method | Interactive | Use case |
|--------|------------|----------|
| SSO Login (browser) | Yes | Developer workstation with AWS SSO configured |
| Access Key + Secret Key | No | CI, legacy IAM users, service accounts |
| Assume Role (STS) | No | Cross-account access, federated identity |
| Profile from ~/.aws/config | No | Select existing named profile |

**SSO flow**: Uses `aws-sdk-go-v2/service/ssooidc` directly:
1. Read `~/.aws/config` to find SSO start URL, region, account ID, role name
2. `RegisterClient` → get client ID + secret
3. `StartDeviceAuthorization` → get verification URI + user code
4. Print verification URI + code, open browser automatically
5. Poll `CreateToken` until user authorizes (with exponential backoff)
6. Write token to `~/.aws/sso/cache/{sha1(startUrl)}.json` (aws-cli compatible format)
7. SDK credential chain picks up the token automatically

**Access Key flow**: Prompt for access key ID + secret access key, optionally session token. Write to `~/.aws/credentials` under a named profile, or store in `~/.skret/credentials.yaml`.

**Assume Role flow**: Prompt for role ARN + (optional) external ID. Uses existing credentials to call `sts:AssumeRole`, caches temporary credentials.

**Profile selection**: List available profiles from `~/.aws/config`, user picks one, skret stores the selection in `.skret.yaml` or `~/.skret/credentials.yaml`.

### Doppler

| Method | Interactive | Use case |
|--------|------------|----------|
| OAuth Login (browser) | Yes | Developer workstation |
| Service Token | No | CI, project-scoped |
| Personal Token | No | CLI scripting, personal use |

**OAuth flow**: Uses Doppler's device authorization endpoint:
1. `POST https://api.doppler.com/v3/auth/device` → device code + verification URI
2. Print verification URI, open browser
3. Poll `POST /v3/auth/device/token` with device code until approved
4. Receive personal access token → store in `~/.skret/credentials.yaml`

**Service Token flow**: Prompt user to paste token (or read from env). Validate with `GET /v3/me` → store in `~/.skret/credentials.yaml`.

**Personal Token flow**: Same as Service Token — paste + validate + store.

### Infisical

| Method | Interactive | Use case |
|--------|------------|----------|
| Browser Login | Yes | Developer workstation |
| Universal Auth (Client ID + Secret) | No | CI, machine identity |
| Token (paste) | No | Manual token, legacy |

**Browser Login flow**: Uses OAuth PKCE:
1. Generate code verifier + challenge
2. Start local HTTP callback server on random port
3. Open browser to `{infisical-url}/api/v1/auth/redirect?callback=http://localhost:{port}&code_challenge={challenge}`
4. User logs in → redirect to callback with authorization code
5. Exchange code for access token via `/api/v1/auth/token`
6. Store token in `~/.skret/credentials.yaml`
7. For self-hosted: `skret auth infisical --url=https://infisical.internal`

**Universal Auth flow**: Prompt for Client ID + Client Secret (or read from env `INFISICAL_CLIENT_ID` + `INFISICAL_CLIENT_SECRET`). Call `POST /api/v1/auth/universal-auth/login` → receive access token → store.

**Token flow**: Paste token + validate with API → store.

---

## 3. Credential resolution chain

Unified chain for all providers. First match wins:

```
1. Environment variables
   AWS:       AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (+ AWS_SESSION_TOKEN)
              AWS_PROFILE → resolve from ~/.aws/
   Doppler:   DOPPLER_TOKEN
   Infisical: INFISICAL_TOKEN
              INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET → exchange for token

2. Standard tool cache (provider-specific)
   AWS:       ~/.aws/sso/cache/*.json (SSO tokens)
              ~/.aws/credentials (static keys)
   Doppler:   (no standard cache — skret-managed only)
   Infisical: (no standard cache — skret-managed only)

3. skret credential store
   ~/.skret/credentials.yaml (Doppler tokens, Infisical tokens, AWS profile prefs)

4. Interactive prompt (terminal only)
   os.IsTerminal(stdin) == true → prompt: "Credentials missing. Login now? [Y/n]"
   os.IsTerminal(stdin) == false → error: "run `skret auth <provider>` to authenticate"
```

---

## 4. Auto-detect integration

When any provider operation fails with an auth error:

```go
func withAutoAuth(ctx context.Context, providerName string, fn func() error) error {
    err := fn()
    if !isAuthError(err) {
        return err
    }

    if !term.IsTerminal(int(os.Stdin.Fd())) {
        return fmt.Errorf("%s: credentials missing or expired; run `skret auth %s`", providerName, providerName)
    }

    fmt.Fprintf(os.Stderr, "%s credentials missing or expired. Login now? [Y/n] ", providerName)
    if !confirmPrompt() {
        return err
    }

    if loginErr := auth.Login(ctx, providerName, nil); loginErr != nil {
        return fmt.Errorf("auth %s: %w", providerName, loginErr)
    }

    return fn()  // retry the original operation
}
```

This wraps `provider.New()`, `importer.New*()`, and `syncer.New*()` calls.

---

## 5. CLI commands

### `skret auth <provider>`

```
$ skret auth aws
? Authentication method:
  > SSO Login (browser)
    Access Key + Secret Key
    Assume Role (STS)
    Profile from ~/.aws/config

$ skret auth doppler
? Authentication method:
  > OAuth Login (browser)
    Service Token
    Personal Token

$ skret auth infisical
? Authentication method:
  > Browser Login
    Universal Auth (Client ID + Secret)
    Token
```

Flags:
- `--method=<name>` — skip interactive menu, use specific method (for scripting)
- `--url=<base-url>` — override base URL (Infisical self-hosted)
- `--profile=<name>` — AWS profile name

Examples:
```bash
skret auth aws                           # interactive menu
skret auth aws --method=sso              # direct SSO login
skret auth aws --method=access-key       # prompt for keys
skret auth doppler --method=service-token  # prompt for token
skret auth infisical --url=https://infisical.internal  # self-hosted
```

### `skret auth status`

```
$ skret auth status
Provider     Status          Details
AWS          authenticated   profile: default, SSO, expires: 2026-04-12 18:30 ICT
Doppler      authenticated   user: n24q02m@gmail.com, expires: 2026-05-12
Infisical    not configured  run: skret auth infisical
```

### `skret auth logout [provider]`

```
$ skret auth logout doppler    # remove Doppler credentials
$ skret auth logout            # remove all skret-managed credentials
```

Logout does NOT delete `~/.aws/` credentials (those belong to aws-cli). Only removes entries from `~/.skret/credentials.yaml` and (for AWS SSO) the specific cache file skret created.

---

## 6. Credential store format

`~/.skret/credentials.yaml` (file permission `0600`):

```yaml
version: "1"
providers:
  doppler:
    method: "oauth"
    token: "dp.pt.xxxxxxxxxxxx"
    email: "n24q02m@gmail.com"
    expires_at: "2026-05-12T00:00:00Z"
  infisical:
    method: "universal-auth"
    token: "st.xxxxxxxxxxxx"
    url: "https://app.infisical.com"
    expires_at: "2026-04-13T00:00:00Z"
  aws:
    preferred_profile: "default"
    sso_cache_file: "bcd1234abcd.json"
```

AWS SSO tokens stored in `~/.aws/sso/cache/{hash}.json` for aws-cli compatibility. Only the reference (preferred profile, cache filename) is in `~/.skret/credentials.yaml`.

---

## 7. Package layout

```
internal/
  auth/
    auth.go             # AuthProvider interface, Login/Logout/Status dispatcher, credential chain
    store.go            # Read/write ~/.skret/credentials.yaml (0600)
    prompt.go           # Interactive method menu, confirm prompt, browser open
    aws_sso.go          # AWS SSO device auth flow (ssooidc SDK)
    aws_keys.go         # AWS access key + assume role flows
    doppler_oauth.go    # Doppler OAuth2 device flow
    doppler_token.go    # Doppler service/personal token flow
    infisical_browser.go # Infisical PKCE browser flow
    infisical_universal.go # Infisical universal-auth flow
    store_test.go
    aws_sso_test.go
    aws_keys_test.go
    doppler_test.go
    infisical_test.go
  cli/
    auth.go             # `skret auth` command + subcommands
    auth_test.go
```

### Interface

```go
// internal/auth/auth.go

type Method struct {
    Name        string   // "sso", "access-key", "oauth", "service-token", etc.
    Description string   // human-readable for menu
    Interactive bool     // requires terminal
}

type Provider interface {
    Name() string
    Methods() []Method
    Login(ctx context.Context, method string, opts map[string]string) (*Credential, error)
    Validate(ctx context.Context, cred *Credential) error
    Logout(ctx context.Context) error
}

type Credential struct {
    Provider  string
    Method    string
    Token     string
    ExpiresAt time.Time
    Metadata  map[string]string  // email, profile, url, etc.
}

func Login(ctx context.Context, providerName string, opts map[string]string) error
func Status(ctx context.Context) ([]ProviderStatus, error)
func Resolve(ctx context.Context, providerName string) (*Credential, error)
```

---

## 8. Dependencies

| Dependency | Purpose | Status |
|---|---|---|
| `aws-sdk-go-v2/service/ssooidc` | AWS SSO device auth | Already indirect dep, promote to direct |
| `aws-sdk-go-v2/service/sso` | AWS SSO role credentials | Already indirect dep |
| `aws-sdk-go-v2/service/sts` | AWS AssumeRole | Already indirect dep |
| `golang.org/x/term` | Terminal detection (`IsTerminal`) | New dep (stdlib extension) |

No other new dependencies. Browser opening via `os/exec` with platform commands (`xdg-open`, `open`, `start`). HTTP flows use `net/http` (already used in importers).

---

## 9. Testing strategy

- **Unit tests**: Mock HTTP servers for Doppler/Infisical API responses. Mock ssooidc client for AWS.
- **Integration tests**: env-gated (`SKRET_E2E_AUTH=1`) tests that run actual auth flows against real APIs.
- **Coverage target**: >= 95% on `internal/auth/`.
- **Credential store tests**: temp directory, verify 0600 permissions, read/write/delete round-trip.
- **Auto-detect tests**: mock terminal detection, verify prompt vs fail-fast behavior.

---

## 10. Migration from existing code

Current importers (`doppler.go`, `infisical.go`) take raw tokens. After this change:

1. `skret import --from=doppler` first tries `auth.Resolve(ctx, "doppler")` to get token from credential chain.
2. If not found + interactive → auto-prompt login.
3. If not found + non-interactive → error with `skret auth doppler` instruction.
4. `DOPPLER_TOKEN` env var still works as highest priority (backward compatible).

Same pattern for `skret import --from=infisical` and all AWS provider operations.

---

## 11. Out of scope

- **GCP/Azure/Cloudflare/OCI auth** — future providers, future auth methods.
- **Multi-factor auth orchestration** — MFA is handled by the browser flow (AWS SSO, Doppler OAuth, Infisical login all support MFA in their web UIs).
- **Token refresh automation** — tokens are refreshed on next use if expired; no background daemon.
- **Encrypted credential store** ��� `0600` file perms is sufficient for v0.1; encrypted store (OS keyring) deferred to v0.2.

---

**End of design.**
