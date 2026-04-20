---
title: Makefile Patterns
description: "Replace `doppler run --` or `infisical run --` with `skret run --` in your Makefiles."
---

Replace `doppler run --` or `infisical run --` with `skret run --` in your Makefiles.

## Basic Replacement

```makefile
# Before (Doppler)
up-app:
	doppler run -- docker compose up -d app

# After (skret)
up-app:
	skret run -- docker compose up -d app
```

## Per-Service Targets

A common pattern: one `make` target per service, each injecting secrets before starting:

```makefile
.PHONY: up-app down-app up-worker down-worker

up-app:
	skret run -- docker compose up -d app

down-app:
	docker compose down app

up-worker:
	skret run -- docker compose up -d worker

down-worker:
	docker compose down worker
```

Note: `down` targets do not need secrets, so no `skret run --` wrapper.

## Environment Overrides

Use `--env` to target specific environments:

```makefile
.PHONY: deploy-staging deploy-prod

deploy-staging:
	skret --env=staging run -- docker compose up -d

deploy-prod:
	skret --env=prod run -- docker compose up -d

test-integration:
	skret --env=dev run -- go test -tags=integration ./...
```

## Export to .env for Tools That Need It

Some tools require a `.env` file instead of environment variables:

```makefile
.PHONY: env-file

env-file:
	skret env > .env

dev:
	skret env > .env
	docker compose up -d
	@echo "Started with secrets in .env"

clean:
	rm -f .env
	docker compose down
```

## Multiple Providers in One Makefile

If your project uses different secret sources per environment:

```yaml
# .skret.yaml
environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
  dev:
    provider: local
    file: ./.secrets.dev.yaml
```

```makefile
# Uses local provider (no AWS credentials needed)
dev:
	skret --env=dev run -- go run ./cmd/server

# Uses AWS SSM (requires AWS credentials)
prod:
	skret --env=prod run -- ./server
```

## Migration Checklist

1. Replace all `doppler run --` with `skret run --`
2. Replace all `infisical run --` with `skret run --`
3. Remove `DOPPLER_TOKEN` / `INFISICAL_TOKEN` from your environment
4. Run `skret init` in each project root
5. Verify: `make up-<service>` works as before
