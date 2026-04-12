# Docker Compose

Two approaches for injecting secrets into Docker Compose services.

## Approach 1: Wrap the Command (Recommended)

Run `docker compose` under `skret run --` so all secrets are available as environment variables:

```bash
skret run -- docker compose up -d
```

Docker Compose inherits the environment from its parent process. Secrets set by `skret run` are passed to containers via the `environment` directive in `docker-compose.yml`:

```yaml
services:
  app:
    image: myapp:latest
    environment:
      - DATABASE_URL
      - REDIS_URL
      - API_KEY
```

Each listed variable is forwarded from the host environment (set by skret) into the container. This is the cleanest approach -- no `.env` file on disk.

### With Makefile

```makefile
up-app:
	skret run -- docker compose up -d app

down-app:
	docker compose down app

logs:
	docker compose logs -f app
```

## Approach 2: Generate `.env` File

For tools or workflows that require a `.env` file:

```bash
skret env > .env
docker compose up -d
```

Reference in `docker-compose.yml`:

```yaml
services:
  app:
    image: myapp:latest
    env_file:
      - .env
```

**Drawbacks:**

- Secrets written to disk (even temporarily)
- Must regenerate `.env` when secrets change
- Must ensure `.env` is in `.gitignore`

### Atomic Update Pattern

If you must use `.env`, regenerate it before each start:

```makefile
up-app:
	skret env > .env
	docker compose up -d app
	rm -f .env

down-app:
	docker compose down app
```

## Approach Comparison

| Aspect | `skret run --` | `skret env > .env` |
|--------|----------------|---------------------|
| Secrets on disk | No | Yes (temporary) |
| Auto-updates | Yes (fetched each run) | No (manual regenerate) |
| Works offline | Only with local provider | Yes, once generated |
| Docker Compose version | Any | Any |
| CI/CD friendly | Yes | Yes |

## Multi-Environment

```bash
# Start staging services
skret --env=staging run -- docker compose -f docker-compose.yml -f docker-compose.staging.yml up -d

# Start production services
skret --env=prod run -- docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## Migrating from `.env`

If you currently use `.env` files with Docker Compose:

```bash
# 1. Import existing .env into skret
skret import --from=dotenv --file=.env

# 2. Verify secrets were imported
skret list

# 3. Switch docker-compose.yml from env_file to environment
# Before:
#   env_file: .env
# After:
#   environment:
#     - DATABASE_URL
#     - REDIS_URL

# 4. Run with skret
skret run -- docker compose up -d

# 5. Remove .env once confirmed
rm .env
```
