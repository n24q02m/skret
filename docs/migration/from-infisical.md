# Migrate from Infisical

## Step 1: Export from Infisical

```bash
# Using skret import (recommended)
INFISICAL_TOKEN=st.YOUR_TOKEN skret import \
  --from=infisical \
  --infisical-project-id=YOUR_PROJECT_ID \
  --infisical-env=prod

# Or export to dotenv first
infisical export --env=prod > .env.infisical
skret import --from=dotenv --file=.env.infisical
```

## Step 2: Verify

```bash
skret list
skret env --format=dotenv
```

## Command Mapping

| Infisical | skret |
|-----------|-------|
| `infisical secrets get KEY` | `skret get KEY` |
| `infisical secrets set KEY=VALUE` | `skret set KEY VALUE` |
| `infisical run -- cmd` | `skret run -- cmd` |
| `infisical export` | `skret env` |
