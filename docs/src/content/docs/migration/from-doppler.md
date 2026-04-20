---
title: Migrate from Doppler
description: "Replace `doppler run --` with `skret run --`:"
---

## Step 1: Export from Doppler

```bash
# Using skret import (recommended)
DOPPLER_TOKEN=dp.st.YOUR_TOKEN skret import \
  --from=doppler \
  --doppler-project=myapp \
  --doppler-config=prd

# Or export to dotenv first
doppler secrets download --no-file --format=env > .env.doppler
skret import --from=dotenv --file=.env.doppler
```

## Step 2: Verify

```bash
skret list
skret env --format=dotenv
```

## Step 3: Update CI/CD

Replace `doppler run --` with `skret run --`:

```yaml
# Before (Doppler)
- run: doppler run -- npm test

# After (skret)
- run: skret run -- npm test
```

## Command Mapping

| Doppler | skret |
|---------|-------|
| `doppler secrets get KEY` | `skret get KEY` |
| `doppler secrets set KEY=VALUE` | `skret set KEY VALUE` |
| `doppler secrets delete KEY` | `skret delete KEY` |
| `doppler run -- cmd` | `skret run -- cmd` |
| `doppler secrets download` | `skret env` |
