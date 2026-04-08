# Migrate from dotenv

## Step 1: Import

```bash
skret import --from=dotenv --file=.env
```

## Step 2: Verify

```bash
skret list
skret env
```

## Step 3: Remove .env

Once verified, you can remove the `.env` file and rely on skret for secret management.

## Step 4: Update docker-compose

```yaml
# Before
services:
  app:
    env_file: .env
    command: npm start

# After
services:
  app:
    command: skret run -- npm start
```
