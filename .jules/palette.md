## 2024-04-12 - Destructive Actions Need Confirmation
**Learning:** Destructive actions like `rollback` and `delete` can cause unintended data loss. Users expect commands that overwrite or permanently remove data to have a confirmation step.
**Action:** Always add a confirmation prompt for destructive actions, along with `--confirm` and `--force` flags to allow bypassing the prompt in automated scripts.
