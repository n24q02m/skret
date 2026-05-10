## 2025-05-10 - Adding confirmation prompt to destructive CLI command (rollback)
**Learning:** Destructive CLI commands in this project (like `delete`) implement an interactive confirmation prompt defaulting to 'No' (`[y/N]`) with `--confirm` and `-f` bypass flags. The `rollback` command modifies secret values state and requires similar confirmation.
**Action:** Added interactive confirmation and bypass flags (`--confirm`, `-f`) to `skret rollback`. Tested logic and mock inputs since bufio panic errors out in test cases without properly mocked `os.Stdin`.
