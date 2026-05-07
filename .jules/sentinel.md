## 2025-05-24 - Command Injection in OpenBrowser
**Vulnerability:** Command and argument injection in `OpenBrowser` via unsanitized URL input.
**Learning:** Passing user-controlled strings directly to CLI tools like `open`, `xdg-open`, or `rundll32` can lead to arbitrary command execution or unexpected behavior if the input contains malicious schemes or flag-like parameters.
**Prevention:** Always validate URL schemes (e.g., allow only `http` and `https`) and use argument separators (e.g., `--`) when supported by the underlying CLI tool to prevent flag injection.
