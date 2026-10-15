## 2026-08-06 - Fix Length Oracle Timing Attack in String Comparisons
**Vulnerability:** The `verifySession` function implemented an early return length check (`got.byteLength !== expected.byteLength`) before calling `crypto.subtle.timingSafeEqual`. This creates a length oracle timing attack vulnerability where attackers can deduce the length or presence of secrets.
**Learning:** Checking string lengths and exiting early avoids throwing exceptions in `timingSafeEqual` but exposes the secret's length via timing differences.
**Prevention:** Always hash both inputs (e.g., using SHA-256) before performing a constant-time comparison when dealing with potentially variable-length secrets. This ensures the comparison operates in constant time regardless of the original inputs' lengths.
