## 2024-04-20 - GitHub Syncer Encryption Optimization
**Learning:** In Go, performing redundant base64 decoding inside concurrent workers parsing constant configuration values causes substantial overhead (~10x regression in CPU and memory allocation observed via benchmark).
**Action:** Always extract invariant operations (e.g., base64 decoding configuration or public keys) outside of synchronization loops to reduce CPU overhead from O(N) to O(1) and safely pass read-only pointers to worker goroutines.
