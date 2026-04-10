# Optimization Learnings

## GitHub Syncer Parallelization
- **Issue**: N+1 HTTP Request problem where each secret update triggered a serial PUT request.
- **Optimization**: Implemented a worker pool with a concurrency limit of 10 using a semaphore channel and `sync.WaitGroup`.
- **Impact**: Significant performance improvement when syncing multiple secrets, especially over high-latency networks.
- **Verification**: Confirmed correctness with existing test suite including race detection.
