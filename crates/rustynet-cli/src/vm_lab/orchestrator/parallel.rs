#![allow(dead_code)]

/// Apply `operation` with at most `max_workers` scoped threads at once.
///
/// Results retain input order. Work is admitted in bounded batches, so a
/// caller can check cancellation between batches without leaving detached
/// mutation behind.
pub fn bounded_parallel_map<T, R, F>(items: &[T], max_workers: usize, operation: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let limit = max_workers.max(1);
    let mut results = Vec::with_capacity(items.len());
    for batch in items.chunks(limit) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|item| scope.spawn(|| operation(item)))
                .collect();
            for handle in handles {
                // A worker panic is deliberately propagated. The orchestration
                // runner converts the stage panic into a failed outcome and
                // still executes always-run cleanup.
                results.push(handle.join().unwrap_or_else(|panic| {
                    std::panic::resume_unwind(panic);
                }));
            }
        });
    }
    results
}

/// Cancellable variant. No new operation is admitted after `cancelled` is
/// observed between batches; remaining inputs receive a deterministic
/// caller-provided result without mutation.
pub fn bounded_parallel_map_cancellable<T, R, F, C>(
    items: &[T],
    max_workers: usize,
    cancelled: &std::sync::atomic::AtomicBool,
    operation: F,
    cancelled_result: C,
) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
    C: Fn(&T) -> R,
{
    use std::sync::atomic::Ordering;
    let limit = max_workers.max(1);
    let mut results = Vec::with_capacity(items.len());
    for batch in items.chunks(limit) {
        if cancelled.load(Ordering::Acquire) {
            results.extend(batch.iter().map(&cancelled_result));
            continue;
        }
        std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|item| scope.spawn(|| operation(item)))
                .collect();
            for handle in handles {
                results.push(handle.join().unwrap_or_else(|panic| {
                    std::panic::resume_unwind(panic);
                }));
            }
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[test]
    fn respects_limit_and_preserves_order() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let started = Instant::now();
        let values = bounded_parallel_map(&[0, 1, 2, 3], 2, |value| {
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(30));
            active.fetch_sub(1, Ordering::SeqCst);
            value * 2
        });
        assert_eq!(values, vec![0, 2, 4, 6]);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert!(started.elapsed() < Duration::from_millis(110));
    }

    #[test]
    fn zero_limit_is_safely_serialized() {
        assert_eq!(
            bounded_parallel_map(&[1, 2], 0, |value| value + 1),
            vec![2, 3]
        );
    }

    #[test]
    fn cancellation_stops_admitting_later_batches() {
        use std::sync::atomic::AtomicBool;
        let cancelled = AtomicBool::new(false);
        let values = bounded_parallel_map_cancellable(
            &[0, 1, 2, 3],
            2,
            &cancelled,
            |value| {
                cancelled.store(true, Ordering::Release);
                *value
            },
            |_| 99,
        );
        assert_eq!(values, vec![0, 1, 99, 99]);
    }
}
