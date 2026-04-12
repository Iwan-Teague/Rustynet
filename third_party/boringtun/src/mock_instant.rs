use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static CLOCK_NANOS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
pub struct Instant {
    nanos: u64,
}

impl Instant {
    pub fn now() -> Self {
        Self {
            nanos: CLOCK_NANOS.load(Ordering::SeqCst),
        }
    }

    pub fn duration_since(&self, earlier: Instant) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }

    pub fn elapsed(&self) -> Duration {
        Self::now().duration_since(*self)
    }
}

#[allow(dead_code)]
pub struct MockClock;

impl MockClock {
    #[allow(dead_code)]
    pub fn advance(duration: Duration) {
        let delta = duration.as_nanos().min(u128::from(u64::MAX)) as u64;
        CLOCK_NANOS.fetch_add(delta, Ordering::SeqCst);
    }
}
