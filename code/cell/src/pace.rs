//! When to send the next cell.
//!
//! Both ends send cells as a Poisson process: the gaps between cells are
//! independent and exponentially distributed, with a mean of
//! `1 / CELLS_PER_SECOND`. The schedule is drawn from fresh randomness and
//! never consults what there is to send, so the timing carries no
//! information about activity. Random gaps (rather than a fixed tick) also
//! avoid a perfectly regular beat that would itself stand out.

use rand_core::{OsRng, RngCore};
use std::time::Duration;
use tokio::time::Instant;

/// Average cells per second, in each direction, on every link.
pub const CELLS_PER_SECOND: f64 = 4.0;

/// A Poisson clock: `tick` waits a random, exponentially distributed time.
pub struct PoissonClock<R = OsRng> {
    rate: f64,
    rng: R,
    next: Instant,
}

impl PoissonClock {
    /// A clock averaging `CELLS_PER_SECOND`, whose first tick is a random
    /// gap from now.
    pub fn new() -> Self {
        Self::with_rng(CELLS_PER_SECOND, OsRng)
    }
}

impl Default for PoissonClock {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RngCore> PoissonClock<R> {
    pub fn with_rng(rate: f64, rng: R) -> Self {
        let mut clock = Self {
            rate,
            rng,
            next: Instant::now(),
        };
        let first = clock.gap();
        clock.next += first;
        clock
    }

    /// One exponentially distributed gap.
    pub fn gap(&mut self) -> Duration {
        // Uniform in (0, 1], so the logarithm is finite.
        let u = ((self.rng.next_u64() >> 11) + 1) as f64 / (1u64 << 53) as f64;
        Duration::from_secs_f64(-u.ln() / self.rate)
    }

    /// Wait for the next cell's turn. The gap after it is measured from
    /// when this one actually fired, so a stall (a busy runtime, a phone
    /// waking up) delays the stream rather than releasing a burst of
    /// overdue cells.
    pub async fn tick(&mut self) {
        tokio::time::sleep_until(self.next).await;
        self.next = Instant::now() + self.gap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic `RngCore` for distribution checks.
    struct SplitMix(u64);

    impl RngCore for SplitMix {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            rand_core::impls::fill_bytes_via_next(self, dest)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    /// Gaps average 1 / rate and spread like an exponential distribution:
    /// standard deviation equal to the mean, and about e^-1 of them longer
    /// than the mean.
    #[tokio::test]
    async fn gaps_are_exponential_with_the_right_mean() {
        let mut clock = PoissonClock::with_rng(CELLS_PER_SECOND, SplitMix(3));
        let gaps: Vec<f64> = (0..20_000).map(|_| clock.gap().as_secs_f64()).collect();
        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
        let longer = gaps.iter().filter(|&&g| g > 0.25).count() as f64 / gaps.len() as f64;
        assert!((mean - 0.25).abs() < 0.01, "mean {mean}");
        assert!((var.sqrt() - 0.25).abs() < 0.015, "sd {}", var.sqrt());
        assert!((longer - (-1f64).exp()).abs() < 0.02, "{longer}");
    }

    #[tokio::test(start_paused = true)]
    async fn ticks_average_the_rate() {
        let mut clock = PoissonClock::new();
        let start = Instant::now();
        for _ in 0..400 {
            clock.tick().await;
        }
        let per_second = 400.0 / start.elapsed().as_secs_f64();
        assert!((3.4..4.6).contains(&per_second), "{per_second}");
    }
}
