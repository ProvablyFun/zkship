//! Summary statistics over raw samples; every sample is also written out.

pub struct Summary {
    pub n: usize,
    pub median: f64,
    pub p95: f64,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub sd: f64,
}

/// Nearest-rank percentiles on a sorted copy.
pub fn summarize(samples: &[f64]) -> Summary {
    assert!(!samples.is_empty());
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();
    let rank = |p: f64| sorted[((p * n as f64).ceil() as usize).clamp(1, n) - 1];
    let mean = sorted.iter().sum::<f64>() / n as f64;
    let var = if n > 1 {
        sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    Summary {
        n,
        median: rank(0.5),
        p95: rank(0.95),
        min: sorted[0],
        max: sorted[n - 1],
        mean,
        sd: var.sqrt(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank() {
        let s = summarize(&(1..=100).map(f64::from).collect::<Vec<_>>());
        assert_eq!((s.median, s.p95, s.min, s.max), (50.0, 95.0, 1.0, 100.0));
        assert_eq!(summarize(&[3.0]).median, 3.0);
    }
}
