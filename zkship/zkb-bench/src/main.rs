//! Benchmark harness for the paper's evaluation (Section 9). Every sample is
//! written to CSV under the output directory; summaries use nearest-rank
//! percentiles.
//!
//! ```text
//! zkb-bench env                       # build/platform facts (JSON on stdout)
//! zkb-bench cold-init                 # first use of each profile (run in a fresh process)
//! zkb-bench setup-once [--rules R]    # one prove + verify, for peak-RSS measurement
//! zkb-bench ops    --out DIR [--setup-iters N] [--answer-iters N] [--warmup N] [--fleets N]
//! zkb-bench sizes  --out DIR
//! zkb-bench games  --out DIR [--rules R] [--strategy S] [--games N] [--seed N]
//! zkb-bench net    --out DIR --rtt-ms X [--mbps Y] [--rules R] [--strategy S] [--games N] [--seed N]
//! ```

#![forbid(unsafe_code)]

mod games;
mod ops;
mod stats;

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use zkb_core::params::Rules;

/// Appends CSV lines, writing the header when a file is created.
pub struct Out {
    dir: PathBuf,
    seen: BTreeSet<String>,
}

impl Out {
    fn new(dir: PathBuf) -> Out {
        std::fs::create_dir_all(&dir).expect("create output directory");
        Out {
            dir,
            seen: BTreeSet::new(),
        }
    }

    pub fn line(&mut self, file: &str, header: &str, row: &str) {
        let path = self.dir.join(file);
        let fresh = !path.exists();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open csv");
        if fresh {
            writeln!(f, "{header}").unwrap();
        } else if self.seen.insert(file.to_string()) {
            // Appending to an existing file: headers must match.
            let first = std::fs::read_to_string(&path).unwrap();
            assert_eq!(
                first.lines().next(),
                Some(header),
                "{file}: header mismatch"
            );
        }
        self.seen.insert(file.to_string());
        writeln!(f, "{row}").unwrap();
    }
}

fn arg<T: std::str::FromStr>(args: &[String], flag: &str, default: Option<T>) -> T {
    match args.iter().position(|a| a == flag) {
        Some(i) => args
            .get(i + 1)
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("bad value for {flag}")),
        None => default.unwrap_or_else(|| panic!("missing {flag}")),
    }
}

fn rules(args: &[String]) -> Rules {
    match arg::<String>(args, "--rules", Some("standard".into())).as_str() {
        "standard" => Rules::Standard,
        "no-touch" => Rules::NoTouch,
        other => panic!("unknown rules {other}"),
    }
}

fn game_config(args: &[String]) -> games::GameConfig {
    games::GameConfig {
        rules: rules(args),
        strategy: games::Strategy::parse(&arg::<String>(
            args,
            "--strategy",
            Some("hunt-target".into()),
        ))
        .expect("strategy: sweep, random or hunt-target"),
        games: arg(args, "--games", Some(10)),
        seed: arg(args, "--seed", Some(1)),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = || Out::new(PathBuf::from(arg::<String>(&args, "--out", None)));
    match args.first().map(String::as_str) {
        Some("env") => env(),
        Some("cold-init") => ops::cold_init(),
        Some("setup-once") => ops::setup_once(rules(&args)),
        Some("ops") => ops::run(
            &mut out(),
            &ops::Config {
                setup_iters: arg(&args, "--setup-iters", Some(100)),
                answer_iters: arg(&args, "--answer-iters", Some(500)),
                warmup: arg(&args, "--warmup", Some(10)),
                fleets: arg(&args, "--fleets", Some(10)),
            },
        ),
        Some("sizes") => ops::sizes(&mut out()),
        Some("games") => games::run_local(&mut out(), &game_config(&args)),
        Some("net") => games::run_net(
            &mut out(),
            &games::NetConfig {
                game: game_config(&args),
                rtt_ms: arg(&args, "--rtt-ms", None),
                mbps: arg(&args, "--mbps", Some(0.0)),
            },
        ),
        _ => {
            eprintln!("usage: see the module documentation in zkb-bench/src/main.rs");
            std::process::exit(2);
        }
    }
}

/// Facts the results depend on that the binary itself knows; the run script
/// adds the machine, toolchain and commit.
fn env() {
    println!(
        "{{\"crate_version\":\"{}\",\"profile\":\"{}\",\"target_arch\":\"{}\",\"avx2_compile_time\":{}}}",
        env!("CARGO_PKG_VERSION"),
        if cfg!(debug_assertions) { "debug" } else { "release" },
        std::env::consts::ARCH,
        cfg!(target_feature = "avx2")
    );
}
