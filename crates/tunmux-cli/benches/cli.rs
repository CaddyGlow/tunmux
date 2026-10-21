use std::hint::black_box;

use clap::Parser;
use criterion::{criterion_group, criterion_main, Criterion};

use tunmux_cli::cli::Cli;

fn cli_benchmarks(c: &mut Criterion) {
    let args = ["tunmux", "status"];
    assert!(Cli::try_parse_from(args).is_ok());
    c.bench_function("cli/parse_status", |b| {
        b.iter(|| black_box(Cli::try_parse_from(black_box(args)).expect("valid arguments")));
    });
}

criterion_group!(benches, cli_benchmarks);
criterion_main!(benches);
