use std::hint::black_box;

use clap::Parser;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use tunmux::cli::Cli;
use tunmux::wireguard::config::{generate_config, parse_config, WgConfigParams};

// Synthetic key material only; these configs are never used to connect.
const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn params() -> WgConfigParams<'static> {
    WgConfigParams {
        private_key: KEY,
        addresses: &["10.0.0.2/32", "fd00::2/128"],
        dns_servers: &["10.0.0.1", "fd00::1"],
        mtu: Some(1420),
        server_public_key: KEY,
        server_ip: "2001:db8::1",
        server_port: 51820,
        preshared_key: Some(KEY),
        allowed_ips: "0.0.0.0/0, ::/0",
    }
}

fn config_benchmarks(c: &mut Criterion) {
    let params = params();
    let config = generate_config(&params);
    let parsed = parse_config(&config).expect("valid synthetic config");
    assert_eq!(parsed.addresses.len(), 2);
    assert_eq!(parsed.peers.len(), 1);

    c.bench_function("wireguard/generate_dual_stack", |b| {
        b.iter(|| black_box(generate_config(black_box(&params))));
    });

    let peer_start = config.find("[Peer]").expect("generated peer section");
    let mut group = c.benchmark_group("wireguard/parse");
    for peer_count in [1, 10, 100] {
        let input = format!(
            "{}{}",
            &config[..peer_start],
            config[peer_start..].repeat(peer_count)
        );
        assert_eq!(
            parse_config(&input)
                .expect("valid multi-peer config")
                .peers
                .len(),
            peer_count
        );
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            &input,
            |b, input| {
                b.iter(|| black_box(parse_config(black_box(input)).expect("valid fixture")));
            },
        );
    }
    group.finish();
}

fn cli_benchmarks(c: &mut Criterion) {
    let args = ["tunmux", "status"];
    assert!(Cli::try_parse_from(args).is_ok());
    c.bench_function("cli/parse_status", |b| {
        b.iter(|| black_box(Cli::try_parse_from(black_box(args)).expect("valid arguments")));
    });
}

fn key_benchmarks(c: &mut Criterion) {
    #[cfg(any(feature = "proton", feature = "mullvad", feature = "ivpn"))]
    {
        use tunmux::shared::crypto::keys::VpnKeys;

        let seed = [42_u8; 32];
        assert!(VpnKeys::from_ed25519_private_key(seed).is_ok());
        c.bench_function("crypto/derive_vpn_keys", |b| {
            b.iter(|| {
                black_box(
                    VpnKeys::from_ed25519_private_key(black_box(seed)).expect("valid fixture"),
                )
            });
        });
    }
    let _ = c;
}

criterion_group!(benches, config_benchmarks, cli_benchmarks, key_benchmarks);
criterion_main!(benches);
