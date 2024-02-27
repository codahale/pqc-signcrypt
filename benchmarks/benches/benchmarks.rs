use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use pqc_signcrypt::{generic, keypair, protocol};

const LENS: &[(usize, &str)] =
    &[(16, "16B"), (256, "256B"), (1024, "1KiB"), (16 * 1024, "16KiB"), (1024 * 1024, "1MiB")];

fn bench_signcrypt(c: &mut Criterion) {
    let (x, y) = (keypair(), keypair());
    let mut g = c.benchmark_group("signcrypt");

    for &(len, id) in LENS {
        let input = vec![0u8; len];
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(format!("gen/{id}"), &len, |b, _| {
            b.iter(|| generic::signcrypt(&x, &y.public_key, &input));
        });
    }

    for &(len, id) in LENS {
        let input = vec![0u8; len];
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(format!("pro/{id}"), &len, |b, _| {
            b.iter(|| protocol::signcrypt(&x, &y.public_key, &input));
        });
    }

    g.finish();
}

fn bench_unsigncrypt(c: &mut Criterion) {
    let (x, y) = (keypair(), keypair());
    let mut g = c.benchmark_group("unsigncrypt");

    for &(len, id) in LENS {
        let input = vec![0u8; len];
        let ciphertext = generic::signcrypt(&x, &y.public_key, &input);
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(format!("gen/{id}"), &len, |b, _| {
            b.iter(|| generic::unsigncrypt(&y, &x.public_key, &ciphertext));
        });
    }

    for &(len, id) in LENS {
        let input = vec![0u8; len];
        let ciphertext = generic::signcrypt(&x, &y.public_key, &input);
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(format!("pro/{id}"), &len, |b, _| {
            b.iter(|| protocol::unsigncrypt(&y, &x.public_key, &ciphertext));
        });
    }

    g.finish();
}

criterion_group!(benches, bench_signcrypt, bench_unsigncrypt);
criterion_main!(benches);
