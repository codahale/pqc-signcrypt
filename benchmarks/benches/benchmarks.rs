use criterion::{criterion_group, criterion_main, Criterion};
use pqc_signcrypt::{generic, keypair, protocol};

fn bench_signcrypt(c: &mut Criterion) {
    let (x, y) = (keypair(), keypair());
    let message = b"this is a message";
    let mut g = c.benchmark_group("signcrypt");
    g.bench_function("generic", |b| {
        b.iter(|| generic::signcrypt(&x, &y.public_key, message));
    });
    g.bench_function("lockstitch", |b| {
        b.iter(|| protocol::signcrypt(&x, &y.public_key, message));
    });
    g.finish();
}

fn bench_unsigncrypt(c: &mut Criterion) {
    let (x, y) = (keypair(), keypair());
    let message = b"this is a message";
    let mut g = c.benchmark_group("unsigncrypt");
    let ciphertext = generic::signcrypt(&x, &y.public_key, message);
    g.bench_function("generic", |b| {
        b.iter(|| generic::unsigncrypt(&y, &x.public_key, &ciphertext));
    });

    let ciphertext = protocol::signcrypt(&x, &y.public_key, message);
    g.bench_function("lockstitch", |b| {
        b.iter(|| protocol::unsigncrypt(&y, &x.public_key, &ciphertext));
    });
}

criterion_group!(benches, bench_signcrypt, bench_unsigncrypt);
criterion_main!(benches);
