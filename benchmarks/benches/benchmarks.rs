use criterion::{criterion_group, criterion_main, Criterion};
use pqc_signcrypt::{keypair, signcrypt, unsigncrypt};

fn bench_signcrypt(c: &mut Criterion) {
    let (x, y) = (keypair(), keypair());
    let message = b"this is a message";
    c.bench_function("signcrypt", |b| {
        b.iter(|| signcrypt(&x, &y.public_key, message));
    });
}

fn bench_unsigncrypt(c: &mut Criterion) {
    let (x, y) = (keypair(), keypair());
    let message = b"this is a message";
    let ciphertext = signcrypt(&x, &y.public_key, message);
    c.bench_function("unsigncrypt", |b| {
        b.iter(|| unsigncrypt(&y, &x.public_key, &ciphertext));
    });
}

criterion_group!(benches, bench_signcrypt, bench_unsigncrypt);
criterion_main!(benches);
