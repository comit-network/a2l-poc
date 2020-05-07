use a2l::hsm_cl;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;

fn encrypt_benchmark(c: &mut Criterion) {
    let public_key = hsm_cl::keygen(b"benchmark").to_pk();
    let msg = a2l::secp256k1::KeyPair::random(&mut thread_rng());

    c.bench_function("encrypt", |b| {
        b.iter(|| hsm_cl::encrypt(black_box(&public_key), black_box(&msg)))
    });
}

fn verify_benchmark(c: &mut Criterion) {
    let public_key = hsm_cl::keygen(b"benchmark").to_pk();
    let msg = a2l::secp256k1::KeyPair::random(&mut thread_rng());

    let (ciphertext, proof) = hsm_cl::encrypt(&public_key, &msg);

    c.bench_function("verify", |b| {
        b.iter(|| {
            hsm_cl::verify(
                black_box(&public_key),
                black_box(&proof),
                black_box((&ciphertext, &msg.to_pk())),
            )
        })
    });
}

fn decrypt_benchmark(c: &mut Criterion) {
    let keypair = hsm_cl::keygen(b"benchmark");
    let msg = a2l::secp256k1::KeyPair::random(&mut thread_rng());

    let (ciphertext, _) = hsm_cl::encrypt(&keypair.to_pk(), &msg);

    c.bench_function("decrypt", |b| {
        b.iter(|| hsm_cl::decrypt(black_box(&keypair), black_box(&ciphertext)))
    });
}

fn multiply_benchmark(c: &mut Criterion) {
    let keypair = hsm_cl::keygen(b"benchmark");
    let msg = a2l::secp256k1::KeyPair::random(&mut thread_rng());

    let (ciphertext, _) = hsm_cl::encrypt(&keypair.to_pk(), &msg);

    c.bench_function("multiply", |b| {
        b.iter(|| black_box(&ciphertext) * black_box(&msg))
    });
}

criterion_group!(
    benches,
    encrypt_benchmark,
    verify_benchmark,
    decrypt_benchmark,
    multiply_benchmark
);
criterion_main!(benches);
