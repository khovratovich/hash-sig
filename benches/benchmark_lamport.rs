use criterion::Criterion;
use hashsig::onetimesig::lamport::Lamport;
use hashsig::onetimesig::OneTimeSignatureScheme;
use hashsig::symmetric::hashprf::Sha256PRF;
use hashsig::symmetric::sha::Sha256Hash;
use rand::rngs::OsRng;

type LamportSha = Lamport<Sha256Hash, Sha256PRF>;

pub fn lamport_bench(c: &mut Criterion) {
    let mut rng = OsRng;

    // benchmark for key generation
    c.bench_function("Lamport-Sha: generate a key pair", |b| {
        b.iter(|| {
            let (_pk, _sk) = LamportSha::gen::<OsRng>(&mut rng);
        });
    });

    // benchmark for signing
    let (pk, sk) = LamportSha::gen::<OsRng>(&mut rng); // Generate a key pair
    let digest = [0u8; 32]; // Example message digest
    c.bench_function("Lamport-Sha: sign a message", |b| {
        b.iter(|| LamportSha::sign(&sk, &digest));
    });

    // benchmark for verification
    let sig = LamportSha::sign(&sk, &digest); // Sign the message
    c.bench_function("Lamport-Sha: verify a signature", |b| {
        b.iter(|| LamportSha::verify(&pk, &digest, &sig));
    });
}
