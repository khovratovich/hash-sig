use criterion::Criterion;
use hashsig::onetimesig::winternitz::Winternitz;
use hashsig::onetimesig::OneTimeSignatureScheme;
use hashsig::symmetric::hashprf::Sha256PRF;
use hashsig::symmetric::sha::Sha256Hash;
use rand::rngs::OsRng;

type WinternitzSha = Winternitz<Sha256Hash, Sha256PRF>;

pub fn winternitz_bench(c: &mut Criterion) {
    let mut rng = OsRng;

    // benchmark for key generation
    c.bench_function("Winternitz-Sha: generate a key pair", |b| {
        b.iter(|| {
            let (_pk, _sk) = WinternitzSha::gen::<OsRng>(&mut rng);
        });
    });

    // benchmark for signing
    let (pk, sk) = WinternitzSha::gen::<OsRng>(&mut rng); // Generate a key pair
    let digest = [0u8; 32]; // Example message digest
    c.bench_function("Winternitz-Sha: sign a message", |b| {
        b.iter(|| WinternitzSha::sign(&sk, &digest));
    });

    // benchmark for verification
    let sig = WinternitzSha::sign(&sk, &digest); // Sign the message
    c.bench_function("Winternitz-Sha: verify a signature", |b| {
        b.iter(|| WinternitzSha::verify(&pk, &digest, &sig));
    });
}
