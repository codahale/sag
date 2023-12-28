use std::iter;

use curve25519_dalek::{RistrettoPoint, Scalar};
use digest::{typenum::consts::U64, Digest};
use rand_core::CryptoRngCore;

pub fn sign<D>(
    ring: &[RistrettoPoint],
    signer: &Scalar,
    mut digest: D,
    mut rng: impl CryptoRngCore,
) -> (Scalar, Vec<Scalar>)
where
    D: Digest<OutputSize = U64> + Clone,
{
    // Encode the points on the ring and sort them by lexical order.
    let ring = encode_ring(ring, &mut digest);

    // Find the index of the signer in the ring.
    let pk = RistrettoPoint::mul_base(signer);
    let index = ring.iter().position(|q| q == &&pk).expect("should include the signer in the ring");

    // Generate a random commitment scalar.
    let alpha = Scalar::random(&mut rng);

    // Generate random fake challenge scalars.
    let mut r = Vec::from_iter(iter::repeat_with(|| Scalar::random(&mut rng)).take(ring.len()));

    // Generate proof scalars.
    let mut c = vec![Scalar::ZERO; ring.len()];
    c[(index + 1) % ring.len()] = {
        let p = RistrettoPoint::mul_base(&alpha);
        let mut digest = digest.clone();
        digest.update(p.compress().as_bytes());
        Scalar::from_hash(digest)
    };
    for i in ((index + 1)..(index + ring.len())).map(|i| i % ring.len()) {
        c[(i + 1) % ring.len()] = {
            let p = (ring[i] * c[i]) + RistrettoPoint::mul_base(&r[i]);
            let mut digest = digest.clone();
            digest.update(p.compress().as_bytes());
            Scalar::from_hash(digest)
        };
    }

    // Close the ring by calculating the correct challenge.
    r[index] = alpha - c[0] * signer;

    // Return the first proof scalar and the ring of challenge scalars.
    (c[0], r)
}

pub fn verify<D>(ring: &[RistrettoPoint], mut digest: D, (c0, r): (Scalar, Vec<Scalar>)) -> bool
where
    D: Digest<OutputSize = U64> + Clone,
{
    // Encode the points on the ring and sort them by lexical order.
    let ring = encode_ring(ring, &mut digest);

    // Re-calculate the proof scalars.
    let mut c = vec![Scalar::ZERO; ring.len()];
    c[0] = c0;
    for i in 0..ring.len() {
        c[(i + 1) % ring.len()] = {
            let p = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c[i], ring[i], &r[i]);
            let mut digest = digest.clone();
            digest.update(p.compress().as_bytes());
            Scalar::from_hash(digest)
        };
    }

    // The signature is valid iff the re-calculated ring ends where it began.
    c[0] == c0
}

fn encode_ring<'ring>(
    ring: &'ring [RistrettoPoint],
    digest: &mut impl Digest,
) -> Vec<&'ring RistrettoPoint> {
    // Encode the points on the ring and sort them by lexical order.
    let mut ring = ring
        .iter()
        .map(|q| (q, q.compress().to_bytes()))
        .collect::<Vec<(&RistrettoPoint, [u8; 32])>>();
    ring.sort_by_cached_key(|(_, encoded)| *encoded);

    // Add the ring in lexical order to the digest.
    for (_, encoded) in ring.iter() {
        digest.update(encoded);
    }

    ring.into_iter().map(|(q, _)| q).collect()
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use sha2::Sha512;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (c, ring) = setup(&mut rng);

        let d = Sha512::new().chain_update(b"what a message");
        let sig = sign(&ring, &c, d.clone(), rng);

        assert!(verify(&ring, d, sig));
    }

    #[test]
    fn bad_ring() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (c, ring) = setup(&mut rng);

        let d = Sha512::new().chain_update(b"what a message");
        let sig = sign(&ring, &c, d.clone(), &mut rng);

        let (_, ring) = setup(&mut rng);
        assert!(!verify(&ring, d, sig));
    }

    #[test]
    fn bad_message() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (c, ring) = setup(&mut rng);

        let d = Sha512::new().chain_update(b"what a message");
        let sig = sign(&ring, &c, d.clone(), rng);

        let d = Sha512::new().chain_update(b"what a wrong message");
        assert!(!verify(&ring, d, sig));
    }

    #[test]
    fn bad_sig1() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (c, ring) = setup(&mut rng);

        let d = Sha512::new().chain_update(b"what a message");
        let (_, r) = sign(&ring, &c, d.clone(), &mut rng);

        let c0 = Scalar::random(&mut rng);

        assert!(!verify(&ring, d, (c0, r)));
    }

    #[test]
    fn bad_sig2() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (c, ring) = setup(&mut rng);

        let d = Sha512::new().chain_update(b"what a message");
        let (c0, mut r) = sign(&ring, &c, d.clone(), &mut rng);

        r[0] = Scalar::random(&mut rng);

        assert!(!verify(&ring, d, (c0, r)));
    }

    fn setup(mut rng: impl CryptoRngCore) -> (Scalar, Vec<RistrettoPoint>) {
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let c = Scalar::random(&mut rng);
        let d = Scalar::random(&mut rng);

        let ring = vec![
            RistrettoPoint::mul_base(&a),
            RistrettoPoint::mul_base(&b),
            RistrettoPoint::mul_base(&c),
            RistrettoPoint::mul_base(&d),
        ];

        (c, ring)
    }
}
