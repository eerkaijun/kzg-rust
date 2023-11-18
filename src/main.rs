pub mod kzg;
use kzg::KZG;
use ark_std::UniformRand;
use ark_bls12_381::{Bls12_381, Fr, G1Projective as G1, G2Projective as G2};

fn main() {
    // initialize kzg instance
    let mut rng = ark_std::test_rng();
    let degree = 16;
    let mut kzg_instance = KZG::<Bls12_381>::new(
        G1::rand(&mut rng),
        G2::rand(&mut rng),
        degree
    );

    // trusted setup ceremony
    let secret = Fr::rand(&mut rng);
    kzg_instance.setup(secret);

    // generate a random polynomial and commit it
    let poly = vec![Fr::rand(&mut rng); degree+1];
    let commitment = kzg_instance.commit(&poly);

    // generate a random point and open the polynomial at that point
    let point = Fr::rand(&mut rng);
    let pi = kzg_instance.open(&poly, point);

    // verify the proof
    let value = kzg_instance.evaluate(&poly, point);
    assert!(kzg_instance.verify(point, value, commitment, pi));
}
