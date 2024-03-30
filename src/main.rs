pub mod kzg;
pub mod asvc;
pub mod utils;
use kzg::KZG;
use asvc::ASVC;
use utils::evaluate;
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

    // test single point evaluation
    test_single_evaluation(&kzg_instance, &poly, commitment);

    // test multi point evaluation
    test_multi_evaluation(&kzg_instance, &poly, commitment);

    // initialize asvc instance
    let asvc_instance = ASVC::<Bls12_381>::key_gen(
        G1::rand(&mut rng),
        G2::rand(&mut rng),
        degree,
        secret
    );

    // generate a random vector and commit to it
    let vector = vec![Fr::rand(&mut rng); degree];
    let commitment = asvc_instance.vector_commit(&vector);

    // test vector evaluation
    test_vector_evaluation(&asvc_instance, &vector, commitment);
}

pub fn test_single_evaluation(
    kzg_instance: &KZG<Bls12_381>,
    poly: &[Fr],
    commitment: G1
) {
    let mut rng = ark_std::test_rng();

    // generate a random point and open the polynomial at that point
    let point = Fr::rand(&mut rng);
    let pi = kzg_instance.open(&poly, point);

    // verify the proof
    let value = evaluate(&poly, point);
    assert!(kzg_instance.verify(point, value, commitment, pi));

    println!("Single point evaluation verified!");
}

pub fn test_multi_evaluation(
    kzg_instance: &KZG<Bls12_381>,
    poly: &[Fr],
    commitment: G1
) {
    let mut rng = ark_std::test_rng();

    // generate three random points and open the polynomial at those points
    let points: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
    let pi = kzg_instance.multi_open(&poly, &points);

    // evaluate the polynomial at those points
    let mut values = vec![];
    for i in 0..points.len() {
        values.push(evaluate(poly, points[i]));
    }

    // verify the proof
    assert!(kzg_instance.verify_multi(&points, &values, commitment, pi));

    println!("Multi points evaluation verified!");
}

pub fn test_vector_evaluation(
    asvc_instance: &ASVC<Bls12_381>,
    vector: &[Fr],
    commitment: G1
) {
    assert!(false);

    println!("Vector evaluation verified!");
}