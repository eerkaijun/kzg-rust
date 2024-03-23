use std::ops::Mul;
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use crate::utils::interpolate;

pub struct ASVC<E: Pairing> {
    pub g1: E::G1,
    pub g2: E::G2,
    pub g2_tau: E::G2,
    pub degree: usize,
    pub crs_g1: Vec<E::G1>,
    pub crs_g2: Vec<E::G2>
}

impl <E: Pairing> ASVC<E> {
    pub fn new(g1: E::G1, g2: E::G2, degree: usize) -> Self {
        Self {
            g1,
            g2,
            g2_tau: g2.mul(E::ScalarField::ZERO),
            degree,
            crs_g1: vec![],
            crs_g2: vec![],
        }
    }

    // the `secret` should be generated through secure MPC
    pub fn setup(&mut self, secret: E::ScalarField) {
        for i in 0..self.degree+1 {
            self.crs_g1.push(self.g1.mul(secret.pow(&[i as u64])));
            self.crs_g2.push(self.g2.mul(secret.pow(&[i as u64])));
        }
        self.g2_tau = self.g2.mul(secret);
    }

    // commit the lagrange polynomial of the vector
    pub fn vector_commit(&self, vector: &[E::ScalarField]) -> E::G1 {
        let indices = (1..=vector.len()).map(|i| E::ScalarField::from(i as u64)).collect::<Vec<_>>();
        let lagrange_poly = interpolate(&indices, vector).unwrap();
        let mut commitment = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..self.degree+1 {
            commitment += self.crs_g1[i] * lagrange_poly[i];
        }
        commitment
    }

    // prove multiple positions in the vector
    pub fn prove_position(&self, indices: &[E::ScalarField], subvector: &[E::ScalarField]) {
        
    }

    // aggregate multiple proofs into one subvector commitment
    pub fn aggregate(&self, proofs: Vec<E::G1>) {

    }

    // verify a subvector commitment
    pub fn verify(&self, commitment: E::G1) -> bool {
        false
    }

}