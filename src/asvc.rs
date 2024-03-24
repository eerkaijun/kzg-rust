use std::ops::Mul;
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use crate::utils::{interpolate, get_omega, div};

pub struct UpdateKey<E: Pairing> {
    pub a_i: E::G1,
    pub u_i: E::G1
}

pub struct ProvingKey<E: Pairing> {
    pub crs_g1: Vec<E::G1>,
    pub crs_g2: Vec<E::G2>,
    pub update_key: UpdateKey<E>,
    pub l_i: Vec<E::G1>
}

pub struct VerificationKey<E: Pairing> {
    pub crs_g1: Vec<E::G1>,
    pub crs_g2: Vec<E::G2>,
    pub a: E::G1
}

pub struct ASVC<E: Pairing> {
    pub g1: E::G1,
    pub g2: E::G2,
    pub g2_tau: E::G2,
    pub degree: usize,
    pub crs_g1: Vec<E::G1>,
    pub crs_g2: Vec<E::G2>
}

impl <E: Pairing> ASVC<E> {
    pub fn key_gen(g1: E::G1, g2: E::G2, degree: usize, secret: E::ScalarField) {
        // set up common reference string
        let mut crs_g1: Vec<E::G1> = Vec::new();
        let mut crs_g2: Vec<E::G2> = Vec::new();
        for i in 0..degree+1 {
            crs_g1.push(g1.mul(secret.pow(&[i as u64])));
            crs_g2.push(g2.mul(secret.pow(&[i as u64])));
        }

        // a_commitment is X^n - 1 multiply by G1
        let a_commit: E::G1 = crs_g1[degree].mul(E::ScalarField::ONE) + crs_g1[0].mul(-E::ScalarField::ONE);

        // a_i is (X^n - 1) / (X - w^i) multiply by G1
        let mut a_i = vec![g1; degree];
        // l_i is Lagrange basis for point i, multiply by G1
        let mut l_i = vec![g1; degree];

        // numerator is X^n - 1
        let mut numerator = vec![E::ScalarField::ZERO; degree];
        numerator[0] = -E::ScalarField::ONE;
        numerator[degree] = E::ScalarField::ONE;
        for i in 0..degree {
            // X-w^i
            let denominator = vec![-get_omega(&numerator).pow([i as u64]), E::ScalarField::ONE];
            let result = div(&numerator, &denominator).unwrap();
            // commit according to crs_g1
            let mut accumulator = crs_g1[0].mul(result[0]);
            for j in 1..degree {
                accumulator += crs_g1[j].mul(result[j]);
            }
            a_i[i] = accumulator;
        }
    }

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