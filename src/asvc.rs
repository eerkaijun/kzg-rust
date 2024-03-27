use std::ops::{Mul, Div};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use crate::utils::{get_omega, div, scalar_mul};

#[derive(Clone)]
pub struct CRS<E: Pairing> {
    pub g1: Vec<E::G1>,
    pub g2: Vec<E::G2>
}

#[derive(Clone)]
pub struct UpdateKey<E: Pairing> {
    pub ai_commitment: Vec<E::G1>,
    pub ui_commitment: Vec<E::G1>
}

pub struct ProvingKey<E: Pairing> {
    pub crs: CRS<E>,
    pub update_key: UpdateKey<E>,
    pub li_commitment: Vec<E::G1>
}

pub struct VerificationKey<E: Pairing> {
    pub crs: CRS<E>,
    pub a_commitment: E::G1
}

pub struct ASVC<E: Pairing> {
    pub degree: usize,
    pub update_key: UpdateKey<E>,
    pub proving_key: ProvingKey<E>,
    pub verification_key: VerificationKey<E>
}

impl <E: Pairing> ASVC<E> {
    pub fn key_gen(g1: E::G1, g2: E::G2, degree: usize, secret: E::ScalarField) -> Self {
        // set up common reference string
        let mut crs_g1: Vec<E::G1> = Vec::new();
        let mut crs_g2: Vec<E::G2> = Vec::new();
        for i in 0..degree+1 {
            crs_g1.push(g1.mul(secret.pow(&[i as u64])));
            crs_g2.push(g2.mul(secret.pow(&[i as u64])));
        }

        // a_commitment is X^n - 1 multiply by G1
        let a_commitment: E::G1 = crs_g1[degree].mul(E::ScalarField::ONE) + crs_g1[0].mul(-E::ScalarField::ONE);

        // ai_commitment is (X^n - 1) / (X - w^i) multiply by G1
        let mut ai_commitment = vec![g1; degree];

        // li_commitment is Lagrange basis for point i, multiply by G1
        let mut li_commitment = vec![g1; degree];

        // ui_commitment is the KZG proofs for lagrage basis for point i
        let mut ui_commitment = vec![g1; degree];

        // ai_numerator is X^n - 1
        let mut ai_numerator = vec![E::ScalarField::ZERO; degree];
        ai_numerator[0] = -E::ScalarField::ONE;
        ai_numerator[degree] = E::ScalarField::ONE;
        for i in 0..degree {
            // ai_denominator is X-w^i
            let ai_denominator = vec![-get_omega(&ai_numerator).pow([i as u64]), E::ScalarField::ONE];
            let ai_polynomial = div(&ai_numerator, &ai_denominator).unwrap(); // TODO: double check if the dimension of ai_polynomial is correct

            // li_polynomial is ai_polynomial / a'(w^i), where a'(w^1) = n * (w^i)
            let li_polynomial = scalar_mul(
                &ai_polynomial,
                (get_omega(&ai_numerator).pow([i as u64])).div(E::ScalarField::from(degree as u32))
            );

            // ui_polynomial is (li_polynomial - 1) / (X - w^i) 
            let mut ui_numerator = li_polynomial.clone();
            ui_numerator[0] = ui_numerator[0] - E::ScalarField::ONE;
            let ui_polynomial = div(&ui_numerator, &ai_denominator).unwrap();

            // commit according to crs_g1
            // TODO: maybe put it into a helper function
            let mut ai_accumulator = crs_g1[0].mul(ai_polynomial[0]);
            let mut li_accumulator = crs_g1[0].mul(li_polynomial[0]);
            let mut ui_accumulator = crs_g1[0].mul(ui_polynomial[0]);
            for j in 1..degree {
                ai_accumulator += crs_g1[j].mul(ai_polynomial[j]);
                li_accumulator += crs_g1[j].mul(li_polynomial[j]);
                ui_accumulator += crs_g1[j].mul(ui_polynomial[j]);
            }
            ai_commitment[i] = ai_accumulator;
            li_commitment[i] = li_accumulator;
            ui_commitment[i] = ui_accumulator;
        }

        let update_key = UpdateKey {
            ai_commitment,
            ui_commitment
        };
        let crs = CRS {
            g1: crs_g1,
            g2: crs_g2
        };

        Self {
            degree,
            update_key: update_key.clone(),
            proving_key: ProvingKey {
                crs: crs.clone(),
                update_key: update_key.clone(),
                li_commitment
            },
            verification_key: VerificationKey {
                crs: crs.clone(),
                a_commitment
            }
        }
    }

    // commit the lagrange polynomial of the vector
    pub fn vector_commit(&self, vector: &[E::ScalarField]) -> E::G1 {
        // TODO: check that vector length is equal to l_commitment length
        let mut commitment = self.proving_key.crs.g1[0].mul(E::ScalarField::ZERO);
        for i in 0..vector.len() {
            commitment += self.proving_key.li_commitment[i] * vector[i]
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