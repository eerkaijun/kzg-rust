/// NOTE: variable naming is based on notation in https://eprint.iacr.org/2020/527.pdf

use std::ops::{Mul, Div};
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use crate::utils::{get_omega, mul, div, scalar_mul, interpolate, evaluate};

#[derive(Clone)]
pub struct CRS<E: Pairing> {
    pub g1: Vec<E::G1>,
    pub g2: Vec<E::G2>
}

// NOTE: currently not in use (update function not implemented yet)
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
        let mut ai_numerator = vec![E::ScalarField::ZERO; degree+1];
        ai_numerator[0] = -E::ScalarField::ONE;
        ai_numerator[degree] = E::ScalarField::ONE;
        for i in 0..degree {
            // ai_denominator is X-w^i
            let ai_denominator = vec![-get_omega(&vec![E::ScalarField::ZERO; degree]).pow([i as u64]), E::ScalarField::ONE];
            let ai_polynomial = div(&ai_numerator, &ai_denominator).unwrap();

            // li_polynomial is ai_polynomial / a'(w^i), where a'(w^i) = n * (w^i)
            let li_polynomial = scalar_mul(
                &ai_polynomial,
                (get_omega(&vec![E::ScalarField::ZERO; degree]).pow([i as u64])).div(E::ScalarField::from(degree as u32))
            );

            // ui_polynomial is (li_polynomial - 1) / (X - w^i) 
            let mut ui_numerator = li_polynomial.clone();
            ui_numerator[0] = ui_numerator[0] - E::ScalarField::ONE;
            let ui_polynomial = div(&ui_numerator, &ai_denominator).unwrap();

            // commit according to crs_g1
            ai_commitment[i] = crs_g1.iter().zip(ai_polynomial.iter())
                .map(|(crs, ai_coeff)| crs.mul(ai_coeff))
                .fold(g1.mul(E::ScalarField::ZERO), |acc, element| acc + element);

            li_commitment[i] = crs_g1.iter().zip(li_polynomial.iter())
                .map(|(crs, li_coeff)| crs.mul(li_coeff))
                .fold(g1.mul(E::ScalarField::ZERO), |acc, element| acc + element);

            ui_commitment[i] = crs_g1.iter().zip(ui_polynomial.iter())
                .map(|(crs, ui_coeff)| crs.mul(ui_coeff))
                .fold(g1.mul(E::ScalarField::ZERO), |acc, element| acc + element);
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
        // check that vector length is equal to l_commitment length
        assert_eq!(vector.len(), self.proving_key.li_commitment.len());

        // commit vector
        let mut commitment = self.proving_key.crs.g1[0].mul(E::ScalarField::ZERO);
        for i in 0..vector.len() {
            commitment += self.proving_key.li_commitment[i] * vector[i]
        }
        commitment
    }

    // prove multiple positions in the vector
    pub fn prove_position(&self, indices: &[usize], vector: &[E::ScalarField]) -> E::G1 {
        // numerator is lagrage interpolation of the vector
        let points: Vec<E::ScalarField> = (0..vector.len()).map(|i| E::ScalarField::from(i as u32)).collect();
        let numerator = interpolate(&points, &vector).unwrap();

        // denominator is product of i in indices (X - w^i)
        let omega = get_omega(&vec![E::ScalarField::ZERO; vector.len()]);
        let mut denominator = vec![-omega.pow([indices[0] as u64]), E::ScalarField::ONE];
        for i in 1..indices.len() {
            denominator = mul(&denominator, &vec![-omega.pow([i as u64]), E::ScalarField::ONE]);
        }

        // quotient is numerator divided by denominator, commited by G1
        let quotient = div(&numerator, &denominator).unwrap();
        let mut pi = self.proving_key.crs.g1[0] * quotient[0];
        for i in 1..quotient.len() {
            pi += self.proving_key.crs.g1[i] * quotient[i];
        }

        pi     
    }

    // verify a subvector commitment
    pub fn verify_position(
        &self,
        commitment: E::G1,
        indices: &[usize],
        subvector: &[E::ScalarField],
        pi: E::G1
    ) -> bool {
        // denominator is product of i in indices (X - w^i)
        let omega = get_omega(&vec![E::ScalarField::ZERO; subvector.len()]);
        let mut denominator = vec![-omega.pow([indices[0] as u64]), E::ScalarField::ONE];
        for i in 1..indices.len() {
            denominator = mul(&denominator, &vec![-omega.pow([i as u64]), E::ScalarField::ONE]);
        }

        // commit denominator
        let mut denominator_commitment = self.verification_key.crs.g2[0].mul(E::ScalarField::ZERO);
        for i in 0..denominator.len() {
            denominator_commitment += self.verification_key.crs.g2[i].mul(denominator[i]);
        }

        // remainer is the product of the lagrange basis of the indices
        let indices_field: Vec<E::ScalarField> = indices.iter().map(|&i| E::ScalarField::from(i as u32)).collect();
        let remainder = interpolate(&indices_field, &subvector).unwrap();

        // commit remainder
        let mut remainder_commitment = self.verification_key.crs.g1[0].mul(E::ScalarField::ZERO);
        for i in 0..remainder.len() {
            remainder_commitment += self.verification_key.crs.g1[i].mul(remainder[i]);
        }

        // verification
        let lhs = E::pairing(pi, denominator_commitment);
        let rhs = E::pairing(commitment - remainder_commitment, self.verification_key.crs.g2[0]);
        lhs == rhs
    }

    // aggregate multiple proofs into one subvector commitment
    pub fn aggregate_proofs(&self, indices: &[usize], proofs: Vec<E::G1>) -> E::G1 {
        // make sure that length of indices is the same as proofs
        assert_eq!(indices.len(), proofs.len());

        // A(X) is product of i in indices (X - w^i)
        let omega = get_omega(&vec![E::ScalarField::ZERO; indices.len()]);
        let mut a_polynomial = vec![-omega.pow([indices[0] as u64]), E::ScalarField::ONE];
        for i in 1..indices.len() {
            a_polynomial = mul(&a_polynomial, &vec![-omega.pow([i as u64]), E::ScalarField::ONE]);
        }

        // A'(X), derivatives of A(X)
        let mut a_derivative = vec![E::ScalarField::ZERO; a_polynomial.len() - 1];
        for i in 1..a_polynomial.len() {
            a_derivative[i - 1] = a_polynomial[i] * E::ScalarField::from(i as u32);
        }

        let pi = indices.iter().enumerate().map(|(k, &i)|{
            proofs[k].mul(evaluate(&a_derivative, omega.pow([i as u64])))
        }).sum::<E::G1>();

        pi
    }

    // TODO: update commmitment and proofs functions

}