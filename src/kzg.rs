use std::ops::Mul;

use ark_ff::Field;
use ark_ec::pairing::Pairing;

pub struct KZG<E: Pairing> {
    pub g1: E::G1,
    pub g2: E::G2,
    pub degree: usize,
    pub crs: Vec<E::G1>,
}

impl <E:Pairing> KZG<E> {
    pub fn new(g1: E::G1, g2: E::G2, degree: usize) -> Self {
        Self {
            g1,
            g2,
            degree,
            crs: vec![],
        }
    }

    pub fn setup(&mut self, secret: E::ScalarField) {
        for i in 0..self.degree+1 {
            self.crs.push(self.g1.mul(secret.pow(&[i as u64])));
        }
    }

    pub fn commit(&self, poly: &[E::ScalarField]) -> E::G1 {
        let mut commitment = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..self.degree+1 {
            commitment += self.crs[i] * poly[i];
        }
        commitment
    }

    pub fn open(&self, poly: &[E::ScalarField], point: E::ScalarField) -> E::ScalarField {
        let value = E::ScalarField::ZERO;
        value
    }

    pub fn verify(
        &self,
        point: E::ScalarField,
        value: E::ScalarField,
        commitment: E::G1,
        proof: E::G1
    ) -> bool {
        false        
    }
}