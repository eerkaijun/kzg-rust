use ark_ff::Field;
use ark_ec::pairing::Pairing;

pub struct KZG<E: Pairing> {
    pub g1: E::G1,
    pub g2: E::G2,
    pub degree: usize,
}

impl <E:Pairing> KZG<E> {
    pub fn new(g1: E::G1, g2: E::G2, degree: usize) -> Self {
        Self {
            g1,
            g2,
            degree,
        }
    }

    pub fn setup(&mut self, secret: E::ScalarField) {

    }

    pub fn commit(&self, poly: &[E::ScalarField]) {

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