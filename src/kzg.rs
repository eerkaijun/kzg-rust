use std::ops::Mul;
use ark_ff::Field;
use ark_ec::pairing::Pairing;
use crate::utils::{div, mul, evaluate, interpolate};

pub struct KZG<E: Pairing> {
    pub g1: E::G1,
    pub g2: E::G2,
    pub g2_tau: E::G2,
    pub degree: usize,
    pub crs_g1: Vec<E::G1>,
    pub crs_g2: Vec<E::G2>,
}

impl <E:Pairing> KZG<E> {
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

    pub fn setup(&mut self, secret: E::ScalarField) {
        for i in 0..self.degree+1 {
            self.crs_g1.push(self.g1.mul(secret.pow(&[i as u64])));
            self.crs_g2.push(self.g2.mul(secret.pow(&[i as u64])));
        }
        self.g2_tau = self.g2.mul(secret);
    }

    pub fn commit(&self, poly: &[E::ScalarField]) -> E::G1 {
        let mut commitment = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..self.degree+1 {
            commitment += self.crs_g1[i] * poly[i];
        }
        commitment
    }

    pub fn open(&self, poly: &[E::ScalarField], point: E::ScalarField) -> E::G1 {
        // evaluate the polynomial at point
        let value = evaluate(poly, point);

        // initialize denominator
        let denominator = [-point, E::ScalarField::ONE];

        // initialize numerator
        let first = poly[0] - value;
        let rest = &poly[1..];
        let temp: Vec<E::ScalarField> = std::iter::once(first).chain(rest.iter().cloned()).collect();
        let numerator: &[E::ScalarField] = &temp;

        // get quotient by dividing numerator by denominator
        let quotient = div(numerator, &denominator).unwrap();

        // calculate pi as proof (quotient multiplied by CRS)
        let mut pi = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..quotient.len() {
            pi += self.crs_g1[i] * quotient[i];
        }

        // return pi
        pi
    }

    pub fn multi_open(&self, poly: &[E::ScalarField], points: &[E::ScalarField]) -> E::G1 {
        // denominator is a polynomial where all its root are points to be evaluated (zero poly)
        let mut zero_poly = vec![-points[0], E::ScalarField::ONE];
        for i in 1..points.len() {
            zero_poly = mul(&zero_poly, &[-points[i], E::ScalarField::ONE]);
        }

        // perform Lagrange interpolation on points
        let mut values = vec![];
        for i in 0..points.len() {
            values.push(evaluate(poly, points[i]));
        }
        let mut lagrange_poly = interpolate(points, &values).unwrap();
        lagrange_poly.resize(poly.len(), E::ScalarField::ZERO); // pad with zeros

        // numerator is the difference between the polynomial and the Lagrange interpolation
        let mut numerator = Vec::with_capacity(poly.len());
        for (coeff1, coeff2) in poly.iter().zip(lagrange_poly.as_slice()) {
            numerator.push(*coeff1 - coeff2);
        }

        // get quotient by dividing numerator by denominator
        let quotient = div(&numerator, &zero_poly).unwrap();

        // calculate pi as proof (quotient multiplied by CRS)
        let mut pi = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..quotient.len() {
            pi += self.crs_g1[i] * quotient[i];
        }

        // return pi
        pi
    }

    pub fn verify(
        &self,
        point: E::ScalarField,
        value: E::ScalarField,
        commitment: E::G1,
        pi: E::G1
    ) -> bool {
        let lhs = E::pairing(pi, self.g2_tau - self.g2.mul(point));
        let rhs = E::pairing(commitment - self.g1.mul(value), self.g2);
        lhs == rhs
    }

    pub fn verify_multi(
        &self,
        points: &[E::ScalarField],
        values: &[E::ScalarField],
        commitment: E::G1,
        pi: E::G1
    ) -> bool {
        // compute the zero polynomial
        let mut zero_poly = vec![-points[0], E::ScalarField::ONE];
        for i in 1..points.len() {
            zero_poly = mul(&zero_poly, &[-points[i], E::ScalarField::ONE]);
        }

        // compute commitment of zero polynomial in regards to crs_g2
        let mut zero_commitment = self.g2.mul(E::ScalarField::ZERO);
        for i in 0..zero_poly.len() {
            zero_commitment += self.crs_g2[i] * zero_poly[i];
        }

        // compute lagrange polynomial
        let lagrange_poly = interpolate(points, &values).unwrap();

        // compute commitment of lagrange polynomial in regards to crs_g1
        let mut lagrange_commitment = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..lagrange_poly.len() {
            lagrange_commitment += self.crs_g1[i] * lagrange_poly[i];
        }

        let lhs = E::pairing(pi, zero_commitment);
        let rhs = E::pairing(commitment - lagrange_commitment, self.g2);
        lhs == rhs
    }
}