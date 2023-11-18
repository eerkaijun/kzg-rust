use std::ops::Mul;
use ark_ff::Field;
use ark_ec::pairing::Pairing;

pub struct KZG<E: Pairing> {
    pub g1: E::G1,
    pub g2: E::G2,
    pub g2_tau: E::G2,
    pub degree: usize,
    pub crs: Vec<E::G1>,
}

impl <E:Pairing> KZG<E> {
    pub fn new(g1: E::G1, g2: E::G2, degree: usize) -> Self {
        Self {
            g1,
            g2,
            g2_tau: g2.mul(E::ScalarField::ZERO),
            degree,
            crs: vec![],
        }
    }

    pub fn setup(&mut self, secret: E::ScalarField) {
        for i in 0..self.degree+1 {
            self.crs.push(self.g1.mul(secret.pow(&[i as u64])));
        }
        self.g2_tau = self.g2.mul(secret);
    }

    pub fn commit(&self, poly: &[E::ScalarField]) -> E::G1 {
        let mut commitment = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..self.degree+1 {
            commitment += self.crs[i] * poly[i];
        }
        commitment
    }

    pub fn open(&self, poly: &[E::ScalarField], point: E::ScalarField) -> E::G1 {
        // evaluate the polynomial at point
        let value = self.evaluate(poly, point);

        // initialize denominator
        let denominator = [-point, E::ScalarField::ONE];

        // initialize numerator
        let first = poly[0] - value;
        let rest = &poly[1..];
        let temp: Vec<E::ScalarField> = std::iter::once(first).chain(rest.iter().cloned()).collect();
        let numerator: &[E::ScalarField] = &temp;

        // get quotient by dividing numerator by denominator
        let quotient = Self::div(numerator, &denominator).unwrap();

        // calculate pi as proof (quotient multiplied by CRS)
        let mut pi = self.g1.mul(E::ScalarField::ZERO);
        for i in 0..quotient.len() {
            pi += self.crs[i] * quotient[i];
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

    // helper function to evaluate polynomial at a point
    pub fn evaluate(&self, poly: &[E::ScalarField], point: E::ScalarField) -> E::ScalarField {
        let mut value = E::ScalarField::ZERO;
        for i in 0..poly.len() {
            value += poly[i] * point.pow(&[i as u64]);
        }
        value
    }

    // helper function for polynomial division
    pub fn div(p1: &[E::ScalarField], p2: &[E::ScalarField]) -> Result<Vec<E::ScalarField>, &'static str> {
        if p2.is_empty() || p2.iter().all(|&x| x == E::ScalarField::ZERO) {
            return Err("Cannot divide by zero polynomial");
        }
    
        if p1.len() < p2.len() {
            return Ok(vec![E::ScalarField::ZERO]);
        }
    
        let mut quotient = vec![E::ScalarField::ZERO; p1.len() - p2.len() + 1];
        let mut remainder: Vec<E::ScalarField> = p1.to_vec();
    
        while remainder.len() >= p2.len() {
            let coeff = *remainder.last().unwrap() / *p2.last().unwrap();
            let pos = remainder.len() - p2.len();
    
            quotient[pos] = coeff;
    
            for (i, &factor) in p2.iter().enumerate() {
                remainder[pos + i] -= factor * coeff;
            }
    
            while let Some(true) = remainder.last().map(|x| *x == E::ScalarField::ZERO) {
                remainder.pop();
            }
        }
    
        Ok(quotient)
    }
}