use ark_ff::Field;

// helper function for polynomial multiplication
pub fn mul<E:Field>(p1: &[E], p2: &[E]) -> Vec<E> {
    let mut result = vec![E::ZERO; p1.len() + p2.len() - 1];

    for (i, &coeff1) in p1.iter().enumerate() {
        for (j, &coeff2) in p2.iter().enumerate() {
            result[i + j] += coeff1 * coeff2;
        }
    }

    result
}

// helper function for polynomial division
pub fn div<E:Field>(p1: &[E], p2: &[E]) -> Result<Vec<E>, &'static str> {
    if p2.is_empty() || p2.iter().all(|&x| x == E::ZERO) {
        return Err("Cannot divide by zero polynomial");
    }

    if p1.len() < p2.len() {
        return Ok(vec![E::ZERO]);
    }

    let mut quotient = vec![E::ZERO; p1.len() - p2.len() + 1];
    let mut remainder: Vec<E> = p1.to_vec();

    while remainder.len() >= p2.len() {
        let coeff = *remainder.last().unwrap() / *p2.last().unwrap();
        let pos = remainder.len() - p2.len();

        quotient[pos] = coeff;

        for (i, &factor) in p2.iter().enumerate() {
            remainder[pos + i] -= factor * coeff;
        }

        while let Some(true) = remainder.last().map(|x| *x == E::ZERO) {
            remainder.pop();
        }
    }

    Ok(quotient)
}

// helper function to evaluate polynomial at a point
pub fn evaluate<E:Field>(poly: &[E], point: E) -> E {
    let mut value = E::ZERO;

    for i in 0..poly.len() {
        value += poly[i] * point.pow(&[i as u64]);
    }

    value
}

// helper function to perform Lagrange interpolation given a set of points
pub fn interpolate<E:Field>(points: &[E], values: &[E]) -> Result<Vec<E>, &'static str> {
    if points.len() != values.len() {
        return Err("Number of points and values do not match");
    }

    let mut result = vec![E::ZERO; points.len()];

    for i in 0..points.len() {
        let mut numerator = E::ONE;
        let mut denominator = E::ONE;

        for j in 0..points.len() {
            if i == j {
                continue;
            }

            numerator *= -points[j];
            denominator *= points[i] - points[j];
        }

        result[i] = values[i] * numerator * denominator.inverse().unwrap();
    }

    Ok(result)
}