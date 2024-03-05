use ark_ec::pairing::Pairing;

pub struct ASVC<E: Pairing> {
    pub proving_key: E::G1,
    pub verification_key: E::G1,
}

impl <E: Pairing> ASVC<E> {

    // TODO: key generation
    pub fn new(g1: E::G1) -> Self {
        Self {
            proving_key: g1,
            verification_key: g1,
        }
    }

    // aggregate multiple proofs into one subvector commitment
    pub fn aggregate(&self, proofs: Vec<E::G1>) {

    }

    // verify a subvector commitment
    pub fn verify(&self, commitment: E::G1) -> bool {
        false
    }

}