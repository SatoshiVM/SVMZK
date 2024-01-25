use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, hash_to_scalar, point_to_bytes, BASEPOINT_G1, BASEPOINT_G2,
};

/// a * b = c
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multiplication {
    pub comm: MultiplicationCommitment,
    pub secret: MultiplicationSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiplicationCommitment {
    pub point: RistrettoPoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiplicationSecret {
    pub value: u64,
    pub secret: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiplicationProof {
    pub d1: RistrettoPoint,
    pub d2: RistrettoPoint,
    pub b_circumflex: Scalar,
    pub s_circumflex: Scalar,
    pub beta_circumflex: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiplicationWitness {
    pub s: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiplicationWithPublicParams {
    pub proof: MultiplicationProof,
    pub a_point: RistrettoPoint,
    pub b_point: RistrettoPoint,
    pub c_point: RistrettoPoint,
}

impl Multiplication {
    pub fn commit(value: u64) -> Self {
        let secret = get_random_scalar();
        let commitment_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(value), secret],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        Self {
            comm: MultiplicationCommitment {
                point: commitment_point,
            },
            secret: MultiplicationSecret {
                value,
                secret,
            },
        }
    }

    pub fn witness(a_secret: Scalar, c_secret: Scalar, val_b: u64) -> MultiplicationWitness {
        let s = c_secret - a_secret * Scalar::from(val_b);

        MultiplicationWitness { s }
    }

    pub fn prove(
        a: &Multiplication,
        b: &Multiplication,
        c: &Multiplication,
        witness: &MultiplicationWitness,
    ) -> MultiplicationProof {
        let Multiplication {
            comm: MultiplicationCommitment { point: a_point },
            secret:
                MultiplicationSecret {
                    value: _a_value,
                    secret: _a_secret,
                },
        } = a;
        let Multiplication {
            comm: MultiplicationCommitment { point: b_point },
            secret:
                MultiplicationSecret {
                    value: b_value,
                    secret: b_secret,
                },
        } = b;
        let Multiplication {
            comm: MultiplicationCommitment { point: c_point },
            secret:
                MultiplicationSecret {
                    value: _c_value,
                    secret: _c_secret,
                },
        } = c;

        let MultiplicationWitness { s } = witness;

        let b_2 = get_random_scalar();
        let s_2 = get_random_scalar();
        let beta_2 = get_random_scalar();

        let d1 = RistrettoPoint::multiscalar_mul(&[b_2, s_2], &[*a_point, *BASEPOINT_G2]);
        let d2 = RistrettoPoint::multiscalar_mul(&[b_2, beta_2], &[*BASEPOINT_G1, *BASEPOINT_G2]);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(a_point));
        hash_vec.append(&mut point_to_bytes(b_point));
        hash_vec.append(&mut point_to_bytes(c_point));
        hash_vec.append(&mut point_to_bytes(&d1));
        hash_vec.append(&mut point_to_bytes(&d2));

        let e = hash_to_scalar(&hash_vec);

        //b^= b0 + e · b, sˆ = s0 + e · s, βˆ = β0 + e · β;
        let b_circumflex = b_2 + e * Scalar::from(*b_value);
        let s_circumflex = s_2 + e * s; // c_secret = s
        let beta_circumflex = beta_2 + e * b_secret;

        MultiplicationProof {
            d1,
            d2,
            b_circumflex,
            s_circumflex,
            beta_circumflex,
        }
    }

    pub fn verify(proof: MultiplicationWithPublicParams) -> bool {
        let MultiplicationWithPublicParams {
            proof:
                MultiplicationProof {
                    d1,
                    d2,
                    b_circumflex,
                    s_circumflex,
                    beta_circumflex,
                },
            a_point,
            b_point,
            c_point,
        } = proof;

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(&a_point));
        hash_vec.append(&mut point_to_bytes(&b_point));
        hash_vec.append(&mut point_to_bytes(&c_point));
        hash_vec.append(&mut point_to_bytes(&d1));
        hash_vec.append(&mut point_to_bytes(&d2));

        let e = hash_to_scalar(&hash_vec);

        // d1 · [c]e = [a]ˆb · hs
        let left = d1 + e * c_point;
        let right = RistrettoPoint::multiscalar_mul(
            &[b_circumflex, s_circumflex],
            &[a_point, *BASEPOINT_G2],
        );
        // d2 · [b]e = gˆb · hβ
        let left2 = d2 + e * b_point;
        let right2 = RistrettoPoint::multiscalar_mul(
            &[b_circumflex, beta_circumflex],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        left2 == right2 && left == right
    }
}

#[cfg(test)]
mod multiplication_tests {
    use super::*;
    use std::assert_eq;

    #[test]
    fn it_works() {
        let a = 30;
        let b = 18;
        let c = a * b;

        let a_comm_secret = Multiplication::commit(a);
        let b_comm_secret = Multiplication::commit(b);
        let c_comm_secret = Multiplication::commit(c);

        let witness =
            Multiplication::witness(a_comm_secret.secret.secret, c_comm_secret.secret.secret, b);

        let proof = Multiplication::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret, &witness);

        let result = Multiplication::verify(MultiplicationWithPublicParams {
            proof,
            a_point: a_comm_secret.comm.point,
            b_point: b_comm_secret.comm.point,
            c_point: c_comm_secret.comm.point,
        });

        assert_eq!(true, result);
    }
}
