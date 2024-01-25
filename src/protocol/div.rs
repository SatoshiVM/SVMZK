use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, hash_to_scalar, point_to_bytes, BASEPOINT_G1, BASEPOINT_G2,
};

/// a / b = c
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Division {
    pub comm: DivisionCommitment,
    pub secret: DivisionSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivisionCommitment {
    pub point: RistrettoPoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivisionSecret {
    pub value: u64,
    pub secret: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivisionProof {
    pub d1: RistrettoPoint,
    pub d2: RistrettoPoint,
    pub b_circumflex: Scalar,
    pub s_circumflex: Scalar,
    pub beta_circumflex: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivisionWitness {
    pub s: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivisionWithPublicParams {
    pub proof: DivisionProof,
    pub a_point: RistrettoPoint,
    pub b_point: RistrettoPoint,
    pub c_point: RistrettoPoint,
}

impl Division {
    pub fn commit(value: u64) -> Self {
        let secret = get_random_scalar();
        let commitment_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(value), secret],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        Self {
            comm: DivisionCommitment {
                point: commitment_point,
            },
            secret: DivisionSecret {
                value,
                secret,
            },
        }
    }

    pub fn witness(a_secret: Scalar, c_secret: Scalar, val_b: u64) -> DivisionWitness {
        let s = a_secret - c_secret * Scalar::from(val_b);

        DivisionWitness { s }
    }

    pub fn prove(
        a: &Division,
        b: &Division,
        c: &Division,
        witness: &DivisionWitness,
    ) -> DivisionProof {
        let Division {
            comm: DivisionCommitment { point: a_point },
            secret:
                DivisionSecret {
                    value: _a_value,
                    secret: _a_secret,
                },
        } = a;
        let Division {
            comm: DivisionCommitment { point: b_point },
            secret:
                DivisionSecret {
                    value: b_value,
                    secret: b_secret,
                },
        } = b;
        let Division {
            comm: DivisionCommitment { point: c_point },
            secret:
                DivisionSecret {
                    value: _c_value,
                    secret: _c_secret,
                },
        } = c;

        let DivisionWitness { s } = witness;

        let b_2 = get_random_scalar();
        let s_2 = get_random_scalar();
        let beta_2 = get_random_scalar();

        let d1 = RistrettoPoint::multiscalar_mul(&[b_2, s_2], &[*c_point, *BASEPOINT_G2]);
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
        let s_circumflex = s_2 + e * s;
        let beta_circumflex = beta_2 + e * b_secret;

        DivisionProof {
            d1,
            d2,
            b_circumflex,
            s_circumflex,
            beta_circumflex,
        }
    }

    pub fn verify(proof: DivisionWithPublicParams) -> bool {
        let DivisionWithPublicParams {
            proof:
                DivisionProof {
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

        // d1 · [a]e = [c]ˆb · hs
        let left = d1 + e * a_point;
        let right = RistrettoPoint::multiscalar_mul(
            &[b_circumflex, s_circumflex],
            &[c_point, *BASEPOINT_G2],
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
mod division_tests {
    use super::*;
    use std::assert_eq;

    #[test]
    fn it_works() {
        let a = 10;
        let b = 5;
        let c = 2;

        let a_comm_secret = Division::commit(a);
        let b_comm_secret = Division::commit(b);
        let c_comm_secret = Division::commit(c);

        let witness =
            Division::witness(a_comm_secret.secret.secret, c_comm_secret.secret.secret, b);

        let proof = Division::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret, &witness);

        let result = Division::verify(DivisionWithPublicParams {
            proof,
            a_point: a_comm_secret.comm.point,
            b_point: b_comm_secret.comm.point,
            c_point: c_comm_secret.comm.point,
        });

        assert_eq!(true, result);
    }
}
