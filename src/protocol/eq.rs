use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, hash_to_scalar, point_to_bytes, BASEPOINT_G1, BASEPOINT_G2,
};

/// eq
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equality {
    pub comm: EqualityCommitment,
    pub secret: EqualitySecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqualityCommitment {
    pub point: RistrettoPoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqualitySecret {
    pub value: u64,
    pub secret: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqualityProof {
    pub d: RistrettoPoint,
    pub u: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqualityWithPublicParams {
    pub proof: EqualityProof,
    pub a_point: RistrettoPoint,
    pub b_point: RistrettoPoint,
    pub c_point: RistrettoPoint,
}

impl Equality {
    pub fn commit(value: u64) -> Self {
        let secret = get_random_scalar();
        let commitment_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(value), secret],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        Self {
            comm: EqualityCommitment {
                point: commitment_point,
            },
            secret: EqualitySecret {
                value,
                secret,
            },
        }
    }

    pub fn commit_c_witness(a_sec: Scalar, b_sec: Scalar) -> Self {
        let t = a_sec - b_sec;
        let commitment_point = t * *BASEPOINT_G2;

        Self {
            comm: EqualityCommitment {
                point: commitment_point,
            },
            secret: EqualitySecret {
                value: 0,
                secret: t,
            },
        }
    }

    pub fn prove(a: &Equality, b: &Equality, c: &Equality) -> EqualityProof {
        let Equality {
            comm: EqualityCommitment { point: a_point },
            secret:
                EqualitySecret {
                    value: _a_value,
                    secret: _a_secret,
                },
        } = a;
        let Equality {
            comm: EqualityCommitment { point: b_point },
            secret:
                EqualitySecret {
                    value: _b_value,
                    secret: _b_secret,
                },
        } = b;
        let Equality {
            comm: EqualityCommitment { point: _c_point },
            secret:
                EqualitySecret {
                    value: _c_value,
                    secret: c_secret,
                },
        } = c;

        let x = get_random_scalar();

        let d = x * *BASEPOINT_G2;

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(a_point));
        hash_vec.append(&mut point_to_bytes(b_point));
        hash_vec.append(&mut point_to_bytes(&d));

        let e = hash_to_scalar(&hash_vec);

        //u = x + e · t;
        let u = x + e * c_secret;

        EqualityProof { d, u }
    }

    pub fn verify(proof: EqualityWithPublicParams) -> bool {
        let EqualityWithPublicParams {
            proof: EqualityProof { d, u },
            a_point,
            b_point,
            c_point: _c_point,
        } = proof;

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(&a_point));
        hash_vec.append(&mut point_to_bytes(&b_point));
        hash_vec.append(&mut point_to_bytes(&d));

        let e = hash_to_scalar(&hash_vec);

        //d · ([a]/[b])e = hu;
        let left = d + (a_point - b_point) * e;
        let right = u * *BASEPOINT_G2;

        left == right
    }
}

#[cfg(test)]
mod equality_tests {
    use super::*;
    use rand::Rng;
    use std::assert_eq;

    #[test]
    fn it_works() {
        let a = 30;
        let b = 30;

        let a_comm_secret = Equality::commit(a);
        let b_comm_secret = Equality::commit(b);
        let c_comm_secret =
            Equality::commit_c_witness(a_comm_secret.secret.secret, b_comm_secret.secret.secret);

        let proof = Equality::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret);

        let result = Equality::verify(EqualityWithPublicParams {
            proof,
            a_point: a_comm_secret.comm.point,
            b_point: b_comm_secret.comm.point,
            c_point: c_comm_secret.comm.point,
        });

        assert_eq!(true, result);
    }

    #[test]
    fn random_eq_protocol_test() {
        for _ in 0..50 {
            let random_a = rand::thread_rng().gen_range(0u64..=1000000);
            let random_b = rand::thread_rng().gen_range(0u64..=1000000);

            let a = random_a;
            let b = random_b;

            let a_comm_secret = Equality::commit(a);
            let b_comm_secret = Equality::commit(b);
            let c_comm_secret = Equality::commit_c_witness(
                a_comm_secret.secret.secret,
                b_comm_secret.secret.secret,
            );

            let proof = Equality::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret);

            let result = Equality::verify(EqualityWithPublicParams {
                proof,
                a_point: a_comm_secret.comm.point,
                b_point: b_comm_secret.comm.point,
                c_point: c_comm_secret.comm.point,
            });

            let result_expect = if a == b { true } else { false };

            assert_eq!(result, result_expect);
        }
    }
}
