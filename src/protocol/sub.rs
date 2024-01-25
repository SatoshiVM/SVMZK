use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, hash_to_scalar, point_to_bytes, BASEPOINT_G1, BASEPOINT_G2,
};

/// a - b = c
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substraction {
    pub comm: SubstractionCommitment,
    pub secret: SubstractionSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstractionCommitment {
    pub point: RistrettoPoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstractionSecret {
    pub value: u64,
    pub secret: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstractionProof {
    pub d: RistrettoPoint,
    pub u: Scalar,
    pub v: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstractionWithPublicParams {
    pub proof: SubstractionProof,
    pub a_point: RistrettoPoint,
    pub b_point: RistrettoPoint,
    pub c_point: RistrettoPoint,
}

impl Substraction {
    pub fn commit(value: u64) -> Self {
        let secret = get_random_scalar();
        let commitment_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(value), secret],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        Self {
            comm: SubstractionCommitment {
                point: commitment_point,
            },
            secret: SubstractionSecret {
                value,
                secret,
            },
        }
    }

    pub fn commit_c_witness(value: u64, a_sec: Scalar, b_sec: Scalar) -> Self {
        let commitment_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(value), a_sec - b_sec],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        Self {
            comm: SubstractionCommitment {
                point: commitment_point,
            },
            secret: SubstractionSecret {
                value,
                secret: a_sec - b_sec,
            },
        }
    }

    pub fn prove(a: &Substraction, b: &Substraction, c: &Substraction) -> SubstractionProof {
        let Substraction {
            comm: SubstractionCommitment { point: a_point },
            secret:
                SubstractionSecret {
                    value: _a_value,
                    secret: _a_secret,
                },
        } = a;
        let Substraction {
            comm: SubstractionCommitment { point: b_point },
            secret:
                SubstractionSecret {
                    value: _b_value,
                    secret: _b_secret,
                },
        } = b;
        let Substraction {
            comm: SubstractionCommitment { point: c_point },
            secret:
                SubstractionSecret {
                    value: c_value,
                    secret: c_secret,
                },
        } = c;

        let x = get_random_scalar();
        let y = get_random_scalar();
        let d_point = RistrettoPoint::multiscalar_mul(&[x, y], &[*BASEPOINT_G1, *BASEPOINT_G2]);
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(a_point));
        hash_vec.append(&mut point_to_bytes(b_point));
        hash_vec.append(&mut point_to_bytes(c_point));
        hash_vec.append(&mut point_to_bytes(&d_point));

        let e = hash_to_scalar(&hash_vec);

        //let u = x + (Scalar::from(a_value.clone()) + Scalar::from(b_value.clone())) * e;
        let u = x + (Scalar::from(*c_value)) * e;
        let v = y + (c_secret) * e;
        SubstractionProof {
            d: d_point,
            u,
            v,
        }
    }

    pub fn verify(proof: SubstractionWithPublicParams) -> bool {
        let SubstractionWithPublicParams {
            proof: SubstractionProof { d: d_point, u, v },
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
        hash_vec.append(&mut point_to_bytes(&d_point));

        let e = hash_to_scalar(&hash_vec);

        let c_cal = a_point - b_point;
        let left = d_point + e * c_point;
        let right = RistrettoPoint::multiscalar_mul(&[u, v], &[*BASEPOINT_G1, *BASEPOINT_G2]);
        c_cal == c_point && left == right
    }
}

#[cfg(test)]
mod substraction_tests {
    use super::*;
    use rand::Rng;
    use std::assert_eq;

    #[test]
    fn it_works() {
        let a = 30;
        let b = 18;
        let c = a - b;

        let a_comm_secret = Substraction::commit(a);
        let b_comm_secret = Substraction::commit(b);
        let c_comm_secret = Substraction::commit_c_witness(
            c,
            a_comm_secret.secret.secret,
            b_comm_secret.secret.secret,
        );

        let proof = Substraction::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret);

        let result = Substraction::verify(SubstractionWithPublicParams {
            proof,
            a_point: a_comm_secret.comm.point,
            b_point: b_comm_secret.comm.point,
            c_point: c_comm_secret.comm.point,
        });

        assert_eq!(
            a_comm_secret.comm.point - b_comm_secret.comm.point,
            c_comm_secret.comm.point
        );
        assert_eq!(true, result);
    }

    #[test]
    fn random_eq_protocol_test() {
        for _ in 0..50 {
            let random_a = rand::thread_rng().gen_range(0u64..=1000000);
            let random_b = rand::thread_rng().gen_range(0u64..=random_a);

            let a = random_a;
            let b = random_b;
            let c = a - b;

            let a_comm_secret = Substraction::commit(a);
            let b_comm_secret = Substraction::commit(b);
            let c_comm_secret = Substraction::commit_c_witness(
                c,
                a_comm_secret.secret.secret,
                b_comm_secret.secret.secret,
            );

            let proof = Substraction::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret);

            let result = Substraction::verify(SubstractionWithPublicParams {
                proof,
                a_point: a_comm_secret.comm.point,
                b_point: b_comm_secret.comm.point,
                c_point: c_comm_secret.comm.point,
            });

            assert_eq!(
                a_comm_secret.comm.point - b_comm_secret.comm.point,
                c_comm_secret.comm.point
            );
            assert_eq!(true, result);
        }
    }

    #[test]
    fn test() {
        let a = 19u64;
        let b = 18;
        let c = a - b;

        let a_secret = get_random_scalar();
        let a_comm = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(a), a_secret],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        let b_secret = get_random_scalar();
        let b_comm = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(b), b_secret],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        let c_secret = a_secret - b_secret;
        let c_comm = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c), c_secret],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        assert_eq!(a_comm - b_comm, c_comm);

        let e = get_random_scalar();

        let x = get_random_scalar();
        let y = get_random_scalar();
        let d_point = RistrettoPoint::multiscalar_mul(&[x, y], &[*BASEPOINT_G1, *BASEPOINT_G2]);
        let u = x + Scalar::from(c) * e;
        let v = y + c_secret * e;

        let left = d_point + e * c_comm;
        let right = RistrettoPoint::multiscalar_mul(&[u, v], &[*BASEPOINT_G1, *BASEPOINT_G2]);
        assert_eq!(left, right);
    }
}
