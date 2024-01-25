use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, hash_to_scalar, point_to_bytes, BASEPOINT_G1, BASEPOINT_G2,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    pub comm: ComparisonCommitment,
    pub secret: ComparisonSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonCommitment {
    pub point: RistrettoPoint,
    pub b0: RistrettoPoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonSecret {
    value: Vec<u8>,
    bi_vec: Vec<RistrettoPoint>,
    ri_vec: Vec<Scalar>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonProof {
    bi_point_vec: Vec<RistrettoPoint>,
    d1: RistrettoPoint,
    d2: RistrettoPoint,
    u_circumflex: Scalar,
    b_circumflex_vec: Vec<Scalar>,
    r_circumflex: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonProofWithPublicParams {
    pub proof: ComparisonProof,
    pub x: RistrettoPoint,
}

impl Comparison {
    pub fn commit(value: i32) -> Self {
        let decomposed = decompose_number(value);
        let len = decomposed.len();
        let (mut b_vec, mut r_vec) = {
            let mut b_vec_tmp = Vec::new();
            let mut r_vec_tmp = Vec::new();
            decomposed.iter().for_each(|each_bit| {
                let secret = get_random_scalar();
                let b_commitment_point = RistrettoPoint::multiscalar_mul(
                    &[Scalar::from(*each_bit), secret],
                    &[*BASEPOINT_G1, *BASEPOINT_G2],
                );
                r_vec_tmp.push(secret);
                b_vec_tmp.push(b_commitment_point);
            });
            (b_vec_tmp, r_vec_tmp)
        };

        let x = {
            let mut tmp = Scalar::zero();
            if value < 0 {
                tmp = -Scalar::from(-value as u64);
            } else {
                tmp = Scalar::from(value as u64);
            }
            tmp
        };
        let s = get_random_scalar();
        let x_commitment_point =
            RistrettoPoint::multiscalar_mul(&[x, s], &[*BASEPOINT_G1, *BASEPOINT_G2]);

        if len > 1 {
            let mut b_sigma = Scalar::from(2_u64) * b_vec[1];
            for i in 2..=len - 1 {
                b_sigma += Scalar::from(2u64.pow(i as u32)) * b_vec[i];
            }
            let b0 = x_commitment_point - b_sigma;
            b_vec[0] = b0;

            let mut r_sigma = Scalar::from(2_u64) * r_vec[1];
            for i in 2..=len - 1 {
                r_sigma += Scalar::from(2u64.pow(i as u32)) * r_vec[i];
            }
            let r0 = s - r_sigma;
            r_vec[0] = r0;
        } else {
            b_vec[0] = x_commitment_point;
            r_vec[0] = s;
        }

        Self {
            comm: ComparisonCommitment {
                point: x_commitment_point,
                b0: RistrettoPoint::default(),
            },
            secret: ComparisonSecret {
                value: decomposed,
                bi_vec: b_vec,
                ri_vec: r_vec,
            },
        }
    }

    pub fn prove(a: &Comparison) -> ComparisonProof {
        let Comparison {
            comm:
                ComparisonCommitment {
                    point: x_commitment_point,
                    b0: _b0,
                },
            secret:
                ComparisonSecret {
                    value: decomposed,
                    bi_vec: b_vec,
                    ri_vec: r_vec,
                },
        } = a;

        let len = decomposed.len();

        let b_i_prime_1 = get_random_scalar();
        let mut b_i_prime_vec = Vec::new();
        b_i_prime_vec.push(b_i_prime_1);
        let mut b_sigma_prime = b_i_prime_1;
        let mut bi_b_sigma_prime = b_i_prime_1 * Scalar::from(decomposed[0]);
        for i in 1..=len - 1 {
            let b_i_prime = get_random_scalar();
            b_i_prime_vec.push(b_i_prime);
            b_sigma_prime += b_i_prime;
            bi_b_sigma_prime += b_i_prime * Scalar::from(decomposed[i]);
        }

        let r_prime = get_random_scalar();
        let d1 = RistrettoPoint::multiscalar_mul(
            &[b_sigma_prime, r_prime],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        let u_prime = get_random_scalar();
        let d2 = RistrettoPoint::multiscalar_mul(
            &[bi_b_sigma_prime, u_prime],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(x_commitment_point));
        for i in 0..=len - 1 {
            hash_vec.append(&mut point_to_bytes(&b_vec[i]));
        }
        hash_vec.append(&mut point_to_bytes(&d1));
        hash_vec.append(&mut point_to_bytes(&d2));

        let e = hash_to_scalar(&hash_vec);

        let (u_circumflex, r_circumflex, b_circumflex_vec) = {
            let mut u_circumflex_tmp = u_prime;
            let mut r_circumflex_tmp = r_prime;
            let mut b_circumflex_tmp = Vec::new();
            for i in 0..=len - 1 {
                let bj_each = Scalar::from(decomposed[i]) * pow_scalar(e, i) + b_i_prime_vec[i];
                b_circumflex_tmp.push(bj_each);
                u_circumflex_tmp += (pow_scalar(e, i) - (bj_each)) * r_vec[i];
                r_circumflex_tmp += r_vec[i] * pow_scalar(e, i);
            }
            (u_circumflex_tmp, r_circumflex_tmp, b_circumflex_tmp)
        };

        ComparisonProof {
            bi_point_vec: b_vec.clone(),
            d1,
            d2,
            u_circumflex,
            b_circumflex_vec,
            r_circumflex,
        }
    }

    pub fn verify(proof: ComparisonProofWithPublicParams) -> bool {
        let ComparisonProofWithPublicParams {
            proof:
                ComparisonProof {
                    bi_point_vec: b_vec,
                    d1,
                    d2,
                    u_circumflex,
                    b_circumflex_vec,
                    r_circumflex,
                },
            x: x_commitment_point,
        } = proof;

        let len = b_vec.len();
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G1));
        hash_vec.append(&mut point_to_bytes(&BASEPOINT_G2));
        hash_vec.append(&mut point_to_bytes(&x_commitment_point));
        for i in 0..=len - 1 {
            hash_vec.append(&mut point_to_bytes(&b_vec[i]));
        }
        hash_vec.append(&mut point_to_bytes(&d1));
        hash_vec.append(&mut point_to_bytes(&d2));

        let e = hash_to_scalar(&hash_vec);

        /////////////verify 1/////////
        let left_1 = {
            let mut tmp = d1;
            for i in 0..=len - 1 {
                tmp += b_vec[i] * pow_scalar(e, i);
            }
            tmp
        };

        let bj_res = {
            let mut tmp = Scalar::zero();
            for i in 0..=len - 1 {
                tmp += b_circumflex_vec[i];
            }
            tmp
        };

        let right_1 = RistrettoPoint::multiscalar_mul(
            &[bj_res, r_circumflex],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );
        /////////////verify 2/////////
        let left_2 = {
            let mut tmp = d2;
            for i in 0..=len - 1 {
                tmp += b_vec[i] * (pow_scalar(e, i) - b_circumflex_vec[i]);
            }
            tmp
        };

        let right_2 = RistrettoPoint::multiscalar_mul(
            &[Scalar::zero(), u_circumflex],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        left_1 == right_1 && left_2 == right_2
    }
}

pub fn decompose_number(mut input: i32) -> Vec<u8> {
    if input < 0 {
        input = -input;
    }
    let mut res = Vec::new();
    for i in format!("{:b}", input).into_bytes() {
        res.push(i - 48);
    }
    res.reverse();
    res
}

pub fn pow_scalar(a: Scalar, pow: usize) -> Scalar {
    
    {
        let mut scalar = Scalar::one();
        for _ in 0..pow {
            scalar *= a;
        }
        scalar
    }
}

#[cfg(test)]
mod com_tests {
    use super::*;
    use rand::Rng;
    use std::assert_eq;

    #[test]
    fn decompose_number_test() {
        let a = 209348i32;
        let decomposed = decompose_number(a);
        assert_eq!(
            vec![0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1],
            decomposed
        );
    }

    /// prove x >= 0
    #[test]
    fn com_protocol_test() {
        let a = 209348i32;
        let x = Comparison::commit(a);

        let proof = Comparison::prove(&x);

        let res = Comparison::verify(ComparisonProofWithPublicParams {
            proof,
            x: x.comm.point,
        });
        assert_eq!(res, true);
    }

    #[test]
    fn random_com_protocol_test() {
        for _ in 0..50 {
            let random = rand::thread_rng().gen_range(-1000000i32..=1000000);
            let a = random;
            let x = Comparison::commit(a);

            let proof = Comparison::prove(&x);

            let res = Comparison::verify(ComparisonProofWithPublicParams {
                proof,
                x: x.comm.point,
            });

            let result_expect = if random > 0 { true } else { false };
            assert_eq!(res, result_expect);
        }
    }

    #[test]
    fn simple_comparison_protocol_test() {
        let a = 209348i32;
        let decomposed = decompose_number(a);
        assert_eq!(
            vec![0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1],
            decomposed
        );
        let len = decomposed.len();

        /////////////prove /////////
        let (mut b_vec, mut r_vec) = {
            let mut b_vec_tmp = Vec::new();
            let mut r_vec_tmp = Vec::new();

            decomposed.iter().for_each(|each_bit| {
                let secret = get_random_scalar();
                let b_commitment_point = RistrettoPoint::multiscalar_mul(
                    &[Scalar::from(*each_bit), secret],
                    &[*BASEPOINT_G1, *BASEPOINT_G2],
                );
                r_vec_tmp.push(secret);
                b_vec_tmp.push(b_commitment_point);
            });
            (b_vec_tmp, r_vec_tmp)
        };

        let x = {
            let mut tmp = Scalar::zero();
            if a < 0 {
                tmp = -Scalar::from(-a as u64);
            } else {
                tmp = Scalar::from(a as u64);
            }
            tmp
        };
        let s = get_random_scalar();
        let x_commitment_point =
            RistrettoPoint::multiscalar_mul(&[x, s], &[*BASEPOINT_G1, *BASEPOINT_G2]);

        if len > 1 {
            let mut b_sigma = Scalar::from(2 as u64) * b_vec[1];
            for i in 2..=len - 1 {
                b_sigma += Scalar::from(2u64.pow(i as u32) as u64) * b_vec[i];
            }
            let b0 = x_commitment_point - b_sigma;
            b_vec[0] = b0;

            let mut r_sigma = Scalar::from(2 as u64) * r_vec[1];
            for i in 2..=len - 1 {
                r_sigma += Scalar::from(2u64.pow(i as u32) as u64) * r_vec[i];
            }
            let r0 = s - r_sigma;
            r_vec[0] = r0;
        } else {
            b_vec[0] = x_commitment_point;
            r_vec[0] = s;
        }

        let b_i_prime_1 = get_random_scalar();
        let mut b_i_prime_vec = Vec::new();
        b_i_prime_vec.push(b_i_prime_1);
        let mut b_sigma_prime = b_i_prime_1;
        let mut bi_b_sigma_prime = b_i_prime_1 * Scalar::from(decomposed[0]);
        for i in 1..=len - 1 {
            let b_i_prime_i = get_random_scalar();
            b_i_prime_vec.push(b_i_prime_i);
            b_sigma_prime += b_i_prime_i;
            bi_b_sigma_prime += b_i_prime_i * Scalar::from(decomposed[i]);
        }

        let r_prime = get_random_scalar();
        let d1 = RistrettoPoint::multiscalar_mul(
            &[b_sigma_prime, r_prime],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        let u_prime = get_random_scalar();
        let d2 = RistrettoPoint::multiscalar_mul(
            &[bi_b_sigma_prime, u_prime],
            &[*BASEPOINT_G1, *BASEPOINT_G2],
        );

        let e = get_random_scalar();

        let (uj, rj, bj) = {
            let mut uj_tmp = u_prime;
            let mut rj_tmp = r_prime;
            let mut bj_tmp = Vec::new();
            for i in 0..=len - 1 {
                let bj_i = Scalar::from(decomposed[i]) * pow_scalar(e, i) + b_i_prime_vec[i];
                bj_tmp.push(bj_i);
                uj_tmp += (pow_scalar(e, i) - (bj_i)) * r_vec[i];
                rj_tmp += r_vec[i] * pow_scalar(e, i);
            }
            (uj_tmp, rj_tmp, bj_tmp)
        };

        /////////////verify 1/////////

        let left_1 = {
            let mut tmp = d1;
            for i in 0..=len - 1 {
                tmp += b_vec[i] * pow_scalar(e, i);
            }
            tmp
        };

        let bj_res = {
            let mut tmp = Scalar::zero();
            for i in 0..=len - 1 {
                tmp += bj[i];
            }
            tmp
        };

        let right_1 =
            RistrettoPoint::multiscalar_mul(&[bj_res, rj], &[*BASEPOINT_G1, *BASEPOINT_G2]);
        assert_eq!(left_1, right_1);

        /////////////verify 2/////////
        let left_2 = {
            let mut tmp = d2;
            for i in 0..=len - 1 {
                tmp += b_vec[i] * (pow_scalar(e, i) - bj[i]);
            }
            tmp
        };

        let right_2 =
            RistrettoPoint::multiscalar_mul(&[Scalar::zero(), uj], &[*BASEPOINT_G1, *BASEPOINT_G2]);
        assert_eq!(left_2, right_2);
    }
}
