#![allow(unused_assignments)]
#![allow(non_snake_case)]

mod protocol;

pub use protocol::{
    add::{Addition, AdditionProofWithPublicParams},
    com::{Comparison, ComparisonProofWithPublicParams},
    div::{Division, DivisionWithPublicParams},
    eq::{Equality, EqualityWithPublicParams},
    mul::{Multiplication, MultiplicationWithPublicParams},
    sub::{Substraction, SubstractionWithPublicParams},
};
mod marco;

#[cfg(test)]
mod com_tests {
    use super::*;
    use rand::Rng;

    /// prove x >= 0
    #[test]
    fn batch_comparison_protocol_test() {
        for i in 2i32..10i32 {
            test_comparison!(i);
            test_comparison_negative!(-i);
        }

        for i in 100000i32..100010i32 {
            test_comparison!(i);
            test_comparison_negative!(-i);
        }

        for i in 500000000i32..500000010i32 {
            test_comparison!(i);
            test_comparison_negative!(-i);
        }
    }

    /// prove x >= 0
    #[test]
    fn small_number_comparison_protocol_test() {
        test_comparison!(1);
        test_comparison!(0);
        test_comparison_negative!(-1);
    }

    /// prove x >= 0
    #[test]
    fn comparison_protocol_test() {
        let a = -20933i32;
        let comparison = Comparison::commit(a);

        let proof = Comparison::prove(&comparison);

        let res = Comparison::verify(ComparisonProofWithPublicParams {
            proof: proof,
            x: comparison.comm.point,
        });
        assert_eq!(res, false);
    }

    /// prove x + y
    #[test]
    fn addition_protocol_test() {
        let mut test_data = vec![
            (10, 58),
            (84, 118),
            (998, 558),
            (154584, 5488),
            (15u64.pow(4), 36u64.pow(5)),
        ];
        for _ in 0..50 {
            let random_a = rand::thread_rng().gen_range(0u64..=1000000);
            let random_b = rand::thread_rng().gen_range(0u64..=1000000);
            test_data.push((random_a, random_b))
        }
        for (x, y) in test_data.clone() {
            test_addition!(x, y, x + y, true);
        }
        for (x, y) in test_data {
            test_addition!(x, y, 100, false);
        }
    }

    /// prove x - y
    #[test]
    fn substraction_protocol_test() {
        let mut test_data = vec![
            (150, 58),
            (844, 118),
            (998, 558),
            (154584, 5488),
            (19u64.pow(9), 3u64.pow(5)),
        ];
        for _ in 0..50 {
            let random_a = rand::thread_rng().gen_range(0u64..=1000000);
            let random_b = rand::thread_rng().gen_range(0u64..=random_a);
            test_data.push((random_a, random_b))
        }
        for (x, y) in test_data.clone() {
            test_substration!(x, y, x - y, true);
        }
        for (x, y) in test_data.clone() {
            test_substration!(x, y, x + y, false);
        }
    }

    /// prove x * y
    #[test]
    fn multiplication_protocol_test() {
        let mut test_data = vec![
            (150, 58),
            (844, 118),
            (998, 558),
            (154584, 5488),
            (3u64.pow(6), 14u64.pow(4)),
        ];
        for _ in 0..50 {
            let random_a = rand::thread_rng().gen_range(0u64..=1000000);
            let random_b = rand::thread_rng().gen_range(0u64..=1000000);
            test_data.push((random_a, random_b))
        }
        for (x, y) in test_data {
            test_multiplication!(x, y, x * y);
        }
    }

    /// prove x / y
    #[test]
    fn division_protocol_test() {
        let mut test_data = vec![
            (150, 50),
            (800, 200),
            (1000, 250),
            (2u64.pow(15), 2u64.pow(15)),
        ];
        for _ in 0..50 {
            let random_a = rand::thread_rng().gen_range(0u64..=1000000);
            let random_b = rand::thread_rng().gen_range(0u64..=1000);
            let random_c = random_a * random_b;
            test_data.push((random_c, random_a))
        }
        for (x, y) in test_data {
            test_division!(x, y, x / y, true);
        }

        let test_data = vec![
            (150, 77),
            (222, 200),
            (53353, 250),
            (2u64.pow(15), 9u64.pow(14)),
        ];
        for (x, y) in test_data {
            test_division!(x, y, x / y, false);
        }
    }

    /// prove x = y
    #[test]
    fn equality_protocol_test() {
        let test_data = vec![
            (15, 15),
            (88, 88),
            (77777, 77777),
            (154584, 154584),
            (2u64.pow(15), 2u64.pow(15)),
        ];
        for (x, y) in test_data {
            test_equality!(x, y, true);
        }
        let test_data = vec![
            (150, 58),
            (844, 118),
            (998, 558),
            (154584, 5488),
            (2u64.pow(15), 3u64.pow(5)),
        ];
        for (x, y) in test_data {
            test_equality!(x, y, false);
        }
    }
}
