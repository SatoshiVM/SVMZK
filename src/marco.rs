#[macro_export]
macro_rules! test_comparison {
    ($size:expr) => {
        let a = $size;
        let comparison = Comparison::commit(a);

        let proof = Comparison::prove(&comparison);

        let res = Comparison::verify(ComparisonProofWithPublicParams {
            proof: proof,
            x: comparison.comm.point,
        });
        assert_eq!(res, true);
    };
}

#[macro_export]
macro_rules! test_comparison_negative {
    ($size:expr) => {
        let a = $size;
        let comparison = Comparison::commit(a);

        let proof = Comparison::prove(&comparison);

        let res = Comparison::verify(ComparisonProofWithPublicParams {
            proof: proof,
            x: comparison.comm.point,
        });
        assert_eq!(res, false);
    };
}

#[macro_export]
macro_rules! test_addition {
    ($a:expr,$b:expr,$c:expr,$result:expr) => {
        let a_comm_secret = Addition::commit($a);
        let b_comm_secret = Addition::commit($b);
        let c_comm_secret = Addition::commit_c_witness(
            $c,
            a_comm_secret.secret.secret,
            b_comm_secret.secret.secret,
        );

        let proof = Addition::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret);

        let result = Addition::verify(AdditionProofWithPublicParams {
            proof: proof,
            a_point: a_comm_secret.comm.point,
            b_point: b_comm_secret.comm.point,
            c_point: c_comm_secret.comm.point,
        });

        assert_eq!($result, result);
    };
}

#[macro_export]
macro_rules! test_substration {
    ($a:expr,$b:expr,$c:expr,$result:expr) => {
        let a_comm_secret = Substraction::commit($a);
        let b_comm_secret = Substraction::commit($b);
        let c_comm_secret = Substraction::commit_c_witness(
            $c,
            a_comm_secret.secret.secret,
            b_comm_secret.secret.secret,
        );

        let proof = Substraction::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret);

        let result = Substraction::verify(SubstractionWithPublicParams {
            proof: proof,
            a_point: a_comm_secret.comm.point,
            b_point: b_comm_secret.comm.point,
            c_point: c_comm_secret.comm.point,
        });

        assert_eq!($result, result);
    };
}

#[macro_export]
macro_rules! test_multiplication {
    ($a:expr,$b:expr,$c:expr) => {
        let a_comm_secret = Multiplication::commit($a);
        let b_comm_secret = Multiplication::commit($b);
        let c_comm_secret = Multiplication::commit($c);

        let witness =
            Multiplication::witness(a_comm_secret.secret.secret, c_comm_secret.secret.secret, $b);

        let proof = Multiplication::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret, &witness);

        let result = Multiplication::verify(MultiplicationWithPublicParams {
            proof: proof,
            a_point: a_comm_secret.comm.point,
            b_point: b_comm_secret.comm.point,
            c_point: c_comm_secret.comm.point,
        });

        assert_eq!(true, result);
    };
}

#[macro_export]
macro_rules! test_division {
    ($a:expr,$b:expr,$c:expr,$result:expr) => {
        let a_comm_secret = Division::commit($a);
        let b_comm_secret = Division::commit($b);
        let c_comm_secret = Division::commit($c);

        let witness =
            Division::witness(a_comm_secret.secret.secret, c_comm_secret.secret.secret, $b);

        let proof = Division::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret, &witness);

        let result = Division::verify(DivisionWithPublicParams {
            proof: proof,
            a_point: a_comm_secret.comm.point,
            b_point: b_comm_secret.comm.point,
            c_point: c_comm_secret.comm.point,
        });

        assert_eq!($result, result);
    };
}

#[macro_export]
macro_rules! test_equality {
    ($a:expr,$b:expr,$result:expr) => {
        let a_comm_secret = Equality::commit($a);
        let b_comm_secret = Equality::commit($b);
        let c_comm_secret =
            Equality::commit_c_witness(a_comm_secret.secret.secret, b_comm_secret.secret.secret);

        let proof = Equality::prove(&a_comm_secret, &b_comm_secret, &c_comm_secret);

        let result = Equality::verify(EqualityWithPublicParams {
            proof: proof,
            a_point: a_comm_secret.comm.point,
            b_point: b_comm_secret.comm.point,
            c_point: c_comm_secret.comm.point,
        });

        assert_eq!($result, result);
    };
}
