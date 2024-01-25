# SVMZK

We describe SVMZK – an efficient NIZK proof toolkit. Given commitments [a], [b], [c], the prover
is able to convince the verifier either one of the following relations:
- Addition: a + b = c;
- Subtraction: a − b = c;
-  Multiplication: a · b = c;
-  Division: a/b = c;
-  Equality: a = b;
-  Comparison: a ≥ b;

## Getting Started

You need to have Rust and Cargo installed on your machine. If you haven't installed Rust, you can do so by following the instructions on the [official Rust website](https://www.rust-lang.org/learn/get-started).

### Build

To build the project without launching it, you can use the following Cargo command:

```shell
cargo build --release
```

### Test

To run the tests, do the following:

```shell
cargo test
```

## Examples

### prove x >= 0 

```
    use SVMZK::{Comparison, ComparisonProofWithPublicParams};
    
    let input = 209348i32;  
    let comm = Comparison::commit(input);

    let proof = Comparison::prove(&comm);

    let res = Comparison::verify(ComparisonProofWithPublicParams {
        proof: proof,
        x: comm.comm.point,
    });
    
    assert_eq!(res,true);
```
