use num_bigint::BigInt;

struct ECCCurve {
    p: BigInt,
    a: BigInt,
    b: BigInt,
    l: usize,
}
