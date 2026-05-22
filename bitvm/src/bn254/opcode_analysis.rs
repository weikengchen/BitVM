//! Analysis scaffolding (not part of the verifier).
//!
//! Measures today's compiled script byte sizes of BN254 field primitives, to
//! estimate the verifier's footprint under hypothetical dedicated opcodes
//! (Fr/Fq add+mul, G1/G2 add+double+scalarmul), each assumed to be 1 byte.
//!
//! A field element is `U254 = BigIntImpl<254, 29>` => 9 limbs (stack items)
//! today; under the new model it is a single item, so a `hinted_mul` (9 hint
//! pulls + 2 rolls + tmul) collapses to one `OP_FQ_MUL` byte.

use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use ark_ff::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bytes(s: crate::treepp::Script) -> usize {
    s.compile().len()
}

#[test]
fn measure_field_primitive_sizes() {
    let mut prng = ChaCha20Rng::seed_from_u64(1);

    println!("--- leaves ---");
    println!("Fq::tmul   (leaf multiply) : {:>8} bytes", bytes(Fq::tmul()));
    println!("Fq::add    (leaf add)      : {:>8} bytes", bytes(Fq::add(1, 0)));
    println!("Fq::sub    (leaf sub)      : {:>8} bytes", bytes(Fq::sub(1, 0)));

    let a = ark_bn254::Fq::rand(&mut prng);
    let b = ark_bn254::Fq::rand(&mut prng);
    let (s, h) = Fq::hinted_mul(1, a, 0, b);
    println!("Fq::hinted_mul             : {:>8} bytes, {} hints", bytes(s), h.len());
    let (s, h) = Fq::hinted_inv(a);
    println!("Fq::hinted_inv             : {:>8} bytes, {} hints", bytes(s), h.len());

    println!("--- tower fields (compose Fq leaves) ---");
    let a2 = ark_bn254::Fq2::rand(&mut prng);
    let b2 = ark_bn254::Fq2::rand(&mut prng);
    let (s, h) = Fq2::hinted_mul(2, a2, 0, b2);
    println!("Fq2::hinted_mul            : {:>8} bytes, {} hints", bytes(s), h.len());

    let a6 = ark_bn254::Fq6::rand(&mut prng);
    let b6 = ark_bn254::Fq6::rand(&mut prng);
    let (s, h) = Fq6::hinted_mul(6, a6, 0, b6);
    println!("Fq6::hinted_mul (dense)    : {:>8} bytes, {} hints", bytes(s), h.len());
    let (s, h) = Fq6::hinted_square(a6);
    println!("Fq6::hinted_square         : {:>8} bytes, {} hints", bytes(s), h.len());

    let a12 = ark_bn254::Fq12::rand(&mut prng);
    let b12 = ark_bn254::Fq12::rand(&mut prng);
    let (s, h) = Fq12::hinted_mul(12, a12, 0, b12);
    println!("Fq12::hinted_mul           : {:>8} bytes, {} hints", bytes(s), h.len());
    let (s, h) = Fq12::hinted_square(a12);
    println!("Fq12::hinted_square        : {:>8} bytes, {} hints", bytes(s), h.len());
}
