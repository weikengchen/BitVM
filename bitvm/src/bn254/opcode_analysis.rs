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
use ark_ff::{Field, UniformRand};
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

/// Reconstruct the size of the full monolithic verifier (`groth16::verifier::Verifier`)
/// by measuring each building block once and multiplying by how often it occurs in
/// `Pairing::hinted_quad_miller_loop_with_c_wi` + the pre-pairing setup.
/// Script length of these hinted ops is value-independent, so random inputs are fine.
#[test]
fn estimate_full_verifier() {
    use crate::bn254::g1::hinted_from_eval_point;
    use crate::bn254::g2::{
        hinted_affine_add_line, hinted_affine_double_line, hinted_check_chord_line,
        hinted_check_tangent_line, hinted_ell_by_constant_affine_and_sparse_mul,
    };
    use crate::bn254::msm::hinted_msm_with_constant_bases_affine;
    use ark_ec::bn::BnConfig;
    use ark_ec::CurveGroup;

    let mut prng = ChaCha20Rng::seed_from_u64(2);

    // random valid inputs
    let a12 = ark_bn254::Fq12::rand(&mut prng);
    let b12 = ark_bn254::Fq12::rand(&mut prng);
    let f12 = ark_bn254::Fq12::rand(&mut prng);
    let a2 = ark_bn254::Fq2::rand(&mut prng);
    let b2 = ark_bn254::Fq2::rand(&mut prng);
    let c3 = ark_bn254::Fq2::rand(&mut prng);
    let c4 = ark_bn254::Fq2::rand(&mut prng);
    let ell_const = (ark_bn254::Fq2::ONE, ark_bn254::Fq2::rand(&mut prng), ark_bn254::Fq2::rand(&mut prng));
    let xfq = ark_bn254::Fq::rand(&mut prng);
    let yfq = ark_bn254::Fq::rand(&mut prng);
    let pg1 = ark_bn254::G1Projective::rand(&mut prng).into_affine();
    let tg2 = ark_bn254::G2Projective::rand(&mut prng).into_affine();
    let qg2 = ark_bn254::G2Projective::rand(&mut prng).into_affine();
    let bases = [ark_bn254::G1Projective::rand(&mut prng).into_affine(),
                 ark_bn254::G1Projective::rand(&mut prng).into_affine()];
    let scalars = [ark_bn254::Fr::rand(&mut prng), ark_bn254::Fr::rand(&mut prng)];

    // ate loop shape
    let ate = ark_bn254::Config::ATE_LOOP_COUNT; // len 65
    let iters = ate.len() - 1; // 64
    let n_nz = (1..ate.len()).filter(|&i| ate[i - 1] == 1 || ate[i - 1] == -1).count();

    // (name, (bytes, tmul_ops), occurrences)
    let m = |s: crate::treepp::Script, h: usize| (bytes(s), h);
    let (sq, sq_t) = { let (s, h) = Fq12::hinted_square(a12); m(s, h.len()) };
    let (mul, mul_t) = { let (s, h) = Fq12::hinted_mul(12, a12, 0, b12); m(s, h.len()) };
    let (fr1, fr1_t) = { let (s, h) = Fq12::hinted_frobenius_map(1, a12); m(s, h.len()) };
    let (fr2, fr2_t) = { let (s, h) = Fq12::hinted_frobenius_map(2, a12); m(s, h.len()) };
    let (fr3, fr3_t) = { let (s, h) = Fq12::hinted_frobenius_map(3, a12); m(s, h.len()) };
    let (ell, ell_t) = { let (s, h) = hinted_ell_by_constant_affine_and_sparse_mul(f12, xfq, yfq, &ell_const); m(s, h.len()) };
    let (tan, tan_t) = { let (s, h) = hinted_check_tangent_line(tg2, c3, c4); m(s, h.len()) };
    let (dbl, dbl_t) = { let (s, h) = hinted_affine_double_line(tg2.x, c3, c4); m(s, h.len()) };
    let (cho, cho_t) = { let (s, h) = hinted_check_chord_line(tg2, qg2, c3, c4); m(s, h.len()) };
    let (addl, addl_t) = { let (s, h) = hinted_affine_add_line(tg2.x, qg2.x, c3, c4); m(s, h.len()) };
    let (f2m, f2m_t) = { let (s, h) = Fq2::hinted_mul(2, a2, 0, b2); m(s, h.len()) };
    let (fev, fev_t) = { let (s, h) = hinted_from_eval_point(pg1); m(s, h.len()) };
    let (finv, finv_t) = { let (s, h) = Fq::hinted_inv(xfq); m(s, h.len()) };
    let (fmul, fmul_t) = { let (s, h) = Fq::hinted_mul(1, xfq, 0, yfq); m(s, h.len()) };
    let (msm, msm_t) = { let (s, h) = hinted_msm_with_constant_bases_affine(&bases, &scalars); m(s, h.len()) };

    let rows: Vec<(&str, usize, usize, usize)> = vec![
        // name, bytes, tmul, count
        ("Fq12 square",          sq,   sq_t,   iters),
        ("Fq12 mul (c/c_inv/wi/frob-prod)", mul, mul_t, n_nz + 4),
        ("Fq12 frobenius",       fr1,  fr1_t,  1),
        ("Fq12 frobenius",       fr2,  fr2_t,  1),
        ("Fq12 frobenius",       fr3,  fr3_t,  1),
        ("ell+sparse mul",       ell,  ell_t,  3 * iters + 3 * n_nz + 6),
        ("g2 tangent line",      tan,  tan_t,  iters),
        ("g2 double line",       dbl,  dbl_t,  iters),
        ("g2 chord line",        cho,  cho_t,  n_nz + 2),
        ("g2 add line",          addl, addl_t, n_nz + 1),
        ("Fq2 mul (beta)",       f2m,  f2m_t,  3),
        ("MSM (G1, 2 bases)",    msm,  msm_t,  1),
        ("Fq inv (pre)",         finv, finv_t, 1),
        ("Fq mul (pre)",         fmul, fmul_t, 1),
        ("from_eval_point (pre)",fev,  fev_t,  3),
    ];

    println!("\nATE_LOOP_COUNT len={}, miller iters={}, nonzero(add) bits={}\n", ate.len(), iters, n_nz);
    println!("{:<34} {:>12} {:>8} {:>6} {:>16} {:>12}", "component", "bytes/ea", "tmul/ea", "count", "subtotal_bytes", "subtotal_tmul");
    let mut tot_bytes = 0usize;
    let mut tot_tmul = 0usize;
    for (name, b, t, c) in &rows {
        let sb = b * c;
        let st = t * c;
        tot_bytes += sb;
        tot_tmul += st;
        println!("{:<34} {:>12} {:>8} {:>6} {:>16} {:>12}", name, b, t, c, sb, st);
    }
    println!("\nESTIMATED full verifier (today) : {} bytes  ({:.2} MB, {:.3} GB)",
        tot_bytes, tot_bytes as f64 / 1e6, tot_bytes as f64 / 1e9);
    println!("Total field multiplications     : {} tmul-ops", tot_tmul);
    println!("Modeled floor @1B/mul-opcode    : {} bytes ({:.1} KB)  [adds/moves add a small multiple]",
        tot_tmul, tot_tmul as f64 / 1e3);
}
