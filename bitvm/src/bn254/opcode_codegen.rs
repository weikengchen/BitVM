//! Codegen prototype (analysis only).
//!
//! Generates EXECUTABLE code for a hypothetical opcode set (1 item = 1 base
//! field element; `OP_FQ_{ADD,SUB,MUL,NEG}` etc. each 1 byte) and validates it
//! against arkworks. Starts with Fq12 multiplication.
//!
//! The emulator is a typed stack machine over real `ark_bn254::Fq` values, so a
//! generated program both (a) proves correct by reproducing arkworks results and
//! (b) yields an exact opcode/byte count.

use ark_ff::{Field, UniformRand};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

type F = ark_bn254::Fq;

#[derive(Clone, Debug)]
enum Op {
    FqAdd,
    FqSub,
    FqMul,
    FqNeg,
    Push(F),
    Pick(u32), // copy item at depth n (from top) to the top
}

fn op_bytes(op: &Op) -> usize {
    match op {
        Op::Push(_) => 33,                              // OP_PUSHBYTES_32 + 32B data
        Op::Pick(n) => push_int_bytes(*n) + 1,          // <n> OP_PICK
        _ => 1,                                         // hypothetical 1-byte opcode
    }
}
fn push_int_bytes(n: u32) -> usize {
    if n <= 16 { 1 } else if n < 128 { 2 } else { 3 }
}

/// Independent interpreter: replays the program over an initial Fq stack.
fn execute(ops: &[Op], init: Vec<F>) -> Vec<F> {
    let mut s = init;
    for op in ops {
        match op {
            Op::FqMul => { let b = s.pop().unwrap(); let a = s.pop().unwrap(); s.push(a * b); }
            Op::FqAdd => { let b = s.pop().unwrap(); let a = s.pop().unwrap(); s.push(a + b); }
            Op::FqSub => { let b = s.pop().unwrap(); let a = s.pop().unwrap(); s.push(a - b); }
            Op::FqNeg => { let a = s.pop().unwrap(); s.push(-a); }
            Op::Push(v) => s.push(*v),
            Op::Pick(n) => { let i = s.len() - 1 - (*n as usize); let v = s[i]; s.push(v); }
        }
    }
    s
}

/// Emits opcodes while mirroring the concrete stack so depths are correct.
/// Compute phase is non-destructive (only Pick + push results), so a value's
/// recorded position stays valid for the whole program.
struct Builder {
    ops: Vec<Op>,
    vals: Vec<F>, // mirror of the runtime stack (for depth math + sanity)
}
impl Builder {
    fn new(init: Vec<F>) -> Self { Self { ops: vec![], vals: init } }
    fn top(&self) -> usize { self.vals.len() - 1 }
    fn pick(&mut self, pos: usize) {
        let d = (self.vals.len() - 1 - pos) as u32;
        self.ops.push(Op::Pick(d));
        let v = self.vals[pos];
        self.vals.push(v);
    }
    fn push_const(&mut self, v: F) -> usize { self.ops.push(Op::Push(v)); self.vals.push(v); self.top() }
    fn mul(&mut self, a: usize, b: usize) -> usize {
        self.pick(a); self.pick(b);
        let y = self.vals.pop().unwrap(); let x = self.vals.pop().unwrap();
        self.ops.push(Op::FqMul); self.vals.push(x * y); self.top()
    }
    fn add(&mut self, a: usize, b: usize) -> usize {
        self.pick(a); self.pick(b);
        let y = self.vals.pop().unwrap(); let x = self.vals.pop().unwrap();
        self.ops.push(Op::FqAdd); self.vals.push(x + y); self.top()
    }
    fn sub(&mut self, a: usize, b: usize) -> usize {
        self.pick(a); self.pick(b);
        let y = self.vals.pop().unwrap(); let x = self.vals.pop().unwrap();
        self.ops.push(Op::FqSub); self.vals.push(x - y); self.top()
    }
    fn mul_small(&mut self, a: usize, k: u64) -> usize { let c = self.push_const(F::from(k)); self.mul(a, c) }
}

// ---- tower layer (BN254): Fq2=Fq[u]/(u^2+1), Fq6=Fq2[v]/(v^3-(9+u)), Fq12=Fq6[w]/(w^2-v) ----
type P2 = [usize; 2];
type P6 = [P2; 3];
type P12 = [P6; 2];

fn fq2_mul(b: &mut Builder, a: P2, q: P2) -> P2 {
    let v0 = b.mul(a[0], q[0]);
    let v1 = b.mul(a[1], q[1]);
    let as_ = b.add(a[0], a[1]);
    let qs = b.add(q[0], q[1]);
    let m = b.mul(as_, qs);
    let c0 = b.sub(v0, v1);          // a0b0 - a1b1   (u^2 = -1)
    let t = b.sub(m, v0);
    let c1 = b.sub(t, v1);           // (a0+a1)(b0+b1) - a0b0 - a1b1
    [c0, c1]
}
fn fq2_add(b: &mut Builder, a: P2, q: P2) -> P2 { [b.add(a[0], q[0]), b.add(a[1], q[1])] }
fn fq2_sub(b: &mut Builder, a: P2, q: P2) -> P2 { [b.sub(a[0], q[0]), b.sub(a[1], q[1])] }
/// multiply by Fq6 non-residue xi = 9 + u
fn fq2_mul_xi(b: &mut Builder, a: P2) -> P2 {
    let a0_9 = b.mul_small(a[0], 9);
    let c0 = b.sub(a0_9, a[1]);      // 9 a0 - a1
    let a1_9 = b.mul_small(a[1], 9);
    let c1 = b.add(a[0], a1_9);      // a0 + 9 a1
    [c0, c1]
}

fn fq6_mul(b: &mut Builder, a: P6, q: P6) -> P6 {
    // schoolbook 3x3 then reduce v^3 = xi
    let a0b0 = fq2_mul(b, a[0], q[0]);
    let a0b1 = fq2_mul(b, a[0], q[1]);
    let a0b2 = fq2_mul(b, a[0], q[2]);
    let a1b0 = fq2_mul(b, a[1], q[0]);
    let a1b1 = fq2_mul(b, a[1], q[1]);
    let a1b2 = fq2_mul(b, a[1], q[2]);
    let a2b0 = fq2_mul(b, a[2], q[0]);
    let a2b1 = fq2_mul(b, a[2], q[1]);
    let a2b2 = fq2_mul(b, a[2], q[2]);
    let t1 = fq2_add(b, a0b1, a1b0);
    let t2a = fq2_add(b, a0b2, a1b1);
    let t2 = fq2_add(b, t2a, a2b0);
    let t3 = fq2_add(b, a1b2, a2b1);
    let xi_t3 = fq2_mul_xi(b, t3);
    let c0 = fq2_add(b, a0b0, xi_t3);
    let xi_a2b2 = fq2_mul_xi(b, a2b2);
    let c1 = fq2_add(b, t1, xi_a2b2);
    let c2 = t2;
    [c0, c1, c2]
}
fn fq6_add(b: &mut Builder, a: P6, q: P6) -> P6 { [fq2_add(b, a[0], q[0]), fq2_add(b, a[1], q[1]), fq2_add(b, a[2], q[2])] }
fn fq6_sub(b: &mut Builder, a: P6, q: P6) -> P6 { [fq2_sub(b, a[0], q[0]), fq2_sub(b, a[1], q[1]), fq2_sub(b, a[2], q[2])] }
/// multiply by Fq12 non-residue w^2 = v : (c0,c1,c2) -> (xi*c2, c0, c1)
fn fq6_mul_v(b: &mut Builder, a: P6) -> P6 { [fq2_mul_xi(b, a[2]), a[0], a[1]] }

fn fq12_mul(b: &mut Builder, a: P12, q: P12) -> P12 {
    let v0 = fq6_mul(b, a[0], q[0]);
    let v1 = fq6_mul(b, a[1], q[1]);
    let as_ = fq6_add(b, a[0], a[1]);
    let qs = fq6_add(b, q[0], q[1]);
    let m = fq6_mul(b, as_, qs);
    let v1_v = fq6_mul_v(b, v1);
    let c0 = fq6_add(b, v0, v1_v);
    let t = fq6_sub(b, m, v0);
    let c1 = fq6_sub(b, t, v1);
    [c0, c1]
}

// ---- decompose ark Fq12 into 12 Fq coords (ark coefficient order) ----
fn d12(x: ark_bn254::Fq12) -> Vec<F> {
    let mut v = vec![];
    for c6 in [x.c0, x.c1] {
        for c2 in [c6.c0, c6.c1, c6.c2] {
            v.push(c2.c0);
            v.push(c2.c1);
        }
    }
    v
}

#[test]
fn generate_fq12_mul() {
    let mut prng = ChaCha20Rng::seed_from_u64(7);
    let a = ark_bn254::Fq12::rand(&mut prng);
    let b = ark_bn254::Fq12::rand(&mut prng);

    // stack layout: a's 12 coords at positions 0..12, b's at 12..24
    let mut init = d12(a);
    init.extend(d12(b));

    // position maps (ark order matches d12 order)
    let a6: P12 = [[[0, 1], [2, 3], [4, 5]], [[6, 7], [8, 9], [10, 11]]];
    let b6: P12 = [[[12, 13], [14, 15], [16, 17]], [[18, 19], [20, 21], [22, 23]]];

    let mut bd = Builder::new(init.clone());
    let res = fq12_mul(&mut bd, a6, b6);
    let res_pos: Vec<usize> = res.iter().flatten().flatten().copied().collect();

    // validate with the INDEPENDENT interpreter against arkworks
    let final_stack = execute(&bd.ops, init);
    let got: Vec<F> = res_pos.iter().map(|&p| final_stack[p]).collect();
    let expect = d12(a * b);
    assert_eq!(got, expect, "generated Fq12 mul does not match arkworks");

    // counts
    let total_bytes: usize = bd.ops.iter().map(op_bytes).sum();
    let n_mul = bd.ops.iter().filter(|o| matches!(o, Op::FqMul)).count();
    let n_add = bd.ops.iter().filter(|o| matches!(o, Op::FqAdd | Op::FqSub | Op::FqNeg)).count();
    let n_pick = bd.ops.iter().filter(|o| matches!(o, Op::Pick(_))).count();
    let n_push = bd.ops.iter().filter(|o| matches!(o, Op::Push(_))).count();

    println!("\n=== generated Fq12 mul (validated against arkworks) ===");
    println!("instructions      : {}", bd.ops.len());
    println!("  FqMul           : {}", n_mul);
    println!("  FqAdd/Sub/Neg   : {}", n_add);
    println!("  Pick (stack)    : {}", n_pick);
    println!("  Push (const 9)  : {}", n_push);
    println!("program size      : {} bytes (compute only)", total_bytes);
    println!("today (hinted)    : 3,217,947 bytes");
    println!("compression       : {:.0}x", 3_217_947f64 / total_bytes as f64);
}
