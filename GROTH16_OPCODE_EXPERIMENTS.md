# Groth16 Verifier with Dedicated BN254 Opcodes — Experiment Results

This branch studies a single question:

> **How small would the BitVM Groth16-over-BN254 verifier become if Bitcoin Script
> had dedicated opcodes for BN254 field and curve arithmetic?**

Today the verifier is built from limb-based, *hinted* big-integer scripts (each
field element is `U254 = BigIntImpl<254, 29>` → **9 limbs / stack items**, and a
field multiply is a multi-thousand-byte "tmul"). We estimate the footprint if
those operations were native single-byte opcodes instead.

All experiment code lives in:

| File | Purpose |
|---|---|
| `bitvm/src/bn254/opcode_analysis.rs` | Measures today's compiled byte sizes; reconstructs the full monolithic verifier by summing components × occurrence counts. |
| `bitvm/src/bn254/opcode_codegen.rs` | A 1-byte-opcode **stack-machine emulator** over `ark_bn254::Fq`, a 1-item tower-field codegen layer, and a generator that emits programs, **validates them against arkworks**, and reports exact sizes. |

> ⚠️ These opcodes are **hypothetical**. They do not exist in Bitcoin consensus or
> in this repo's `bitcoin-scriptexec`. The numbers below are byte-size estimates
> produced by an emulator; generated programs are validated for *arithmetic
> correctness* against arkworks, not for consensus validity.

---

## The hypothetical opcode set

- **Field:** `OP_FR_ADD`, `OP_FR_MUL`, `OP_FQ_ADD`, `OP_FQ_MUL`
- **Curve:** `OP_G1_ADD`, `OP_G1_DOUBLE`, `OP_G1_SCALARMUL`, `OP_G2_ADD`, `OP_G2_DOUBLE`
- **One extra beyond the original list:** `OP_FQ_INV` — the verifier needs field
  inversion (for `from_eval_point` and `c_inv`), which is not expressible from
  add/mul cheaply.

### Modeling assumptions

- **1 field element = 1 stack item** (vs. 9 limbs today).
- **Each new opcode = 1 byte.** Stack moves are realistic: `OP_PICK`/`OP_ROLL` cost
  `push(depth) + opcode` (≈2–3 B); a 32-byte field constant push ≈ 33 B.
- **Metric:** script bytes only.
- **Derived ops:** `sub`/`neg` → add-class; `square` → mul; `Fq2/Fq6/Fq12`
  arithmetic are *compositions* of the new opcodes (not their own opcodes).
- **Curve opcodes (G1+G2)** collapse the MSM and the G2 point updates; line-
  coefficient evaluation for the pairing remains field-level (a plain point
  add/double opcode does not produce the line slope the Miller loop needs).

---

## Results

### 1. Baseline — today's verifier (validates the README's "~1 GB")

Leaf and tower primitives, measured (`measure_field_primitive_sizes`):

| primitive | bytes | "tmul" hints |
|---|--:|--:|
| `Fq::add` | 415 | – |
| `Fq::tmul` (one multiply) | 67,663 | – |
| `Fq::hinted_mul` | 67,744 | 1 |
| `Fq::hinted_inv` | 67,832 | 2 |
| `Fq2::hinted_mul` | 190,619 | 2 |
| `Fq6::hinted_mul` (dense) | 1,066,421 | 10 |
| `Fq12::hinted_mul` | 3,217,947 | 30 |
| `Fq12::hinted_square` | 2,155,690 | 20 |

Full **monolithic** verifier (`groth16/verifier.rs`), reconstructed by weighting
each block by its occurrence in the 64-iteration quad Miller loop (+21 add steps)
and the pre-pairing setup (`estimate_full_verifier`):

| component | bytes/ea | × count | subtotal |
|---|--:|--:|--:|
| **ell + sparse mul** (line eval) | 2,222,815 | 261 | **580 MB** (65%) |
| Fq12 square | 2,155,690 | 64 | 138 MB (15%) |
| Fq12 mul (c/c_inv/wi/frob) | 3,217,947 | 25 | 80 MB (9%) |
| g2 tangent/double/chord/add lines | – | 173 | 71 MB (8%) |
| MSM (G1, 2 bases) | 19,391,088 | 1 | 19 MB (2%) |
| frobenius ×3, Fq2 mul, pre-setup | – | – | ~6 MB |
| **TOTAL (today)** | | | **≈ 895 MB** |

- **Total field multiplications across the verifier: 10,632.**
- ≈ 895 MB matches the repo README's "~1 GB" figure (slight underestimate — minor
  constant pushes/`equalverify` glue excluded).

### 2. Under the new opcodes (executable + validated)

Validated primitive programs (each run through an independent interpreter and
asserted equal to arkworks):

| primitive | bytes | vs today |
|---|--:|--:|
| `fq_mul` | 5 | – |
| `fq2_mul` | 40 | 4,765× |
| **`fq12_mul`** | **2,425** | **1,327×** |
| `fq12_square` (via `mul(a,a)`) | 2,413 | 893× |

Full verifier under the new opcodes (`generate_full_verifier`), summed over the
same schedule as the baseline:

| component | bytes/ea | × count | subtotal | validated |
|---|--:|--:|--:|:--:|
| **ell + sparse mul** | 2,445 | 261 | **638 KB** (72%) | ✓ |
| Fq12 square | 2,413 | 64 | 154 KB (17%) | ✓ |
| Fq12 mul | 2,425 | 25 | 61 KB (7%) | ✓ |
| g2 lines | 161 | 173 | 28 KB (3%) | ~modeled |
| frobenius, Fq2 mul, MSM, pre-setup | – | – | ~1 KB | mixed |
| **TOTAL (new opcodes)** | | | **≈ 882 KB** | |

- **≈ 882 KB → 1,015× smaller** than today, and it **fits in a single 4 MB
  tapscript** with ~4.5× headroom.

### 3. Why it is ~hundreds of KB, not "tens of KB"

The *multiplications-only floor* is `10,632 muls × 1 B = 10.6 KB`. The realized
figure is far larger because **once a multiply costs 1 byte, stack movement and
additions dominate.** Breakdown of one validated `fq12_mul` (2,425 B):

| | count | bytes | share |
|---|--:|--:|--:|
| arithmetic (`FqMul` + `FqAdd/Sub`) | 95 + 215 | ~310 | 13% |
| `Pick` stack-copies | 620 | ~1,650 | 68% |
| `Push` (const 9 for non-residue) | 14 | ~460 | 19% |

The two biggest line items (ell, square) are large because **each is a full Fq12
multiply** (ell uses full-mul as a conservative proxy for the sparse `mul_by_034`;
square is `mul(a,a)`), and because they are the most *frequent* ops (ell fires for
every point on every Miller step → 261×; square once per iteration → 64×).

### 4. The 882 KB is a conservative upper bound

Known headroom, none of which changes the "fits in one tapscript" conclusion:

- **Roll-based scheduling** (consume operands on top instead of re-`Pick`ing from
  depth) — the largest lever; the naive codegen is ~4× heavier than necessary.
- **Real sparse `mul_by_034`** for the dominant ell term (~0.6×) and a **dedicated
  Fq12 squaring** (~0.7×).
- **Toom-3/LC multiplies** (30 muls, as the real code uses) vs the prototype's
  schoolbook 95.
- **Push the constant `9` once** instead of per multiply (removes the 19%).

**Optimized estimate: ≈ 150–200 KB.**

---

## Takeaways

1. The full ~895 MB verifier collapses to **~882 KB (validated) / ~150–200 KB
   (optimized)** under these opcodes — **~1,000–6,000×**.
2. It **fits in a single Bitcoin tapscript**, which means the entire chunking
   apparatus (364 taps, BLAKE3 state-hashing, WOTS bit-commitments) becomes
   **unnecessary for the proof arithmetic**.
3. The dominant cost is **field arithmetic in the Miller loop** (the `ell` term,
   72%), so the **Fq add/mul opcodes do the heavy lifting**; the **G1/G2 opcodes
   cleanly collapse the MSM** (19 MB → ~3 bytes) but help the pairing only at the
   point-update step.
4. Counterintuitively, with 1-byte multiplies the bottleneck shifts to **data
   movement** — an efficient stack layout matters more than shaving multiplies.

## Caveats

- Dominant ops (Fq2/Fq12 mul, Fq12 square) are **validated executables**;
  `g2` lines, frobenius and MSM are **modeled** from the validated `fq2_mul`/
  `fq_mul` units and the chosen curve opcodes.
- `ell` uses full-mul as a conservative proxy for the sparse mul, and squaring is
  `mul(a,a)` — both inflate the estimate (hence "upper bound").
- The opcodes are hypothetical; this is a size study, not a consensus proposal.

## Reproduce

```bash
# (opt-level 0 just speeds up compilation; the tests only build/measure scripts)
CARGO_PROFILE_DEV_OPT_LEVEL=0 cargo test -p bitvm --lib \
  bn254::opcode_analysis::measure_field_primitive_sizes -- --nocapture --exact
CARGO_PROFILE_DEV_OPT_LEVEL=0 cargo test -p bitvm --lib \
  bn254::opcode_analysis::estimate_full_verifier -- --nocapture --exact
CARGO_PROFILE_DEV_OPT_LEVEL=0 cargo test -p bitvm --lib \
  bn254::opcode_codegen::generate_fq12_mul -- --nocapture --exact
CARGO_PROFILE_DEV_OPT_LEVEL=0 cargo test -p bitvm --lib \
  bn254::opcode_codegen::generate_full_verifier -- --nocapture --exact
```
