# DESIGN 01 -- Capability Format Respec

**Status:** Design proposal (final widths need workload data + an encoding study -- see
"Honest scope"). **Builds on:** the *verified* decision to keep the CRF **separate**
from GPRs (CRF_ARCHITECTURE_ALIGNMENT_VERDICT), and the 36-instruction ISA.
**Verification plan:** Sail types first (`veda_types.sail`), then RTL `/vreg`, then
re-run the full self-check corpus.

## Problem (four spec-level walls, from the current 128-bit format)

| Field | Now | Wall |
|-------|-----|------|
| Length | 16b | object <= 64 KiB (and PCC compartment <= 64 KiB) |
| generation | 8b | 255 destroy/reuse then permanent retirement |
| Base | 32b | 4 GiB physical ceiling |
| Object_ID | 23b | 8.4 M live objects |

These are not "unbuilt features" -- the current format literally cannot *express*
Linux-scale objects, memory, churn, or object counts.

## Key insight -- the separate CRF is an asset here

CHERI had to compress capabilities to 128 bits because it *merged* them into the 64-bit
GPR file (widening every GPR was unacceptable). **Veda-Core's CRF is physically
separate** (verified decision). Therefore we can **widen the capability without touching
the 64-bit GPR datapath at all** -- a clean radical move CHERI could not make cheaply.
Compression becomes an *optional later* area optimization, not a prerequisite.

## Decision -- widen the separate CRF to 256 bits (+ out-of-band Tag)

Concrete starting budget (256 data bits + 1 Tag, out-of-band as today):

| Field | Bits | Range / note |
|-------|------|--------------|
| Object_ID | 44 | ~17.6 trillion objects (namespace as "address space", DESIGN_00) |
| Base | 56 | 64 PiB physical -- future-proof past 4 GiB |
| Length | 40 | up to 1 TiB per object (kernel text, framebuffers, vmalloc) |
| Offset | 40 | cursor, same range as Length (0 <= Offset < Length) |
| Perms | 16 | CHERI-aligned set + Permit_NMC_Compute + Permit_Attenuate + spare |
| otype | 16 | 65 536 seal/compartment types |
| generation | 24 | ~16.7 M reuse before retirement (kills the 255 wall in practice) |
| flags | 20 | COW-hint, residency-mirror, CID, reserved |
| **Total** | **256** | |

**Area-conscious alternative (192-bit):** ID 40 / Base 48 / Length 32 / Offset 32 /
Perms 16 / otype 12 / gen 12 = 192. 4 GiB max object, 4096 reuse. Use if 256-bit CRF
area is unacceptable; pairs well with sweeping revocation (DESIGN_06) to offset the
narrower generation.

**Long-term option (compressed 128-bit):** a CHERI-Concentrate-style
{exponent, base-mantissa, top-mantissa} bounds encoding keyed on Offset. Deferred:
needs a real derivation pass (CHERI's own Concentrate took dedicated work); do it only
if silicon area later demands 128-bit.

## CRF entry count (16 vs 32) -- a separate axis, but decide the index width NOW

Entry *count* is orthogonal to field *width* above -- count is a register-index/encoding
decision, width is a field-width decision -- but both live in this respec because the
capability-index field is part of the same instruction formats. Verified against the real
Sail/RTL/LLVM (adversarial pass, 2026-08-11):

- **The format is already 5-bit-shaped.** Every capability operand is a standard RISC-V
  5-bit register slot whose MSB is a hardcoded `0b0` pad: Sail encodes `0b0 @ encdec_vcap(...)`
  (`veda_cap_insts.sail:23/174/248`, `veda_ocl_insts.sail`, `veda_bind_insts.sail:104`);
  RTL slices only the low 4 bits, skipping pads `instr[11]/[19]/[24]`
  (`$veda_rd_cap[3:0]=$instr[10:7]`, `rs1_cap=$instr[18:15]`, `rs2_cap=$instr[23:20]`); LLVM
  uses stock 5-bit fields with `C0-C15` = 0-15. **Going to 32 needs NO instruction-format
  change**: `vcapidx` bits(4)->bits(5) reclaiming the existing pad bits, RTL `/vreg[15:0]`
  -> `[31:0]` (`veda_core.tlv:1411`) plus `[3:0]`->`[4:0]` slices, and `C16-C31` LLVM defs.
  Backward compatible by construction -- shipped binaries carry 0 in the new MSB and decode
  identically to `c0-c15`.
- **Timing rule (load-bearing):** because widening reinterprets the currently-reserved
  `0b0` pad bits as index bits, the 16-vs-32 choice must be made **during this respec**, not
  deferred to Phase 7. Deferring means shipping 16-entry hardware whose decode silently
  aliases any future `c16-c31` encoding to `c0-c15`. Even if the decision is **stay at 16 for
  now** (recommended -- see below), this doc must **reserve the pad bits as
  index-extension-reserved** so the door stays open.
- **One concrete cheap fix, independent of 16-vs-32 (do it in the Sail respec):** close a
  real Sail/RTL decode divergence. Sail already traps a nonzero pad bit as an encdec no-match
  (illegal instruction -- correct forward-compat), but the RTL ignores `instr[11]/[19]/[24]`.
  Add a decode-guard so 16-entry RTL **traps** on a nonzero capability-index MSB instead of
  aliasing to `c0-c15`, making any future `c16-c31` opcode fail-closed on old hardware.
- **Do NOT widen the CRF pre-emptively.** The frozen CRF verdict's own §2 justification for
  16 (pressure = simultaneously-live *object-handles*, cheaply re-derivable via Bind) is
  specific to the object-handle codegen model and does **not** transfer to DESIGN_05 Part A
  purecap, where a pointer is a capability-*with-offset* and Bind does not restore the offset
  -- so under purecap the rationale must be rewritten (see DESIGN_07 R9). But under purecap,
  pressure beyond 16 does not *fail*: it saturates at the allocatable limit and spills as
  bounded, TCM-tier traffic via OCS.C/OCS.C into the M24 capability-spill scratch. 16-entry
  register files are routine compiler targets, and CHERI's 32 is MIPS-ISA congruence, not a
  sized pressure figure -- so 32 is **not** a benchmark 16 must meet. Decide 16-vs-32 from a
  real Phase-7 purecap spill-traffic study, not a priori. **This respec's job is only to
  reserve the index bits and close the decode divergence, keeping the cheap door open.**

## New instruction -- CAndPerm (rights attenuation)

The current 36-instruction set has **no per-holder rights attenuation**. Real CHERI has
`CAndPerm`. Without it, giving a domain a read-only view of a live object forces a
*separate Object_ID aliasing the same Base* -- which breaks temporal safety (destroying
one ID does not revoke the alias).

**Add `CAndPerm` (Custom-2, next free funct7):** `cd = cs1` with `Perms &= rs2`
(monotonic clear-only). Sealed cs1 -> soft-fail (Tag cleared), matching the OCA/CSetBounds
"manipulate" family already in the spec. This gives per-*holder* attenuation with **no**
new Object_ID and **no** aliasing -- the same live object, a weaker capability. Essential
for the multi-process Linux rights model (read-only text shared to children, etc.).

**Status: BUILT AND VERIFIED IN SAIL (Phase 1, first increment, 2026-08-11).**
`funct7 = 0b0010111` -- the next free Custom-2/funct3=001 slot, chosen after a full
enumeration of every existing user of that space (OCA 0001010, CSetBounds 0001000,
CSetBoundsExact 0001001, CSeal 0010000, CUnseal 0010001, OCInvoke 0010010, OSpecialRW
0010011, OCJALR 0010100, CSealEntry 0010101, OCRETURN 0010110), the same "grep the whole
file first" discipline that once caught a real OCJALR/OSpecialRW collision. Implemented in
`veda_cap_insts.sail` in the OCA idiom exactly: fields written unconditionally, Tag cleared
on an untagged or already-sealed source; **no bounds term** (masking Perms cannot produce an
out-of-window value, so tag+seal are the only soft-fail conditions). Monotonicity is
structural, not a check: bitwise AND can only clear, never grant.
Verified on the real Sail model: **67/67 self-check tests pass** -- the full 65-test verified
baseline with **zero regressions**, plus two new tests (`vc_candperm.S`: exact AND semantic
against a computed expectation, mask=0 clears every permission while the Tag survives,
Base/Length/Offset untouched; `vc_candperm_neg.S`: a `CSealEntry`-sealed source soft-fails
with Tag=0). Both were mutation-tested (see the milestone results doc) so they cannot pass
vacuously.

## Finding surfaced by increment 3 -- "return to unbounded" needs its own mechanism

Widening the compartment-bounds registers exposed a latent design wart that was invisible
while every field was 16 bits.

PCC's "no compartment active" state is encoded as `veda_pcc_length == all-ones`. Leaving a
compartment is therefore done by `OCInvoke`/`OCRETURN` **through a code object whose Length is
the saturated value** -- the caller has to synthesise a max-length object purely to say
"unbounded". That worked incidentally when Length was 16 bits, because `0xFFFF` was both a
plausible literal and the sentinel.

At 40 bits it no longer does, for a concrete reason: **the compact single-GPR populate
descriptor has a 16-bit Length field and can no longer express the sentinel at all.** Creating
an unbounded code object now requires the wide populate path. Every test that used the old
idiom had to be converted, which is a strong smell -- an operation as ordinary as "return from
a compartment" should not require constructing a specially-shaped object.

This is not a bug and increment 3 does not change it (the sentinel remains all-ones, which is
the semantically correct choice -- keeping the old numeric value would have made a legitimate
65535-byte compartment read as unbounded). But it is a real design question worth its own
increment:

- Should `OCRETURN` **restore** the previously-saved bounds rather than take them from its
  operand capability? There is already precedent in the trap path (`veda_mepcc_base/_length`
  save-and-restore), and it would make compartment exit symmetric with compartment entry
  instead of requiring a synthesised object.
- Who is authorised to decide the restored bounds is the real security question, and is
  exactly why this needs analysis rather than a quick change.

Recorded here so the awkwardness is not silently normalised by having "fixed" the tests.

## Generation vs churn (why 24 bits, honestly)

Even 24-bit generation is finite. Linux allocates continuously. Two mechanisms combine:
(1) object-centric slab caches *reuse without destroy* (churn amortized inside a live
slab object -- but then intra-slab UAF is not caught, an honest temporal-safety
weakening); (2) **sweeping revocation** (DESIGN_06) reclaims IDs so generation pressure
stays bounded. 24 bits is the starting point, not a proof.

**Status: BUILT AND VERIFIED IN SAIL (Phase 1, increment 4, 2026-08-11).** `odt_entry
.generation` widened 8 -> 24, matching the capability field, so the last narrow-to-wide bridge
is gone (Bind and the dereference recheck now copy/compare directly). The retirement ceiling
moves from **255 reuses per slot to ~16.7M**. The mechanism is unchanged in kind: the counter
freezes at maximum and the next bump retires the slot.

**How a 16.7M threshold is tested, since it cannot be looped to.** The 8-bit test reached the
ceiling with `.rept 256`; `.rept 16777216` is not a test. The threshold is instead exercised by
**direct ODT-state injection near the boundary** -- a reset seed (Object_ID 55) placed at
`generation = 0xFFFFFE`, one below the real threshold, so two destroys cross the genuine
saturate-then-retire transition. This is the project's own established technique (every seeded
object is written directly at reset; the RTL uses the same injection for owner-hart tests it has
no second hart to drive), and it deliberately tests the **true 24-bit constant** rather than a
reduced stand-in threshold, which would leave the shipping boundary arithmetic untested.

## Blast radius (what this touches -- plan before coding)

- `veda_types.sail` field widths; every CGet* query; the pack/unpack used by
  OCL.C/OCS.C and the GDB stub.
- RTL `/vreg` fields; the ODT entry layout (Base/Length/generation widen too).
- Re-run: Sail self-check (65/65 today), 51/51 ACT4 (should be untouched -- GPR datapath
  unchanged), RTL smoke.

## Resolved implementation decisions (Increment 2, grounded 2026-08-11)

An adversarial read-only grounding pass over the whole Veda Sail model reconciled this
target against what Sail can actually express and surfaced seven real decisions. All are
now settled; three notes below **override or sharpen** the earlier text of this doc, per the
"challenge, don't recite" discipline.

**Confirmed 256-bit layout (MSB->LSB, exactly 256 data bits, NO pad bit):** Object_ID[255:212]
44 / Base[211:156] 56 / Length[155:116] 40 / Offset[115:76] 40 / Perms[75:60] 16 /
otype[59:44] 16 / generation[43:20] 24 / flags[19:0] 20. The old `@ 0b0` pad (bit 0) and the
unpack pad-skip **cease to exist**; pack/unpack are re-derived field-by-field. `UNSEALED_OTYPE`
(0xFFFF) and `VEDA_OTYPE_SENTRY` (0xFFFE) are unchanged (otype stays 16-bit).

1. **Tag granule -> widen to 32 bytes (OVERRIDES the earlier "granule size stays" line).**
   A 256-bit capability is 32 bytes = two 16-byte granules. Keeping the 16-byte granule is a
   **forgery hazard**: the tag store's `__ReadRAM_Meta` reads a single bit at the start
   granule, so a plain-store tamper of bytes 16..31 of a stored capability would leave the
   start-granule tag set and be **invisible** -- a permission/generation forgery primitive.
   Widen the granule to 32 bytes so the one-capability-one-granule invariant (which makes the
   tag store's width-oblivious semantics correct-by-construction) survives, plain-store
   invalidation stays complete, and the meta functions stay untouched. This matches CHERI's
   own capability-sized-granule model. `>>4 -> >>5`, granule count halves.
2. **OCL.C/OCS.C require 32-byte natural alignment, HARD trap on violation** (new cause
   `VEDA_CAUSE_CAP_MISALIGNED`). This is the only alignment rule under which the single-granule
   mapping is well-defined; hard-trap matches the existing OCL/OCS Tag/Seal violation family,
   and a misaligned capability spill/reload is a compiler/ABI bug, not a recoverable soft
   condition.
3. **ODT index domain -- bounded direct-mapped window.** The capability legitimately carries
   the full 44-bit Object_ID (format future-proof, RTL-compatible), but a flat `vector(2^44)`
   ODT is ~300 TiB and will not compile. Keep the modeled table at its current flat size
   (2^23) and make `odt_lookup`/`odt_write` trap `unsigned(id) >= MODELED_SIZE` as
   OBJECT_NOT_FOUND before indexing. This is the honest interim until the segmented-Object_ID
   trilemma (DESIGN_06) is designed -- the same "real, bounded, honestly-scoped" discipline as
   the RTL's 256-entry ODT.
4. **flags(20) -- opaque/reserved, minted as zeros by Bind.** Assigning a bit layout now
   (especially the CID sub-field width) ahead of the DESIGN_00 namespace work would be an
   under-sourced guess. Reserve the 20 bits, mint zeros, let a later design assign positions.
5. **Rename the capability's `Reserved` field to `generation`** and add the separate `flags`.
   Sail's type checker turns every stale `.Reserved` into a compile error (not a silent bug),
   so the rename is safe and removes a genuinely misleading name.
6. **ODT-Populate operand redesign is a SEPARATE follow-on increment.** Base56+Length40+Perms16
   = 112 bits no longer fits the single-GPR packed descriptor, and `veda_attr` (bits(32)) can't
   hold Length40+Perms16. Widen `veda_attr` to bits(64) and stage Base via a GPR/second CSR;
   retire the packed descriptor. Because Bind can `zero_extend` a still-narrow ODT Base into the
   wide capability, the ODT-entry widening + Populate redesign can land AFTER the core struct
   widen as its own tested increment -- keeping the atomic core change smaller.
7. **Gate `Ext_Veda` on `xlen == 64`** (reverses the earlier xlen-generic decisions; drops
   NMC_ADD.W on RV32). A 56-bit Base / 44-bit Object_ID design is semantically RV64-scale;
   `zero_extend(Base:56)` into a 32-bit `xlenbits` is ill-typed, and the xlen-generic gymnastics
   become impossible once fields exceed 32 bits. Per compliance-over-loss-aversion, gating is
   the correct, honest trade. This is a **prerequisite that lands before any width edit**.

**R9 (index bits):** stay at `vcapidx = bits(4)`; **no Sail change** -- Sail is already the
fail-closed golden model (a nonzero index MSB is an `encdec` no-match). R9's decode-guard is an
RTL-side change; the Sail model already has the property.

**Decomposition:** the struct widen + pack/unpack + tag-granule + OCL.C/OCS.C + Bind
(zero-extend bridge to a still-narrow ODT) + all arithmetic consumers + otype range-guards +
the xlen gate form **one atomic commit** (Sail forbids a partially-wide struct); the corpus is
red throughout and green only at the end. ODT-entry widening + Populate redesign follow as a
separate green increment. Six Sail proof risks were catalogued (xlen typecheck, OCA slice
comment, otype-vs-Offset sentinel forgery, Kind-Int tag-store bound, Base+Offset wrap, ODT
index-vs-array-size) and each has a stated resolution.
