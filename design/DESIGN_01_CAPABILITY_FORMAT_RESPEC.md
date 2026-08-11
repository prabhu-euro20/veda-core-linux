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

## Generation vs churn (why 24 bits, honestly)

Even 24-bit generation is finite. Linux allocates continuously. Two mechanisms combine:
(1) object-centric slab caches *reuse without destroy* (churn amortized inside a live
slab object -- but then intra-slab UAF is not caught, an honest temporal-safety
weakening); (2) **sweeping revocation** (DESIGN_06) reclaims IDs so generation pressure
stays bounded. 24 bits is the starting point, not a proof.

## Blast radius (what this touches -- plan before coding)

- `veda_types.sail` field widths; every CGet* query; the pack/unpack used by
  OCL.C/OCS.C and the GDB stub.
- RTL `/vreg` fields; the ODT entry layout (Base/Length/generation widen too).
- Tag-memory granule size stays; capability is now 32 bytes -> OCL.C/OCS.C move 256 bits.
- Re-run: 63/63 Sail self-check, 51/51 ACT4 (should be untouched -- GPR datapath
  unchanged), 49/49 RTL smoke.
