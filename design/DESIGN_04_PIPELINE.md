# DESIGN 04 -- Pipelining the Core

**Status:** Design proposal. **Builds on:** the single-cycle base (ACT4 51/51), the
synthesis critical-path study (capability check chain 95 gate levels < plain load 114),
the M24 DRAM-stall FSM. **Verification plan:** pipeline the RVA23 base first, re-pass
ACT4 51/51, then layer Veda checks, re-pass the full smoke corpus.

## Problem

The core is single-cycle. For real silicon (and for Linux to run at usable speed) it
must be pipelined. Concern: do the five capability checks (Tag/generation/seal/perm/
bounds) lengthen the critical path and cap Fmax?

## The measurement that de-risks this

The synthesis study already answered the central fear: the full OCL.D check chain is
**95 gate levels vs 114 for a plain load** -- *shorter*. Why: the checks run **parallel**
to effective-address computation (unconditional address calc; blocking is a downstream
mux), and Base is 32-bit (now 56-bit, DESIGN_01) not a full 64-bit rs1 add. So the check
chain is **not** the critical path. Pipelining is therefore a standard exercise plus
capability-specific hazard/forwarding.

## Decision -- a classic 5-stage pipeline with three capability additions

Stages: IF -> ID -> EX -> MEM -> WB. Additions:

1. **Object-Bind is a "capability-load" micro-op.** The ODT is DRAM-resident, so
   Object-Bind is a memory operation that fills a capability register -- treat it exactly
   like a load that writes the CRF instead of a GPR. It occupies MEM and may stall
   (DRAM latency / residency fault). The **M24 stall FSM is the seed** of this stall
   path; reuse it as the general pipeline memory-stall mechanism.
2. **Capability hazard + forwarding.** A `bind cN; use cN` sequence is a RAW hazard on
   the CRF, identical in spirit to a GPR load-use hazard. Add CRF scoreboard bits and
   forward a freshly-bound/derived capability from MEM/WB back to EX. Manipulate-family
   ops (OCA/CSetBounds/CAndPerm/CSeal) that derive cN from cM also need CRF forwarding.
3. **Checks live in EX/MEM, combinational.** Tag/gen/seal/perm/bounds compute in
   parallel with address calc (proven to fit under plain-load depth). A violation
   converts the access to a trap in MEM -- reuse the M9 trap machinery and M14's
   NOP-forcing-on-violation idea (already an every-cycle unconditional check in RTL).

## Interactions to get right

- **PCC fetch-bounds check (M14)** is already every-cycle in RTL; in a pipeline it is a
  check in IF against veda_pcc_base/length. Keep it; it composes.
- **Precise exceptions:** capability violations must be precise (Linux needs precise
  faults for COW/paging, DESIGN_02). Standard in-order pipeline precise-exception
  handling applies; the single trap chokepoint ($veda_trap_taken, M21) helps.
- **Object-Bind latency hiding:** with the pipeline, back-to-back binds to *different*
  registers can overlap; the TCM ODT tier (M24) keeps hot binds at 1 cycle. Register
  pressure study (1.186x-1.561x) is the amortization model.

## CORRECTION -- the 95 < 114 result does not answer the pipelined multi-hart question

Recorded after being challenged on exactly this, and the challenge was right.

The synthesis study measured **combinational gate depth in the single-cycle, single-hart core**,
where `odt_mem` is a flat array read combinationally inside one long cycle. Quoting it as evidence
that capability checks are free on the **pipelined multi-hart** line compares two different
machines. Gate depth is not even the right unit once the design is pipelined -- the question becomes
which stage the check lands in, whether it fits that stage's budget, and what structural hazards it
creates.

### An internal tension in this document, previously unnoticed

This document states, of Bind: *"The ODT is DRAM-resident, so Object-Bind is a memory operation."*
It then states, of the checks: *"Checks live in EX/MEM, combinational."*

**Both cannot hold.** The per-dereference generation check reads that same DRAM-resident ODT. So on
a pipelined core every load and store needs a **second memory access** beside its data access -- a
structural hazard in MEM, and DRAM latency on the check path unless something covers it. The
single-cycle core hid this entirely, because there a flat-array read costs nothing.

The M24 TCM tier is the partial answer, at **32 entries**. That is a working-set assumption which has
never been validated against any real workload.

### What multi-hart adds, which DESIGN_03 does not cover

DESIGN_03's claim -- cache-less by pillar, therefore no coherence protocol -- is sound for object
**data**. But it also means every hart's every dereference goes to DRAM/MSA **for its ODT check**.
N harts x one ODT read per dereference is N-fold read bandwidth on one shared structure. DESIGN_03
discusses MSA bottlenecking for *shared-atomic* traffic only; ODT read bandwidth for **ordinary
loads and stores** appears in neither document.

**The cache-less pillar is therefore in direct tension with a per-access live-state check.** That
tension is unresolved and is not a detail -- it is the central throughput question for this line.

### A candidate direction, not a decision

The generation check asks *"was this revoked?"* on every access. The alternative is to push the work
to the revocation: when page-out or Destroy runs, invalidate every capability register naming that
object -- a CAM across the 16-entry CRF. Revocation is rare; dereference is not. Capabilities spilled
to memory are not in the register file, but they are reloaded by `OCL.C`, which is **already** a
memory operation and can carry the check there. The per-dereference path would then need **no ODT
read at all**.

Its real cost, stated rather than hidden: on multi-hart, revocation becomes a **cross-hart
broadcast** -- the coherence-like mechanism DESIGN_03 avoids. But it would sit on the rare path
instead of the common one, which is the same trade that settled DESIGN_02's cached-Base decision.

### MEASURED: the per-access check reads 256 bits to use 26

Prompted by the question "why is the ODT in DRAM at all, and is that efficient" -- which turned out
to be an incomplete question with a measurable answer underneath it.

Enumerating every field `veda_check_access` consumes from the ODT entry, read out of the function
rather than recalled:

| field | width |
|---|---|
| `valid` | 1 |
| `generation` | 24 |
| `resident` | 1 |
| **total** | **26 bits** |

`entry.Base` appears in that function **only inside a comment stating it is deliberately not used** --
the address is formed from `cap.Base`. `Length`, `Perms` and `owner_hart` are never read on the hot
path at all.

So the machine fetches a **32-byte (256-bit) descriptor to obtain 26 bits**: roughly **10x read
amplification on the hottest path in the design**. In the RTL it is about 4x, because the RTL
additionally needs the 36-bit `id_hi` anti-alias tag -- itself a consequence of truncating `local` to
8 bits for slot indexing, not a semantic requirement.

### The real finding: one structure is doing two jobs with opposite profiles

| | naming / descriptor | validation |
|---|---|---|
| holds | Base, Length, Perms, owner_hart, id_hi | valid, generation, resident |
| size | ~230 bits | **26 bits** |
| touched by | Bind, Populate, Destroy, page-out, page-in -- **rare** | **every load and store** |
| must cover | the object namespace | only what is currently resident |

They are one structure by **history, not by design**: the ODT began as a protection table, DESIGN_02
promoted it into the machine's whole memory map, and the access path was never revisited. DRAM is
the right home for the descriptor. It is the wrong home for a 26-bit check on every memory access.

### The cache-less pillar has been read too strictly

"Cache-less" exists to buy **determinism**. What destroys determinism is **dynamic replacement**, not
SRAM. A flat, directly-indexed, statically-placed SRAM array is O(1) and fully predictable -- a
**scratchpad, not a cache**. M24's TCM tier already relies on exactly this reasoning; it simply
applies it to whole 32-byte entries rather than to the 26 bits that are actually hot.

### Proposal -- an object validity vector (not yet decided)

Split the hot fields into their own flat array: `{valid, generation, resident}` per slot, padded to
4 bytes, in SRAM, indexed by the slot number the design already computes. The descriptor table stays
in DRAM and is read only at Bind / Populate / Destroy / page-out / page-in.

**No semantic change**: same fields, same checks, same causes, same determinism. Only the storage
and the access path move.

Coverage in the same 1 KB of on-chip memory M24 already spends:

| | objects covered |
|---|---|
| today, whole 32-byte entries | 32 |
| validity vector only | **256** |
| at 32 KB | **8192** |

**8x more hot coverage per byte, at identical semantics.** The second-order gain matters more for
multi-hart: a 26-bit structure is far easier to bank or multi-port than a 256-bit one, which is
precisely the N-harts-reading-one-structure bandwidth problem above.

**Where this must not be oversold:** it does **not** remove tiering. The slot space is still bounded
by (resident regions x entries per region) and a real machine sizes that far above 768. What it buys
is a hot tier 8-10x more effective per byte -- not the disappearance of the tier.

### Two candidate directions, compared

| | validity vector | eager revocation (CAM the CRF at page-out/Destroy) |
|---|---|---|
| per-access cost | small deterministic SRAM read | **no ODT read at all** |
| revocation cost | unchanged | CAM over 16 CRF entries, plus a cross-hart broadcast |
| semantic change | **none** | real -- moves *when* the check happens |
| multi-hart | easy to bank (26 bits vs 256) | needs cross-hart invalidation, the very mechanism DESIGN_03 avoids |
| risk | low, a reorganisation | higher: new invalidation path, and memory-resident capabilities need separate treatment via OCL.C |

**Recommended order: the validity vector first**, precisely because it changes no semantics -- it
relocates state rather than altering when a check occurs. Eager revocation is a genuine
architectural change and reintroduces a coherence-shaped mechanism on multi-hart. They are **not
mutually exclusive**: eager revocation can be layered afterwards, and by then its benefit would be
measurable against a known baseline rather than argued.

### What must be measured before any of this is decided

1. ODT read bandwidth per hart per cycle under a realistic instruction mix.
2. TCM hit rate for a real working set -- is 32 entries remotely enough, and for what?
3. Whether the ODT read is a genuine structural hazard in MEM alongside the data access, or can be
   dual-ported / banked away.
4. MSA serialization behaviour at N harts for ordinary traffic, not just atomics.

Until those exist, **no steady-state performance claim should be made for the pipelined multi-hart
line**, and the 95 < 114 figure must be cited only for what it is: the single-cycle load path.

## Honest open items

- **Superscalar / OoO** is out of scope for the first pipeline; note that capability
  checks being off the critical path is *more* favorable to higher issue widths later.
- **Real DRAM controller + memory hierarchy** must be added (today zero real latency
  model in the committed core outside M24's parameter). This is the biggest new RTL
  block and interacts with DESIGN_02 paging.
- **Branch prediction** is orthogonal (base ISA).
- Fmax numbers require a real PDK synthesis + place-and-route -- the 95<114 result is
  technology-independent gate depth, not picoseconds.
