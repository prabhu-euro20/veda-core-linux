# DESIGN 08 -- The Object-Namespace Scale Decision (the ODT trilemma, resolved)

**Status:** Design decision. This is the "next big radical decision" DESIGN_06 flagged and did
not claim solved. **Builds on:** DESIGN_00 (process = protection domain), DESIGN_01 (the 44-bit
Object_ID), DESIGN_02 (ODT-as-mm, residency/backing faults), DESIGN_06 (the trilemma statement +
the segmented-Object_ID leading candidate). **Verification plan:** a bounded Sail experiment
proving the mechanism is expressible with its pillar invariants machine-checked (Section 9),
before any RTL.

Grounded 2026-08-11 by a complete read of the trilemma statement, the pillar constraints, the
real post-respec footprint arithmetic, and the historical prior art, followed by a five-architect
design panel (one instructed to challenge the framing itself) and an adversarial pillar-by-pillar
judging pass. The decision below is the author's, taking the panel and judges as input, not a
rubber stamp of either.

---

## 1. The problem, now acute

A single ODT cannot be simultaneously **(a) flat** (O(1), the determinism pillar), **(b)
resident and cache-less** (the no-cache pillar), and **(c) huge** (millions-to-billions of live
objects for a whole OS). Pick any two.

The respec (DESIGN_01) made this urgent rather than theoretical. At the old 23-bit Object_ID a
flat resident ODT was ~80-100 MiB -- comfortably DRAM-resident. At the new **44-bit Object_ID a
flat table of 2^44 entries x 32 bytes is ~512 TiB** and, in the words of the Sail model's own
comment, "will not compile." Widening the namespace to Linux scale is exactly what removed the
option of keeping the whole table resident. The interim answer shipped in increments 1-4 -- a
bounded flat window (ids at or above the modeled size read as not-found) -- is honest for the
embedded line but is not a Linux answer. This document supplies the Linux answer.

## 2. The decision -- Domain-Segmented Object_ID

Split the 44-bit Object_ID into a **fixed, context-independent** partition:

```
  Object_ID[43:0]  =  { region [43:24] (20 bits) , local [23:0] (24 bits) }
```

- **region (20 bits) = a protection domain** (DESIGN_00: a process/compartment/allocation
  arena). ~1,048,576 domains. This is the load-bearing choice -- see Section 3.
- **local (24 bits) = an object within that domain.** ~16.7M objects per domain.

The partition is a fixed split of the one global 44-bit ID, never a runtime-variable or
per-process boundary, so a full Object_ID still names the same object everywhere (Single Address
Space pillar preserved; `{region=A, local=k}` and `{region=B, local=k}` are different global
objects, and a capability to either means the same object system-wide).

**Structure:**

- A single **Region Table (RT)**, flat and DRAM-resident, `2^20` entries. Each entry is packed
  tight (~20-24 bytes, not rounded up to 32): `{ rt_valid, region_odt_base (physical),
  region_resident, region_backing, region_generation, owner_domain_meta }`. Fixed resident cost
  **~20-24 MiB** -- small, flat, always present.
- Each domain's **per-region ODT** is a flat, direct-mapped array of up to `2^24` entries at 32
  bytes (512 MiB logical ceiling), **demand-paged** in 4 KiB / 128-entry granules via the
  existing DESIGN_02 residency mechanism. Only the touched granules of *active* domains consume
  DRAM.

**Lookup shape (fixed-depth 2, never a variable-depth walk):**
`RT[region] -> region_odt_base ; ODT_at(region_odt_base)[local] -> entry`.

## 3. Why region = domain is the whole point (not a bit-split)

If "region" were an arbitrary top-bit slice, the outer table (the RT) would face the same scaling
problem as the flat ODT: objects would scatter across the region space and the RT would have to be
huge too. Making the region a **semantic protection domain** is what bounds the outer level:

- A protection domain is a **heavyweight OS entity** -- a process, a compartment, an allocation
  arena. Even a large server has domains in the thousands to low millions, never billions.
- The count explosion that a whole-OS workload produces -- R1 SLAB-CARVE mints one Object_ID per
  live slab element (DESIGN_07), driving live objects into the millions-to-billions -- lands
  **entirely in the 24-bit local dimension, which demand-pages.** It never touches the 20-bit
  region count. The unbounded thing (objects) goes in the demand-paged dimension; the bounded
  thing (domains) goes in the resident, flat dimension.

That is the single insight that keeps the outer level resident, flat, and small while the total
namespace scales. It is the SASOS reframe (DESIGN_00: address space = the Object_ID namespace,
process = domain) applied to the *structure* of the namespace, not a mechanical hack bolted beside
it.

## 4. The cost refinement the panel missed -- the Current-Region Base Register (CRBR)

The panel's strongest objection to segmentation was honest and serious: a naive scheme adds **+1
dependent DRAM read to every hot-path Object-Bind** (RT read, then ODT read), doubling the serial
memory dependency on the machine's hottest path, with no measured cost because the repo models
zero real DRAM latency. Presented that way it is a real, unhedged throughput regression.

It does not have to fall on every bind. **On domain entry (OCInvoke, which already swaps
compartment context and narrows PCC) the hardware loads the current domain's `region_odt_base`
into a single architectural register -- the CRBR -- exactly as it already loads
`veda_pcc_base/_length`.** Then:

- **Intra-domain bind (the common case):** the object's region field equals the current region,
  so the ODT base is already in the CRBR. **One DRAM read (the ODT read) -- identical to today,
  no regression.**
- **Cross-domain bind (the rarer case -- touching another domain's shared object):** the region
  field differs, so the RT is read for that region's base, then its ODT. **Two reads.**

This is not a cache and not a TLB: the CRBR holds exactly one base (the current domain's), set
**explicitly at domain entry**, never filled-on-miss, never evicted, carrying no access history. A
cross-domain access does **not** update it. So there is no history-dependent state and no timing
channel -- the same discipline that makes `veda_pcc_base` sound. The fast/slow split is decided by
the object's region field (visible in the capability), a **static, program-structural** property,
exactly like the M24 TCM tier's static Object_ID placement, which the project already treats as
determinism-safe (GhostRider: placement is compile-time, not secret-correlated).

Net cost story, honestly: **intra-domain binds have no regression; only cross-domain binds pay the
extra read** -- which is precisely where the exclusive-by-default / private-fast-shared-slower
philosophy (DESIGN_03, UPMEM precedent) already expects the cost to fall.

## 5. Pillar-by-pillar

- **Object-Centric:** strengthened -- the region *is* a domain, the model's core organizing
  concept; every access is still an Object_ID resolved through the ODT.
- **Capability-based:** unchanged -- the entry the two-step lookup produces is the same checked
  capability metadata; Tag unforgeability is untouched.
- **Address-Less:** preserved -- software still holds only Object_IDs and opaque capabilities. The
  region bits are part of the Object_ID, not an address; `region_odt_base` is a *physical* base
  that lives only inside the MSA/RT and must never be exposed to software (Section 7, a verified
  invariant, not an assumption).
- **Single Address Space:** preserved -- the split is fixed and global; a full Object_ID names the
  same object everywhere.
- **Deterministic:** preserved in **shape**, narrowed in **scope**, widened in **constant** --
  see Section 6.
- **(Proposed 6th) Provably non-speculative:** preserved -- a region or granule fault is a
  bounded, explicit, gating trap serialized at issue, never a fill-on-miss or a speculative tier.

## 6. The honest determinism re-statement

For an object whose region is resident **and** whose target ODT granule is resident (or both
locked, RTOS-style), Object-Bind is a fixed-shape O(1) operation: **one read intra-domain, a
worst-case-bounded two reads cross-domain**, data-independent in depth, no branch on secret data,
no cache, no speculation. This is a *tightening* of today's claim in the worst-case read count
(1 -> 2) and, for the common intra-domain path, **no change at all**.

What becomes best-effort -- explicitly outside the deterministic guarantee, exactly as DESIGN_06
and DESIGN_02 already pre-authorized for paging -- are two bounded, explicit fault classes:

- **REGION_FAULT** -- first touch of a non-resident domain's region; the handler pages its ODT
  base region in.
- **granule residency fault** -- a local index in a non-resident ODT granule (the existing
  DESIGN_02 residency fault, at ODT-granule scope).

Both are explicit architectural traps, never silent cache misses. We do **not** claim global
determinism, and we attach **no cycle number** to either the 2-read path or the fault penalty,
because the repo still models zero real DRAM latency (Section 8) -- the determinism claim is
**structural (fixed read-count), not yet a measured cycle bound.**

## 7. The RTOS mode -- the deterministic line as a mode, not a fork

The embedded/RTOS deployment does not need a separate ISA. Add a mode in which **all live regions
and their ODT granules are locked resident.** No region can then fault, so the fault path, though
present in the hardware, is architecturally never taken, and WCET is provable by physical
inspection. This captures the deterministic embedded line's guarantee **on one core and one
toolchain** -- a lock/pin, not a second profile with two verification targets. The Linux
deployment leaves regions pageable; the same silicon serves both.

## 8. Rejected alternatives (recorded so they are not re-litigated)

- **Strict fixed-depth two-level ODT** (a directory always walked to a page, two reads on *every*
  bind, no fast path). Rejected: it doubles read traffic forever with no offsetting win, and it
  literally builds two object-indexed DRAM arrays traversed in series, which breaks the DESIGN_02
  "exactly one indirection structure" commitment. The domain-segmented scheme with the CRBR keeps
  the common path at one read and adds only a *resident* RT that feeds the single ODT check.
- **Hardware-hashed ODT.** Rejected, and the reason is sharper than "breaks flat": even a
  bounded-probe (cuckoo/fixed-D) hash fixes the read *count* but not the read *latency* leakage --
  an Object_ID-correlated DRAM row-buffer timing channel remains, which is exactly the cache-timing
  class the cache-less pillar exists to eliminate. DESIGN_06 already named hashing rejected; this
  records *why* it stays rejected. Its one salvageable niche -- all probes in locked TCM SRAM at
  fixed latency -- is precisely the embedded regime where the bounded flat window already suffices.
- **Bounded flat ODT only** (decline axis (c), embedded-forever). Kept, but as the **RTOS mode of
  this decision** (Section 7), not as the Linux answer -- declining "huge" is the known pick-any-two
  escape, not a resolution of the trilemma for a general OS.

## 9. Honest tradeoffs and open residuals

Adopting this decision does **not** close these; they become explicit follow-on work, and several
become hard prerequisites:

- **The +1 cross-domain read is unmeasured.** The CRBR removes it from the intra-domain path, but
  the cross-domain cost, and the fault penalties, cannot be adjudicated until a real DRAM-latency
  model exists (DESIGN_04's open item). No "it is cheap enough" claim is made here.
- **The trilemma reappears, bounded, at the RT.** 2^20 domains is a hard architectural ceiling.
  It is defensible because a protection domain is heavyweight (never a per-allocation object), but
  it is a real wall with no graceful degradation short of paging the RT -- which would reintroduce
  the forbidden variable-depth walk. We accept and own the ceiling; we do not pretend it is absent.
- **Segmentation moves zero bits.** 2^20 x 512 MiB = 512 TiB, the same ceiling as the flat table.
  We buy residency granularity, not a smaller namespace; "huge" is satisfied only by never making
  the cold parts resident.
- **Cross-domain sharing is actively hurt.** A widely-shared object (a common library, a shared
  buffer) lives in one region that must stay resident whenever any sharer runs, and all sharers
  funnel through that one region's ODT, re-concentrating the DESIGN_06 MSA hot-lock per region.
  Locality helps private objects and hurts shared ones. **A shared-region residency/policy story
  is an open design item.**
- **New security surface, three parts, all must be closed:** (a) the RT and `region_odt_base` must
  be **strictly MSA-private** -- a single instruction exposing the base breaks the address-less
  pillar, so this becomes a *verified invariant*, not a stated assumption; (b) **region-grant
  authority** -- which domain may mint into which region -- is a new authority question, and a bug
  letting domain A mint into region B is a compartment-escape of the Milestone-19 class; (c) a
  stale/corrupt `region_odt_base` has **region-wide blast radius**, so the DESIGN_07 R2 per-entry
  MAC must extend to RT entries.
- **Reclamation is now a hard prerequisite, not a someday.** Under R1 SLAB-CARVE the 24-bit local
  space and the 24-bit generation fill under churn; without Cornucopia-style sweeping revocation
  (DESIGN_06, DESIGN_07 Rev-B, unstarted) a hot domain exhausts its local namespace. Widening the
  counter (increment 4) raised the ceiling; it did not remove the need to reclaim.
- **Large-object internal paging is orthogonal and still unsolved** (DESIGN_02: a 1 TiB object
  cannot fault as one unit). Under this decision it stacks as a second paging scheme beneath
  region/granule paging.
- **Formal-proof debt grows:** the RT state, the REGION_FAULT cause, and the MSA-private-RT
  invariant all expand the surface the eventual Coq/Rocq proof must cover.

## 10. The Sail experiment that validates this (next step, before RTL)

Smallest experiment that proves the mechanism is expressible and its pillar invariants hold, using
the existing bounded-window discipline so it compiles:

1. Add `veda_region_table : vector(REGION_MODELED, region_entry)` with `region_entry = {rt_valid,
   region_odt_base:bits(56), region_resident:bool, region_backing:bits(56),
   region_generation:bits(24)}`, `REGION_MODELED` tiny (e.g. 8), exactly as `veda_odt` is bounded.
2. Decompose `object_id` into `region = id[43:24]`, `local = id[23:0]`; guard `unsigned(region) >=
   REGION_MODELED` as OBJECT_NOT_FOUND before touching the RT, mirroring the existing out-of-range
   guard.
3. Make `odt_lookup` two-step with the CRBR: if `region == current_region` use the CRBR base (one
   read); else read `RT[region]`, and if `!region_resident` raise a new **VEDA_CAUSE_REGION_FAULT**
   (bounded explicit trap, sibling of the DESIGN_02 residency fault); then index the region's ODT
   by `local`, faulting on a non-resident granule.
4. Machine-check three invariants as property tests: (i) `{region=A,local=k}` and
   `{region=B,local=k}` resolve to **different** entries (single-address-space); (ii) the resident
   hot path performs a **fixed** read count with no data-dependent branch on secret data
   (fixed-shape); (iii) a region fault is raised as an **explicit architectural trap**, never a
   silent lookup miss (cache-less). Reuse the increment-4 `generation = 0xFFFFFE` injection style
   to test `region_generation` retirement.

Success = the property tests pass and the model compiles under the bounded windows, proving
region-table + per-region ODT + region-fault + CRBR are expressible with the pillar invariants
machine-checked -- exactly the "design doc + Sail experiment" DESIGN_06 asked for.
