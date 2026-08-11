# DESIGN 06 -- Build Order, Interrupt Architecture, and the Honestly-Open Questions

**Status:** Design proposal + honest risk register.

## Build order (dependency-sequenced)

1. **Capability format respec (DESIGN_01)** -- widen the separate CRF (256-bit), add
   CAndPerm, widen ODT entry. Sail types -> RTL -> re-pass 63/51/49. *Nothing downstream
   is well-defined until objects, IDs, and generation are Linux-scale.*
2. **ODT as unified mm (DESIGN_02)** -- residency/COW/backing fields, MSA fault paths.
   Sail-first, mutation-tested.
3. **Interrupt + timer architecture (below)** -- prerequisite even for UP preemptive
   Linux.
4. **Pipeline (DESIGN_04)** -- keep ACT4 51/51; add CRF hazard/forwarding.
5. **Multi-hart (DESIGN_03)** -- shared ODT, shared-bind mode, real aq/rl, MSA
   serialization; promote M12 injection tests to real 2-hart tests.
6. **Purecap toolchain (DESIGN_05 Part A)** -- pointer=capability; libc under M19.
7. **OS model (DESIGN_05 Part C)** -- domains, object-COW fork, object paging, preemptive
   scheduler.
8. **Linux ABI port** -- UP nommu first, then MMU-less SMP, then full semantics.

Steps 1-5 are hardware (verified-discipline territory); 6-8 are the long software tail.

## Interrupt / timer architecture (Veda-native, not a bolted-on CLINT/PLIC)

Linux needs a timer (preemption) and device interrupts. Today RTL has *no* interrupt
wiring; Sail borrows the base-model timer. Decision, grounded in the project's own
EMERGENCY_HANDLING_DESIGN_REVIEW:

- **A single non-nestable NMI-class timer + a small interrupt set**, entering through the
  trusted switcher with a **fresh minimal capability context** (Tag=0 CRF) -- the
  emergency-handling doc's one genuinely-novel decision. This gives confused-deputy-free
  interrupt entry.
- **PCC auto-reset on trap (M21) already applies to interrupts** (timer-interrupt
  PCC-reset is verified in Sail) -- the interrupt path composes with compartments for
  free.
- **Object-based interrupt routing:** an interrupt source is bound to a handler *domain*
  via a capability, not a raw vector table -- the object-centric analog of a PLIC. (Design
  sketch; not yet detailed.)

## THE genuinely-open question -- the ODT scale/flat/deterministic trilemma

A single ODT cannot be simultaneously (a) **flat** (O(1), determinism pillar),
(b) **resident & cache-less** (no cache pillar), and (c) **huge** (millions of live
objects for a whole OS). Pick-any-two is the tension.

**Leading candidate: segmented Object_ID.** Split `Object_ID` = { region (top bits),
local (low bits) }. The resident ODT is flat *per active region*; inactive regions live
in a backing object store and fault in (DESIGN_02 residency, applied to the ODT itself).
This keeps flat-per-region O(1) lookups (determinism for the active working set) and
cache-less semantics (a region is resident or it faults -- no speculative cache tier),
while scaling the total namespace. Cost: a region fault is a bounded, explicit event
(not a silent cache miss), which fits the deterministic-for-resident scoping.

**This is the next big radical decision and is NOT claimed solved.** Alternatives to
weigh: a hardware-hashed ODT (breaks flat/determinism), a two-level ODT (Intel-432's
choice -- but 432 needed it for on-chip storage, a constraint Veda's DRAM-resident ODT
does not share), or accepting a bounded global object count (embedded-only, not general
Linux). Segmented-ID is my recommendation; it needs its own design doc + Sail experiment.

**RESOLVED (2026-08-11) in DESIGN_08.** The decision is domain-segmented Object_ID:
`{region:20, local:24}` where **region = a protection domain** (not an arbitrary bit-split).
The count explosion (R1 SLAB-CARVE) lands in the demand-paged 24-bit local dimension and never
touches the resident, flat 20-bit region count -- the bounded thing (domains) stays resident,
the unbounded thing (objects) pages. A Current-Region Base Register loaded at domain entry keeps
intra-domain binds at one read (no regression); only cross-domain binds pay the extra RT read.
Determinism is preserved in shape and re-scoped to resident regions; the RTOS line becomes a
lock-resident mode of the same core, not a separate profile. See DESIGN_08 for the full decision,
rejected alternatives, honest tradeoffs, and the validating Sail experiment.

## Other honest open questions

- **Determinism scope:** must be re-stated as "deterministic check path + resident/locked
  objects; best-effort for paged objects." Paging and DRAM latency are non-deterministic
  by nature. Do not overclaim.
- **Object reclamation / revocation at OS scale:** continuous churn needs Cornucopia-
  style sweeping revocation to bound generation/ID pressure (DESIGN_01). Unstarted.
- **S-mode: keep or fold into ODA-possession?** (DESIGN_05 Part B.) Undecided.
- **Large-object internal paging:** a 1 TiB object cannot fault as a unit; may need a
  per-object residency bitmap -- a page-like concept *inside* an object. (DESIGN_02.)
- **MSA as global serialization point** can bottleneck on a hot shared object; per-object
  serialization helps but a single hot lock is still hot (physics, not fixable by the
  model). (DESIGN_03.)
- **Formal proof debt:** the Coq/Rocq export exists but no theorem is proven; the core
  "Tag=0 => no write" property is still unproven. Grows with every mechanism added here.
- **Effort calibration:** CheriBSD = 13 years, 1800+ commits, GBP 190M, for a *less*
  radical (address-based) change. This is a multi-year, eventually team-scale program.
  Realistic single-person+AI reach: steps 1-4 and a UP nommu purecap boot -- which would
  itself be a world-first (Linux-class kernel on an address-less ISA).

## What is genuinely believable

None of the eight decisions requires abandoning a pillar; each extends a verified
mechanism. The apparent Linux-vs-Veda contradiction dissolves under the SASOS reframe
(DESIGN_00). The remaining risk is scale and effort, not feasibility-in-principle -- with
one real caveat, the ODT trilemma, which is the next decision to take.
