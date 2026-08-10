# DESIGN 03 -- Multi-Hart: Object-Granular Coherence with No Coherence Protocol

**Status:** Design proposal. **Builds on:** owner-hart ODT enforcement (M12,
exclusive-by-default), Veda-Atomic (9 ops), the MSA serialization point, the cache-less
pillar, the aq/rl safety analysis (which already flagged multi-hart as the reopening
condition). **Verification plan:** the M12 owner-hart *injection* tests become real
2-hart tests; Sail multi-hart mode; then multi-core RTL.

## Problem

Linux is SMP-first: kernel data (runqueues, dcache, locks, RCU) is shared and mutated
concurrently across harts. Veda-Core today is single-hart, aq/rl are no-ops, and binding
is exclusive-by-default (the opposite of shared kernel state).

## The insight that makes this *easier* than a normal SMP machine

Conventional SMP is hard because of **caches**: each core caches lines, so you need a
coherence protocol (MESI/MOESI, snooping/directory) to stop stale copies. **Veda-Core
is cache-less by pillar.** Therefore:

> There are no private cached copies, so there is no incoherence, so **there is no
> coherence protocol to build.** Two harts reading/writing a shared object via
> OCL.D/OCS.D go straight to DRAM/MSA -- naturally coherent.

The only two things left for correct SMP are **atomicity** (read-modify-write) and
**ordering** (fences). Both are memory-side concerns, and Veda-Core already puts
compute/atomics at the MSA.

## Decision -- coherence unit = the object; the MSA is the serialization point

1. **Data coherence: free.** Plain OCL.D/OCS.D to shared objects are coherent by
   construction (no caches). No snoop, no directory, no MESI.
2. **Atomicity: MSA-serialized.** Veda-Atomic / NMC RMW to a shared object are executed
   *at the MSA* (already the design), which serializes concurrent RMW to the same object.
   The object is the granule of atomic serialization.
3. **Ordering: give aq/rl real semantics.** The bits are already decoded (ATOMIC_AQRL
   analysis). Implement them as real acquire/release fences on the issuing hart. This is
   the exact requirement that analysis named for multi-hart.
4. **Binding policy: exclusive-by-default stays; add a `shared` bind mode.** Private
   objects keep owner-hart exclusivity (UPMEM precedent: architect contention away).
   Kernel shared structures are bound with a new **shared** mode (owner_hart =
   VEDA_OWNER_SHARED sentinel) that permits concurrent multi-hart binding; those objects
   rely on (2)+(3) for correctness.

## Why exclusive-default + shared-mode is right, not a hack

Most memory is genuinely private (stacks, per-task state, per-CPU data -- Linux itself
uses per-CPU variables precisely to *avoid* sharing). Keeping those exclusive gives the
verifier a strong default (no races possible) and matches UPMEM's measured 93x win on
workloads that avoid cross-unit sync. Only the deliberately-shared minority pays the
serialized-atomic cost -- which is exactly where Linux already expects contention.

## Bootstrapping SMP incrementally

- **Phase 1:** real 2-hart RTL, shared ODT with owner-hart already enforced (M12 logic),
  `shared` mode, real aq/rl. Turn the M12 injection tests into genuine concurrent tests.
- **Phase 2:** UP (single-CPU) Linux first -- needs only preemption (timer interrupt,
  see DESIGN_06 interrupt architecture), not SMP.
- **Phase 3:** SMP Linux -- kernel shared structures use `shared` objects + MSA atomics.

## Honest open items

- **MSA as global serialization point can bottleneck** under heavy shared-atomic
  traffic. Mitigation: per-object (not global) serialization at the MSA -- the object
  granule helps here. Contention on a *single hot* shared object (e.g. a global lock) is
  still a bottleneck -- the same physics as any machine; the object model does not
  magically fix a hot lock.
- **RVWMO alignment:** define Veda's memory model per-object and prove aq/rl give the
  ordering Linux's `smp_*` barriers assume. Non-trivial; needs a formal memory-model pass.
- **Cross-hart TCM contention** (NordSec 2025, 68 kbps covert channel) applies once TCM
  is shared -- keep TCM per-hart-private or statically time-partitioned (already flagged
  in TCM_FAST_PATH_DESIGN).
- **DMA/devices** are additional "harts" touching shared objects -- see DESIGN_05 IO-ODT.
