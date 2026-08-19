# ROADMAP -- From the Verified Single-Cycle Core to a Pipelined, Multi-Hart, Throughput-Capable, Linux-Facing Veda-Core

**Status:** Living plan, grounded 2026-08-11. Every factual claim below was extracted from a
complete read of the verified line's own documents (NEXT_STEPS_ROADMAP.md, VEDA_CORE_SPEC.md,
TCM_FAST_PATH_DESIGN.md, DRAM_TCM_LATENCY_STUDY.md, SYNTHESIS_CRITICAL_PATH_STUDY.md,
SCALING_BARRIERS_RESEARCH.md, OBJECT_CENTRIC_VS_TRADITIONAL_BENCHMARK.md,
CRF_ARCHITECTURE_ALIGNMENT_VERDICT.md, ATOMIC_AQRL_SAFETY_ANALYSIS.md,
DESIGN_SOUL_AND_UNIQUENESS.md, MINIMAL_OS_KERNEL_DESIGN.md, and rtl/veda_core.tlv itself) --
not from memory. The design decisions this plan sequences are `design/DESIGN_00..06`.

**Two-line thesis:** The verified line proved the security architecture (Sail through M22 +
OS-kernel milestones, RTL through M25 + ecall/syscall0 mirrors, ACT4 51/51 on veda_core.tlv
itself, toolchain through M17+). What it deliberately did not build is speed and concurrency:
zero real memory latency outside M24's parameter, one hart, one pipeline stage. This line
builds exactly that, without giving up a pillar.

---

## Workspace rules (fixed 2026-08-11)

- `~/makerchip/rva23-core` -- the deterministic embedded line. **Frozen: no file
  modifications from this line's sessions.** Read-only reference (docs, spec, toolchain
  binaries, test corpora) is allowed and expected.
- `~/veda-core` (this repo, `veda-core-linux` remote) -- design source of truth for the new
  line. Implementation repos cite these docs, never the reverse.
- Future pipelined-RTL work happens in a **fresh clone** of the `Veda-Core` repo on a
  `linux-core` branch -- never in the frozen working tree.
- Verification gates carried over unchanged: Sail-first, mutation-tested, zero-regression
  trio (Sail self-check + RTL smoke + ACT4 51/51), one tag across repos per closed milestone.

---

## Phase sequence (dependency-ordered, from DESIGN_06)

### Phase 1 -- Capability format respec (DESIGN_01) -- COMPLETE (Sail layer), 2026-08-11

All four capability-format walls plus the retirement wall are removed in behaviour, and the
last open architectural question -- the ODT scale/flat/deterministic trilemma -- is decided
(DESIGN_08) and validated in Sail. Increments 1-4 (CAndPerm, 256-bit format, ODT/populate/PCC
widen, generation widen) each built and mutation-tested; the DESIGN_08 domain-segmented
Object_ID mechanism (region table + CRBR + region fault) is expressed and its three invariants
machine-checked, all at 72/72 self-check with zero regressions. What remains before Phase 1 can
be called fully closed is the RTL mirror of this Sail work (Phase 1 was Sail-first by design)
and the DESIGN_08 Section-9 open items (a DRAM cost model to measure the cross-domain read,
shared-region residency policy, MSA-private-RT as a verified invariant, region-grant authority,
RT-entry MAC, and reclamation), which are follow-on work, not gaps in the decided mechanism.


**Increment 1 (2026-08-11): CAndPerm -- DONE, verified in Sail.** funct7 `0b0010111`
(chosen after a full enumeration of the Custom-2/funct3=001 space), OCA idiom, monotonic
clear-only, sealed/untagged source soft-fails. **67/67 self-check tests pass** (65-test
verified baseline with zero regressions + 2 new), and both new tests were **mutation-tested**
(mask-ignored and seal-check-dropped mutants each killed exactly the intended test). Work in
`Veda-Core-sail-riscv` branch `phase1-respec`; tests + results doc in `veda-core-sindhu`
(`veda-core/PHASE1_SAIL_RESPEC_CANDPERM_RESULTS.md`). Baseline was established on a freshly
built simulator *before* the change, so the result is attributable.

**Increment 2 (2026-08-11): the 256-bit capability format -- DONE, verified in Sail.**
Object_ID 44 / Base 56 / Length 40 / Offset 40 / Perms 16 / otype 16 / generation 24 / flags
20 = 256 exactly (no pad bit; pack/unpack re-derived field-by-field). All four spec-level
walls removed in the format. **69/69 self-check tests pass.** Two decisions overrode earlier
design text and are recorded in DESIGN_01: the **tag granule widened 16 -> 32 bytes** (a
16-byte granule would have let a plain store rewrite the half of a stored capability holding
Perms/otype/generation while its tag survived -- a forgery primitive), and **Ext_Veda is now
RV64-only** (56-bit Base cannot be zero-extended into a 32-bit register; there is no RV32
Veda-Core under any Linux-scale format). Also: 32-byte alignment for OCL.C/OCS.C as a hard
trap, an otype representability guard closing a reintroduced sentinel-forgery path, and a
bounded ODT index window. ODT entry and PCC deliberately stay narrow (lossless zero-extend /
truncate bridges) so the atomic change stayed as small as possible. Results:
`veda-core/PHASE1_SAIL_RESPEC_256BIT_RESULTS.md`.

**Increment 3 (2026-08-11): widen the ODT entry, populate, and PCC -- DONE, verified in Sail.**
`odt_entry.Base` 32->56, `odt_entry.Length` 16->40, `veda_attr` 32->64 (Length[55:16] |
Perms[15:0], backward-compatible by construction), PCC/mepcc base->56 / length->40,
`VEDA_PCC_UNBOUNDED` 0xFFFF->0xFFFFFFFFFF. **This is where the 4 GiB and 64 KiB walls actually
fall in behaviour** (increment 2 removed them only in the format). Plain `populate` stays the
compact single-GPR form (existing programs unchanged); `populate.fast` is now the wide path.
**70/70 self-check** -- incl. a new `vc_large_object` test (128 KiB object, access beyond the
old 64 KiB limit, bound still enforced at the new limit). Generation deliberately stays 8 bits
(deferred: widening it makes the `vc_gen_retire` saturation loops infeasible -- needs its own
increment + a non-looping test strategy). The sentinel width change broke 16 compartment tests;
all diagnosed against the running sim by 16 parallel agents under a "report a real bug rather
than invent a fix" rule -- **zero real bugs**, all the documented semantic change, corpus
independently re-verified 70/70. Surfaced a real design wart (returning to unbounded PCC now
needs a synthesised max-length object; the compact descriptor can't express the sentinel) --
recorded in DESIGN_01 as an open question (should OCRETURN restore saved bounds?), flagged not
fixed. Results: `veda-core/PHASE1_SAIL_RESPEC_ODT_WIDEN_RESULTS.md`.

**Increment 4 (2026-08-11): widen the generation counter -- DONE, verified in Sail.**
`odt_entry.generation` 8 -> 24, matching the capability field, so the last narrow-to-wide bridge
is gone (Bind and the dereference recheck copy/compare directly). The **retirement ceiling moves
from 255 reuses per slot to ~16.7M** -- the fifth and final width wall. **70/70 self-check.**
The real problem this increment solved was not the width swap but **how to test a threshold too
large to loop to**: the old negative test used `.rept 256`, and `.rept 16777216` is not a test.
Answer: **direct ODT-state injection near the boundary** -- a reset seed (Object_ID 55) at
`generation = 0xFFFFFE`, one below the real threshold, so two destroys cross the genuine
saturate-then-retire transition at the **true 24-bit constant** rather than a reduced stand-in.
This is the project's own established technique (every seeded object is written directly at
reset; the RTL uses the same injection for owner-hart tests it cannot otherwise drive). The
positive test was unaffected (5 re-populates, nowhere near any threshold). Results:
`veda-core/PHASE1_SAIL_RESPEC_GENERATION_RESULTS.md`.

**Phase 1 status: the capability format and the ODT entry are now width-consistent** -- all four
format walls plus the retirement wall are removed in behaviour. **Next: the ODT index window /
segmented-Object_ID (DESIGN_06)** -- the 44-bit namespace is expressible and backable per-entry,
but the modeled table is still a bounded flat window, so ids above it read as not-found. That is
the trilemma decision (flat vs resident vs huge), and it is the last piece before Phase 1 can be
called closed. Note also that widening generation raises the reuse ceiling but does not remove
the need for **sweeping revocation** (DESIGN_06) under truly unbounded churn.


The current 128-bit format cannot express Linux-scale anything: Length 16b caps objects at
64 KiB, Base 32b caps physical memory at 4 GiB, Object_ID 23b caps live objects at 8.4M,
generation 8b retires a slot after 255 reuses (the RTL already had to add a `retired` flag
because the 8-bit counter empirically wrapped into a real ABA use-after-free).

- Widen the **separate** CRF to 256 bits (ID 44 / Base 56 / Length 40 / Offset 40 / Perms 16
  / otype 16 / gen 24 / flags 20). The separate-CRF verdict (kept 16/separate) is what makes
  this cheap -- the 64-bit GPR datapath is untouched. 192-bit fallback documented in DESIGN_01.
- Add **CAndPerm** (monotonic per-holder rights attenuation) -- prerequisite for read-only
  sharing without Object_ID aliasing, which fork/COW (Phase 2) depends on.
- Blast radius (from DESIGN_01 + tlv read): Sail `veda_types.sail` widths, every CGet*,
  OCL.C/OCS.C pack/unpack (capability becomes 32 bytes -- tag granule decision needed), ODT
  entry layout (16B entries widen; the low-8-bit index aliasing fixed in M15 must not
  regress), RTL `/vreg` fields, GDB stub.
- Gate: full trio re-pass. ACT4 should be untouched (GPR datapath unchanged) -- verify, not assume.

### Phase 2 -- ODT as the unified memory manager (DESIGN_02) + the trilemma decision

- Add `resident` / `cow` / `backing` to ODT entries; residency faults and COW faults as new
  MSA-mediated causes reusing the verified trap machinery. No page tables, no TLB, no satp:
  the ODT *is* the mm. fork = CAndPerm-attenuated sharing + COW-on-write mint; mmap(file) =
  object whose backing is the file.
- **Take the ODT scale/flat/deterministic trilemma decision** (DESIGN_06's one genuinely
  open architectural question). Leading candidate: segmented Object_ID (flat-per-region
  resident ODT, region faults as explicit bounded events). Needs its own design doc + a Sail
  experiment before any RTL. This is the next radical decision of the project.
- Determinism re-scope, stated honestly: deterministic = check path + resident/locked
  objects; paged objects are best-effort. WCET story updated accordingly.
- Gate: Sail residency/COW corpus (positive + negative + mutation), then RTL mirror.

### Phase 3 -- Interrupt + timer architecture (DESIGN_06)

Prerequisite for any preemptive OS work, and deliberately Veda-native (no bolted-on
CLINT/PLIC): single non-nestable NMI-class timer + small interrupt set, entering via the
trusted switcher with a fresh minimal capability context (Tag=0 CRF) per the
EMERGENCY_HANDLING design (2-3 cycle bounded capture target; CV32RT's real best is 6).
M21's PCC-reset-on-trap already composes with interrupts (verified in Sail for the timer).
Object-based interrupt routing (source bound to handler domain by capability) replaces the
vector table. RTL today has zero interrupt wiring -- this is new RTL, Sail-first.

### Phase 4 -- Pipeline the core (DESIGN_04)

Strategy fixed by DESIGN_04: **pipeline the RVA23 base first, re-pass ACT4 51/51, then layer
the Veda checks, re-pass the full smoke corpus.** De-risked by the synthesis study: the full
5-check chain + address calc is 95 gate levels vs 114 for a plain load -- checks are parallel
to address calc, not the critical path.

Known RTL realities the re-staging must handle (from the complete veda_core.tlv read):

- Everything lives in one TL-Verilog stage @0 with `>>1` state self-references; SandPiper's
  order-independent elaboration currently permits forward references that only work within
  one stage -- signal-per-stage assignment is a real redesign, not a mechanical move.
- Six trailing raw `\SV` always_ff blocks (stores, NMC/atomic RMW, ODT writes, owner-claim,
  OCS.C) reference SandPiper's mangled @0 signal names directly; each must be re-homed (or
  converted to TLV) when its signals move stage.
- The "force $instr to NOP suppresses every write path" argument is only valid single-cycle;
  in a pipeline it becomes per-stage squash/bubble logic, and the trap mutual-exclusivity
  proofs must be re-established per stage.
- Object-Bind becomes a **capability-load micro-op** in MEM (may stall: DRAM latency /
  residency fault); the M24 stall FSM is the seed of the general memory-stall path. CRF
  scoreboard + forwarding for bind-use and manipulate-family RAW hazards.
- PCC fetch-bounds check moves to IF (it is already an unconditional every-cycle check);
  precise capability exceptions in MEM (Linux COW/paging needs precise faults, Phase 2).
- The many free simultaneous combinational read ports (elfmem, odt_mem x2, tag_mem,
  tcm_scratch) become real ported memories -- part of the real memory system below.
- Test-budget reality: 46+ smoke tests carry repeat(N) budgets as tight as repeat(12);
  latency/pipelining changes require the named mechanical budget-widening pass.
- Gate: ACT4 51/51 on the pipelined base, then the full Veda smoke corpus, then (new) a
  synthesis re-run of the staged check path to confirm the 95<114 margin holds per-stage.

### Phase 5 -- Throughput memory system (DESIGN_08 -- to be authored next)

The spec's own admitted #1 open problem: no designed mechanism hides DRAM payload latency
(hidden today by DRAM_EXTRA_CYCLES=0 and the deliberately narrow M24 stall scope -- ordinary
ld/sd and OCL.D/OCS.D are still unmodeled). The honest numbers that frame this: rebind churn
costs 11+(7+E)xN cycles (E*N linear); M24's TCM tier zeroes it up to 17 hot objects and
degrades gracefully to 1.795x at k=32 (vs 4.057x undefended); bind-once-reuse is +10 cycles
fixed. DESIGN_07 will specify:

- **MSA object-granular prefetch/streaming**: at Object-Bind the MSA knows Base+Length and
  may burst-read the object into an on-chip object buffer -- deterministic, bind-triggered,
  never access-history-adaptive (GhostRider constraint already adopted by M24), so no
  cache-timing channel is reintroduced. This converts the object model's bind-time knowledge
  into the throughput answer, instead of importing a cache hierarchy.
- Real latency modeling for ALL memory traffic (extending M24's FSM scope), with the
  budget-widening pass, then flipping the committed default to E>0 so every future number is
  honest by default.
- TCM tiers formalized (ODT tier + spill scratch + scheduler save areas), per-hart-private
  by construction ahead of Phase 6.
- Sub-object residency (per-object bitmap) for large objects -- required once Length is 40b
  (a 1 TiB object cannot fault or prefetch as one unit); DESIGN_02's flagged open item.
- Compose the k-sweep x latency numbers into one honest before/after table (the named
  "single most valuable next step" from the verdict addendum, still undone).
- DMA/row-buffer notes: object = spatial-locality unit; streaming exploits DRAM row buffers
  deterministically.

### Phase 6 -- Multi-hart (DESIGN_03)

Named by the verified line as "the single largest undertaking on this list." The insight
that keeps it tractable: cache-less means **no coherence protocol exists to build** -- only
atomicity (MSA-serialized per object) and ordering (real aq/rl) remain.

- 2-hart RTL instantiation: MHARTID localparam becomes a real per-instance parameter; shared
  ODT with real arbitration (the owner-hart logic M12 built is ready but was only ever
  verified by state injection -- promote to genuine concurrent tests).
- `shared` bind mode (VEDA_OWNER_SHARED sentinel) for deliberately-shared kernel objects;
  exclusive-by-default stays (UPMEM precedent: 93x on partition-friendly workloads).
- **aq/rl get real semantics** -- the AQRL analysis's explicitly reopened hard prerequisite:
  either genuine acquire/release fences or a stated, tested decision for unconditional SC.
  FENCE stops being a functional NOP. A Veda memory-model statement (per-object) aligned
  with what Linux's smp_* barriers assume -- needs a real memory-model pass.
- Veda-Atomic atomicity today is a free artifact of single-cycle execution -- in a pipelined
  multi-hart core it becomes an explicit MSA serialization mechanism (per-object, not one
  global lock: LazyPIM's measured 87.9%-blocked warning against coarse global locks).
- TCM goes per-hart-private banks (or a statically time-partitioned arbiter, HPCA 2014)
  before any multi-hart security claim -- the 68 kbps NordSec contention channel is the
  recorded reason.
- Sail's single-process simulator cannot execute two harts -- the verification harness
  itself is part of this phase's work (multi-hart Sail mode or a credible RTL-level
  concurrent testbench).

### Phase 7 -- Purecap toolchain (DESIGN_05 Part A)

pointer = capability (the audit proved shadow schemes hit a structural ceiling): CRF calling
convention, sizeof(void*)=32, uintptr_t = capability, capability-aware varargs/memcpy/union
handling, generalizing the already-verified globals cap-table pattern to all pointer
storage. Calibration stated honestly: this is the CHERI-LLVM multi-year road; CheriBSD is
the proof it terminates.

### Phase 8 -- OS model (DESIGN_05 Part C)

Domains (sentry + TSC + cap-table + CRF), preemptive scheduler on Phase 3's timer +
capability-context save/restore, object-COW fork, object paging, syscalls through the
verified switcher (kernel = ODA holder), IO-ODT for devices/DMA (object-based IOMMU).

### Phase 9 -- Linux ABI port

> **OPEN DECISION, 2026-08-13:** "Linux ABI port" is used in this corpus to mean two different
> projects -- the literal Linux kernel ported, or our own kernel exposing a Linux-compatible syscall
> surface -- and four documents word it four different ways. The difference is multi-year effort,
> what software can run, and where this architecture's confused-deputy property survives. See
> DESIGN_06, "OPEN DECISION". **Until it is settled, no document should claim Linux applications
> run.**

UP nommu first, then SMP. Sequenced last deliberately; per DESIGN_06's calibration, a
realistic single-person+AI horizon is Phases 1-5 plus a UP nommu purecap boot -- itself a
world-first for an address-less ISA.

---

## Security & robustness hardening (DESIGN_07 -- adversarially derived, done 2026-08-11)

DESIGN_07 red-teamed DESIGN_00-06 across 6 attack surfaces and verified every finding against
the real files. Adopted radical decisions, attached to the phases above:

- **Phase 1-2** (highest-leverage, close real *present* logical gaps by construction): **R1
  object-granular allocation** (SLAB-CARVE child Object_IDs -> closes the dominant intra-slab
  UAF class), **Rev-A selective revocation** (per-object epoch/delegation vector), **Rev-B
  sweeping revocation** (hardware sweep engine; the concrete form of DESIGN_06's Cornucopia
  item, must include the CRF in scope), **Rev-E range-gate all capability memory paths +
  validate ODT-Populate Base**. All co-depend on the 44-bit ID / 256-bit format.
- **Phase 1 (also) + Phase 7**: **R9 CRF entry-count under purecap** -- the frozen verdict's
  16-entry §2 rationale (object-handle pressure, cheap re-Bind) does NOT transfer to purecap
  (Bind does not restore a pointer's Offset), but 16 is NOT shown insufficient (overflow spills
  bounded TCM-tier via OCS.C/OCL.C; CHERI's 32 is ISA congruence, not a pressure bar). Action:
  reserve the already-5-bit-shaped index pad bits + close the Sail/RTL decode divergence in the
  Phase-1 respec (cheap, but the bits are decided now, not deferrable); a Phase-7 purecap
  spill-traffic study decides 16-vs-32 -- not an a-priori widening.
- **Phase 4**: **R5 provably-non-speculative capability enforcement** -- a new 6th pillar,
  landed as a DESIGN_04 pipeline contract *before* Phase 4 RTL (the check gates access, not a
  post-hoc trap; capability micro-ops serialize at issue).
- **Phase 6 multi-hart reopening checklist**: **R3** per-object MSA transaction (recheck+access
  indivisible -> closes cross-hart TOCTOU), **R4** Integrity Manager returns as MSA witness,
  **Rev-C** real aq/rl or SC-by-default, **Rev-D** atomic ODT compare-and-set claim.
- **Phase 3 / boot**: **R7** hardware root-of-trust + measured boot (replaces the `initial`
  ODT-seed scaffold), **Rev-F** attestable lifecycle measurement.
- **Phase 8 IO**: **R8** object-based IOMMU (interconnect carries Object_IDs, MSA is the sole
  DRAM reference monitor) -- specify before any second bus master / DMA.
- **Silicon-realization phase (T3 physical-fault hardening, explicitly optional)**: **R6**
  dual-rail fail-closed check enforcement, **R6b** tag ECC/parity, **R2** per-entry ODT
  integrity MAC.

Two findings rejected on verification (recorded so they are not re-raised): ODT-region is
already isolated from base-ISA stores by construction; TCM static placement already covers the
same-hart cross-compartment case (no flush needed).

## Hardening found by BUILDING it -- R10..R43, and why this section exists

**The section above records the 2026-08-11 red-team pass, which reasoned over DESIGN_00-06 and
produced R1..R9 plus Rev-A..Rev-F. It is intact and still correct. It is also only a third of the
register.** Implementing the design produced **fifty-four more findings, R10 through R69**, and they
are a different kind: the red-team pass found things by *reading the design*, while these were found
by *running the two layers against each other* and by adversarially attacking what had just been
built. Several were exploitable. **None of them could have been predicted from the documents alone**,
which is the argument for keeping the Sail model and the RTL as two independently-written layers with
a differential harness between them.

**All sixty-nine live in `design/DESIGN_07_ROBUSTNESS_AND_SECURITY_HARDENING.md`, which now runs
R1..R69 with no gaps, re-audited 2026-08-19.** A register-integrity audit on 2026-08-18 found four numbers with no entry --
R18, R25, R27, R28 -- and **three of them were shipped, verified hardware fixes**, two of exploitable
class, invisible because they had landed under a parallel `RTL-n` numbering or been co-committed under
another finding's heading. They are entered now.

**The shape of what implementation found, as a class** -- worth stating because it predicts where the
next ones will be:

- **Fail-open where the model is fail-closed.** The Sail model refuses unallocated encodings by
  construction; the RTL had no such mechanism and executed them (R30), returned zero for undefined
  CSRs (R32), and ignored reserved-zero fields (R30(b)).
- **A refusal raised, and the effect happening anyway.** R21 and R28 are the same shape: the trap
  fired and the write landed.
- **Permissions that exist, are attenuable, are reported attenuated, and govern nothing.** R40 --
  `PERM_LOAD_CAPABILITY` and `PERM_STORE_CAPABILITY` were never read by any check, so a delegation
  attenuated to *data only* could lift a live capability out of the bytes it was allowed to read.
- **Arithmetic the model cannot express.** R18 -- the bounds check wrapped at 64 bits; Sail's
  `unsigned()` is arbitrary-precision and could not have the bug.
- **A justification that expired without anything sending a reader back to it.** R36 -- the custom
  privilege-drop instruction was justified by "this core has no trap to return from", and Milestone 9
  built the traps twenty-seven milestones before anyone re-read the sentence.
- **A test that names a weakness and then pins it as the contract.** Three separate times this pass:
  R27's CSR test, `vc_check_order.S` PHASE D, and `vc_ocl_ocs_c.S`, each green while demonstrating the
  gap it was written to exercise.

**Still open, honestly** (both entered in DESIGN_07 rather than left in a task list): **R42** --
`PERM_GLOBAL` and `PERM_STORE_LOCAL_CAPABILITY` are allocated and enforced by neither layer; they need
a local-vs-global capability distinction this architecture does not have, and the specification's
cause table now says "Allocated, NOT enforced" rather than claiming Active. **R43** -- `Rebind` does
not enforce the "already-bound" precondition its own specification describes.

**Phase 2 status, measured.** `resident`, `cow`, the residency and copy-on-write faults, the
page-out/page-in pair, the per-object bind gate and the segmented-Object_ID trilemma decision
(DESIGN_08) are all built and mirrored on both layers. **Phase 2's last item, `backing`, is now DECIDED AGAINST rather than
unbuilt** (DESIGN_07 R64, from a 19-agent adversarial design pass). The ODT entry carries
`valid`/`generation`/`owner_hart`/`retired`/`resident`/`owner_domain`/`cow` and will carry no
`backing`: there is no instruction that reads an ODT field into a GPR at all, so a stored `backing`
would be write-only storage -- exactly what `region_backing` has been for five increments. The
prerequisite DESIGN_02 named and said belongs FIRST was built instead: **CSR `0x7C9`
`veda_mfaultobj`**, the bind-side fault-identification channel. `mmap(file)` accordingly still has no
mechanism, and R64 records the reopening condition and the three residuals rather than leaving the
gap silent. Phase 2's stated
gate -- "Sail residency/COW corpus (positive + negative + mutation), then RTL mirror" -- is met.

**Reproducing all of it is one command**: `veda-core/verification.sh` in the implementation repo. It
runs the Sail self-check suite, the RTL milestone suite, the ACT4 conformance suite and the
cross-layer differential suite. As of 2026-08-19: **120/120, 109/109, 51/51, 25/25**, and it now ends
with an explicit verdict line.

**Read that command's history before trusting any earlier number.** Until R46 it **could not fail**:
it captured each suite's output into a variable and never read an exit code. It was measured exiting
0 while printing `Cross-layer diff : 0/21 as expected` -- the 21 differential probes had not run at
all, because `difftest/rundiff.sh` took `iverilog` from the caller's ambient `PATH` while both of its
sibling runners self-activate conda. The exit code is now the verdict, plus a guard the exit code
cannot give: every suite must report a **nonzero total**.

## Immediate next actions (in order)

1. **DESIGN_08_THROUGHPUT_AND_MEMORY_SYSTEM.md** -- the MSA object-prefetch/streaming design
   (Phase 5's spec), quantified against the E*N / k-sweep numbers above.
2. **Segmented-Object_ID design doc + Sail experiment** -- the trilemma decision (Phase 2
   gate; DESIGN_01's ID-width choice wants this settled before freezing 44 bits, and now also
   carries R1/Rev-A/Rev-B ODT-entry field additions).
3. **Phase 1 Sail work begins** in a `Veda-Core-sail-riscv` branch: veda_types.sail respec
   behind a build-time switch (256-bit format + CAndPerm + R1 carve mode + Rev-A epoch
   vector), self-check corpus re-pass.
   **R47 changed what item 2 and the R1 carve mode owe.** The R1 design pass could not recommend its
   deletion-shaped Variant S because *"it needs an ODA-scoping design that does not exist"*. It
   exists now, built and verified on both layers: Populate is contained inside the minter's own
   window, so carving a child inside a parent arena is what Populate already does -- hold an ODA
   whose window **is** the arena. What R1 still owes is the **namespace** half (per-element
   Object_IDs and where they come from), not the **authority** half. See DESIGN_07 R47.
4. RTL `linux-core` clone is created only when Phase 1 Sail is green -- Sail-first, as always.

## Standing constraints (from the verified line's own docs)

- No competitor-comparison framing in outward-facing text; 1970s lineage (Plessey 250,
  Cambridge CAP) is welcome. ASCII `--` only. No Co-Authored-By trailers.
- Hardware-first: if hardware can close a gap by construction, it gets priority.
- Do not overclaim: no blanket side-channel-immunity claims (ODT-path-scoped only), no
  "standardization-soon" framing, determinism claims re-scoped per Phase 2, WCET tooling is
  a real unstarted cost, formal-proof debt (Tag=0 => no write, still unproven) grows with
  every phase and needs its own track.
