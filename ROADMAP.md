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

### Phase 1 -- Capability format respec (DESIGN_01)

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

## Immediate next actions (in order)

1. **DESIGN_08_THROUGHPUT_AND_MEMORY_SYSTEM.md** -- the MSA object-prefetch/streaming design
   (Phase 5's spec), quantified against the E*N / k-sweep numbers above.
2. **Segmented-Object_ID design doc + Sail experiment** -- the trilemma decision (Phase 2
   gate; DESIGN_01's ID-width choice wants this settled before freezing 44 bits, and now also
   carries R1/Rev-A/Rev-B ODT-entry field additions).
3. **Phase 1 Sail work begins** in a `Veda-Core-sail-riscv` branch: veda_types.sail respec
   behind a build-time switch (256-bit format + CAndPerm + R1 carve mode + Rev-A epoch
   vector), self-check corpus re-pass.
4. RTL `linux-core` clone is created only when Phase 1 Sail is green -- Sail-first, as always.

## Standing constraints (from the verified line's own docs)

- No competitor-comparison framing in outward-facing text; 1970s lineage (Plessey 250,
  Cambridge CAP) is welcome. ASCII `--` only. No Co-Authored-By trailers.
- Hardware-first: if hardware can close a gap by construction, it gets priority.
- Do not overclaim: no blanket side-channel-immunity claims (ODT-path-scoped only), no
  "standardization-soon" framing, determinism claims re-scoped per Phase 2, WCET tooling is
  a real unstarted cost, formal-proof debt (Tag=0 => no write, still unproven) grows with
  every phase and needs its own track.
