# Veda-Core-Linux -- Architecture Design for an Address-Less, Object-Centric, Linux-Capable Core

**What this repo is:** the design source of truth for evolving the verified deterministic
Veda-Core into a **multi-hart, pipelined, Linux-portable, hardware-native-security core** --
without diluting the five pillars: Object-Centric, Capability-based, Address-Less,
Single Address Space, Deterministic. Implementation repos cite these docs, never the reverse.

**Status (2026-08-12): Phase 1 is complete and machine-verified on both layers.** The
capability-format respec and the object-namespace scale decision are built and checked, not
proposals-only:

- **Sail (formal model)** -- `Veda-Core-sail-riscv` fork, branch `phase1-respec`: **110/110**
  self-check (256-bit format, widened ODT entry + generation, the DESIGN_08 region table, the R10
  CRBR hardening, and all of Phase 2 -- object residency, the page-out/page-in pair and
  copy-on-write), every increment mutation-tested.
- **RTL (hardware)** -- `veda-core-sindhu`, branch `sindhu`: **99/99** smoke tests, mirroring the
  Sail model through the Phase-2 increments and the R36..R59 hardening.
- **Conformance** -- RISC-V International ACT4 RV64I: **51/51**.
- **Cross-layer differential** -- twenty-five probes run the same program on both layers and compare
  signatures word for word: **25/25 as expected**. This is the suite that finds what neither layer
  can find alone.

**Reproduce all four with one command**: `veda-core/verification.sh` in the implementation repo. It
ends with an explicit verdict line, reads every suite's exit code, and refuses any suite reporting a
zero total -- none of which it did until R46, when it was measured exiting 0 while the entire
cross-layer differential suite had not run.

Both build on the frozen verified deterministic line (ACT4 51/51 on `veda_core.tlv`), which
stays untouched -- read-only reference only.

**Method:** Every decision here *extends* a verified Veda-Core mechanism; none rewrites the
proven base. Radical on open questions, conservative on what already works. Sail-first,
mutation-tested, zero-regression at every increment. All docs are English (matching the
existing repo); discussion may be in Telugu.

---

## The one idea that unlocks everything

Linux does **not** actually require per-process virtual address translation -- it
requires **isolation** and **private-but-shareable state**. Conventional systems
conflate translation and protection in the page table, which makes "no MMU" look
like "no isolation." Single-Address-Space OS research (Opal, Nemesis, **Mungi** --
already cited in this project's REAL_MATH doc, 10x cheaper context switches)
separated them decades ago: one global address space, protection via capabilities.

**Veda-Core-Linux is the first *address-less* SASOS with a Linux ABI.**

- **"Address space"** = the global `Object_ID` namespace (single, system-wide -- pillar preserved).
- **"Process"** = a protection domain = a capability set (OCInvoke compartment, TSC-rooted).
- **"Isolation"** = not possessing a capability -- *not* the absence of translation.

Everything below follows from taking this reframe seriously.

---

## The nine design documents (index)

Docs 00-06 are the original sequenced decisions; 07 and 08 were added as the work proceeded
(07 from an adversarial security pass, 08 to settle the one open trilemma 06 named).

| # | Doc | Decision | Builds on (verified) |
|---|-----|----------|----------------------|
| 00 | `design/DESIGN_00_SASOS_REFRAME.md` | Process = capability domain; address space stays single/global | OCInvoke, TSC, MOS switcher |
| 01 | `design/DESIGN_01_CAPABILITY_FORMAT_RESPEC.md` | Widen the *separate* CRF (256-bit); add CAndPerm | CRF-separate decision, 36-instr ISA |
| 02 | `design/DESIGN_02_ODT_UNIFIED_MM.md` | ODT becomes the unified mm structure (residency+COW+backing). No page tables. | ODT, Object-Bind, MSA fault model |
| 03 | `design/DESIGN_03_MULTIHART_OBJECT_COHERENCE.md` | Coherence unit = object; **no coherence protocol** (cache-less); MSA serializes atomics | owner-hart, Veda-Atomic, MSA, cache-less pillar |
| 04 | `design/DESIGN_04_PIPELINE.md` | Object-Bind = capability-load micro-op; checks parallel to addr-calc | synthesis study (95<114 gates), M24 stall FSM |
| 05 | `design/DESIGN_05_PURECAP_PRIVILEGE_PROCESS.md` | pointer = capability; privilege = ODA possession | OCL.C/OCS.C, tag memory, ODA, `mstatus.MPP`/`mret` (R36 retired `droppriv`) |
| 06 | `design/DESIGN_06_BUILD_ORDER_AND_OPEN_QUESTIONS.md` | Sequenced plan; names the ODT trilemma (since resolved in 08) | whole-project Sail-first discipline |
| 07 | `design/DESIGN_07_ROBUSTNESS_AND_SECURITY_HARDENING.md` | Adversarial 6-lens red-team (R1-R9) **plus sixty-six more findings, R10..R75, produced by BUILDING it** -- the register runs R1..R75 with no gaps | the whole verified base + 01/08 |
| 08 | `design/DESIGN_08_OBJECT_NAMESPACE_SCALE.md` | The ODT trilemma, **resolved**: domain-segmented Object_ID `{region:20, local:24}` + the CRBR | ODT, Region Table, the 06 trilemma |

---

## Build order (architect's sequence) and where it stands

1. **Capability format respec** (01) -- large objects + large ID space + wide generation.
   **-- DONE, both layers** (Sail 72/72 and RTL 62/62 at the time; the suites now stand at
   104/104 and 90/90).
2. **Object-namespace scale** (08) -- the segmented-Object_ID + CRBR decision.
   **-- DONE, both layers** (Sail region table + RTL increment RTL-4). Closes Phase 1.
3. **ODT as unified mm** (02) -- residency/COW/backing, Sail-first. **-- DONE except `backing`,
   both layers**: object residency, the page-out/page-in pair, copy-on-write with an eligibility
   predicate (R38), and the per-object bind gate are all built and mirrored. The ODT entry carries
   no `backing` field yet, so `mmap(file)` has no mechanism -- that is the one Phase 2 item left.
4. **Pipeline** the single-hart core (04) -- keep ACT4 51/51.
5. **Multi-hart** (03) -- shared ODT, shared-binding, real aq/rl, MSA serialization.
6. **Purecap toolchain** (05) -- pointer = capability value.
7. **OS model** -- switcher -> real domains, object-COW fork, object paging.
8. **Linux ABI port** on top.

Steps 1-4 are hardware (the project's strength, verified discipline); 5-8 are the long software tail.

---

## The trilemma is solved; here is what is genuinely still open

The **ODT scale-vs-flat-vs-deterministic trilemma** that `design/DESIGN_06` named -- a flat,
resident, cache-less ODT cannot also be huge -- is **resolved in `design/DESIGN_08`**:
domain-segmented `Object_ID`, where the top 20 bits select a resident, flat *region* and the low
24 name an object within it, with a Current-Region Base Register (CRBR) keeping an intra-domain
bind at one memory read. It is built and machine-checked on both layers.

What that decision left genuinely open (from DESIGN_08 Section 9 and DESIGN_07's residuals), not
glossed over:

- **The cross-domain +1 read is unmeasured** -- no DRAM latency model exists yet.
- **Cross-domain sharing** actively costs (a shared region pins DRAM and re-concentrates the MSA
  hot-lock) -- an open policy question.
- **Region-grant authority** is a new compartment-escape surface; the Region Table has no
  populate instruction or authority gate yet (it is reset-seeded).
- **Reclamation / sweeping revocation** becomes a hard prerequisite under object-granular churn.
- **R10** (found while building the RTL region table): loading the CRBR at a domain crossing
  without a matching restore is itself a compartment escape -- fixed by deriving the region from
  the entered/returned-to code capability's own Object_ID and validating every load through the
  Region Table. **Closed on both layers**; the residual is the obligation it leaves behind, namely
  that a future Region-Table-write instruction must refuse to clear residency on the current region
  or on any saved one.

---

## Repository layout and how the layers relate

Three repos, one discipline (Sail-first, then RTL mirror, design cited by both):

- **`veda-core-linux`** (this repo, local `~/veda-core`) -- the design source of truth:
  `DESIGN_00..08` + `ROADMAP.md`. Every implementation decision lands here first or is recorded
  here as a finding.
- **`Veda-Core-sail-riscv`** fork, branch `phase1-respec` -- the formal model. Each increment is
  built, self-checked, and mutation-tested before it is called done.
- **`veda-core-sindhu`**, branch `sindhu` -- the RTL (TL-Verilog) implementation line, mirroring
  the Sail work increment by increment.

The frozen deterministic embedded line (`Veda-Core` / `~/makerchip/rva23-core`) is **read-only
reference only** -- its verified base and its toolchain are reused, never modified from this line.
