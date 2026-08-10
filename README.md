# Veda-Core-Linux -- Architecture Design for an Address-Less, Object-Centric, Linux-Capable Core

**Status:** Design proposals (not yet implemented). Foundational architecture docs for
evolving the *verified* Veda-Core (63/63 Sail, 51/51 ACT4, 49/49 RTL) into a
**multi-hart, pipelined, Linux-portable, hardware-native-security core** -- without
diluting the five pillars: Object-Centric, Capability-based, Address-Less,
Single Address Space, Deterministic.

**Method:** Every decision here *extends* a verified Veda-Core mechanism; none rewrites
the proven base. Radical on open questions, conservative on what already works.
All docs are English (matching the existing repo); discussion may be in Telugu.

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

## The seven design decisions (index)

| # | Doc | Decision | Builds on (verified) |
|---|-----|----------|----------------------|
| 00 | `design/DESIGN_00_SASOS_REFRAME.md` | Process = capability domain; address space stays single/global | OCInvoke, TSC, MOS switcher |
| 01 | `design/DESIGN_01_CAPABILITY_FORMAT_RESPEC.md` | Widen the *separate* CRF (256-bit); add CAndPerm | CRF-separate decision, 36-instr ISA |
| 02 | `design/DESIGN_02_ODT_UNIFIED_MM.md` | ODT becomes the unified mm structure (residency+COW+backing). No page tables. | ODT, Object-Bind, MSA fault model |
| 03 | `design/DESIGN_03_MULTIHART_OBJECT_COHERENCE.md` | Coherence unit = object; **no coherence protocol** (cache-less); MSA serializes atomics | owner-hart, Veda-Atomic, MSA, cache-less pillar |
| 04 | `design/DESIGN_04_PIPELINE.md` | Object-Bind = capability-load micro-op; checks parallel to addr-calc | synthesis study (95<114 gates), M24 stall FSM |
| 05 | `design/DESIGN_05_PURECAP_PRIVILEGE_PROCESS.md` | pointer = capability; privilege = ODA possession | OCL.C/OCS.C, tag memory, ODA, droppriv |
| 06 | `design/DESIGN_06_BUILD_ORDER_AND_OPEN_QUESTIONS.md` | Sequenced plan + the one genuinely unsolved trilemma | whole-project Sail-first discipline |

---

## Build order (architect's sequence)

1. **Capability format respec** (01) -- large objects + large ID space + wide generation.
2. **ODT as unified mm** (02) -- residency/COW/backing, Sail-first.
3. **Pipeline** the single-hart core (04) -- keep ACT4 51/51.
4. **Multi-hart** (03) -- shared ODT, shared-binding, real aq/rl, MSA serialization.
5. **Purecap toolchain** (05) -- pointer = capability value.
6. **OS model** -- switcher -> real domains, object-COW fork, object paging.
7. **Linux ABI port** on top.

Steps 1-4 are hardware (the project's strength, verified discipline); 5-7 are the long software tail.

---

## The one honest unsolved problem

The **ODT scale-vs-flat-vs-deterministic trilemma** (see `design/DESIGN_06`): a flat,
resident, cache-less ODT cannot also be huge. Leading candidate: **segmented Object_ID**
(top bits select a region; the resident ODT stays flat *per region*). This is the next
big radical decision and is **not** claimed solved here.

---

## How to push this into your new remote

This repo was built in an ephemeral cloud workspace. To land it in your new GitHub remote:

```bash
# Option A -- from the delivered git bundle (keeps full history):
git clone veda-core-linux.bundle veda-core-linux
cd veda-core-linux
git remote set-url origin git@github.com:<you>/veda-core-linux.git   # your new repo
git push -u origin master

# Option B -- from the delivered files:
cd veda-core-linux
git init && git add . && git commit -m "Foundational architecture: address-less object-centric Linux-capable core"
git remote add origin git@github.com:<you>/veda-core-linux.git
git push -u origin master
```
