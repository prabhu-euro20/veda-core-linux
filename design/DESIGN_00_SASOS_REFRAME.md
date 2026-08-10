# DESIGN 00 -- The SASOS Reframe (conceptual foundation)

**Status:** Design proposal. **Builds on:** OCInvoke compartments, TSC, sentries,
MOS-A/B/C switcher (all verified). **Verification plan:** Sail model of the domain
abstraction first, then RTL.

## Problem

Linux appears to require per-process virtual address spaces (page tables). Veda-Core
is single-address-space and address-less. Naively these contradict.

## Insight

**Translation != Protection.** The page table does both, which is why removing it
looks like removing isolation. Separate them (SASOS: Opal/Nemesis/Mungi):

- One global namespace for *naming* memory.
- Capabilities for *protecting/sharing* memory.

Veda-Core is the address-less limit of this: the global namespace is `Object_ID`,
not an address.

## Decision

Redefine the OS primitives in Veda-native terms:

- **Address space -> the `Object_ID` namespace.** Global, single, system-wide. An
  `Object_ID` means the same object everywhere. (Pillar: single address space -- preserved.)
- **Process -> protection domain.** A domain is: a live capability set (the CRF
  contents at entry) + a *capability table* object it owns (its "cap page" -- the set
  of capabilities it may bind) + a TSC (trusted stack) + an entry sentry. This is a
  direct generalization of the MOS-C thread model, which already gives each thread a
  code object, a save area, and sentry-mediated entry/exit.
- **Isolation -> capability non-possession.** Domain A cannot touch domain B's private
  object because A holds no capability (and cannot forge one -- Tag unforgeability,
  already verified). No translation needed to isolate.
- **Sharing -> capability hand-off.** Trivial in a single namespace: pass a capability
  (via the trusted switcher / a shared object). Read-only sharing via CAndPerm
  (DESIGN_01) to attenuate before hand-off.

## What this buys immediately

- `fork`, `mmap`, per-process isolation stop being "impossible" -- they become object
  operations (DESIGN_02). The hard part moves from *concept* to *engineering*.
- The trusted switcher (MOS-A/B) is exactly the kernel/user boundary crossing
  mechanism, already built and verified.
- Kernel vs user becomes "holds the ODA authority vs does not" (DESIGN_05), not a
  hardware ring.

## What it costs / honest scope

- A domain's private-state scale is bounded by the `Object_ID` namespace and by the
  ODT (DESIGN_01/02/06). "Everything is an object at process granularity" needs the
  respec's large ID space *and* object reclamation (Cornucopia-style sweeping
  revocation) or the namespace exhausts.
- Domains need a *capability table per domain* (the "cap page"). This is the closest
  thing to a per-process structure -- but it maps capability-slots -> Object_IDs, it is
  **not** an address translation table, so the address-less pillar holds.

## Precedent (not invented)

Mungi (single-address-space, capability-protected, no per-process translation) shipped
this model; this project already measured its 10x context-switch advantage. The novel
part is doing it **address-less** (Object_ID instead of a shared 64-bit address) and
with a **Linux ABI** on top.
