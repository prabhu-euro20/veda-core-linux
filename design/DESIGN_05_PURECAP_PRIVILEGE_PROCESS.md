# DESIGN 05 -- Purecap Kernel, Capability-Native Privilege, and the Process Model

**Status:** Design proposal. **Builds on:** OCL.C/OCS.C + tag memory, the globals
cap-table (already round-trips capabilities through memory), M19 purecap mode, ODA +
OSpecialRW, droppriv, the MOS switcher. **Verification plan:** purecap-compile a
freestanding libc under M19 (zero ordinary ld/sd), then a nommu init.

## Part A -- pointer = capability (purecap codegen)

The prior scope-limit audit proved a *shadow* scheme hits a ceiling (return values,
indirect calls, void*, RCU publication). For a **complete** object-centric kernel, the
only sound representation is: **every C pointer is a 128/256-bit capability value.**

- In registers: capabilities live in the CRF.
- In memory: capabilities are stored/loaded via OCL.C/OCS.C (tag-preserving). The
  globals cap-table already does exactly this -- generalize it to all pointer storage.
- **Provenance travels with the value**, so returns, indirect calls, void*, and
  `rcu_assign_pointer`/`rcu_dereference` (publishing a pointer through shared memory)
  all work structurally -- the value *is* the capability.

Toolchain deltas (this is the CHERI-LLVM ~2015-2019 road, calibrated): a CRF calling
convention (arguments/returns in capability registers), `sizeof(void*) = 16/32`,
capability-aware varargs, DwarfRegNum for the CRF, and struct layout for embedded
capabilities. CheriBSD proved a purecap kernel is real; this is engineering, not
research.

- **`uintptr_t` = capability** (not a plain integer), so int<->ptr round-trips preserve
  provenance. This directly fixes the audit's "unsigned long silently-wrong" finding.
- **Genuine int->ptr (MMIO addresses)** becomes an explicit device-object Bind (Part C),
  not a raw cast -- the only place raw addresses are named, and they are named as objects.

## Part B -- capability-native privilege

CHERI showed rings can be largely replaced by capabilities; Veda already went ring-free
(1-bit $priv + one-way droppriv + ODA authority). Extend to a real OS:

- **Kernel = the domain that holds the ODA** (Object Descriptor Authority). Holding the
  ODA authorizes ODT-Populate/Destroy -- i.e., the kernel *is* the entity that can create,
  destroy, and remap objects. That is precisely "the memory manager." User domains do
  not hold the ODA and thus cannot mint/free objects.
- **Kernel/user crossing = the trusted switcher** (MOS-A/B, verified): sentry-mediated
  OCInvoke in, OCRETURN out, non-argument registers cleared, TSC/SSC swapped. This is
  syscall entry/exit.
- **Minimal M-mode remains** only for boot, trap-entry vectoring, and hart bootstrap --
  everything above it is capability-mediated. (Whether to keep a real S-mode at all, or
  fold "supervisor" entirely into ODA-possession, is an open decision -- DESIGN_06.)

## Part C -- the process model (putting DESIGN_00 into mechanism)

- **A process is a protection domain:** { entry sentry, TSC (trusted stack), a
  per-domain *capability table* object listing the Object_IDs it may bind, and its live
  CRF at entry }. Generalizes the MOS-C thread descriptor.
- **Scheduling:** the MOS-C cooperative round-robin + full GPR context save is the seed;
  add preemption via a timer interrupt (DESIGN_06) and capability-context save/restore
  (CRF + SCRs) on switch.
- **Syscalls:** ecall (already in RTL, M23) traps to the switcher, which enters the
  kernel domain (holding ODA). Arguments passed as capabilities; `copy_to_user`/
  `copy_from_user` become capability-checked object copies (the user capability is
  validated by hardware on use -- the classic confused-deputy defense, for free).
- **Devices/DMA (IO-ODT):** memory-mapped device registers are objects (ODT entries with
  a device Base); DMA-capable devices are *capability holders* checked by an IO-side MSA
  -- an object-based IOMMU. A device can only touch objects it has capabilities for.

## Honest scope

- Purecap kernel is a multi-year effort (CheriBSD calibration) even though each step is
  known-engineering. The audit's remaining tail (memcpy/struct copy of capabilities,
  unions overlapping a capability, variadic) all need capability-aware handling.
- Keeping (or removing) S-mode is unresolved (DESIGN_06). A minimal M-mode is assumed.
- The confused-deputy-for-free property assumes user pointers are passed *as
  capabilities*; a legacy syscall ABI passing integer pointers would lose it.
