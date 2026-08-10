# DESIGN 02 -- The ODT as the Unified Memory-Management Structure

**Status:** Design proposal. **Builds on:** the flat DRAM-resident ODT, Object-Bind
(lookup-and-cache), generation re-check, the MSA request/result model, ODT-Populate/
Destroy (all verified). **Verification plan:** Sail model of residency + COW faults
first, then RTL, mutation-tested per the project's discipline.

## Problem

Linux memory management assumes: virtual->physical translation (page tables), demand
paging, mmap, COW. Veda-Core has no MMU and, by pillar, must not grow a conventional
one (Sv39/TLB/satp). But it *does* already have one table that every access consults:
the ODT.

## Decision -- promote the ODT from "protection table" to "the mm"

The ODT already stores Base/Length/Perms/generation/owner_hart and is walked on every
Object-Bind. Extend each entry with three fields and the ODT becomes the single
structure that a page table + VMA list + swap map jointly provide elsewhere:

- **`resident` bit** -- is the object's backing memory present?
- **`backing` pointer** -- where its contents live when not resident (swap/file/store).
- **`cow` bit** -- is this object copy-on-write shared?

No TLB. No Sv39. No satp. **The ODT *is* the memory map.** This is the address-less
pillar taken to its conclusion: there is exactly one indirection structure in the
machine, and it is object-indexed.

## Mechanism 1 -- object-granular demand paging

On Object-Bind (or first dereference) of a non-`resident` object, the MSA raises a
**residency fault** (a new cause, Veda-specific). The handler fetches contents from
`backing`, allocates physical Base (ODT-Populate-Fast), sets `resident`, and resumes.
This is paging at *object* granularity instead of 4 KiB pages. `mmap(file)` becomes:
create an object whose `backing` is the file; pages fault in on touch.

Determinism note (honest): paging is inherently non-deterministic. Scope the
determinism pillar to (a) the check path (already 95<114 gates) and (b) *locked/resident*
objects (RTOS-style). Pageable objects are best-effort. State this in the WCET story;
do not claim determinism for backing-store misses.

## Mechanism 2 -- object-granular copy-on-write (enables fork)

`fork` (DESIGN_00: child = new domain) marks the parent's writable data objects `cow`
in the ODT; parent and child both hold read-only-attenuated capabilities (CAndPerm,
DESIGN_01) to the same Object_IDs. Read-only objects (text) are shared as-is. On the
first write to a `cow` object, hardware traps (reuse the existing store-side violation
path); the handler mints a fresh Object_ID (ODT-Populate), copies contents, clears
`cow`, and rebinds the writer. **No page copying, no eager duplication** -- object-level
COW built entirely from existing trap + Populate + Rebind + the new `cow` bit.

## Mechanism 3 -- the MSA becomes the pager/fault engine

The MSA request/result model (verified, deliberately simple) already sits between the
core and memory. Residency faults and COW faults are new MSA-mediated events. The M24
DRAM-stall FSM is the seed of the multi-cycle fault path. The EMERGENCY_HANDLING design
(fresh minimal capability context for handlers) is exactly the right entry model for
fault handlers.

## Why this is philosophy-positive, not a compromise

A conventional MMU would be a *second* indirection layer bolted beside the ODT,
contradicting "one object mechanism." Unifying residency/COW/backing *into* the ODT
keeps the machine at one indirection structure -- strengthening the object-centric and
address-less pillars rather than diluting them.

## Honest open items

- ODT must now scale to the working set of a whole OS (see the trilemma, DESIGN_06).
- `backing` for anonymous memory needs a swap object store design.
- Large-object paging granularity: a 1 TiB object cannot fault as one unit -- objects may
  need internal page-sized residency sub-tracking (a per-object residency bitmap), which
  reintroduces a page-like concept *inside* an object. Flagged, not solved.
