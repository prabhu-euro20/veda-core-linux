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

**Settled in implementation (Sail, 2026-08-12): the answer to "Bind *or* first
dereference" is BOTH, and the "or" above was hiding a hole.** The dereference re-check
computes its address from the capability's *cached* `Base`, never from the live entry. A
page-out leaves `valid` true and does not bump `generation` (only Populate and Destroy
do), so a capability minted while the object was resident and held across an eviction
would read and write whatever now occupies that memory, with every existing check
passing. Bind-side checking is still worth having -- it invokes the pager before a
capability with a meaningless Base is minted -- but **the dereference term is the one
that closes the hole**, and it is free, because both dereference checkers already read
the entry.

Note this is the opposite conclusion from DESIGN_08's region residency, which is checked
at Bind only and correctly so: region residency governs whether a domain's *table* is
paged in, and by dereference time the capability has cached everything it needs from that
table. Object residency governs the *backing memory the cached Base points at*. Same
word, different referent.

Two further rules the implementation had to fix, both about not blurring distinctions:
**residency is checked LAST** among entry-derived tests (a never-populated slot and a
destroyed object are now *also* non-resident, and "never existed" / "revoked" must keep
winning over "paged out"); and the residency fault gets **its own cause (0x0A), not a
reuse of REGION_FAULT (0x09)**, because the two demand different repair -- page the
domain's table in, versus fetch this object's contents.

Determinism note (honest): paging is inherently non-deterministic. Scope the
determinism pillar to (a) the check path (already 95<114 gates) and (b) *locked/resident*
objects (RTOS-style). Pageable objects are best-effort. State this in the WCET story;
do not claim determinism for backing-store misses.

## Mechanism 2 -- object-granular copy-on-write (enables fork)

**CORRECTION, found while implementing mechanism 1 (2026-08-12): as written below, this
COW is BYPASSABLE and therefore only advisory.** Bind mints the capability's `Perms`
straight from the ODT entry, verbatim, with no attenuation, on all three bind modes; and
CAndPerm writes only the capability register, never the table. So a domain that can name
a `cow` object's Object_ID can simply **re-Bind it and receive a fully writable
capability**, never touching the attenuated one it was given. The register-local
attenuation the scheme below relies on is not a security boundary.

The fix must be hardware, matching the project's hardware-first rule: **Bind of a `cow`
object must itself return a store-attenuated capability**, so the ODT entry is the sole
authority and no re-derivation can escape it. Software handing out attenuated
capabilities is then a convenience, not the enforcement.

A second gap to close first: `PERM_STORE_VIOLATION` (0x13) -- the very trap this
mechanism plans to reuse -- currently has **zero test coverage** in the corpus. Building
COW on an unexercised path would be building on sand.

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
