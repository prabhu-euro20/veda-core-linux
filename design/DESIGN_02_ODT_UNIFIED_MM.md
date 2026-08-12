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

### The cached-Base fork, and the decision (2026-08-12)

Found while grounding increment 2. This document's original sketch of mechanism 1 -- "the
handler fetches contents from `backing`, allocates physical Base, sets `resident`, and
resumes" -- skips a problem that decides the whole mechanism's shape, so it is settled
here before any more fields are added.

**The inevitability.** A capability caches `Base` at Bind time; the access path computes
its address from `cap.Base`, never from the live entry. That caching is deliberate and is
what makes the fast path fast. But paging exists precisely to free a frame and give it to
another object. So when the paged-out object returns, the frame it used is *already
someone else's* and it must come back at a **different Base**. This is not a design
choice to be optimised away -- it is what paging means. Which means a cached `Base`
**must** be invalidated on page-in.

Concretely, without a resolution: every check passes -- tag, valid, generation, resident,
bounds -- and the access lands in whatever object now owns the old frame. Read *and*
write.

**Two resolutions, and only two:**

- **(A) Bump `generation` on page-OUT, and let holders re-Bind.** The stale capability
  takes the existing stale-capability trap (0x02) on its next use; the holder re-Binds,
  receives the new Base (Rebind already preserves Offset), and retries.
- **(B) Stop caching `Base` in capabilities.** Every access re-reads the entry, so Base
  is never stale.

**Decision: (A).**

The reasoning is about *where the cost lands*, not about which is more elegant. Paging is
a rare event; (B) pays for it on **every load and store, permanently, including in
programs that never page at all**. It would also add a DRAM read to every access, which
damages two pillars at once: the cache-less pillar (a miss must be an explicit bounded
trap, not a silent per-access fetch) and the determinism pillar (per-access timing would
depend on memory). (A) puts the cost exactly where the event happens, and needs **no new
hardware** -- `generation` and Rebind are already built, verified, and mutation-tested.

**The honest cost of (A), stated plainly:** paging is **not transparent** under this
design. A holder whose object was paged out sees a trap and must re-Bind. Conventional
paging hides this entirely. That is a real difference, and it is not hidden here -- but it
is consistent with what this document already concedes above, that pageable objects are
best-effort rather than deterministic. (B) would buy transparency by spending a pillar.

**Consequences that follow from (A), and are therefore now design commitments:**

- The generation bump belongs to **page-out**, not page-in. Page-in must preserve
  `generation`, or a capability that survived the round trip would be invalidated twice
  and the budget would burn twice as fast.
- Page-in therefore **cannot be plain ODT-Populate**, which bumps `generation` whenever
  the old entry was valid -- and a paged-out object is valid-but-non-resident. Using
  Populate as the repair primitive would invalidate every capability on every page-in,
  making demand paging useless. A distinct, generation-preserving page-in path is
  required, gated on `valid & not resident` so it cannot be used to silently repoint a
  live object.
- Each page-out consumes one of the 2^24 generation values for that slot. A hot,
  frequently-paged object is exactly the workload that approaches retirement, so
  reclamation (DESIGN_07 Rev-B sweeping revocation) is a harder prerequisite here than
  the original sketch implied.
- Capabilities spilled to memory via OCS.C are reached by this scheme (they fault on
  reload like any other), which is the one thing Rebind alone could not have covered.

**Sequencing consequence:** `backing` is *not* the next increment. A field no instruction
can read, feeding a repair path that cannot repair, would be motion without progress. The
order is: (1) the page-out / page-in pair with the generation contract above, (2) tests
proving the full cycle -- page out, stale trap, re-Bind, new Base, success -- and only
then (3) `backing`, once there is a real reader and a real repair path for it to serve.

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

Added 2026-08-12, from grounding increment 2. These are real gaps, not polish:

- **What `backing` DENOTES is genuinely undecided.** This document says only "pointer".
  The apparent in-tree precedent, `region_entry.region_backing : bits(56)`, turns out to
  be a **placeholder**, not a decision: it has zero readers in Sail, the RTL calls it
  "genuinely UNUSED ... field parity", and its width was copied from `region_odt_base` (a
  physical base) without any recorded reasoning about meaning. It must not be cited as
  precedent. The three live candidates -- raw physical address, another Object_ID, or an
  opaque software-defined handle -- differ in whether they introduce a **second naming
  domain**, which is the clause this document actually commits to ("exactly one
  indirection structure ... object-indexed"). An Object_ID is the best textual fit (this
  document's own `mmap(file)` sentence already treats the backing as an object) but is
  insufficient alone: it says *which* object, not *where inside it*, and it raises
  recursion (the backing object has its own `resident` bit) and bootstrap questions that
  need a pin/lock concept that does not exist yet.
- **There is no way to read an ODT entry field at all.** No instruction reads an entry
  into a GPR -- the query family reads the *capability register*, never the table. So a
  pager cannot read `backing` back by any means today. Writing it is cheap (a second CSR,
  or a new Custom-0 funct7); **reading it is the pillar-sensitive half** and is the part
  with no existing mechanism.
- **The handler cannot identify which object faulted.** `mtval` carries {cap_idx, cause},
  not an Object_ID. A pager written today would have to decode the faulting instruction
  at `mepc`, or dispatch on the capability index. That is a software workaround for a
  missing architectural channel, and it should be resolved before `backing` is designed
  rather than after.
- **Page-in via Populate silently resets `owner_hart`** to unowned, so hart ownership does
  not survive a page-out/page-in cycle. Invisible in a single-hart model; a real hole once
  multi-hart lands.
- **The RTL entry has no room for all three fields as currently laid out.** 32-byte entry,
  25 bytes used, 7 spare, and the byte-aligned-flag convention costs a whole byte per
  flag. `resident` + `cow` leaves 5 bytes = 40 bits for `backing`, which fits neither a
  56-bit address nor a 44-bit Object_ID comfortably alongside future needs. Either the
  flags get bit-packed (breaking the byte-alignment convention that keeps the three
  hand-written layout copies diffable -- the same convention whose absence caused RTL-3's
  worst mutation hazard) or `ODT_ENTRY_BYTES` doubles to 64. That decision should be made
  deliberately, not discovered by the RTL mirror one increment later.
- **RTL is one increment behind Sail**: `resident` (increment 1) is Sail-only. Any
  spare-byte arithmetic above is a projection until that mirror lands.
