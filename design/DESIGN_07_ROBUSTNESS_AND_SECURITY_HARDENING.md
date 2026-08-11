# DESIGN 07 -- Robustness & Security Hardening (adversarial push-back on DESIGN 00-06)

**Status:** Design proposals, adversarially derived. **Method:** a 6-lens red-team
(temporal safety, ODT integrity, multi-hart concurrency, speculation/microarchitecture,
fault injection, boot/IO authority) attacked DESIGN_00-06 + the verified spec + the real
`veda_core.tlv`, and every finding was then checked by an independent skeptic against the
real files for (a) is-the-weakness-real, (b) is-the-fix-pillar-legal, (c) does-it-close-the-
class. 21 findings survived to a verdict: 7 adopted, 10 adopted-with-correction, 2 rejected.
Every claim below cites the real file that grounds it; nothing is asserted from assumption.

## Why a threat-model split is the first decision

The single most important correction the verification pass forced: **the current design's
declared adversary is a logical/software attacker** (EVIDENCE_INDEX.md scopes the
tag-unforgeability result to "the pure-corruption attacker model"; the threat docs cover
software-corruption and cache-timing only). Several strong findings attack adversaries the
design never claimed to resist. Honesty requires stating which model each decision serves,
so nothing here is oversold:

- **T1 Logical / software adversary** -- forged/confused pointers, UAF, type confusion,
  compartment escape. The design's current claim. Hardening here closes *real present* gaps.
- **T2 Concurrent / multi-hart adversary** -- races, TOCTOU, ordering. Out of scope for the
  frozen single-hart core, but **in scope the moment Phase 6 lands** -- these are latent
  design-line requirements, not live bugs.
- **T3 Physical / fault-injection adversary** -- rowhammer, glitch, laser, DRAM tamper.
  Never claimed. Hardening here is an **explicit, optional silicon-phase** posture, adopted
  as a decision but flagged as not-urgent relative to T1/T2 logical work.

A decision that closes a T1 gap by construction is worth more, sooner, than one that hardens
against T3. The ordering below reflects that.

---

## Tier A -- T1 (logical) decisions: close real present gaps by construction

### R1 (flagship). Object-granular allocation -- close intra-slab use-after-free

**Weakness (real, self-admitted).** DESIGN_01:73 admits verbatim that object-centric slab
caches "reuse without destroy ... but then intra-slab UAF is not caught, an honest
temporal-safety weakening." The generation counter bumps *only* on ODT-Destroy
(VEDA_CORE_SPEC.md), and a slab that recycles a slot without destroying the arena Object_ID
never bumps it. A stale holder re-points its Offset (OCA moves Offset within the live
window) into a freed-then-reallocated slab slot; bounds, tag, and generation all pass because
the arena stayed live. **This is the dominant real Linux-kernel exploitation class** (the
cross-cache / dirty-cred / msg_msg family), and the hardware sees nothing.

**Radical decision.** Make the object model the allocation granule. Add a hardware
**SLAB-CARVE** Object-Bind mode that atomically mints a *fresh child Object_ID* with its own
ODT entry (own Base = parent.Base + offset, own Length, own generation) carved from a live
parent arena; `free()` becomes ODT-Destroy of the *child* ID, which staleifies every
capability to that element on its next dereference through the **existing** per-dereference
re-check -- no new check path. The parent arena carries a **carve-only Permit** (not directly
dereferenceable), so every actual byte access must go through a child ID.

**Closes the class?** Yes, by construction, given the carve-only parent Permit. Note
(verifier): CSetBounds already narrows spatially but derives a *same-ID, same-generation*
capability -- zero temporal benefit. The load-bearing new parts are (a) minting a **fresh
Object_ID + generation** on carve and (b) the carve-only Permit.

**Pillars.** Strengthens Object-Centric (every allocation is a real Object_ID, not a raw
offset), stays cache-less single-transaction (carve = one ODT write, free = one generation
bump), one namespace, no software-held raw address. **Cost:** one ODT entry per live slab
element -> pressures the Object_ID ceiling and ODT footprint; **must be co-designed with the
DESIGN_01 44-bit ID widening** and the throughput/TCM tier (carve/free each pay a DRAM-tier
ODT access unless the child lands in TCM). **Attaches to:** Phase 1-2.

### Rev-A. Selective revocation -- per-object epoch/delegation vector

**Weakness (real, self-admitted).** VEDA_CORE_SPEC.md states the generation counter "revokes
*all* outstanding capabilities for a destroyed object uniformly, not one holder at a time,"
and true selective revocation "would require ... a per-holder authority table ... deliberately
out of scope." CAndPerm (DESIGN_01) is monotonic-clear *at mint time* and cannot retract an
already-handed capability. DESIGN_02's fork/COW hands multiple live holders capabilities to
the same Object_IDs -- so there is no way to yank one domain's access to a still-shared object
without destroying it for everyone (a confused-deputy gap).

**Radical decision.** Extend each ODT entry with a small **k-bit valid-epoch vector** indexed
by a delegation/compartment ID. Each Bind/CAndPerm derivation stamps the deriving ID into the
capability; the MSA's existing per-dereference check adds **one bit-test** (capability's ID vs
the entry's per-ID valid bit) in the same flat lookup. A new **O-REVOKE-ID** instruction
clears one delegatee's bit: selective revocation of exactly one holder, object stays live for
the rest, effective on their next dereference.

**Closes the class?** Only for a **bounded fan-out of k delegatees per object** (not
arbitrary) -- verifier correction, downgraded from the original "closes the class." Deeper
delegation still needs software policy. Also a verifier correction: this is a **new
authority-index semantic**, not activation of CHERI's reserved side-channel-tagging CID (a
different mechanism). **Pillars:** one extra field-read in the same single transaction, no
cache, no raw address. **Cost:** needs the 256-bit format (current 8-bit Reserved is full);
~16 MiB extra DRAM over the full ODT; new instruction + dereference-path change. **Attaches
to:** Phase 1-2.

### Rev-B. Sweeping revocation -- a hardware sweep engine (the cache-less design's advantage)

**Weakness (real, self-admitted).** DESIGN_06:66-67 / DESIGN_01:73-74 name Cornucopia-style
sweeping revocation but leave it **entirely unstarted**. The generation counter is finite:
the 8-bit ABA-on-wrap bug was real and is already fixed via a `retired` flag, but retirement
then leaks the namespace per-slot under churn (a hot/recursive slot exhausting its 255 reuses
is called "catastrophic" in the stack-frame analysis).

**Radical decision.** Build sweeping revocation as a **hardware sweep engine** the cache-less
design is uniquely suited to run: (1) quarantine a to-be-freed Object_ID (mark non-bindable);
(2) the MSA walks the flat ODT, the OCL.C/OCS.C tag store, **and the CRF** clearing tags on
any capability pointing at a quarantined ID; (3) reset that ID's generation to 0 and un-retire
it -- ABA-free by construction because no un-swept holder survives. Cache-less means there are
no stale cached copies to chase and no coherence protocol to fight, so the sweep is a bounded
linear scan.

**Closes the class?** Yes for both ABA and retirement-exhaustion. **Verifier corrections:**
(1) the pressure is **per-slot** (recursion, hot arenas), *not* a global 8.4M-namespace DoS --
do not overclaim; (2) the sweep scope **must include the CRF**, not just ODT + tag memory
(the original finding under-stated this). **Pillars:** run the long sweep **off the WCET path
as a best-effort background event** (DESIGN_02's paging-non-determinism precedent), so
determinism-for-resident holds. **Cost:** multi-ms non-deterministic sweep, quarantine
free->reuse latency, new sweep-engine RTL, a quarantine bit per entry, the hardest of the
temporal-safety proofs. **Attaches to:** Phase 2 (the concrete form of DESIGN_06's open item).

### Rev-E. Range-gate the capability memory paths + validate ODT-Populate Base

**Weakness (real, sharper than first stated).** The only elfmem-range gate in the RTL is on
the *base-ISA* store path; OCS.C/OCL.C/NMC/Atomic write elfmem/tag_mem gated only by the
capability's own Length, never against the backing window, and **ODT-Populate writes a
software-supplied raw Base with zero range validation**. So an ODA-authorized Populate can
seat an object's Base outside the legal backing region, Bind mints a capability to it, and a
capability store then drives an out-of-range tag/elfmem index (undefined behavior). This is a
defensive asymmetry: the base path guards exactly this, the capability paths do not.

**Radical decision.** Extend the base-ISA range-gate idiom to **all** capability memory paths
(trap instead of indexing tag/elfmem when the resolved address is outside the legal window),
and **validate ODT-Populate's new Base** against the legal backing window at populate time.
Verifier note: this is the **cheaper, pillar-legal** fix -- the original "object-following MAC
across all regions" breaks the flat ODT transaction (a 4096-granule bitmap cannot fit a
16-byte entry). **Closes** the out-of-range-index class by construction. **Pillars:** clean
(reuses the resolved address, no new structure). **Attaches to:** Phase 1-2 hardening.

---

## Tier B -- T2 (multi-hart) decisions: bind these to the Phase 6 reopening checklist

These are **not live bugs** (MHARTID is a fixed localparam = 0, one in-order writer). They
are requirements that become real the instant a second hart exists, and the design already
fences multi-hart as reopening work (ATOMIC_AQRL_SAFETY_ANALYSIS.md explicitly reopens on a
second hart). The contribution here is writing down *exactly* what must be atomic/ordered.

### R3. Per-object MSA transaction: recheck and access are indivisible

**Weakness.** The dereference-time generation/valid recheck is a single combinational
`odt_mem` read that is **not atomic** with the memory access it guards (the commit is a later
posedge write, in a separate always_ff from Populate/Destroy). Under two harts, a TOCTOU
window opens: hart A destroys+repopulates an Object_ID between hart B's recheck and B's
commit. DESIGN_03's "coherence is free" covers only *data* races, not this metadata-vs-data
race; its atomic lane covers only Veda-Atomic RMW, not ordinary OCL/OCS.

**Radical decision.** Extend the per-object MSA serialization granule DESIGN_03 already
declares for atomics to cover **ordinary OCL/OCS check+access**: the generation/valid read
and the commit become one indivisible per-Object_ID MSA transaction that cannot straddle a
same-Object_ID mutate. **Closes** the cross-hart UAF/type-confusion write by construction.
**Pillars:** Object_ID-keyed lane (no raw address, no coherence protocol), cost falls only on
the deliberately-shared minority (exclusive-default keeps the 1-cycle fast path).

### R4. The Integrity Manager returns as a hardware witness

**Weakness.** The Object Tracking Table + Violation Log were removed from the MSA "until a
second hart exists" (VEDA_CORE_SPEC.md) -- a condition Phase 6 now meets. ODT
Populate/Destroy/owner-claim are ordinary instruction-issued `odt_mem` writes with no
arbitration and no cross-hart witness (last-writer-wins).

**Radical decision.** Bring back the Integrity Manager as **MSA-side bookkeeping** on traffic
the MSA already serializes: last-committed generation + owner per live Object_ID, plus a
bounded Violation Log of detected races / wrong-owner claims / invariant breaks. **Does NOT
close the class alone** (verifier: it is a witness, not atomicity -- it needs R3 for the
actual TOCTOU closure); it detects and audits. **Pillars -- the load-bearing subtlety:** it
must **never substitute for the DRAM-resident ODT on the check path** and must have a
**deterministic, non-adaptive overflow policy** (drop-oldest-vs-trap, stated) -- cross either
line and it becomes a cache (pillar-breaking). Realizing it requires funneling ODT mutations
through the MSA serialization point (which they are not today) -- the correct move anyway.

### Rev-C. aq/rl get real semantics, or an explicit SC-by-default decision

ATOMIC_AQRL_SAFETY_ANALYSIS.md already flags this as a hard prerequisite: aq/rl are decoded
but do nothing, so multi-hart software expecting acquire/release ordering silently gets none.
**Decision:** at Phase 6, either give aq/rl real MSA-enforced per-object acquire/release
semantics, **or** declare Veda-Atomic unconditionally sequentially-consistent by design (bits
become real no-ops by decision, tested). Verifier: the **SC-by-default path is the
construction-closing one** (serialize all shared-object atomics at the per-object MSA point);
real acquire/release needs the unstarted formal per-object memory-model pass first. FENCE
stops being a functional NOP.

### Rev-D. Atomic ODT owner-claim / populate / destroy (compare-and-set)

The owner-claim is a split combinational-read + unsynchronized posedge-write with no arbiter.
**Decision:** make claim/populate/destroy a single hardware **compare-and-set per Object_ID**
at the MSA (test owner == UNOWNED||self, and if so write owner = self, atomically), with a
bounded round-robin arbiter so exactly one racing hart wins and the loser hard-traps (cause
0x06, already defined). Bounded WCET (arbiter depth), no cache. Fold into the Phase 6
checklist beside Rev-C.

---

## Tier C -- the new pillar: provably non-speculative capability enforcement

### R5. Make non-speculation an explicit, machine-checked contract (a 6th pillar)

**Weakness (a guarantee gap, not a live leak).** The cache-less pillar's own justification is
avoiding speculative cross-compartment leakage (CRF_ARCHITECTURE_ALIGNMENT_VERDICT.md quotes
the industry's own admission that a speculative capability core "remains vulnerable to
side-channel leakage arising from speculative execution across compartment boundaries").
Today that safety is an *accident of single-cycle execution*. DESIGN_04 dismisses control
speculation in one line ("Branch prediction is orthogonal") and never defines what a
mis-speculated in-flight instruction may observe or mutate -- so the guarantee is **asserted,
not architected**, the moment Phase 4 pipelines the core.

**Radical decision -- elevate an implicit property into an explicit pillar.** A capability
check must be a **gating precondition** of the access it authorizes, never a post-hoc trap on
an already-issued transient: no OCL/OCS/OCA/Object-Bind/Veda-Atomic micro-op may read data,
forward a value, or perturb any shared microarchitectural state until its five checks pass
**and** its authorizing PCC/CRF state is non-speculative (all older control transfers
resolved). Concretely, capability micro-ops **serialize at issue** (stall in ID until control
resolves) -- cheap precisely because the object layer is **opt-in and rare** relative to plain
RV64I (which may still speculate freely; the cache-less pillar already covers its channel).
Machine-check the invariant: *no wrong-path capability micro-op changes committed or
observable state.* Also fuse the domain-crossing authority transition (OCInvoke narrow /
OCRETURN widen) atomically to the pipeline redirect so authority-in-the-pipeline always equals
authority-at-commit.

**Honest framing (verifier).** On the currently-planned in-order, no-branch-prediction,
cache-less pipeline this is a **contract/documentation gap, not a live Spectre leak** -- the
cache-less pillar already removes the primary covert channel. Land it as an explicit DESIGN_04
pipeline contract **before** Phase 4 RTL, so the guarantee survives pipelining by construction
rather than by luck. This is the property this architecture can make and mainstream
speculative capability cores cannot -- stated on our own terms, as our own invariant.
**Pillars:** strengthens determinism/WCET (the temporal twin of the cache-less spatial
guarantee); no cache, no raw address; bounded cost paid only by capability-touching code.
**Attaches to:** Phase 4 (as a precondition).

---

## Tier D -- T3 (physical / fault-injection) decisions: silicon-phase posture

Adopted as decisions for the hardware-realization phase, explicitly **outside the currently
declared threat model** -- real hardening, not urgent relative to T1/T2.

### R6. Dual-rail, fail-closed check enforcement (single-glitch resistance)

**Weakness.** All five checks OR-collapse into one violation net whose only enforcement is a
downstream write-enable / NOP-force select (confirmed in RTL: the five OCL checks reduce to
one bit that gates the elfmem write and the tag-clear together). A single glitch on that net
fails **open** -- bypassing all five checks at once, and skipping the tag-clear so forged bytes
stay tagged. The generation recheck likewise collapses to one `gen_stale` bit off one 8-bit
compare.

**Radical decision.** Encode each of the five checks (and the generation recheck) as a
complementary **2-of-2 rail pair** on independent cones; the enforcement gate permits a write
**only** on the legal codeword {allow=1, deny=0} and traps on a violation **and** on either
inconsistent codeword {0,0}/{1,1} (a stuck/glitched rail). Store generation as
value+complement so a flipped generation byte is detected -> forced stale -> trap. Fixed
fail-secure default: the enforcement mux's unselected branch is *trap*, never *permit*.
**Verifier tightening (required to truly close the class):** the legal codeword must **drive
the write-enable itself**, and tag-clear must be **positively asserted** from the same
codeword -- not merely share the gated block -- else the write-enable is a residual single
point. **Pillars:** touches only internal combinational check/enforce logic; the synthesis
study's own numbers (233 check cells, checks *beside* not *before* the 64-bit adder) support
keeping the 95-gate depth and determinism when ~2x-ing the shallower check cones. One
mechanism covers all five checks + the recheck.

### R2. Per-entry ODT integrity MAC

**Weakness.** The ODT is ordinary DRAM with zero integrity protection; every security field
(Base/Length/Perms/owner_hart/generation) is copied verbatim into the CRF at Bind. A DRAM
bit-flip on an entry (rowhammer/fault) then a victim Bind mints a legitimately-Tagged
over-privileged capability -- no trap. (Verifier precision: the exploit window is
corrupt-DRAM-**then**-Bind; a post-Bind flip is inert because live fields sit in on-chip
flops.)

**Radical decision.** A per-entry **keyed-PRF MAC** over {Object_ID, Base, Length, Perms,
owner_hart, generation, slot_index} with an MSA-only, reset-minted key that never leaves the
MSA, verified **combinationally in the same single-transaction lookup**; validity gates on
MAC-match in addition to id-match. Binding slot_index + generation into the MAC also kills
entry relocation/splice/replay. A corrupted entry can never reach Tag=1 -- it fails MAC ->
invalid -> trap. **Pillars:** synergistic with Tag unforgeability (forged entry -> Tag=0 by
construction); still one fixed-width line read + fixed-latency PRF = bounded constant WCET; no
cache, no history-adaptive placement; the key is not placement state. **Honest limits
(verifier):** ~64 bits/entry eats the only remaining ODT slack; a PRF engine is needed on the
Bind read path **and** every Populate/Destroy write path (re-MAC on every generation bump);
defends a **T3 threat the design does not currently claim** -- so it is a correct, well-scoped
hardening, **not urgent** versus logical-layer work. Residual (not a gap in this fix): the CRF
flops themselves are unMAC'd -- a different SPOF outside this lens.

### R6b (folded into R6). Tag-bit integrity

Store the capability Tag as a small ECC/parity codeword (tag + complement + parity), so any
single-cell flip is detected and the load fail-closes to Tag=0/trap. Verifier: the plain
ECC/parity variant is cheap and pillar-clean; a keyed-MAC-over-the-capability variant adds
gate depth on the known-critical Tag/gen check path (Fmax risk) -- **defer the MAC variant**
unless a T3 model is formally adopted. Reframe honestly: this is single-event-upset hardening
beyond the software-forgery model (the bare-tag convention is shared with the whole
tagged-capability field), **not** "closes Pillar 2."

---

## Tier E -- foundation: root of trust and IO authority

### R7. Hardware root-of-trust + measured boot

**Weakness.** The trust anchor -- which objects exist and their Base/Length/Perms/valid/owner
-- is seeded by an `initial begin` block the RTL itself labels a temporary test scaffold.
Reset-into-Machine is the ungated root; there is no measured/secure boot, no attestation
anywhere.

**Radical decision.** (1) An immutable on-die boot ROM + fused device key that, at reset,
**measures** the first-stage image and the initial ODT into a tamper-evident measurement
register before any Object-Bind can succeed. (2) Replace the `initial begin` seed with a
hardware **ODT-seal latch**: the MSA refuses every Bind until the boot ROM has loaded the
initial ODT from a **signed manifest** and extended the measurement. (3) Mint the **first ODA
inside the boot ROM** with ROM-fixed Perms/bounds, so reset-into-Machine is no longer the
root -- the root is the ROM measurement, and Machine-mode inherits only what the measured
manifest granted. **Closes** seed provenance by construction (no capability exists that was
not ROM-minted or monotonically derived from a ROM-measured seed). **Honest limit:** does not
prove the manifest *contents* benign (a signed-but-malicious manifest still seeds an
attributable bad graph -- detectable, not impossible). **Cost:** multi-quarter silicon effort
(ROM, fuses, hash engine, signed-manifest flow, a new must-verify ROM TCB). Adopt as the
silicon-threat-model anchor. **Attaches to:** Phase 3 / boot.

### Rev-F. Attestable lifecycle (append-only measurement of Populate/Destroy)

The red-team's arena-authority-lattice was judged **disproportionate** -- "the ODA-holder can
remap any object" is DESIGN_05's *deliberate* kernel=ODA trust model (the equivalent of "a
privileged kernel can remap any page"), reasoned explicitly against the CHERI revocation
precedent. **Keep only the cheap, pillar-neutral half:** a hardware **append-only measurement
of every ODT-Populate/Destroy** into the boot measurement register, giving attestable
lifecycle operations and after-the-fact detection of a rogue remap. Drop the lattice.

### R8 (IO). Object-based IOMMU -- specify before any second bus master

**Weakness.** DESIGN_05's "object-based IOMMU" is a two-sentence sketch; the RTL models one
bus master (the CPU) and leaves object payloads at raw physical DRAM addresses. A real
DMA-capable device would be an unchecked confused deputy touching object bytes directly,
bypassing the CPU-side check. **Not exploitable today** (no second master exists; the RTL
comments already flag the single-master assumption must be revisited).

**Radical decision.** Move the capability check off the CPU issue-path onto the **memory
boundary**: make the MSA the sole DRAM gatekeeper for **every** bus master. No transaction
reaches DRAM except as an object-relative request {Object_ID, offset, width,
holder_capability}; the interconnect carries **Object_IDs, not physical addresses**, and the
MSA is the only unit that resolves an Object_ID to a physical row. Devices become first-class
ODA-minted capability holders. **Closes** confused-deputy and DMA-bypass by construction (no
path to DRAM skips the check = a complete-mediation reference monitor), and makes "never a raw
address, even internally" *true at the bus* (today Base is a raw physical address the CPU
trusts). **Load-bearing subtlety (verifier):** the CPU fast-path must be designed as
**verified-authority, not a fill-on-miss cache** -- get this wrong and it reopens the bypass or
breaks the cache-less pillar. **Decision:** the IO-ODT must be specified to this standard
**before** any DMA engine or second master is added. **Attaches to:** Phase 8 (IO), gated
ahead of any multi-master hardware.

---

## Deliberately NOT done (rejected findings -- recorded so they are not re-raised)

- **ODT-region authorization bypass via base-ISA store: rejected -- grounding was wrong.**
  `odt_mem` (0x9000_0000) and `elfmem` (0x8000_0000) are **disjoint** SystemVerilog arrays; a
  base-ISA store can only index elfmem and there is no decode routing any address into
  odt_mem. The "MSA-exclusive ODT port, undecodable to base-ISA" that a fix would propose
  **already exists by construction**. Against the *authorization* attacker (no ODA/M-mode) the
  ODT storage is sound; only the *physical-tamper* residual remains, which is R2's job. This
  is a positive result: ODT region isolation is already correct.
- **TCM cross-compartment residency channel: rejected -- weakness invented.** TCM routing is a
  pure static function of Object_ID (never history/frequency-adaptive), so there is no
  warm/cold residency for a same-hart neighbouring compartment to observe. The multi-hart
  *contention* scoping in the frozen doc is correct (that is a shared-arbiter channel, a
  genuinely multi-hart-only concern). No domain-switch TCM flush is needed; partitioning would
  *harm* the k<=17 fully-closed result for zero security gain. (One doc-clarity nit only, and
  that file is frozen/read-only.)

---

## Pillar update and roadmap attachment

The five pillars gain a sixth, first-class: **Provably Non-Speculative Capability
Enforcement** (R5) -- the capability gate is a precondition of access, machine-checked to
survive pipelining. It is the temporal counterpart of the cache-less spatial guarantee.

Attachment to ROADMAP.md phases: **Phase 1-2** carry R1, Rev-A, Rev-B, Rev-E (object-granular
allocation, selective + sweeping revocation, range-gating) -- these are the highest-leverage
T1 closures and co-depend on the 44-bit ID / 256-bit format decision. **Phase 4** must land
R5 as a precondition contract. **Phase 6** binds R3, R4, Rev-C, Rev-D as the multi-hart
reopening checklist. **Phase 3 / boot** carries R7 + Rev-F. **Phase 8** gates R8 ahead of any
DMA. **Silicon-realization phase** carries R6, R6b, R2 (T3 hardening). Every one of these
extends a verified mechanism; none abandons a pillar.
