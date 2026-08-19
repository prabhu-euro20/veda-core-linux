# DESIGN 07 -- Robustness & Security Hardening (adversarial push-back on DESIGN 00-06)

**Status:** Design proposals, adversarially derived. **Method:** a 6-lens red-team
(temporal safety, ODT integrity, multi-hart concurrency, speculation/microarchitecture,
fault injection, boot/IO authority) attacked DESIGN_00-06 + the verified spec + the real
`veda_core.tlv`, and every finding was then checked by an independent skeptic against the
real files for (a) is-the-weakness-real, (b) is-the-fix-pillar-legal, (c) does-it-close-the-
class. 21 findings survived to a verdict: 7 adopted, 10 adopted-with-correction, 2 rejected.
Every claim below cites the real file that grounds it; nothing is asserted from assumption.

**Reading the labels (`R1`..`R9`, `Rev-A`..`Rev-F`):** these number the *findings* in this
document -- weaknesses in the design, each with a proposed hardware-native fix. `Rev-*` is the
revocation family (taking access back). They are **not implementation steps and not an ordered
work plan**: a finding stays open until some increment happens to close it, and several are
deliberately long-horizon. Cite them as "DESIGN_07 R2", never a bare "R2" -- the RTL mirror uses
its own, unrelated `RTL-1` / `RTL-2a` / `RTL-2b` / `RTL-3` increment numbering, and the two schemes
briefly collided because both began with "R". See `veda-core-sindhu`
`veda-core/rtl/LABELLING_CONVENTION.md`.

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

## Tier F -- forward-scaling correctness (a rationale gap, NOT a security/threat finding)

Surfaced by a direct design question ("is 16 CRF entries a future overhead?"), then run
through the same adversarial-verify discipline as the security findings. Labeled honestly:
this is a correctness/rationale/scaling item, not an attack surface.

### R9. The 16-entry CRF rationale does not transfer to purecap -- but 16 is not shown insufficient

**The gap (real).** The frozen CRF verdict justifies 16 entries partly on a §2 argument
specific to the *object-handle* codegen model: pressure = simultaneously-live object-handles,
cheaply re-derivable via Bind from the ODT. That leg does **not** carry to DESIGN_05 Part A
purecap, where every C pointer is a capability-*with-offset*: Bind restores
Tag/Base/Length/Perms/otype but **not** the Offset, so re-Bind stops substituting for
holding/spilling a live pointer value. The verdict is also literally silent on purecap (zero
"purecap" hits; its §6 escape clause frames the revisit trigger as an empirical workload-shape
unknown and never names this structural pointer=capability pressure-conversion, which is
knowable a priori).

**The honest correction (this is where the original finding was overstated).** This is a
*rationale gap + a forward spill-cost question*, **not** a demonstrated insufficiency. Under
purecap, CRF pressure beyond the allocatable limit does not fail -- it saturates and spills as
bounded, **TCM-tier** traffic via OCS.C/OCL.C into the already-built M24 capability-spill
scratch (the cache-less analogue of CHERI's cheap CSC/CLC). 16-entry register files are
routine, well-served compiler targets. And CHERI's 32 is **MIPS-ISA congruence, not a sized
register-pressure figure** (the frozen verdict's own Addendum says so) -- so 32 is not a
benchmark 16 must meet. **Do not claim 16 is insufficient; do not cite 32 as the bar.**

**Actions.** (1) *Now, in the DESIGN_01 respec:* reserve the capability-index pad bits as
index-extension-reserved and close the Sail/RTL decode divergence (RTL must trap a nonzero
index MSB, not alias `c16-c31` to `c0-c15`) -- the format is already 5-bit-shaped, so the
32-entry door is cheap but its bits are decided here, not deferrable to Phase 7. See DESIGN_01
"CRF entry count (16 vs 32)". (2) *Phase 7:* a quantitative purecap **spill-traffic** study
(simultaneously-live capability-register pressure over per-function live ranges on a purecap
corpus, and resulting OCS.C/OCL.C volume against the TCM scratch), plus a rewritten SPEC §2
rationale that no longer leans on Bind-re-derivation for pointer values. That study -- not an
a-priori widening -- decides 16 vs 32. **Pillars:** untouched (index-bit reservation + a
decode guard; no cache, no raw address). **Attaches to:** DESIGN_01 (bits) + Phase 7 (study).

---

## Tier G -- found during implementation, not by the original review

### R10. A CRBR load without a matching restore is a compartment escape

**Found while implementing the DESIGN_08 region table in RTL (increment RTL-4), not by this
document's original panel.** It is a T1 (single-hart) confused-deputy finding, and it is created by
*adding* a feature rather than by omitting one -- which is exactly why it is worth recording.

**The mechanism.** DESIGN_08 Section 4 specifies that the Current-Region Base Register is "set
explicitly at domain entry (OCInvoke)" and stops there. It says nothing about the return path,
about trap entry, or about what happens if the region a live CRBR names is later paged out. Combine
that silence with `veda_region_is_resident`'s deliberate shortcut -- **the current region is treated
as resident without consulting the Region Table at all**, which is precisely what buys the one-read
fast path -- and the hole is immediate:

> Domain A invokes domain B. OCInvoke loads the CRBR with B. OCReturn's only operand is a sentry
> capability, and no saved-caller-region state exists anywhere, so the CRBR is never restored. A
> resumes with **B as its current region**, and the current region is fault-exempt by construction.
> A now holds unchecked, Region-Table-free access to B's entire object namespace, and keeps it
> indefinitely.

A second, independent path to the same state: a trap handler that runs with the faulting domain's
CRBR still loaded can page that domain out, after which "always resident" is simply false and the
stale base points at reused DRAM -- which the hardware would then read as object descriptors.

**The fix, and it needs no new architectural state.** The caller's domain is already carried,
unforgeably, in the capability each crossing operates on. OCInvoke enters a sealed code capability
whose Object_ID's region field *is* the entered domain; OCReturn consumes a sentry capability naming
the caller's code object, whose region field *is* the caller's domain. So:

> **The CRBR is loaded only from the Object_ID of the code capability being entered or returned to,
> and every CRBR load is validated through the Region Table -- never through the fast path.**

The second clause is the load-bearing one: it makes "the current region is always resident" true
**by construction** rather than by software convention, because a CRBR can then only ever name a
region the RT said was resident. Trap entry and `mret` need the symmetric save/restore, mirroring
the `mepcc` discipline (conditional capture, self-consuming) that a real nested-trap bug already
forced on PCC in the RTL.

**Status: IMPLEMENTED AND VERIFIED IN SAIL (2026-08-12). RTL mirror pending.**

The Sail model now loads the CRBR at both crossings from the entered/returned-to code capability's
own `Object_ID[43:24]`, validated RT-direct via a new `veda_region_rt_resident` that deliberately
omits the current-region exemption (using the exempt function would be circular -- a stale current
region would validate its own successor). A non-resident target raises `VEDA_CAUSE_REGION_FAULT`
and commits nothing. Trap entry saves the CRBR and resets to region 0; `mret`/`sret` restores it,
self-consuming, under its own sentinel guard (`VEDA_REGION_NONE = 0xFFFFF`, an out-of-window value
-- region 0 is a *legitimate* region, so "saved == 0" cannot mean "nothing saved" the way
`VEDA_PCC_UNBOUNDED` does for mepcc). Read-only CSRs `0x7C6`/`0x7C7` expose the CRBR and its saved
shadow; read-only is deliberate, since a writable one would be a Milestone-19/20-class self-escape.

**76/76** self-check (72 baseline unchanged -- every existing crossing uses a region-0 code
capability and region 0 is RT-resident-seeded, so the strictly validated load passes -- plus four
new tests). **Mutation-tested 6/6 killed**: both region gates, the `rt_valid` fail-closed conjunct,
the trap reset, the `mret` restore, and the self-consume.

Two obligations this leaves written down rather than assumed: the restore is **infallible** (no RT
re-validation at `mret`, because the model's `mret` path cannot raise a trap -- verified by reading
the dispatch), which is sound only while the Region Table is immutable after reset; **the future
RT-write instruction must refuse to clear residency on the current region and on any saved region**,
or that soundness lapses. **Pillars:** untouched -- no cache, no fill-on-miss; the single register's
load path is now explicit and RT-validated.

**RTL mirror landed too (increment RTL-5, `veda-core-sindhu` commit `c24107e`): R10 is now closed on
both layers.** 62/62 baseline, 62/62 after the mechanism with no new tests (zero regression
demonstrated), 64/64 with two new tests -- which are the *entire* coverage of R10 in RTL, since every
crossing in the pre-existing corpus is region 0. Mutation: 7 of 8 killed, each on its intended test.

The eighth is reported as **surviving**, not dropped: routing the load's validation through the
fast-path-exempt signal reintroduces the circularity, but that is *unobservable by construction*
once every load is RT-validated -- a region can only become current after the Region Table has
vouched for it. It is defence-in-depth, and nothing can distinguish it until an RT-write instruction
exists that could revoke residency underneath a live CRBR. Which is the same instruction the
obligation above constrains.

**Multi-hart generalization is open** and belongs on the Phase 6 checklist alongside
R3/R4/Rev-C/Rev-D: a real multi-hart core must also answer what happens when one hart evicts a
region that another hart's CRBR names. The single-hart answer (hardware refuses to clear `resident`
on the current region) does not generalize for free.

---

## Tier H -- found by adversarially reviewing our own just-shipped increment

### R19 DECIDED -- and the question dissolved rather than resolved

**Status: DECIDED. All three recorded options rejected as posed. The premise was false.**

R19 asked: does supporting `fork()` force this architecture to contain one piece of code that can read
every object? **The answer is no, and it never did.**

`veda_bind_perms` is `if e.cow then e.Perms & 0xFFF7 else e.Perms` (`veda_regs.sail:822-823`, mirrored at
`veda_core.tlv:2795`). The mask `0xFFF7` clears **bit 3 only**. PERM_STORE is bit 3; **PERM_LOAD is bit 2**
(`veda_types.sail:190-191`). So a COW-attenuated capability **is a read capability** -- which is exactly why
the fault is a store fault and not a load fault.

**The principal that takes the 0x0C fault already holds read on the object it needs copied.** The copy is
performed by the faulting domain with capabilities it already has. That is option **(d), self-service**,
which R19 did not list. Options (a), (b) and (c) were all payments to avoid granting an authority the right
party already holds.

**Six corrections to the R19 framing, recorded because they are worth more than the decision.**

1. **The premise is false** -- see above.
2. **"It arrives by accident rather than by decision" is wrong.** Universal content-read already exists two
   ways: `veda.odt.populate.fast` / `page.in` write a full 56-bit physical Base from a GPR with **zero range
   validation**, gated only Machine|ODA; and `veda.bind` needs no capability and no ODA at all -- only the
   domain gate, which every handler passes. It was decided, argued and **quantified**: DESIGN_05 defines
   kernel = ODA holder deliberately, Rev-F rejected the lattice that would remove it as disproportionate,
   and R17 Decision 4 measured the handler exemption at **69 of 76 tests failing without it**.
3. **The 93/93 and 80/80 contain ZERO evidence about copying.** Both "COW repair" tests repair by executing
   `veda.odt.set.cow x28 <- 0` -- **clearing the bit and copying nothing** (`vc_cow_repair.S:88` and its RTL
   twin), and both sidestep the dispatch problem by asserting the faulting index is `c0`. What is verified
   end-to-end is fault -> identify -> clear -> retry. Calling the fork chain "complete on both layers"
   overstated what those numbers cover; the chain is complete **up to the point where the mechanism would
   first do work.**
4. **Option (b) was costed against machinery that does not exist** -- see the correction now struck into
   DESIGN_02. There is no MSA in either layer.
5. **"What settles it is a measurement, not an argument" was wrong twice.** The measurement cannot be taken
   (no DRAM model exists in the repo; the controller is unbuilt and sits in an unstarted phase), and the
   security half needs no measurement at all -- Arm's `CPY*T*`/`CPY*RT*` variants demonstrate in production
   silicon that hardware can copy without the issuer exercising its own authority over the source.
   **A throughput measurement must never be allowed to decide a security question.**
6. **The hard part was never the copy. It is the rename.** `csetbounds` and `CAndPerm` preserve Object_ID and
   generation while carrying a different cached Base, and there are 16 capability registers plus unbounded
   tagged spills -- so a domain routinely holds **N capabilities to one object, only one of which faults**.
   Rebind that one and the other N-1 silently keep reading the pre-copy object while writes land in the copy.
   **The domain's view of its own memory forks in two, and nothing traps.** Hardware cannot even detect it:
   there are no back-references from objects to capabilities, and the only per-entry lever is the generation
   bump, which is indiscriminate.

**Why option (b) is rejected on official precedent rather than taste.** IBM shipped the interruptible
whole-operand copy in 1964 (MVCL), held the interruptible category to seven instructions for the
architecture's life, documented a real machine taking a protection exception where "the move continues into
the subsequent blocks of the first operand, which are not protected" with the progress registers possibly
stale -- and then **replaced it**: the z/Architecture Principles of Operation carries a section titled
"Condition-Code Alternative to Interruptibility", and MVCLE is explicitly intended for use in place of MOVE
LONG because it is *not* interruptible. Arm needed an entire new exception class for MOPS solely because
half-done copy state is not portable between PEs, and ships **no interrupt-latency bound**. RISC-V has
ratified **no** unbounded-length memory instruction.

**Why option (c) is rejected by its own only shipping precedent.** z/Architecture's key-crossing moves are
per-invocation copy authority validated against a revocable key mask -- exactly (c)'s structure, in silicon
since S/370 -- and they demonstrate its flaw: MVCOS lets problem-state code fetch under another key into
storage it owns and then read the result. **Authority-to-move is authority-to-read.** Every proposal this
round that let software name the destination frame died on precisely this, in four independent attacks.

**What IS ratified as hardware:** only the COW fault's own eligibility predicate -- who is entitled to cause
a split. That is where a real security problem remains and where hardware is the right answer.

**Recorded but NOT ratified:** if a hardware copy is ever built, its shape is settled -- a bounded **fixed
32-byte granule** (simultaneously the widest existing single transaction in both layers and exactly the tag
granule, so one step carries exactly one tag and the multi-granule interaction is avoided rather than
tested), software loop, cursor in an ordinary GPR, per-step re-validation from the live ODT, destination
unbindable until the last granule lands, and **no software-nameable source and no software-nameable
destination frame** -- both from a hardware-written fault record. It is not built now because after
correction 1 it buys no security property that `fork()` needs, and the hardware-first rule is conditional on
there being a security problem for hardware to solve.

**Prerequisite filed separately and independent of all of this: copy-on-write is BYPASSABLE in the shipped
default.** `ext_reset` sets `veda_mode = zeros()`, so purecap is OFF, and ordinary base-ISA `ld`/`sd` never
consult `entry.cow`. A plain `sd` to a `CGetBase`-derived address defeats COW entirely, and a trap handler
runs with unbounded PCC by design. **COW is advisory until this is closed, and no copier decision changes
that.** See also R22, which is the same disclosure surface seen from the other side.

### R23. Two RTL-only defects found while grounding the R19 reorder -- one is an out-of-object write

**Status: BOTH FIXED IN RTL. Neither is proven by the suite; their tests are owed.**

Neither was the thing being looked for. Both surfaced because the R19 check-reorder was sent for
adversarial review BEFORE implementation, and two independent lenses read the capability paths.

**(a) The capability bounds check asked whether SIXTEEN bytes fit, for a THIRTY-TWO byte access.**

`$veda_oclc_bounds_ok` used `65'd16`. The access is a whole 256-bit capability -- confirmed three
independent ways: `$veda_ocsc_packed[255:0]` (:3215), `$veda_oclc_load_data[255:0]` (:4994, whose
own comment reads *"a capability is 32 bytes now -- both arms read 32, not 16"*), and the elfmem
store extent `+0..+31`. Sail has always passed `32` (`veda_ocl_insts.sail:188` and `:224`), so this
was **RTL-only**.

The hole, concretely: for an object of Length `L`, offset `L-16` satisfies `(L-16)+16 <= L`, so the
check **passes** -- and the access then reads or writes through `Base+L+15`, **sixteen bytes past
the object**, with a valid capability and no trap. That is a real out-of-object write primitive,
not merely a mis-reported cause. Same class as R18's wrap, found the same way: by reading the width
rather than trusting the check.

It also made the R19 reorder's headline promise false. That reorder guarantees "an out-of-bounds
store to a copy-on-write object reports 0x01 and never arms a copy" -- with this width, a store 16
bytes past the object is not seen as out of bounds at all, falls through to the new bottom arm, and
reports 0x0C. **Shipping the reorder first would have made its own guarantee false on two of seven
chains, with no test to say so** -- the "applied to four of five arms" shape this record already
names three times. Hence fixed FIRST, on its own.

**(b) `veda.rebind` did not strip store permission from a copy-on-write object, three lines below
the arm that does.**

The Bind arm masks with `16'hFFF7` when the entry is cow. The Rebind arm, three lines below and
directly under a comment stating *"a copy-on-write object never hands out store permission, however
often it is bound"*, handed out `$veda_odt_perms` verbatim with no cow test. **The file contradicted
its own written intent** -- the identical shape as the CAndPerm defect, where a derivation arm
silently kept a right its neighbour strips. Sail masks both paths (`veda_bind_insts.sail:308` and
`:341`). RTL-only divergence.

Not a copy-on-write escape by itself -- `$veda_cow_write` reads the ENTRY, so a rebind-derived
capability still traps 0x0C. But it makes R19's "the two bit patterns are indistinguishable"
argument **Sail-only** today, which matters because that indistinguishability is the whole reason
the eligibility predicate is open.

**What 80/80 proves and does not.** The suite passes with both fixes. That proves **no regression**
and nothing more: no existing test stores at offset `L-16` through a capability, and none rebinds a
cow object and inspects the resulting Perms. **Both tests are owed and are tracked.** Recording this
distinction explicitly because the same sentence -- "the suite is green" -- has already been shown
twice in this document to mean far less than it appears to.

### R19 increment 1 -- every refusal now precedes every repair, on both layers

**Status: DONE. Sail 94/94, RTL 82/82, seven mutants killed with per-phase attribution.**

**The rule, stated once and applied everywhere.** A cause chain has two classes of arm.
*Refusals* (0x02 tag, 0x03 seal, 0x12/0x13 perms, 0x1f NMC, 0x08 alignment, 0x01 bounds) say
"never allowed"; order among them is cosmetic. *Repairs* (0x0A residency, 0x0C copy-on-write) say
"fix something and retry", and **each one arms real work in a handler** -- a page-in, or an
allocate-copy-mint. Raising a repair for an access a refusal was going to reject anyway arms that
work for nothing. **So every refusal precedes every repair.**

That rule was already written down in this codebase, for residency, in its own words -- "raised only
for an access that would otherwise have SUCCEEDED. That is an information-flow property." The cow
arm violated it from the day it landed, sitting third in every chain.

**0x0A precedes 0x0C**, because you cannot copy an object that is not in memory: the handler would
dereference a Base whose frame the pager may already have reassigned.

**The gate is what makes the move possible.** `veda_bind_perms` masks a cow object's Perms with
`0xFFF7`, clearing PERM_STORE and leaving PERM_LOAD, so a freshly bound capability lacks store **by
construction**. Moving cow below the permission arm without gating would make every fork-triggered
write report "you may not write" instead of "copy me" -- copy-on-write would never fire at all. The
permission arm is therefore gated on `not(entry.cow)`, and the old order's property is preserved
exactly, by the gate rather than by precedence.

**Corrections to the proposal, made before it was built.** The reorder was sent for adversarial
review first, and three of its claims were wrong:

- **"This closes rights amplification" is FALSE.** A principal that can trigger 0x0C out of bounds
  can trigger it at offset 0 and get the same private copy. There is no rights delta. Ship this as
  ordering hygiene and resource containment, never as closing amplification.
- **The one genuine closure is a different one.** `veda_setbounds` with rs2 = 0 constructs a tagged,
  generation-current capability of **Length 0 in one instruction**. Under the old order that
  zero-entitlement capability stored, reached the cow arm before bounds was consulted, took 0x0C,
  and a handler would have rebound it to a **full-Length** capability minted from the entry. Under
  the new order every offset is out of bounds, so it can never arm a split.
- **"Every capability to a cow object lacks store" is too strong.** The parent's pre-cow capability
  retains it -- that is the fork case, and it is why the fault reads the ENTRY, not the capability.

**Alignment had to be hoisted, and that was not in the proposal.** Sail's 32-byte alignment test
lived in the OCL.C / OCS.C **callers**, after the checker returned Ok; the RTL's has always been an
arm inside the chain. Moving cow last without hoisting would have made a misaligned store to a cow
object report 0x0C in Sail and 0x08 in RTL -- a divergence created on a state where the layers agree
today. Hoisting also closed two pre-existing divergences nobody had noticed (misaligned + out of
bounds, and misaligned + non-resident).

**0x0C is NOT the fallthrough.** The RTL default is deliberately hostile (`5'h02`) with every arm
explicit. 0x0C is the only cause in the machine that instructs software to hand back a fresh
writable object: a spurious 0x0A makes the pager refuse loudly, a spurious 0x0C **succeeds
silently**. All seven chains now have one shape, diffable against Sail arm for arm.

**Untouched on purpose:** the violation OR-expressions. They also feed R21's stall gate, and
restructuring one is the single way this edit could reopen R21. The trap set is provably unchanged:
`(cow) | (!STORE)` and `(!STORE & !cow) | (cow)` both reduce to `cow | !STORE`.

**Why the corpus was blind to all of this.** No test in either layer made an access fail **more than
one check at once**, so nothing could observe which cause won. That is the whole reason the defect
survived. `vc_check_order.S` and `veda_smoke_check_order.S` are the first.

**The mutant that survived, and what it exposed.** Removing the `not(entry.cow)` gate was caught by
**nothing** in a 94-test Sail corpus. The existing copy-on-write tests inspect the attenuated
capability with CGetPerm and **never dereference through it** -- attenuation tested as bookkeeping,
never as enforcement, the identical shape as the CAndPerm defect. Phase D exists because that mutant
lived, and it is the phase that now kills it.

**Verification.** Sail: 3 mutants, 3 killed (whole reorder, the gate, cow-above-residency). RTL:
7 mutants, 7 killed -- **one per cow-bearing chain, each breaking exactly one phase and no other**,
which is what proves the edit reached all five rather than four. Pristine restored byte-identical
and re-run on both layers.

**One process failure worth recording.** After the first Sail mutation sweep the source was restored
but the model was **not rebuilt**, so the next run measured a mutant's binary and a correct new test
looked broken. Caught by running the simulator under an instruction trace rather than assuming the
test was wrong. Restore-then-rebuild, always -- the same contaminated-sweep class already recorded
for the RTL.

### The audit: a differential harness, a mutation census, and what they found

**Status: harness and census BUILT. First work item (temporal safety) CLOSED on both layers.
Sail 95/95, RTL 83/83. Census 22 survivors -> 16.**

Three separate things get called "audit" and they have different readiness conditions. An
implementation audit was the least valuable -- four had just been done on the same warm surface. A
design audit would have spent its budget rediscovering already-recorded open questions, since three
of five pillars are already documented as not-what-the-docs-claim. **The one that was ready, and by
far the most valuable, was a COVERAGE audit: does the verification actually verify?** The evidence
for that was not opinion -- it was four independent facts from this session's own work: the
copy-on-write gate mutant survived a 94-test corpus; no test in either layer made an access fail two
checks at once; R15 and R23a were paths with no check at all; and both "COW repair" tests repair by
clearing the bit and copying nothing.

#### The cross-layer differential harness

Sail and the RTL are **two independent implementations of one specification**, so any behavioural
difference is a bug in one of them -- and **nothing compared them**. The two corpora are not even the
same programs. Three RTL-only defects in this project were found by a human reading code and none by
a test.

`veda-core/difftest` closes that. One probe, both layers, compared byte for byte through the
**official RISC-V arch-test signature mechanism**. It asserts nothing; divergence is the finding.

On its first real run it found `veda.rebind` behaving differently on a never-bound register.

#### R24 -- my proposed fix was REFUTED, and the real defect is larger

I proposed requiring `veda.rebind` to refuse unless its destination is TAGGED, on four grounds.
**All four fell, and the decisive one is that the fix does not deliver its own primary purpose:**
c11 and c12 are seeded TAGGED on *both* layers, so both would pass the new check and then diverge
anyway on otype. It converts a 13-register divergence into a 2-register divergence of identical
shape -- a narrower accident, not agreement by decision. Ground (2) and ground (4) also contradict
each other: if the preserved Offset is garbage worth refusing, the encodings are not redundant; if
they are redundant, nothing garbage is carried. And ground (3) is self-refuting -- a check that tests
"tagged" cannot be the fail-closed guard for state that is *undefined*, since four to five registers
come out of reset tagged and holding fixture contents.

**It was never a rebind problem.** `cgettype x3, c0` on a reset machine returns 0x0000 on Sail and
0xFFFF on the RTL -- one instruction, no rebind, and the query family is deliberately ungated.

A probe measuring all 16 registers x 6 queries as the first instructions after reset found
**16 of 16 capability registers diverge**: c0-c9 and c15 on otype alone, c10-c14 on tag, otype,
perms, base and length. Sail's reset otype of 0x0000 sits inside the sealable range CSeal mints
from, so **every unwritten Sail register is indistinguishable from one deliberately sealed with type
zero**, while the RTL's own comment states "0xFFFF (the default) means UNSEALED".

The codebase already learned this exact lesson and failed to generalise it: `step_ext.sail` records
that leaving `veda_pcc_length` at Sail's default zero-initialisation would hard-trap on cycle one and
calls a defined reset *"a real correctness requirement, not defensive styling"*. Every Veda register
got that treatment in `ext_reset()`. **The capability register file is the only one that did not.**

Not fixed in this increment, deliberately: the reset seeds are scaffolding for states unreachable
through the ISA by design (the R10 region-crossing fixtures, the DESIGN_02 residency fixture).
Deleting them naively deletes the `rt_valid` negative test and the dereference-side residency test.
They must MOVE to a layer-parallel injection, and that is its own increment with real coverage risk.

#### The mutation census -- 22 of 54 checks were unverified

Every dereference path decides two things: whether a trap fires (the `*_violation` OR-expression) and
which number a handler reads (the `*_cause` chain). The cause chain is only consulted when the
violation fires, so **the violation expression is the enforcement layer**. Removing one term at a
time from all seven of them -- 54 mutants, full suite each -- produced **22 survivors**: checks
present and correct today that nothing would notice being deleted tomorrow.

Three shapes, none of them a coincidence:

1. **The two most security-critical checks were the least verified.** `$veda_gen_stale` and
   `$veda_sealed` each survived on **six of seven** chains.
2. **Coverage falls off as the path gets less ordinary** -- 1/6 unverified on plain load, rising to
   5/9 on NMC_ADD.W. Precisely the paths where R15 and R23a were found.
3. **One of my own tests passed for the right reason on one axis and the wrong one on another.**
   `veda_smoke_check_order.S` P3/P4/P5 drive the NMC and atomic chains through a Length-0 capability
   and assert BOUNDS, yet the bounds term survives its mutant on all three -- because the object is
   *also* copy-on-write, so cow fires the trap and the cause chain still reports 0x01. Those phases
   verify the cause ORDER and not the trap DECISION. **A hand-written test could not have found that.**

#### Temporal safety closed -- the first work item, both layers

`$veda_gen_stale` **is** the use-after-free defence. Delete it on six of seven paths and a stale
capability reads and writes freed memory with no trap, and every one of 82 tests stays green.

The construction is the whole point. The check is `(!valid) | (generation mismatch)`, so merely
destroying an object proves only the validity half -- which any validity check would also catch. The
half that matters is the other one, so `vc_uaf.S` / `veda_smoke_uaf.S` **destroy and then RE-POPULATE
the same slot**. Afterwards the stale capability is tagged, unsealed, permitted, in bounds and
resident; **only the generation differs**, so nothing else can refuse it. That is the real shape of
use-after-free: the object is freed, **the slot is reused**, and an old pointer must not reach the new
occupant. A control phase proves a fresh bind to the same object still works, so the refusal is the
generation and not the object.

Object 20 is minted fresh rather than reusing a fixture, because the difftest had just shown all 16
capability registers diverge at reset -- a temporal-safety test built on a fixture would inherit that.

**No model or RTL change was needed. The checks were already correct; they were unverified.**

Verification: six RTL mutants (one per chain) now all killed by this test, census 22 -> 16. Two Sail
mutants killed. The Sail NMC mutant was killed by **this test alone**, so that path's generation
check was unverified on the Sail side too. Pristine restored and rebuilt on both layers.

### R34. The boot context has ambient authority -- ACCEPTED as architecture, with the scope corrected

**Status: MEASURED AND ACCEPTED. No change made to the purecap gate, and the reason is recorded so it
is not re-proposed. One real defect was found while investigating it -- R35, below.**

Measured on BOTH layers and in agreement, so this documents architecture rather than a divergence
(`difftest/probes/p12_ambient_boot.S`). From the reset context an ordinary `sd`:

| | |
|---|---|
| writes a **copy-on-write** object | the COW fault never fires |
| writes **past** the object Length | lands |
| writes a **load-only** object | lands |
| **destroys a capability tag** | silently |
| traps taken | **zero** |
| *control:* the same write through the capability path | **traps** |

**THE SCOPE IS BIGGER THAN I FIRST RECORDED, and the correction came from the adversarial pass on my
own entry.** I wrote that this is "precisely the unbounded boot context". It is not. `veda_pcc_save_and_reset()`
(`veda_regs.sail:235-247`) sets `veda_pcc_length = VEDA_PCC_UNBOUNDED` and `veda_pcc_base = zeros()` on
**every trap**, and a trap never touches `veda_mode` -- verified by grep, there is no assignment to it
on any trap, save-and-reset or xret path. So with purecap off, **every trap handler re-enters the same
unchecked ambient context as reset.** The window is reset PLUS every trap, not reset alone.

That is not an escalation -- the handler at `mtvec` is trusted code, and `mtvec` is Machine-gated, so
the ambient context is entered by the code reset already trusts, exactly as with the `Machine`
disjunct. But it changes how *often* the unchecked path is live, and any future audit or provenance
story has to account for a window that opens on every fault rather than once at boot.

**The scope is still narrower than "purecap is off" in the other direction, and that part holds.**

    $veda_purecap_violation = ($is_load || $is_store) &&
                              ($veda_mode[0] || ($veda_pcc_length != UNBOUNDED))

The second disjunct means **every bounded-PCC context -- every compartment -- already refuses ordinary
memory access regardless of the mode bit.** This is precisely the unbounded boot context: the one
context whose authority nothing derived. And fetch is the same shape -- `$veda_pcc_violation` also
keys on `pcc_length != UNBOUNDED`, so at reset instruction fetch is unchecked too.

**MY OWN PROPOSAL WAS REFUTED, and recording why is the point of this entry.** I argued that in an
address-less machine the primordial authority is not *addressing* but *naming*, that the ODA already
is that root, and that the fix was to mint a root ODA at reset and delete the
`cur_privilege == Machine |` disjunct. Three independent findings killed it:

1. **It denies nothing.** With the root minted at reset, the set of principals that can mutate the ODT
   is *identical* before and after. It is a change of provenance, not of extent -- and it recreates
   exactly the emptiness that correctly killed the purecap latch: an authority gate whose authority no
   reachable context lacks denies nothing. Four existing tests that prove the gate exists
   (`vc_umode_compartment_basic.S`, `veda_smoke_m4_neg.S`, `veda_smoke_m11_neg.S`,
   `veda_smoke_paging_refusals_neg.S` part D) would have had nothing left to prove.
2. **It does not touch the finding it is named after.** R34 is the purecap gate on ordinary load/store;
   the proposal modifies neither line. After it lands, every measured bypass above still happens.
3. **It would make things worse.** `OSpecialRW` is Machine-gated on both layers, so a U-mode
   compartment would *inherit* the root ODA through OCInvoke and **never be able to shed it**.

Removing the disjunct alone is not an option either: verified by provenance, `veda_oda_tag` resets
false, the only writer is `OSpecialRW`, which needs a capability already carrying PERM_ACCESS_SYSTEM_
REGISTERS, and the only way to set that bit in an ODT entry is the Populate the gate just closed.
**The authority graph would have no root and the machine would brick.**

**And the `Machine` disjunct is not a hole.** Untrusted code cannot reach Machine except by causing
trusted code to run: Machine is set at reset, on trap delivery into `mtvec` (Machine-gated), and by
`MRET` (itself Machine-guarded, target from `mstatus.MPP` which only Machine can write). The disjunct
grants naming authority to precisely the code reset already trusts.

**One recorded sentence is wrong and is corrected here.** R26 states Veda-Core has "no root-capability
analogue". The model's own comment contradicts it: `veda_regs.sail:85` invokes the almighty-root
convention as the stated model for `veda_pcc_length`'s unbounded reset. The gap R26 named does not
exist in the form it named it.

**What remains open is not this.** It is R7's already-adopted answer -- mint the first ODA inside a
*measured boot ROM*, not at reset -- and the measured cost of closing the ambient path at all: the
test **programs** barely use ordinary memory (9 of 99 Sail files, 7 of 94 RTL files), but **all 14
differential probes do**, because the signature and `tohost` conventions are plain stores. The cost of
purecap-at-reset is harness-shaped, not program-shaped, and that is a much better starting position
than it appeared. Folded into R7.

### R35. veda_attr had no privilege term -- an RTL-only authority grant, found while refuting R34

**Status: FIXED AND VERIFIED. RTL 89/89, mutant killed.**

Five compartment-state CSR write arms. R27 added `&& >>1$priv` to four of them. **`veda_attr` (0x7C4)
sat between them and did not get it** -- I walked past it in that increment.

Sail refuses the write: `csrPriv(0x7C4)` is bits [9:8] = `0b11`, Machine-only by the RISC-V
convention, enforced by the generic `check_CSR_priv` before any Veda clause runs. So this was an
**RTL-only authority grant**, the same shape as every other finding this session: a gate present on
one layer, absent on the other, on a path that feeds authority.

**What it granted, at its real size.** `veda_attr` supplies Length and Perms to Populate-Fast. It is
not itself a mint. But a principal after `veda.droppriv` -- holding neither privilege nor a tagged ODA
-- could **choose the Length and Perms of an object that a later privileged Populate-Fast will mint.**
Control over the contents of someone else's mint, which on a machine whose thesis is derived authority
is exactly the wrong direction. The test drives it with the worst case: unbounded Length plus
Execute|Invoke.

**Only the privilege term shipped, and the companion is REFUTED BY MEASUREMENT.** The obvious next
step -- adding `$csr_is_veda_attr` to `$veda_csr_escape_violation` so a *compartment* cannot stage it
either -- would break `veda_smoke_m14.S:66`, `veda_smoke_r11b_pin.S:127` and
`veda_smoke_r11_crossing_neg.S:169`, all of which write 0x7C4 from **inside** a compartment with no
`ocreturn` or trap in between. **They are not test bugs.** They are the documented return path: leaving
a compartment needs a max-Length code object, so the compartment must be able to stage the descriptor
that builds it. Blocking that would break the architecture's own way out.

Measured before editing: **no test in the corpus writes 0x7C4 after `veda.droppriv`**, so the privilege
half costs nothing.

**A second correction to an earlier entry, from the same pass.** R27 added a `cur_privilege == Machine`
test inside `write_CSR(0x7C0..0x7C3)` on the Sail layer. **That arm is inert.** `doCSR` calls
`check_CSR_result` -> `check_CSR` -> `check_CSR_priv` *first* (`sys/sys_control.sail:38-41`, composed
at `:54-59`), and `csrPriv` for those addresses is bits [9:8] = `0b11` = Machine, so `write_CSR` is
unreachable at any lower privilege and the inner test can never be false. The behaviour is correct;
the record overstated what that half of R27 did. **Only R27's RTL mirror was ever live** -- which is
also why R35 mattered: on the layer where the term does work, one of the five arms did not have it.

### R44. An unallocated encoding whose refusal cause leaked ODT state -- and the probe that watched it was blind twice

**Status: FIXED AND VERIFIED ON BOTH LAYERS. Sail 102/102, RTL 90/90, ACT4 51/51, differential 21/21.
The fix ADDS NO MECHANISM -- it moves one condition into the decode. Found by the adversarial pass on
R1, because `veda.bind` mode `0b11` is the exact encoding slot SLAB-CARVE would occupy and the two
layers had to be made to agree about it before anything could be built there.**

`veda.bind` mode `0b11` is `VEDA_BIND_RESERVED`. Both layers agreed it must trap. **They disagreed
about why, and the difference was a function of state the instruction was never entitled to consult.**

| | before |
|---|---|
| **Sail** | reached `VEDA_BIND_RESERVED => Illegal_Instruction()` only AFTER three state-dependent traps had had their chance -- region residency (`REGION_FAULT 0x09`), the per-object domain gate (`DOMAIN_VIOLATION 0x0B`), object residency (`RESIDENCY_FAULT 0x0A`) |
| **RTL** | mode `0b11` is absent from `$veda_decoded`, so it is `$veda_undef_encoding` and refused **at decode** -- `Illegal_Instruction` unconditionally, with the three fault signals gated on the three real modes only |

**MEASURED BEFORE THE FIX** (`difftest/probes/p19_bind_reserved_mode.S`, against region 2, which both
layers seed valid-but-non-resident so the reproduction needs no setup):

| word | Sail | RTL | after |
|---|---|---|---|
| mcause | **0x18** (a Veda trap) | **0x02** (illegal instruction) | 0x02 on both |
| mtval | **0x49** = (c2 << 5) \| 0x09 REGION_FAULT | the raw instruction word | the raw word on both |
| control, region 0 | 0x02 | 0x02 | unchanged |

**WHY IT MATTERS BEYOND PARITY.** On Sail the refusal cause for an **unallocated encoding** depended on
another domain's paging state. That is a small **ODT oracle**: unprivileged code can issue
reserved-mode binds and learn, from the cause alone, whether a region is resident or whether a domain
matches -- about objects it has no right to. An instruction's *legality* must not depend on the state
of a table it was never entitled to read.

**THE FIX DELETES A SPECIAL CASE RATHER THAN ADDING A CHECK.** The `encdec` clause gains
`& mode != 0b11`, so mode `0b11` **does not decode at all** and the model's own wildcard clause catches
it -- `mapping clause encdec = ILLEGAL(s) <-> s` in `postlude/insts_end.sail`, whose own rule R30
already cited by name: *"the encdec mapping must come last to ensure that all unmatched encodings
decode to an illegal instruction."* An unallocated encoding is now refused by the same general
mechanism as every other unallocated encoding, instead of by a hand-written arm that ran too late.
The `VEDA_BIND_RESERVED` match arm stays -- Sail requires exhaustiveness -- marked unreachable by
construction, so that if it ever fires again the guard has been lost.

**AND THE PROBE THAT SHOULD HAVE CAUGHT IT WAS BLIND TWICE OVER.** `difftest/probes/p5_reserved.S`
exists to prove unallocated encodings are refused. It used `Object_ID 1` -- region 0, resident,
`owner_domain` ANY -- so **all three Sail gates pass and it measured the one case where the layers
already agreed**. And its handler counted traps and read `mepc`, **never `mcause`**, so even a
different cause would have been invisible. It has reported AGREE throughout. Both blind spots are
closed: p5 now records the cause of each of its three refusals.

**That is the fourth time in this pass that a green test turned out to pin the wrong thing**, after
`veda_smoke_r27_csr_priv.S`, `vc_check_order.S` PHASE D and `vc_ocl_ocs_c.S`. **Counting a refusal is
not checking it.**

### R45. Aliasing ODT entries are unchecked, and the executing-object pin is name-scoped while its guarantee is memory-scoped

**Status: MEASURED, THEN FIXED AND VERIFIED ON BOTH LAYERS. Sail 103/103, RTL 90/90, ACT4 51/51,
differential 21/21. The reproduction came first and is kept as the test.**

**WHAT WAS DECIDED, AND THE LINE IS DELIBERATE: aliasing stays legal; the pin becomes memory-scoped.**
Two names for one range is not itself a defect -- SLAB-CARVE (R1) mints children *inside* a parent's
window by construction, so a machine that refused overlap outright could never carve. What was wrong
is that a pin whose whole purpose is *"do not evict the memory the CPU is executing from"* was
comparing **names**.

**MEASURED FIRST.** `sail_tests/vc_r45_odt_alias_neg.S` populated 800 and 801 at the same Base --
neither refused -- stored through one and read it back through the other; then, from inside a live
compartment executing object 810, populated 811 at 810's own Base and paged it out. **Both succeeded.**
Its control showed the pin still refusing 810 itself, so the mechanism was not broken -- it was
looking at the wrong thing.

**THE FIX IS O(1) AND NEEDS NO DISJOINTNESS TABLE.** Enforcing disjointness at Populate would mean
testing a new window against every live entry -- 2^23 in this model -- which is not a hardware
operation. The pin does not need that: it needs **one** window, the one being executed, and that is
two live registers. One range overlap, computed 57 bits wide because Base is 56 and Length is 40 and
**R18 was a bounds check that wrapped at its own width**.

**MY FIRST DRAFT WAS REFUTED BY THE CORPUS, IN THE CONTROL THAT EXISTS FOR EXACTLY THIS.**
`vc_r11b_executing_pin_neg` PART D: *"an unrelated object is still evictable while a compartment runs.
Without it, a core that refused every eviction outright would pass everything above."* Its CODE object
is populated with Length UNBOUNDED, so the window covered all memory and my arm **refused every
eviction on the machine.** It caught it on the first run. The arm is now gated on a **bounded**
compartment: an unbounded PCC describes no region, so the window test degenerates rather than being
conservative, and R26 already settled that the **name** is the trustworthy predicate there.
**The residual is stated rather than hidden:** a compartment entered on an unbounded code object still
gets only the name pin.

**AND MY OWN TEST WAS WRONG ABOUT THE LINE, WHICH SHARPENED IT.** It asserted that *minting* a fresh
alias at the running Base would be refused. It is not, and the fix is not what was wrong -- the
assertion was. A name that does not exist yet has no window to compare, and creating a second name for
memory harms nothing. **Creation is free; the alias is useless as an eviction handle.** The test now
proves both halves, plus a disjoint control that still evicts cleanly.

**A TESTING CONSTRAINT THIS CORPUS HAD NEVER HIT, worth keeping.** Inside a *bounded* compartment the
purecap rule refuses every ordinary load and store, and `RVMODEL_HALT_PASS` stores to `tohost` -- so a
test cannot halt or branch to a failure label from inside one. The other pin test never met this
because its compartment is UNBOUNDED, which is the single structural difference between the two files.
The body records; the assertions run after an `ecall` escape that clears the saved bound first.

*(The finding as first derived follows.)*

**No disjointness check exists anywhere.** Populate takes `Base` verbatim
(`veda_ocl_insts.sail` Populate and Populate-Fast), and a grep for `overlap|disjoint|intersect` across
the Veda model, `veda_core.tlv` and `VEDA_CORE_SPEC.md` returns only unrelated hits. **Two Object_IDs
may name the same memory.**

R11(b) pinned the executing object so a Populate cannot pull the ground out from under running code.
But the pin is an **identity test on the name**:

    veda_object_is_executing(object_id) = (object_id == veda_pcc_object) | (...== veda_mepcc_object)

while the property it is protecting is about **memory**. So an authority holding Machine or a tagged
ODA -- R11(b)'s own stated adversary -- can Populate a **second name** at the **same Base** as the
running compartment's code object and then page *that* name out: the pin compares 190 against 180 and
passes. Fetch cannot notice, because `ext_fetch_check_pc` compares the PC against PCC's **cached**
bounds only.

**HONEST SEVERITY.** Nothing is corrupted in-tree today: there is no pager acting on the answer, and
the eviction only clears the second name's `resident` bit and bumps its generation. What is wrong is
the **architectural statement** -- and the RTL sets that standard itself for the converse case, where
its own comment says a silent refusal *"is worse than either trapping or succeeding, because the pager
then reuses memory it does not own"*.

**THE CORPUS CANNOT SEE IT.** `vc_r11b_executing_pin_neg.S` PART D is the over-refusal control and
populates its second object at a **disjoint** label. So the suite covers the disjoint case and the
same-name case and **nothing in between**. No test in any corpus populates a second object at an
already-live Base.

**BEARS DIRECTLY ON R1.** SLAB-CARVE mints child objects *inside* a parent's window by construction --
aliasing is not an edge case there, it is the mechanism. A carve design cannot be built on an ODT that
has no opinion about overlap.

## REGISTER INTEGRITY AUDIT -- the four numbers that had no entry, and why

**Prompted by a direct question about the numbering, audited across all three repositories by
enumerating every `R<n>` reference in every `.md`, `.tlv`, `.sail`, `.S`, `.sv`, `.sh` file and in
every commit message, then differencing that against the `###` headings in this file.** Four numbers
had no entry: **R18, R25, R27, R28**. Three of them are **shipped, verified hardware fixes**, and two
of those are exploitable-class. **The record understated what this machine already defends against.**

**THE THREE CAUSES ARE DISTINCT AND ALL REAL:**

1. **Two numbering series ran in parallel.** RTL-side increments were numbered `RTL-1..RTL-18` while
   findings were numbered `R1..`. **R18 landed as "RTL-16 (R18)"** and was recorded under the RTL
   number, so it never got an `R` heading here.
2. **Co-committed findings inherit the other one's entry.** **R28 shipped inside commit `dfd4ec6`,
   "R26 + R28"**. R26 got the heading; R28 rode along in the same commit and in the same source
   comment block, and was never lifted out.
3. **One number was simply skipped.** **R25 appears NOWHERE** -- not in any document, any source file,
   any test, or any commit message in any of the three repositories. It was never allocated.

**THE LESSON, WHICH IS THE SAME ONE THIS FILE KEEPS LEARNING.** A record that is missing entries is
not neutral: it made three real defences invisible, and it would have let a future reader conclude the
bounds check had never been audited for wrap. The gaps are closed below, reconstructed from the
primary records -- the source comments and the commits -- rather than from memory.

### R18. The bounds check wrapped, and it was straightforwardly exploitable

**Status: FIXED AND VERIFIED, long since. Shipped as "RTL-16 (R18)" in commit `4433e87`, live at
`veda_core.tlv:3441` and `:3501`, with its own negative test `veda_smoke_bounds_wrap_neg.S` in the
passing corpus. Back-filled here because it had no entry.**

The bounds addition was **64 bits wide on both sides**, and the offset is a full, attacker-chosen
64-bit GPR. **`offset = 0xFFFFFFFFFFFFFFF8` makes `offset + 8` wrap to 0**, so `0 <= Length` passes --
and the address computation is a modular 64-bit add too, so it lands at **`Base - 8`**. Every other
term of the violation is satisfied by a perfectly ordinary capability: tagged, in-generation,
unsealed, permitted, resident. **The access retires with no trap, reading and WRITING the eight bytes
immediately below the object** -- in a packed allocator, the tail of the neighbouring object.

**SAIL COULD NOT EXPRESS THE BUG.** Its `unsigned()` yields an arbitrary-precision integer, so
`unsigned(offset) + width` cannot wrap. **The model was right and the hardware was wrong** -- and this
is the shape of divergence a differential harness finds only if a probe happens to enter the state.

The fix does the arithmetic one bit wider than the widest operand, so the carry has somewhere to go:
`2^64-1 + 16` needs 65 bits, and at 65 bits the sum is far larger than any 40-bit `Length`.
**Widening the COMPARE is what matters** -- clamping the offset instead would silently alias a huge
offset onto a legal one, which is the same bug wearing a hat.

### R27. The weaker gate was on the stronger authority

**Status: FIXED AND VERIFIED. Shipped in commit `949c937`, live at `veda_core.tlv:5327`, with its own
test `veda_smoke_r27_csr_priv.S`. Referenced four times in this document and never given a heading.
Back-filled.**

Milestone 20 gated five compartment-state CSRs together, so a compartment could not rewrite its own
execution bounds or forge its own trap return -- **but only 0x7C5 ever got the privilege term.** The
four that rewrite PCC and MEPCC directly carried the PCC-bounds half alone. **The weaker gate was on
the stronger authority.**

It is also what turned R26 from a partial escape into a complete one: once the "am I in a compartment"
predicate is forged by entering on a sentinel-Length object, **these** are the CSRs that let the
compartment widen its own PCC and fetch anywhere. R27 does not close R26 -- only explicit compartment
state does -- but it means forging the predicate stopped being sufficient on its own.

**AND R39 LATER CORRECTED R27's OWN PREMISE.** R27 gated the write-enable rather than trapping, "to
match Sail". That matched Sail's inner `write_CSR` clause and missed the generic `check_CSR_priv` that
runs above it, which traps. The four arms remain as defence in depth and the generic check is now the
real gate -- see R39.

### R28. The escape violation trapped, and the write landed anyway

**Status: FIXED AND VERIFIED. Shipped inside commit `dfd4ec6` ("R26 + R28"), live at
`veda_core.tlv:5346`. It inherited R26's entry and never got its own. Back-filled.**

`$veda_csr_escape_violation` already listed all six CSRs and **correctly raised a trap.** But **only
one of the five write-enables -- `veda_mode` -- ever consulted it.** For 0x7C0-0x7C3 the trap fired
**and the register changed**: a compartment could rewrite its own PCC bounds or forge its trap return,
take the trap, and **keep the write**.

Sail is fail-closed here by construction -- `write_CSR` returns `Err(())` before any assignment, so
nothing is written. An RTL-only divergence, and **the same fail-open shape as R21: the refusal was
raised and the effect happened anyway.**

**FOUND BY THE R26 AUTHORITY TEST, not by reading.** From inside a sentinel-Length compartment the
`mtvec` write was refused while the 0x7C3 write landed -- which is only possible if the two are gated
differently. And it was **"applied to four of five arms" for the fourth time in this project**, the
first time in code nobody had just edited.

### R25. Never allocated

**Status: NOT A FINDING. Recorded so that nobody spends time looking for it.** `R25` appears zero
times in every document, source file, test and commit message across `veda-core`, `veda-core-sindhu`
and `veda-core-sail-riscv`. The number was skipped.

### R42. GLOBAL and STORE_LOCAL_CAPABILITY need a local-vs-global notion first

**Status: RECORDED, NOT YET MEASURED. Split out of R40, which closed 0x14 and 0x15 and deliberately
left these two. Entered here rather than living only in a task list, because a task list does not
survive and this document does.**

Perms bit 0 GLOBAL and bit 6 STORE_LOCAL_CAPABILITY, and their causes 0x10 and 0x16, are allocated and
enforced by neither layer. `VEDA_CORE_SPEC.md` now reads **"Allocated, NOT enforced"** for both.

They are not two more arms in the dereference chain. The rule is that a capability lacking GLOBAL is
*local* and may only be stored into memory through a capability granting STORE_LOCAL_CAPABILITY, and
its purpose is **temporal safety** -- stopping a short-lived reference from outliving its frame by
being written somewhere durable. Building it needs a decision on what "local" even means in an
object-centric, address-less machine with no stack in the usual sense but with an SSC and a per-domain
CRF; on who mints local capabilities and at which instruction; on whether OCInvoke and OCReturn should
mint or strip GLOBAL at a domain crossing; and on the fact that **STORE_LOCAL_CAPABILITY is checked on
the AUTHORISING capability while GLOBAL is checked on the capability BEING STORED** -- which would be
the first check in this machine reading permissions from two different capabilities at once. Weigh it
against the existing sealed/OCInvoke machinery first: some of what GLOBAL buys may already be reachable
through `otype` sealing plus the region/domain gate.

### R43. Rebind does not check that the register it refreshes names the same object

**Status: DECIDED AND CLOSED ON BOTH LAYERS. The instruction was narrowed rather than the
specification amended, and closing it removed the LAST untagged sealedness read in the machine --
which forced two existing tests to be re-aimed and settled a collision the register had not seen
coming. Sail 118/118, RTL 107/107, ACT4 51/51, differential 25/25.
Originally entered as RECORDED, NOT YET MEASURED; the original text follows.**

#### The decision, and why this way round

R43 offered two exits: narrow Rebind to a genuine refresh, or amend Section 4 so the specification
stops describing a precondition the hardware does not enforce. **Narrowed.**

- Leaving the two disagreeing is exactly the defect class R40 closed in the cause table.
- Amending the specification would **permanently foreclose** Perms-from-register and leave the
  landmine armed: R43's own text says the finding *"becomes one the moment anybody makes Rebind
  preserve the holder's own Perms"*.
- Hardware-first: the check is two comparisons on values already in registers.

`CTag(rd)` and `cur.Object_ID == object_id`, both **soft-fail, not trap** -- the comment directly
above the Rebind arm records that *"Rebind never traps for ANY failure reason"*, so a refusal that
trapped would change the instruction's contract far beyond this finding. Tag first, because
`isSealedCap` on an untagged register reads an otype that means nothing.

#### The consequence nobody had noticed: the last untagged sealedness read

Before landing anything I enumerated **every** `isSealedCap` consumer on both layers and checked each
for a tag guard. OCInvoke and OCReturn check `CTag` on every operand first; CUnseal conjoins
`CTag(cs1idx)` into its `ok`; the dereference path checks the tag first; the CGet family, CSeal,
CSealEntry, CSetBounds and CAndPerm all conjoin it; the ODA predicate leads with `veda_oda_tag`.

**Rebind was the only exception** -- and `vc_r24_crf_reset.S`'s own header says so in as many words:
*"One enforcement decision reads sealedness with NO tag conjunct: Rebind soft-fails on
`isSealedCap(destination)` alone."*

So R43 closes the last one, and **the reset otype becomes unobservable**: no path can now read a
register's sealedness without its tag.

#### That settled a collision, and the collision is itself a finding of the CLASS B shape

Two tests used **Rebind-into-an-untagged-register as their discriminator**, and both were green:

| test | its probe | what it was protecting |
|---|---|---|
| `vc_r24_crf_reset.S` P1 | *"rebind into the NEVER-WRITTEN register must SUCCEED"* | the reset otype is the unsealed sentinel, not 0 |
| `vc_r50_oclear.S` control 2 | *"a cleared register is still REBINDABLE"* | OCLEAR writes the sentinel rather than all-zeros |

**R24's test named the weakness in its header and then asserted it as the contract.** That is
precisely the class DESIGN_07 records three earlier instances of -- R27's CSR test,
`vc_check_order.S` PHASE D, and `vc_ocl_ocs_c.S` -- each green while demonstrating the gap it was
written to exercise. This is the fourth, and the first found by a fix colliding with it rather than
by accident.

Neither property becomes *wrong*; both become **unreachable**, which is what a fix should do. An
all-zeros OCLEAR is now behaviourally identical to one writing the sentinel, because nothing can read
that otype. Both tests are re-aimed to assert what still matters -- a never-written or cleared
register is tag-0 and a plain Bind into it yields a usable capability -- and R24's P1 additionally
now pins **R43's positive arm**: the test that pinned the gap pins the fix.

#### Coverage

`sail_tests/vc_r43_rebind_identity_neg.S` and `rtl/sim/veda_smoke_r43_rebind_identity.S` +
testbench. Three controls: a genuine bind works, **rebinding the same object still works** (so
refusing every Rebind cannot pass), and after a refusal a plain Bind still works (a refusal is a
refusal, not a corruption). Two findings: a different Object_ID, and an untagged destination. And the
whole file asserts **zero traps**, pinning the soft-fail contract.

---

**The original entry, kept verbatim:**

**Status: RECORDED, NOT YET MEASURED. Found while refuting a proposed R38(b) closure. Not an
escalation today, and entered now precisely so it is not discovered as one later.**

`VEDA_CORE_SPEC.md` §4 defines Rebind as refreshing **"an ALREADY-BOUND capability register's"**
`Base`/`Length`/`Perms`/`otype`/generation from the ODT, leaving `Offset` unchanged. The
implementation does not enforce "already-bound": it does **not** check `CTag(rd)`, so an untagged
register works; it does **not** check `cur.Object_ID == object_id`, because the Object_ID comes from a
GPR; it reads the current register only for `isSealedCap` and `Offset`; and then it writes
`wCTag(rd, true)`. **Preserving an `Offset` that was meaningful in object A and applying it to object
B is incoherent with the instruction's own stated purpose.**

**NOT AN ESCALATION TODAY**, because Rebind re-derives `Perms` from the entry and sits behind the same
`veda_bind_domain_ok` gate as Bind -- it grants no more than a plain Bind of the same name would. **It
becomes one the moment anybody makes Rebind preserve the holder's own `Perms`**, which is exactly the
R38(b) closure that was refuted: hold a full-permission capability to A, Rebind against B, keep A's
permissions on B's bounds.

**THE CORPUS DEPENDS ON THE LOOSE FORM**, which is why this is a decision and not a free tightening:
`veda_smoke_residency.S:93` rebinds into c5 *"UNTOUCHED SINCE RESET"*, and `veda_smoke_m12.S:56`
rebinds c2 against a different object to exercise the owner gate.

**DECIDE**: either narrow Rebind to a genuine refresh -- require the tag and the Object_ID match,
update those tests, and then Perms-from-register becomes safe and closes half the ADVISORY escape --
or amend §4 so the specification stops describing a precondition the hardware does not enforce.
Leaving the two disagreeing is the defect class R40 just closed in the cause table.

### R38(b) RESOLVED. A copy-on-write object is not pageable, and the recovery that looked available was unsafe

**Status: FIXED AND VERIFIED ON BOTH LAYERS. Sail 102/102, RTL 90/90, ACT4 51/51, differential 20/20.
One term added to `page.out`'s existing refusal chain. The measurement that recorded the defect is
renamed rather than edited, because its name -- "lockout" -- stopped being true.**

R38 made the split right belong to whoever held PERM_STORE at the moment the object became
copy-on-write. Because `set.cow` deliberately does not bump the generation, that entitlement lives in
exactly one place: the live capability registers that predate it. **`veda.odt.page.out` exists to
destroy exactly those.** It bumps the generation -- which is how outstanding capabilities are
invalidated, and it is necessary, because every capability caches its own `Base` and page-in supplies
a new one -- while carrying `cow` across untouched. One round trip left an object **nobody could
split**: every pre-cow capability stale, the entry still copy-on-write, and the only way back in a
`Bind` that masks store off.

**THE FIX IS NOT THE ONE THE RECORD NAMED FIRST, AND THE SEARCH FOR A CHEAPER ONE IS WHAT FOUND THE
SECOND DEFECT.** The recorded leading closure was this refusal, with its cost stated: copy-on-write
objects become unpageable, and in a system under memory pressure those are the common pages. Before
accepting that, three cheaper closures were worked through and each was refuted at source:

- **Make `Rebind` preserve the holder's own `Perms` instead of re-deriving them from the entry.** This
  would have let a paged-out holder refresh its capability and keep its store permission -- and it
  would also have closed half the ADVISORY escape. **Refuted by the specification**: §4 defines Rebind
  as refreshing *"`Base`/`Length`/`Perms`/`otype`/generation **from the ODT**, leaving `Offset`
  unchanged"*. Taking `Perms` from the register is an ISA change, and relocation transparency -- the
  goal Rebind exists for -- does not require it. Worse, Rebind takes its `Object_ID` from a GPR and
  does not check it against the register's own, so preserving `Perms` would have made it an authority
  *transfer*: hold a full-permission capability to A, Rebind against B, keep A's permissions on B's
  bounds.
- **Let page-out skip the generation bump for copy-on-write objects, relying on `resident` alone.**
  Unsound: page-in supplies a NEW `Base` and capabilities cache the old one, which is the reason the
  bump exists.
- **Record the entitlement in the entry.** The ODT has exactly one per-principal field,
  `owner_domain`, and it holds ONE domain -- while fork's whole point is that parent and child are
  DIFFERENT domains and both are entitled. **A per-(domain, object) entitlement needs a table this
  design does not have.** That is the successor, named rather than half-built.

**AND THE "RECOVERY" I HAD RECORDED WAS UNSAFE, which is the sharper half of this entry.** The
measurement's phase 5 said *"privileged software can still release the object by clearing cow"* and
treated it as the escape hatch. It is not one. **Clearing `cow` on a genuinely shared object lets
every sharer write the same object** -- precisely the isolation copy-on-write was providing. A
recovery that silently merges two writers is worse than the lockout it repairs. That is why the
refusal is placed **at the instruction that destroys the evidence**, rather than attempted afterwards
from state that no longer exists.

**THE COST, STATED RATHER THAN HIDDEN.** A copy-on-write object cannot be evicted until the sharing
resolves -- one sharer writes and takes its private copy, or software tears the sharing down
deliberately. Under memory pressure those are common pages, and this is a real limitation.
**It cannot be weaponised**: `page.out` and `veda.odt.set.cow` both require
`cur_privilege == Machine | veda_oda_authorized()`, so unprivileged code cannot mark objects
copy-on-write to pin memory.

**BLAST RADIUS: ZERO.** Measured before editing -- of the twelve tests in the corpus that call
`page.out`, **not one also calls `set.cow`.** The composition the defect lived in had never been
exercised, which is exactly why a differential suite reporting green had nothing to say about it.
`difftest/probes/p18_cow_not_pageable.S` closes that: word 2 is the whole increment -- the entitlement
is still there after the refusal -- and word 3 is the control proving a NON-cow object still pages out
and back in cleanly, so a layer that had simply broken `page.out` could not pass.

### R41. A Populate carried the previous occupant's policy, and the two layers disagreed about it

**Status: FIXED AND VERIFIED. Sail 101/101, RTL 90/90, ACT4 51/51, differential 18/18. Found by the
adversarial pass on R38 -- after R38 had already been committed.**

| | Sail, before | RTL |
|---|---|---|
| `VEDA_ODT_POPULATE` `cow` | `old_entry.cow` (**carried**) | `<= 8'h00` (**cleared**) |
| `VEDA_ODT_POPULATE` `owner_domain` | `old_entry.owner_domain` (**carried**) | `<= VEDA_DOMAIN_ANY` |
| `VEDA_ODT_POPULATE_FAST` `cow` | `false` | `<= 8'h00` |
| `VEDA_ODT_POPULATE_FAST` `owner_domain` | `VEDA_DOMAIN_ANY` | `<= VEDA_DOMAIN_ANY` |

**The two Sail populate variants disagreed with each other on both policy fields, and plain Populate
disagreed with the RTL on both.** The RTL had the reasoning written down -- *"Populate may reuse a slot
whose previous object was copy-on-write -- without this, the new object would be born copy-on-write and
its first write would fault for no reason"* -- and the `odt_entry` struct's own comment on
`owner_domain` says `VEDA_DOMAIN_ANY` is *"how every object is created"*, which plain Populate made
false. Sail's plain clause was the outlier on three independent counts at once.

**R38 IS WHAT TURNED IT FROM A NUISANCE INTO A LOCKOUT.** While the cow arm ignored capability
permissions, a stale `cow` only meant a spurious 0x0C a handler could clear. Now the split right
belongs to whoever held PERM_STORE when the object became copy-on-write -- and **an object born
copy-on-write has no such principal, ever.** Populate returns a status in `rd`, not a capability, so
the minter must Bind, and Bind masks store off a cow entry. The freshly minted object was unwritable by
anyone, from creation.

**MEASURED BEFORE THE FIX, NOT ASSERTED.** `difftest/probes/p16_populate_policy_reset.S` was written
first and run against the un-rebuilt model, capturing the divergence live:

| word | Sail (pre-fix) | RTL | after |
|---|---|---|---|
| Perms after re-populate | **0x04** -- LOAD only | 0x0C | 0x0C on both |
| traps after a store on the new object | **1** -- it faulted | 0 | 0 on both |
| control: a real cow object still refuses | 0x53 | 0x53 | unchanged |

**THE COVERAGE GAP IS THE REAL LESSON.** No probe in the suite composed Populate with `set.cow`, so a
two-field divergence sat inside a differential harness reporting 16/16. A harness only compares the
states its probes enter.

**AND THE FORK RECIPE IN DESIGN_02 WAS DEAD AS WRITTEN, WHICH THE SAME PASS CAUGHT.** It said parent
and child both hold *"read-only-attenuated capabilities (CAndPerm)"* and that the first write traps --
which under R38 yields 0x13 for both of them, so `fork` could never complete its first write. The
`CAndPerm` step never did any work in the first place: what stops the write landing on the shared
object is the **entry's `cow` bit**, not the capability's permissions. DESIGN_02 is corrected: parent
and child share their capabilities with store permission intact, which makes them exactly the
principals R38 entitles. A redundant attenuation became a fatal one the moment the predicate started
reading permissions -- the second time in this increment, after the RTL test's *"be explicit"*
re-bind.

### R40. Four permission bits the specification declares Active are enforced by neither layer

**Status: THE SEVERE PAIR IS FIXED AND VERIFIED ON BOTH LAYERS -- 0x14 PERMIT_LOAD_CAPABILITY and
0x15 PERMIT_STORE_CAPABILITY. The escape was DEMONSTRATED before it was closed. The other two, 0x10
GLOBAL and 0x16 PERMIT_STORE_LOCAL_CAPABILITY, are deliberately NOT built and the specification table
now says so instead of claiming they are Active.**

**THE ESCAPE, RUN RATHER THAN ARGUED.** `sail_tests/vc_r40_cap_perm_enforce_neg.S` was written first
and bisected stage by stage against the un-fixed model, so that "it failed" could not be confused with
"the setup was wrong":

| stage | before the fix |
|---|---|
| setup + control: the owner spills a capability naming a secret object and reads it back | **SUCCESS** -- tag 1, Object_ID 771, zero traps |
| `CAndPerm` clears bit 4 and keeps bit 2 | **SUCCESS** -- the attenuation is real and visible to `CGetPerm` |
| `OCL.C` through that data-only view | **FAILED at the tag assertion** -- a live, tagged capability was lifted |

**A delegation the machine accepted as "data only" handed over authority over an object it was never
given.** After the fix the same three stages pass, and the refusal carries cause 0x14 with the
dereferenced capability's index -- not the destination's, which is what the bisection caught in my own
expected value.

**THE DECISION: A TRAP, NOT A CLEARED TAG.** A hybrid ISA where one instruction loads both data and
capabilities has to clear the tag instead of faulting, or an ordinary `memcpy` over mixed memory would
fault constantly. **This machine has no such case**: `OCL.D`/`OCS.D` and `OCL.C`/`OCS.C` are separate
instructions and the data path already invalidates tags byte-granularly, so a data copier cannot move
a capability at all and never needs the permission. Veda-Core's own cause table has called 0x14 and
0x15 *Violations* since the permission set was adopted, and silence would be the failure mode R30 and
R32 closed elsewhere -- a refusal software cannot observe is one it will not honour.

**ORDERING: THE COARSER PERMISSION FIRST.** Reading the bytes at all is the prerequisite; reading them
as AUTHORITY is the additional right, so 0x12 outranks 0x14 and 0x13 outranks 0x15. Both sit above
alignment, bounds, residency and copy-on-write, because a refusal outranks a repair request. Three RTL
tests confirmed the ordering empirically before their objects were updated -- a misaligned `OCL.C`
reported 0x14 rather than 0x08, an out-of-bounds `OCS.C` reported 0x15 rather than 0x01, and a
copy-on-write `OCS.C` reported 0x15 rather than 0x0C. Each is the permission refusal correctly winning.

**`need_cap` IS AN EXPLICIT PARAMETER, NOT DERIVED FROM `check_align`,** even though the two coincide
today: `OCL.C`/`OCS.C` are the only capability-width accesses and the only align-checked ones. Tying
"this access is 32-byte aligned" to "this access moves authority" is the kind of unstated coupling
this record keeps finding, and a future unaligned capability access would silently take the wrong
permission with it.

**BLAST RADIUS: TWELVE TESTS, AND EVERY ONE OF THEM WAS RELYING ON THE GAP.** Five Sail tests, seven
RTL tests. They divide cleanly: tests that pin the scratch fixture's `Perms` value, and tests that
spill a capability into an object which now has to grant permission for it. The seeded scratch object
and the `c11` residency fixture gained bits 4 and 5 on both layers; four self-populated containers
gained them in their own descriptors. The spill-slot test already carried a note that a slot must be
at least 32 bytes -- "a real ABI consequence of the format change, not a test fudge" -- and the same
sentence now covers permission as well as size.

**WHAT IS DELIBERATELY NOT BUILT, AND WHY IT IS NOT A QUICK FIX.** `0x10` GLOBAL and `0x16`
PERMIT_STORE_LOCAL_CAPABILITY both require a **local/global capability distinction this architecture
does not have.** GLOBAL marks a capability that may be stored into globally-reachable memory;
STORE_LOCAL_CAPABILITY is the authority to store one that lacks it. The pair exists to stop a
short-lived reference -- a stack capability being the canonical case -- from outliving its frame by
being written somewhere durable. That is a real temporal-safety mechanism and it deserves its own
increment with its own design, not a bit bolted onto the dereference chain. `VEDA_CORE_SPEC.md`'s
cause table now reads **"Allocated, NOT enforced"** for both, because a specification that overstates
what a machine enforces is the same defect class as a machine that fails open.

Every `permBit` call in the Sail model enforces exactly eight permissions: EXECUTE, LOAD, STORE,
ACCESS_SYSTEM_REGISTERS, SEAL, UNSEAL, INVOKE, NMC_COMPUTE. Every permission bit the RTL ever indexes
is one of five: `rs1cap_perms[1]`, `[2]`, `[3]`, `[10]`, `[12]`.

**Never enforced on either layer: bit 0 GLOBAL, bit 4 LOAD_CAPABILITY, bit 5 STORE_CAPABILITY, bit 6
STORE_LOCAL_CAPABILITY.** Cause codes `0x10`, `0x14`, `0x15`, `0x16` appear **zero times** in the whole
Sail model and **zero times** in `veda_core.tlv`. `VEDA_CORE_SPEC.md` marks all four **Active**, in a
table whose own vocabulary distinguishes Active from *"Reserved slot, kept available"* (0x08) and
*"reserved"* (0x09-0x0f, 0x17). Bit 11 SET_CID is also unenforced and is the one the spec honestly
marks reserved/inactive.

**THE ATTENUATION IS REAL AND GOVERNS NOTHING.** `CAndPerm` genuinely applies the mask
(`$veda_rs1cap_perms & $rs2_data[15:0]`), the cleared bit is stored in the capability, and `CGetPerm`
faithfully reports it cleared. No check ever reads it.

**WHY THESE THREE IN PARTICULAR ARE THE SEVERE ONES.** They are exactly the bits that decide whether
**authority itself** may move through memory. `OCS_C` calls `veda_check_access(capidx, offset, 32,
false, true, true)` and `OCL_C` the load equivalent -- so capability-width memory access is authorised
by the plain DATA permissions. Reachable consequence:

1. an owner stores a capability into object O with `OCS.C`
2. it delegates O with `CAndPerm` clearing bit 4, keeping bit 2 -- *"data only"*
3. the delegate runs `OCL.C`, passes the PERM_LOAD check, and the model executes
   `C(rd) = loaded_cap; CTag(rd) = tag` -- **a live, tagged capability, naming an object it was never
   given.**

In an address-less machine where all authority is capabilities, that is amplification through an
attenuation the machine accepted and ignored.

**THE RECEIPT IS ALREADY IN THE CORPUS, PASSING.** `vc_ocl_ocs_c.S` performs its whole
capability-through-memory round trip through Object_ID 1, whose Perms are `0x100C` -- bits 2, 3 and 12,
with **bits 4 and 5 clear**. It has been green since Milestone 7. This is the third time this session a
passing test has turned out to demonstrate the gap it was written to exercise, after `veda_smoke_r27_
csr_priv.S` and `vc_check_order.S` PHASE D. **A corpus can only catch what someone thought to assert.**

**WHAT IT BEARS ON R38.** The recorded Design A wanted to spend one of the remaining free Perms bits on
a new "may split" permission. The free bits are 13, 14 and 15 -- **not 11, which is SET_CID; the
earlier note was wrong.** Adding a fifth decorative bit to a lattice where four are already decorative
would have been the wrong order of work, and R38 resolved with no new bit at all.

**WHAT IS NOT YET DECIDED, and why this is recorded rather than half-built.** Three of the four are
straightforward arms in the two dereference checkers. **GLOBAL is not**: it governs whether a "local"
capability may be stored into globally-reachable memory, and this machine has no local/global
distinction to test -- adding the arm would need that concept first. And the trap-versus-tag-clear
question is a real architectural choice: Veda-Core's own spec already declares all four as
*Violations*, and unlike a machine where one instruction moves both data and capabilities, here
`OCL.D`/`OCS.D` and `OCL.C`/`OCS.C` are **separate instructions** with byte-granular tag invalidation
on the data path -- so a data copier cannot move a capability by accident, and there is no
generic-memcpy case that a trap would break. That argues for the trap, which is what the spec says.
Stated here so the increment starts from a decision rather than a habit.

### R38 RESOLVED. The predicate is PERM_STORE, and both designs I recorded were refuted first

**Status: FIXED AND VERIFIED ON BOTH LAYERS. Sail 101/101, RTL 90/90, ACT4 51/51, differential 17/17.
One condition deleted in two Sail arms and five RTL cause-chain arms. No new permission bit. The
finding as first measured is the entry below this one.**

**THE TWO DESIGNS I HAD RECORDED WERE BOTH WRONG, AND THE CODEBASE SAID SO IN A COMMENT SITTING THREE
LINES ABOVE THE FUNCTION THEY BOTH WANTED TO CHANGE.** Design A was a new attenuable "may split"
permission bit; Design B was to stop stripping PERM_STORE at Bind so PERM_STORE itself carried the
right. Both rest a refusal on a capability the delegator attenuates with `CAndPerm`. DESIGN_02's own
correction, recorded at both `veda_bind_perms` call sites, kills that outright: *"a capability handed
out with store stripped is only ADVISORY, because the holder can re-Bind the name and get a fresh,
fully-permissioned one. So the attenuation has to happen HERE, where the entry is the authority and no
re-derivation can escape it."* Bind's domain gate defaults to `VEDA_DOMAIN_ANY` -- *"how every object
is created"* -- so **any domain may re-Bind any object and re-derive Perms from the entry.**
Capability-carried attenuation is not binding by default, and neither recorded design survived that.

**AND DESIGN A HAD A SECOND, WORSE DEFECT AN ADVERSARIAL PASS FOUND THAT I HAD NOT.** The cow arm is
the LAST arm of the chain and its `else` is the SUCCESS path. Conditioning it on a new permission,
while leaving the store arm gated on not-cow, makes a capability that HAS store but lacks the new bit
fall straight through to Ok -- **the fork parent's first write silently mutates the shared object, on
both layers, with no attacker and no attenuation.** Design A was not merely insufficient; it was a
silent write-through.

**THE ANSWER NEEDED NO NEW MECHANISM, ONLY THE DELETION OF ONE CONDITION.** The store-permission arm
carried `& not(entry.cow)`, so on a cow object the capability's own store permission was never
consulted at all. Deleting that conjunct -- in `veda_check_access`, in `veda_check_nmc_access`, and in
the five RTL cause chains -- lets it decide:

| | before | after |
|---|---|---|
| capability WITH PERM_STORE, cow object | 0x0C, splits | 0x0C, splits |
| capability WITHOUT it, cow object | **0x0C, splits** | **0x13, refused** |
| re-Bind after set.cow | store stripped, splits anyway | store stripped, **cannot escape** |

Because `veda.odt.set.cow` deliberately does not bump the generation, the capabilities that still carry
store are exactly those minted BEFORE the object became copy-on-write. So the rule the hardware now
enforces is: **whoever held write authority at the moment the object became copy-on-write may cause the
split; whoever learns the Object_ID afterwards may read.** That is what copy-on-write has always
meant -- the copy is owed to the writers that existed at fork, not to anyone who later learns the name.

**AND IT IS NON-ADVISORY PRECISELY BECAUSE THE BIND-TIME MASK STAYS.** The 0xFFF7 mask is the one
attenuation a re-Bind cannot escape, and this change is what gives it something to enforce **during
the cow window** -- an inert-where-it-mattered mechanism activated rather than a new one added.

**A CORRECTION TO MY OWN CLAIM, KEPT BECAUSE OF HOW IT HAPPENED.** I first wrote that the mask "did no
enforcement work at all", and put that sentence in the Sail source, the RTL source, this document and
the commit message. It is overstated. The old arm read `... & not(entry.cow)`, so the mask was inert
only *while* cow was set; the moment cow was cleared the same arm refused a store-stripped capability
with 0x13, and every object that completed a repair was enforced by it. **Two independent readers gave
me opposite answers on exactly this point and I took the wrong one without checking** -- the failure
mode this record keeps warning about, committed while writing the entry that warns about it. Corrected
in all four places.

**WHAT IT DELIBERATELY CANNOT EXPRESS, and why that is not a loss.** "Read-only but splittable" is
now inexpressible: if an entry's Perms lack PERM_STORE, no capability to it may ever force a copy. A
reader who wants a private writable version should ALLOCATE one and copy through the read capability
it already holds -- the same self-service answer R19 decided for the copier itself. Copy-on-write
exists to DEFER a copy that is already owed, not to manufacture an entitlement the holder never had.

**THE BLAST RADIUS WAS THREE FILES, AND THE ONE THAT BROKE TAUGHT SOMETHING.** Every existing COW test
binds BEFORE `set.cow`, so their fault assertions were untouched. The three that changed all encoded
the defect: `vc_check_order.S` PHASE D, its RTL mirror, and `p14_cow_eligibility.S`. PHASE D is worth
quoting, because it was a **mutation-caught** test whose own header recorded the right observation and
drew the opposite conclusion: *"every existing cow test inspects the attenuated capability with
CGetPerm and never DEREFERENCES through it -- attenuation tested as bookkeeping, never as
enforcement."* Correct. Dereferencing through the attenuated capability is the right test; expecting
0x0C from it was the defect. It still catches its original mutant, now in the enforcing direction.

**AND THE RTL MIRROR FAILED FOR A REASON WORTH KEEPING.** Its P7 positive control regressed from 0x2C
to 0x33 -- because the phase carried a line reading `veda.bind c1, 1  # re-bind c1 (P2 left it
unchanged, be explicit)`. Added for tidiness, harmless right up until the predicate started reading
permissions, at which point that re-bind ran the mask and **turned the positive control into a
negative one**: the phase that exists to prove copy-on-write still fires would have been proving the
opposite. The line is gone and the reason is in the source. A redundant re-derivation is not neutral in
a machine where derivation attenuates.

**THE PROBE NOW CARRIES A POSITIVE CONTROL, which it did not before.** `p14_cow_eligibility.S`
measures the refusal AND that a pre-cow holder still splits (0x6C). Without that word the probe would
pass just as happily if the cow arm had been deleted -- the same false-AGREE this suite already has a
receipt for.

**ONE THING THIS OPENS, MEASURED AND RECORDED RATHER THAN PATCHED: R38(b).** The split right now lives
only inside live capability registers, and `veda.odt.page.out` invalidates every live capability
(`generation + 1`) while carrying `cow` across unchanged. After one paging round trip **nobody on the
machine can split the object.** That was an argument until it was run:
`sail_tests/vc_r38_cow_paging_lockout.S` pins all five phases, including that privileged software can
still release the object by clearing `cow`. It is fail-closed -- it denies a write, never grants one --
and before this change the "liveness" came from the hole itself. The leading closure is to make
page-out refuse on a copy-on-write object, and its cost has to be stated with it: copy-on-write objects
become unpageable, which is the exact memory pressure paging exists to relieve. Recorded, not
half-built.

**A METHOD NOTE I OWE THE RECORD.** I edited the tree while independent analysis agents were reading
it, so one of them correctly reported that its own brief was stale. That is this project's own
"a sweep tree is not truth" lesson arriving from the other side -- I was the writer this time. Their
findings were treated as claims to verify at source, which is how the paging interaction above was
confirmed: the agent's argument rested on paging bumping the generation, a comment in this very file
said paging never bumps, and **the comment was the fossil.** It has been corrected in both dereference
checkers.

### R38. The copy-on-write fault asks WHETHER, never WHO

**Status: RESOLVED by the entry above. The predicate is the capability's own PERM_STORE; the two
designs recorded below were refuted before anything was built. The finding as first measured follows.**

"R19 DECIDED" left exactly one thing ratified as hardware and unbuilt: *"the COW fault's own
eligibility predicate -- who is entitled to cause a split. That is where a real security problem
remains and where hardware is the right answer."* This is that predicate, measured.

**Today it is the whole of it, on both layers:**

    Sail:  else if need_store & entry.cow then Err(VEDA_CAUSE_COW_FAULT)
    RTL:   $veda_cow_write = $veda_check_odt_cow

No owner test, no domain test, no permission test. The fault fires for **anyone** holding **any**
capability to a cow entry who attempts **any** store.

**Measured** (`difftest/probes/p14_cow_eligibility.S`), and the control is what makes it a finding:

| | measured |
|---|---|
| the delegate's capability permissions | `0x0004` -- **LOAD only**; Bind stripped STORE because the entry is cow |
| three consecutive stores through it | `0x0C` COW every time -- unlimited, unrated, unrefused |
| **control:** same missing store permission on a **non-cow** object | **`0x13` PERM_STORE** |

**So the machine can already distinguish "you may not write" from "you may not write yet" -- and it
chooses the second without ever asking who is asking.** A principal handed a read-only view arms an
allocation on every store attempt, indefinitely, **holding no write authority at all**. The model's
own comment beside the fault already names the category: *"the rest is ordering hygiene and resource
containment."*

**THE DESIGN, and the constraint that rules out the obvious answer.** The obvious predicate is
"only the owning domain may split", and the machinery exists (`veda_bind_domain_ok` already reads
`e.owner_domain`). **It breaks the primary use case.** In `fork` the child is typically a *different*
domain, and the child splitting is the entire point. An owner-only predicate would make `fork` work
only within one domain.

What distinguishes a legitimate splitter from an exhaustion attacker is not who they are but **what
they were given** -- and this machine expresses that in exactly one way: **a permission bit the
delegator controls**. A parent forking hands the child a capability *with* it; a domain handing out a
read-only view hands one *without*, and a store attempt then takes the ordinary `0x13` the control
above already demonstrates. `CAndPerm` can clear it, so it is **attenuable** -- which is what makes it
a capability property rather than a policy. Perms bits 11, 13, 14 and 15 are unallocated.

**One rule the implementation must not get wrong:** `veda_bind_perms` clears bit 3 when the entry is
cow. The split bit must be **preserved** through that masking, or nobody could ever split and `fork`
would be dead rather than merely ungoverned.

**The honest limit, stated so it is not oversold.** This does not stop an owner exhausting itself, and
it does not stop a delegate that was deliberately given the right. It converts an **ambient** capacity
into a **delegated** one -- which is what this machine does everywhere else, and is the whole of what
it buys. Not ratified here for the same reason the bounded-granule copy was not: it is a new
architectural rule, and the record's discipline is to state the shape, measure the problem, and let
the increment be taken deliberately rather than at the end of a long pass.

### R37. The three Special Capability Registers never got R24's reset

**Status: FIXED AND VERIFIED. Sail 99/99, differential probe flipped DIVERGE -> AGREE, mutant killed.**

R24 gave the capability register **file** a defined architectural reset, because Sail's struct default
leaves `otype` at 0x0000 and `isSealedCap` is `otype != UNSEALED_OTYPE` -- so an untouched register
read as **sealed with type zero**, a type CSeal can genuinely mint. **`veda_oda`, `veda_tsc` and
`veda_ssc` were not in that fix and had no reset at all.**

**It matters most on the ODA.** `veda_oda_authorized()` reads
`veda_oda_tag & not(isSealedCap(veda_oda)) & permBit(Perms, PERM_ACCESS_SYSTEM_REGISTERS)`, so this
register's sealedness is an input to the gate on **every ODT-mutating instruction**. The gate was
false at reset either way -- but only because the **tag** is false. **Fail-closed by accident of a
different field, not by this one being right**, which is precisely the argument R24 made.

Measured (`difftest/probes/p13_scr_reset.S`): all three read otype 0x0000 on Sail against 0xFFFF on
the RTL. **The probe's control is what makes it a finding rather than a guess** -- an untouched CRF
register, already fixed by R24, agreed at 0xFFFF on both, so the divergence was specific to these
three and not a general disagreement about what an unwritten capability looks like. `OSpecialRW`
swaps rather than writes, so the reset value was directly observable by software.

**AND THE SELF-CHECK SUITE IS STRUCTURALLY BLIND TO IT.** Under the mutant that removes
`veda_reset_scr()`, **all 99 Sail tests still pass** and only the differential probe dies. That is the
**third time this session** the harness caught what the self-check corpus cannot: a self-check test can
only observe what a program can ask, and no program in that corpus asks what an untouched Special
Capability Register contains. The same reason R24 needed the harness, and the reason R31 -- making
that harness able to fail at all -- was worth doing before any of this.

### R39. The layer had no generic CSR privilege check -- and R36 could not be fixed without it

**Status: FIXED AND VERIFIED ON BOTH LAYERS. Sail 100/100, RTL 90/90, ACT4 51/51, differential 17/17
including a probe that could not previously be written at all. R36 is RESOLVED by this same increment;
its own entry below is the finding, this is the answer.**

**THE DECISION WAS FORCED, NOT CHOSEN, WHICH IS WHY IT COULD BE TAKEN ALONE.** R36 recorded two
opposite candidates -- specify `veda.droppriv` in the model, or delete it from the RTL and use
`mstatus.MPP` + `mret` -- and deliberately picked neither. Reading the project's own record decided it:
`MILESTONE_PLAN.md`'s Milestone 4 addendum justified the custom instruction on exactly one ground,
*"real `mret` is a trap-return semantic this core has no trap to return from"*. **Milestone 9 built the
traps and MRET.** The premise expired and the instruction outlived it. The RTL already decoded MRET at
a fixed literal and already used it as the restore point for PCC, MEPCC, the region and the trap
depth -- it was the privilege-restore point in every respect except privilege. So the RTL moved to the
model, and **the model needed no change at all**: it had implemented this since long before Veda
existed.

**PULLING ON THAT THREAD FOUND SOMETHING BIGGER.** `check_CSR()` in the model is a conjunction of four
independent tests. This layer had grown three of them across three increments and was missing the
first, which is also the only one that is about authority:

| model | this layer, before |
|---|---|
| `check_CSR_access` (read-only) | `$csr_is_readonly` -- R32 |
| `is_CSR_accessible` (address) | `$csr_addr_known` -- R32 |
| `veda_allows_CSR_access` | `$veda_csr_escape_violation` -- M20/R26 |
| **`check_CSR_priv`** | **nothing whatsoever** |

The rule is a field comparison, not a list: `csrPriv(csr) = csr[9..8]`, and
`check_CSR_priv(csr, p) = privLevel_to_CSR_privbits(p) >=_u csrPriv(csr)`. **Every one of the fourteen
CSRs this core implements lives at 0x3xx or 0x7Cx, so all fourteen were readable and writable from
unprivileged code.** `mtvec`'s only guard was the compartment-escape check, which fires only while a
compartment is *live* -- so unprivileged code **outside** a compartment could install its own trap
vector. `mscratch`, `mepc`, `mcause` and `mtval` had no guard at all.

**THE EVIDENCE WAS ALREADY IN THE CORPUS, PASSING.** `veda_smoke_r27_csr_priv.S` dropped privilege,
read and wrote 0x7C0-0x7C3, asserted a trap count of **zero**, and called that *"matching Sail: the
register holds, nothing traps"*. Its own header even recorded the gap -- *"This layer has NO standard
CSR privilege check at all -- verified by grep"* -- and then asserted the gap was correct. It had read
the inner Veda `write_CSR` clause and missed the generic gate that runs above it. **A test that names a
weakness and then pins it as the contract is worse than no test: it converts an open question into a
settled one in the wrong direction.**

**VERIFIED BY RUNNING BOTH LAYERS, NOT BY READING EITHER.** A throwaway probe entered U-mode via
`mstatus.MPP` + `mret` and issued `csrr x10, 0x7c1`: Illegal_Instruction, `mepc` exactly at the `csrr`.
That probe is now `sail_tests/vc_r39_csr_priv.S`, because the model being right was never the problem --
nothing in the suite *said* what the contract was, which is how the RTL test came to assert its
opposite.

**WHY THE TWO HAD TO SHIP TOGETHER.** With the privilege check in place and no trap-raises-privilege, a
handler entered after a drop cannot `csrr mepc` and cannot `mret`: **every post-drop trap livelocks.**
That is the concrete form of R36's warning that "23 gates change their meaning at once". The coherent
whole is the standard one -- trap raises to Machine, `mret` restores from MPP, MRET below Machine is
illegal, MPP is WARL-legalised to the two modes this hart actually has, and a CSR access below the
address's own privilege traps.

**THE MPP LEGALISATION IS LOAD-BEARING, NOT TIDINESS.** `$priv` is one bit. Accepting `MPP = 0b01/0b10`
would let software park a Supervisor encoding in a field that `$priv` cannot represent, and `MPP[1]`
would then read as Machine. The legalisation is what stops "write MPP, `mret`" being an escalation --
and the MRET privilege gate is the second, independent stop on the same path. Both are kept: **an
escalation that needs only one mistake to reopen is not closed.**

**AND ECALL FINALLY TELLS THE HANDLER WHO CALLED.** `mcause` for `ecall` was hardcoded 0x0B, "from
Machine mode", carrying the comment *"the only possible value since this core only ever runs M-mode"* --
false in the same file, which defines `$priv` and had ten test programs that cleared it. So an
unprivileged compartment's syscall announced itself to the handler as the kernel's own. Stated at its
real size: **not an escalation, a caller-identity forgery at the one boundary whose entire job is to
identify the caller** -- and it matters because the handler's authority does not come from the mode.
Six ODT gates accept `$veda_oda_authorized` with no privilege term at all, so a handler that decides
how far to trust a request by reading `mcause` is deciding how to spend authority it still holds.

**TWO THINGS THE WORK FOUND THAT I DID NOT GO LOOKING FOR.**

*The refusal was delivering the value anyway.* The R39 test asserted that an unprivileged `csrr` leaves
`rd` untouched, and it failed: the trap fired **and** 0xFFFFFFFFFF landed in the register. `$reg_write`
carried a bare `$is_csr_access`, written at Milestone 9 on the stated ground that *"a CSR read/write is
never itself a Veda-Core violation"* -- true then, falsified since by R32, by M20/R26 and now by R39,
with none of the three coming back to that line. For a check whose distinguishing property is that
**reads** are gated, a trap that still hands over the data is the entire property lost. Found by a test
asserting the strong form rather than the observable one.

*The nested-trap case, and where the hardware-first rule actually ends.* `mstatus.MPP` is a single save
slot, so a nested trap's inner `mret` consumes it and the outer `mret` returns to User. This broke the
M21 restore test, which had no privileged state to save before. **Hardware does not fix this, and the
reason is a real distinction rather than a concession.** R12 made the hardware track MEPCC by depth and
poison it, correctly, because stale *bounds* can hand back authority never held. A stale MPP can only
restore **less** privilege than was held -- the specification pins the post-`mret` value to the least
privileged supported mode, so the failure direction is de-escalation. **Hardware tracks what can
escalate; software saves what can only de-escalate.** The handler now saves `mstatus` beside the `mepc`
it already saved, for the reason its own comment already gave. Building a depth-tracked MPP would have
been non-standard hardware solving a problem the specification already made safe -- and would have put
this layer straight back into R36's position, implementing privilege behaviour the model does not
define.

**WHAT THE DIFFERENTIAL HARNESS CAN NOW DO THAT IT COULD NOT.** `p13_scr_reset.S` recorded the
limitation in its own header: OSpecialRW was *"a clean cross-layer measurement, unlike the privilege
model"*, because the two layers did not share a mechanism for leaving Machine mode. `p15_priv_model.S`
measures it now, word for word identical on both, and **non-trivially**: MPP reads User; the U-mode CSR
read leaves 0xBAD standing; cause 0x02; MRET-below-Machine 0x02; `ecall` 0x08; and an arithmetic
control returning 10, so that "both layers trapped everything" cannot pass as agreement -- the exact
false-AGREE this suite already has a receipt for in `p2_derive.S`.

**HONEST LIMITS, NAMED.** `mstatus` implements MIE, MPIE and MPP and reads zero everywhere else. SXL,
UXL, MPRV, MXR, SUM, TVM/TW/TSR and the S-mode triple have no consumer on this hart -- no S-mode, no
virtual memory, no interrupt delivery -- and reporting them would be advertising features that do not
exist, which is the failure mode R32 closed for CSR addresses. The probe therefore compares the MPP
field and says so, rather than comparing the whole word and calling the difference either agreement or
a defect. Custom-3 is unclaimed again and every encoding in it now raises Illegal_Instruction on both
layers, which is what the model always said.

### R36. Twenty-three security gates rest on a privilege bit the specification does not define

**Status: RESOLVED by R39 above, which is the same increment. `veda.droppriv` is retired, Custom-3 is
unclaimed, and privilege is the specification's: trap raises to Machine, `mret` restores from
`mstatus.MPP`, software drops by writing MPP and executing `mret`. The decision was forced rather than
chosen -- this instruction's own recorded justification expired at Milestone 9 -- and the model needed
no change to accept it. The finding as first measured follows.**

Found while asking a narrower question: why can the differential harness not compare privileged
behaviour? Because the two layers do not share a privilege mechanism -- and the reason is worse than
a mechanism difference.

| | Sail | RTL |
|---|---|---|
| how privilege drops | `mstatus.MPP` + `mret`, standard RISC-V | `veda.droppriv`, custom-3, **one way** |
| how a trap affects it | **raises to Machine** | **nothing -- the mux has no trap arm** |
| how `mret` affects it | restores from `MPP` | **nothing -- no mret arm either** |
| is the instruction specified? | **`droppriv` and custom-3 appear ZERO times in the whole model** | 3 sites |

`$priv` has exactly one writer in the RTL:

    $priv = $reset ? 1'b1 : (>>1$is_veda_droppriv ? 1'b0 : >>1$priv);

Set at reset, cleared once, **never restored by anything**. And **23 consumers gate on it** --
including R27's four CSR arms and the R35 `veda_attr` term shipped this same session.

**So the privilege half of this layer's security rests on a bit whose only writer is an instruction
the specification does not define, and whose value no trap can restore.** That is not a verification
gap with a security consequence attached; it is the other way round.

**Measured, not argued** (`veda_smoke_r36_priv_trap.S`): after `veda.droppriv`, a Populate is refused,
the trap handler entered on that refusal is **still unprivileged**, and a privileged CSR write from
inside the handler does not land. `$priv` reads 0 at the end. **A handler entered after a single drop
cannot perform any of the 23 privileged operations** -- it cannot install a trap vector, use
OSpecialRW, stage `veda_attr`, or Populate. On Sail the same handler is Machine by construction.

**The two candidate resolutions are opposite, which is why this is recorded rather than fixed:**

- **Specify `droppriv` in Sail.** Then the RTL is right, the model is incomplete, and a one-way
  privilege drop with no trap restore becomes a deliberate architectural property -- a strong one,
  arguably, since it means a compartment cannot regain privilege by faulting. But it also means a
  machine that has dropped privilege once can never run a privileged handler again, which no operating
  system can live with.
- **Delete `droppriv` from the RTL and use `mret`/`MPP`.** Then Sail is right, the RTL was scaffolding,
  and 23 gates change their meaning at once.

**The test asserts neither answer.** It pins the measured behaviour so that whichever way the decision
goes, the change is visible rather than silent -- the same discipline as recording an expected-DIVERGE
probe rather than hiding it.

**And a test-writing note worth keeping, because it is the session's recurring shape and it caught me
again.** The first draft of this test bound into **c11** and read tag 1, concluding the opposite. c11
is a **seeded fixture**, and the suite runs with `+veda_fixtures`: a *failed* bind leaves the fixture's
own tag standing, so the test was measuring the fixture rather than the bind. Moved to c9, which is
outside the fixture range on both layers -- the property R24 established when it needed exactly this.
The trap count is now asserted alongside, which is what stops the tag check passing for an unrelated
reason.

### R30. The RTL executes encodings the architecture never allocated

**Status: FIXED AND VERIFIED. RTL 88/88, Sail 99/99, and four differential probes flipped from
DIVERGE to AGREE. All three adversarial lenses landed before the first edit -- one of them on my own
security framing, which was overstated and is corrected below.**

Custom-0 with funct3 = 000 defines exactly three encodings -- 0000011 Populate, 0000100
Populate-Fast, 0000101 page-in. Issue funct7 = 0001010 in that space and **Sail raises
Illegal_Instruction; the RTL retires it as a no-op.** `$veda_illegal_instr` is a list of specific
named refusals with no catch-all arm for an unrecognised encoding.

**GROUNDED IN THE OFFICIAL UPSTREAM MODEL, read in full.** `model/sys/insts_begin.sail` declares
`ILLEGAL : word` and its own comment states the rule: *"the encdec mapping must come last to ensure
that all unmatched encodings decode to an illegal instruction."* The wildcard clause lives in
`postlude/insts_end.sail`. **Sail is fail-closed by construction. The RTL has no such mechanism at
all** -- `$veda_illegal_instr` is a list of seven named refusals and is the file's only
illegal-instruction source.

**THE SPACE IS BIGGER THAN THE FINDING SAID, in three ways, and the enumeration was mechanical.**

*Veda claims FOUR major opcodes in the RTL, not two*: custom-0 0x0b, custom-1 0x2b (ATOMIC),
custom-2 0x5b, custom-3 0x7b (DropPriv). Sail knows only three -- there is no custom-3 clause
anywhere in the model. A catch-all covering 0x0b/0x5b leaves two whole opcodes open.

*There are TWO classes, and the second one is worse.* Class 1 is fail-open **silent**: nothing
decodes, the instruction retires as a no-op. Class 2 is fail-open **active**: the RTL decodes an
encoding the architecture never allocated and executes it **as a defined instruction**, because
three decoders are over-broad --

| decoder | what it fails to test | consequence, measured |
|---|---|---|
| `$is_veda_bind` (`:1351`) | `imm[11:2]`, which Sail pins to zero | 1023 of 1024 patterns Sail refuses **mint a capability here** |
| `$is_veda_ospecialrw` selector (`:3747`) | gates the ODA write on `!is_tsc && !is_ssc` | 29 selectors Sail refuses perform the **ODA swap** |
| `$is_veda_droppriv` (`:1658`) | `funct3` entirely | all 8 values clear `$priv` |

*And the base ISA is fail-open too.* Measured by running the hardware, not by reading it:
**`mul x3, x1, x2` with 3 and 4 retires `x3 = 0` and takes no trap; `ebreak` does nothing.** The
whole M extension is a silent no-op. The base decode is a flat list of positive AND-terms with no
default arm.

**MY SECURITY FRAMING WAS WRONG, AND THE ADVERSARIAL PASS IS WHAT CAUGHT IT.** I justified this as
*"attenuate then delegate under forward incompatibility"* -- a binary built for a machine with
attenuation instruction X, run on a machine without it, silently delegating full authority. **That
scenario cannot fire on this machine.** Every attenuation instruction Veda has is decoded AND
enforced in the RTL: CAndPerm (`:1564`, gate `:3281`), CSetBounds/Exact (`:1618-1619`, gate `:3318`),
OCA -- with `vc_candperm_enforce_neg.S` and `veda_smoke_perm_enforce_neg.S` proving the enforcement
rather than the bookkeeping. And there is no sub-extension granularity to create a mixed deployment:
`currentlyEnabled(Ext_Veda)` is one boolean with no misa bit and no version CSR. The scenario needs a
Veda v2 that does not exist.

**Worse for my framing: not one of the fail-open encodings grants authority the executing code did
not already have.** Checked one at a time. The Bind hole executes as a Bind the same code could have
issued legally with `imm = 0`. The OSpecialRW hole reaches the ODA -- which selector `00000` reaches
legally, from the same privilege level, so my "the one that today reaches a privileged register" was
false as stated. The AMO hole is gated by the FULL dereference check set and zeroes eight bytes
inside a window the holder already has store permission for -- an integrity divergence, not an
escalation. Bind mode 11 is a no-op, and a no-op confers nothing.

**THE HONEST JUSTIFICATION, which is weaker and still sufficient.** R30 is a systematic Sail/RTL
divergence and a violation of the fail-closed principle this design applies everywhere else. It is
not an exploit today. It is worth closing because **fail-open is what hides bugs**, and this project
has the receipt: `difftest/probes/p2_derive.S` records a draft that used the wrong funct3 for
CAndPerm, "which decodes as nothing -- and the probe still reported AGREE, because BOTH layers did
the same no-op." A machine that traps on the unallocated makes a forgotten decode **loud on its
first simulation**. That is the only direction a capability machine may fail in, and it is what makes
every future extension safe rather than this one.

**THE DESIGN, and the blast radius is known before the first edit.** `$veda_undef_encoding =
$veda_op_claimed && !$veda_decoded`, joining `$veda_illegal_instr` -- which already supplies
mcause 0x02 and `mtval` = the raw faulting word, exactly what a diagnosing handler needs. It must be
wired into **both** `$veda_trap_taken` (`:4183`) and `$veda_illegal_instr` (`:4251`); they are
separate lists, and adding to one alone gives either a trap with the wrong cause or a cause with no
trap. `$veda_decoded` must list TERMINAL signals, never umbrellas -- listing `$is_veda_bind` instead
of its three mode terminals is exactly how the Class 2 holes arose.

**WHAT SHIPPED, and the shape of it matters more than the line count.** The four over-broad decoders
were fixed by **narrowing the decode signal itself, not by adding a parallel gate**: every consumer
downstream -- the register writeback at `:4876`, the memory write at `:5565`, the result mux at
`:5211` -- inherits the narrowing, so there is no second place to forget. `$is_veda_bind` now pins
`$instr[31:22] == 0`; `$is_veda_atomic` requires one of the nine allocated op values, verified value
by value against Sail's `encdec_veda_atomicop`; `$is_veda_droppriv` tests `funct3`; and
`$is_veda_ospecialrw` requires a known SCR selector, which fixes the ODA gate as a side effect rather
than needing it rewritten.

Then `$veda_undef_encoding = $veda_op_claimed && !$veda_decoded`, wired into **both**
`$veda_trap_taken` and `$veda_illegal_instr`. `$veda_decoded` lists **terminals only** -- and the rule
is checkable rather than remembered: every name in it must be defined by a comparison against
`$opcode`/`$funct3`/`$funct7`, never by an OR.

**One existing test had locked the defect in.** `rtl/sim/veda_smoke_m8_neg.S:68` executed `veda.bind`
mode 11 and its own comment asserted it "must be a complete no-op". Milestone 8 had closed the
original gap -- the mode field was decoded and never checked -- by making mode 11 a clean no-op.
**That was half right, and the test then locked the remaining half in.** The destination-unchanged
assertion survives untouched; what changed is that the test now also counts the trap and checks
mcause, because without that **a refusal and a silent no-op look identical from the destination
register**, which is precisely why this went unnoticed for three milestones.

The test also had to gain a handler, and that was predicted rather than discovered: it never
installed `mtvec`, which resets to 0, so the new trap would send the PC to 0 -- outside `elfmem`'s
declared `[0x8000_0000 : 0x8007_FFFF]` -- the fetch would return X and **the whole register file
would go X**, the same unreadable shape that cost real debugging time on the paging test earlier in
this session. The adversarial blast-radius pass found that before the first edit.

**VERIFICATION.** RTL 88/88 with every image rebuilt from source; Sail 99/99 unchanged, since that
layer was already correct. Four probes flipped DIVERGE -> AGREE: `p5_reserved` (all three classes of
unallocated encoding), `p6_overbroad` (the four narrowed decoders), `p7_csr_space` (R32), and
**`p2_derive`, which is the one that matters most** -- its own header records the draft whose wrong
funct3 "decodes as nothing" while the probe still said AGREE. That encoding traps on both layers now,
so the probe is a real derivation test again.

They were recorded as expected-DIVERGE first, deliberately: an expected-DIVERGE probe that starts
agreeing **fails the suite** until someone updates the verdict, so closing a finding has to come back
through the file rather than being assumed.

Four mutants, all killed by `veda_smoke_m8_neg` and the R32 probe: delete the catch-all from
`$veda_illegal_instr`; force `$veda_undef_encoding` to zero; force `$veda_csr_undef` to zero; and --
the one that matters -- **list the bind UMBRELLA instead of its three mode terminals**, which is the
exact mistake that created the Class 2 holes in the first place.

**THE LAYER BELOW: reserved-zero fields, closed in the next increment (R30b).** The catch-all above is
opcode/funct3/funct7/selector-granular. Sail pins bits below that, and a 1 in any of them means no
encdec clause matches, so the wildcard catches it. This layer never looked. Five classes, measured
on both layers before touching anything -- Sail 5 traps, RTL 1:

| class | where it applies |
|---|---|
| bit 19 above a 4-bit vcap `rs1` | 19 of 27 encodings |
| bit 11 above a vcap `rd` | 11 encodings |
| bit 24 above a vcap `rs2` | CSeal, CUnseal, OCInvoke, OCJALR |
| `rd` field nonzero where the instruction has no destination | OCInvoke, OCJALR, OCReturn |
| `rs2` field nonzero where the slot is pinned to zero | CapQuery, CSealEntry, OCReturn, ODT-Destroy, ODT-PageOut |

**Why these bits exist is the reason to enforce them, and it is not "because Sail does".** The
capability register file has SIXTEEN entries, so every capability operand is a 4-bit field with a
hardwired zero above it inside a 5-bit RISC-V register slot. **That spare bit is the extension
budget.** Ignored, `cseal c2, c1, c17` silently uses `c1` as the sealing AUTHORITY here while a
32-register successor would use `c17` -- **register-index aliasing, and in a capability machine
aliasing a register means using the wrong authority.** Enforcing it now means no binary can ever come
to depend on the bit being ignored. Not an escalation today, for the same reason R30 is not.

**Derived, not guessed.** Every encdec clause in the four Veda opcodes was parsed and its field roles
extracted -- which operands are 4-bit vcap, which are plain 5-bit GPRs, which slots are pinned to
zero. **The seven ODT instructions came out with ALL-GPR operands and therefore no reserved bits at
all**, which is exactly the distinction that would have broken them had the terms been applied
uniformly. 26 decodes narrowed, zero ODT decodes touched.

**No new trap source was needed.** Narrowing the decode makes `$veda_decoded` false, so
`$veda_undef_encoding` fires and the existing umbrella supplies the cause and mtval. The previous
increment's infrastructure does the work.

Blast radius measured before the first edit: all **203** test sources across both corpora and the
probes, scanned against the same derived table -- **not one sets a reserved bit.**

**And the mutation pass caught a vacuous phase in my own probe.** Forcing `$veda_resv_rd_zero` true
SURVIVED the count-only version, because `c1` is not a sentry: the OCReturn would decode and then
fail its own checks, trapping either way with an identical count. **Recording mcause separates them**
-- 0x02 for an unallocated encoding, 0x18 for one that decoded and then failed -- and with that the
mutant dies on word 14. Five predicates, five mutants, all killed. Same lesson the census taught: a
phase can pass for the wrong reason on one axis while looking right on another.

**STILL OPEN: the base ISA's own decode**, where `mul` retires `x3 = 0` and `ebreak` does nothing.
That is a larger surface than Veda's and is its own increment. One thing is already known about it
and is worth recording here, because it is a trap: **R30's checkable rule does not transfer.** "Every
name in the decoded set must be a comparison against `$opcode`/`$funct3`/`$funct7`, never an OR" is
sound in Veda's space because every umbrella there is literally an OR. In the base ISA `$is_load`,
`$is_store`, `$is_jalr` and `$is_fence` are each a plain comparison against `$opcode` alone -- they
are **umbrellas that look like terminals**, and listing them would re-open the whole space.

### R33. The base ISA is fail-open too, and one umbrella was destroying capabilities

**Status: CLOSED. All four increments shipped in the order the adversarial pass forced --
R33a, then the two class-B debts, then the catch-all. `mul 3*4` went from retiring `x3 = 0` with zero
traps to trapping. Smoke 88/88, ACT4 51/51, differential suite 13/13, eight mutants all killed.**

R30 closed Veda's own opcode space. The base ISA had the same disease and a worse symptom. Measured
by running the hardware: **`mul x3, x1, x2` with 3 and 4 retires `x3 = 0` and takes no trap; `ebreak`
does nothing.** The base decode is a flat list of positive AND-terms with no default arm, and the
only base-gated inputs to `$veda_trap_taken` in the whole file are `$is_ecall` and
`$veda_purecap_violation` -- which is zero in the shipped default. **There is no trap source at all.**

**R33a: FOUR UMBRELLAS THAT LOOKED LIKE TERMINALS.** `$is_load`, `$is_store`, `$is_jalr` and
`$is_fence` were each a bare comparison against `$opcode` with no funct3 test. **R30's checkable rule
does not transfer**: "a terminal is a comparison, an umbrella is an OR" is sound in Veda's space,
where every umbrella literally is an OR, and false here -- these four are written in the exact shape
the rule calls safe, which is why they went unnoticed.

**And one of them destroys capabilities.** The store block writes data through an if/else-if chain on
the four widths with no else, so an unallocated store writes nothing and looks harmless. But the
**tag invalidation is a separate `if` at the same nesting level, gated only on the umbrella.** A
store with `funct3` in {100,101,110,111} therefore **cleared the capability tag at rs1+imm and wrote
no data** -- a silent capability kill from an instruction RV64I does not define. Measured in
`p9_tag_destroy.S`: tag 1 on Sail, 0 here, now 1 on both, with a control proving a *legal* store
clears it on both layers so the probe is not merely observing that stores clear tags.

Also corrected: **RV64 has seven loads, not eight.** `funct3=111` is not LDU -- the model's
`valid_load_encdec` guard is `(width < xlen_bytes) | (not(is_unsigned) & width <= xlen_bytes)`, and at
width 8 unsigned both disjuncts are false. And **FENCE is tightened to `funct3=000` and no further**:
the reserved fm/pred/succ combinations are to be *ignored* by the base spec, not refused, and
over-tightening is the predictable way to break the fence conformance test, which executes exactly
those reserved words.

ACT4 51/51 and smoke 88/88, both **unchanged** -- the predicted result, since R33a is
behaviour-identical for every legitimately-encoded instruction.

**WHY R33b -- THE CATCH-ALL -- IS NOT SHIPPED, and this is the whole value of the adversarial pass.**

*First, why R33a had to land alone.* None of the side-effect paths are gated on `$veda_trap_taken`.
A catch-all alone would produce a machine that reports mcause 0x02 with mtval holding the offending
word -- **which a handler correctly reads as "the instruction did not execute"** -- while the tag
clear still happened. It would look closed, the suite would pass, and the primitive would survive
behind an illegal-instruction report. Under this document's own value that a green suite measuring
the wrong artifact is worse than a red one, that is the worst available outcome.

*Second, and this is what stopped R33b.* Two adversarial lenses cleared it with byte-level evidence
-- the smoke corpus has **zero** undecoded words across 6,380, and every one of ACT4's 71,137
undecoded words sits after a `jal <failedtest_*>` in unreachable tail padding, with the run-length
arithmetic closing exactly. **The third lens landed.** Class (B) -- instructions allocated in the
claimed ISA and missing from this RTL -- is **five instructions with three distinct correct
behaviours**, and a catch-all converts every one of them into illegal-instruction, which is a
different wrong answer rather than a fix:

| instruction | correct behaviour | what a catch-all would do |
|---|---|---|
| `EBREAK` | Breakpoint exception, **mcause 3**, mtval policy-controlled and *not* the instruction word | mcause 2 with mtval = the word |
| `CSRRC`, `CSRRWI`, `CSRRSI`, `CSRRCI` | a real read-modify-write | trap |

The RTL records both omissions openly -- EBREAK as "deferred", the CSR scope cut stated in its own
comment -- so these are known debts, not oversights. But the mcause chain has **no path to 3**: it is
a three-way ternary yielding 0x02, 0x0B or 0x18, and mtval keys off the illegal term first. EBREAK
cannot be made correct without touching both.

**A second-order gap in R32, found by the same lens and verified at source.** `$is_csr_access` is
`$is_csrrw || $is_csrrs` -- only two of Zicsr's six forms -- and `$veda_csr_undef` is gated on it. So
**R32's address check never sees CSRRC, CSRRWI, CSRRSI or CSRRCI at all**: a `csrrci` to a
nonexistent CSR is **doubly silent** -- the instruction does not decode, and the address validity
check does not fire either. Closing the CSR forms is therefore not only a feature debt, it completes
a fix that is already shipped.

**The order that follows from all of this**, and it is the opposite of the order I would have chosen
without the attack: close the class-B debts *first*, then land the catch-all, whose carve-out shrinks
to nothing as each debt closes. Shipping the catch-all first would bake five wrong answers into the
machine and no test in either suite could catch them. **All three shipped in that order.**

**R33c -- all six Zicsr forms.** `funct3` is `{is_imm, csrop}`, so only 000 and 100 are unallocated in
that opcode; the immediate is the rs1 *field* zero-extended, not a register read. The access-type
table is mirrored exactly, including the rule that **a SET or CLEAR whose source is zero is a PURE
READ that must not write** -- which is what `csrr` expands to and what every trap handler in this
project depends on.

**And it completed R32, which had already shipped.** `$veda_csr_undef` is gated on `$is_csr_access`,
and that was the OR of CSRRW and CSRRS *only* -- so a `csrrci` to a nonexistent CSR was **doubly
silent**: the instruction did not decode, and the address check did not fire either. Extending the OR
closes that, and extends the compartment escape gates to the four new write paths in the same stroke.
**That was the real hazard: four ways into the compartment-state CSRs that no gate had ever seen.**

**R33d -- EBREAK, mcause 3, mtval = the faulting PC.** Both values **measured** against this project's
own Sail config rather than assumed, because the breakpoint mtval is policy-controlled by
`base.xtval_nonzero.software_breakpoint`. The trap chain had **no path to 3** -- a three-way ternary
yielding 0x02/0x0B/0x18 -- so this needed a fourth mcause arm, an mtval arm, and a trap source that
deliberately does *not* join `$veda_illegal_instr`, because a breakpoint is a real synchronous
exception and not an illegal instruction.

**R33b -- the catch-all**, written as the **complement** rather than a positive opcode list, so
`$veda_undef_encoding` and `$base_undef_encoding` partition the whole opcode space with no third
region. 59 terminals; the only three opcode-only entries are LUI, AUIPC and JAL, which is correct
since U-type and J-type have no funct fields to constrain.

**Purely additive -- a trap and nothing else -- and proven rather than assumed.** After R33a every
effect path is an OR of positive decode terms, so a word no terminal claims already did nothing and
now also traps. No side-effect squashing was needed, which is exactly what R33a bought.

**Eight mutants, all killed**, and **one survived first** -- which is the other half of the lesson.
Forcing `$csr_write_en` true SURVIVED, because `csrrsi` with `imm=0` writes `old | 0`, which is `old`:
the register is unchanged either way and the probe could not tell a pure read from a
read-modify-write. **The discriminator is a READ-ONLY CSR.** `csrr x3, 0x7C6` *is* `csrrs` with
`rs1=x0`, so under the correct rule it is a pure read and must not trap; with the rule broken it
becomes a write to a read-only CSR and does. Sail 1 trap, mutant 2. **The same vacuity shape the
census keeps finding, on a phase I had just written.**

### R32. The CSR address space is a second fail-open surface, and the encoding catch-all cannot reach it

**Status: FIXED AND VERIFIED, in the same increment as R30. Found by the adversarial pass on R30's
own fix -- the lens that was asked to prove the fix incomplete, and did.**

Sail is fail-closed for CSR addresses by exactly the construction it uses for encodings:
`postlude/csr_end.sail:11` is a last wildcard `is_CSR_accessible(_) = false`, and `veda_regs.sail`
declares accessibility for 0x7C0..0x7C8 only. **The RTL has no address-validity term anywhere** --
`$csr_rdata`'s default arm is `64'b0`, and neither `$veda_illegal_instr` nor `$veda_trap_taken`
carries an unknown-CSR term.

Measured (`difftest/probes/p7_csr_space.S`): `csrrw x1, 0x7C9, x2` traps on Sail and **reads ZERO**
on the RTL, silently. A control read of the defined 0x7C1 returns the same value on both, so this is
not a layer refusing everything.

**Zero is worse than a no-op**, because zero is a value software can act on. A handler probing for a
feature by reading its CSR concludes the feature is present and disabled, rather than absent.

**An opcode-keyed catch-all cannot close it**: a CSR access is opcode `1110011`, not one of the four
custom opcodes, so `$veda_op_claimed` is false and behaviour is bit-identical before and after the
R30 fix. **Two fail-open surfaces, two separate fixes.**

**WHAT SHIPPED.** `$csr_addr_known` enumerates all fourteen CSRs this core implements -- 0x305,
0x340-0x343 and 0x7C0-0x7C8 -- and `$veda_csr_undef` fires on an access to anything else, joining the
same `$veda_illegal_instr` umbrella. It also covers a case the finding did not name: **0x7C6, 0x7C7
and 0x7C8 are READ-ONLY in the model** -- their `is_CSR_accessible` clauses carry
`access_type == CSRRead`, so a write is inaccessible and traps before any dispatch, which is why no
`write_CSR` clause exists for them. This layer had no write path and simply ignored the attempt;
it now refuses it.

> **Kept as written, corrected here (2026-08-19).** The enumeration above is the list **as it stood
> when R32 shipped**. Two CSRs have been allocated since -- **0x7C9 `veda_mfaultobj`** (R64, read-only)
> and **0x8CA `veda_xretain`** (R71, read-write) -- and both were added to `$csr_addr_known` with the
> fix that introduced them, `0x7C9` also to `$csr_is_readonly`. Extracted from `veda_core.tlv` rather
> than recalled, the decode list is now **seventeen** addresses: `0x300`, `0x305`, `0x340`-`0x343`,
> `0x7C0`-`0x7C9`, and **`0x8CA`** -- the retain mask, moved out of the Machine custom range
> entirely by R74 so unprivileged compartments can reach it. The mechanism R32 shipped is
> unchanged; only its inventory moved.

Verified by `p7_csr_space` flipping to AGREE, and by a mutant that forces `$veda_csr_undef` to zero
and is killed.

**How it was found is the part worth keeping.** Nobody looked for it. `difftest/probes/p2_derive.S`
meant to exercise OCA and typed the wrong major opcode -- OCA is custom-2/funct3=001, the probe wrote
custom-0/funct3=000. The typo produced an undefined instruction, the two layers disagreed about it,
and the disagreement sat unread for the reasons in the next finding.

### R31. The differential harness could not fail, nobody ran it, and it compared padding

**Status: FIXED. The suite now fails, is runnable, and pins every known divergence.**

The cross-layer harness built during the audit was the project's only mechanical check that its two
implementations agree. Four defects, each of which alone made it decorative:

1. **It could not fail.** `set -uo pipefail` with no `-e`, and both the AGREE and DIVERGE branches
   ended in an `echo`. Measured: it returned **exit 0 on a divergence it had just printed in full**.
2. **Nothing invoked it.** Its entire caller was one line in a README.
3. **It compared padding.** It diffed a fixed `head -192` of each signature, but Sail emits exactly
   the words between `begin_signature` and `end_signature` -- 16 for most probes -- while the RTL
   testbench always dumps its full 192-word window. So 176 words of Sail EOF were compared against
   176 words of RTL `x`, and **every probe reported DIVERGE**. That is exactly as useless as every
   probe reporting AGREE, and it drowned two real divergences in noise.
4. **It measured two different vintages.** It consumed `rtl/sim/veda_core.sv`, which is SandPiper
   output that only `run_veda_smoke_test.sh` regenerates. Land a change in `veda_core.tlv`, skip the
   smoke script, and the harness compares a current Sail model against RTL of unknown age --
   inventing divergences that are history rather than defects. **This one was found in a fix I had
   just made an hour earlier**: I made it rebuild `sim_diff.vvp` from `veda_core.sv` every run and
   wrote in the comment that this killed the staleness class. It moved the staleness up one level.

Fixed: exit code is the verdict (0 agree, 1 diverge, 2 infrastructure); comparison length comes from
the Sail signature, which is derived from the real linker symbols; the harness refuses to run when
`veda_core.tlv` is newer than the transpiled `veda_core.sv`; and `run_difftests.sh` runs every probe
against a **recorded expected verdict**.

**Expected-DIVERGE is deliberate, and it matters.** Hiding a real divergence behind an
all-must-agree suite would repeat the mistake this document keeps finding. Three probes are recorded
as DIVERGE with their reasons, and a fingerprint of the divergence is pinned, so **either direction
now fails**: an expected-AGREE probe that diverges, an expected-DIVERGE probe that agrees (the open
item closed -- update the table), or one that diverges *differently*.

With the padding removed, the two real divergences it had been hiding are R30 above and the c11
fixture, which is R24's open half seen through a second probe.

### R24. The capability register file had no architectural reset state

**Status: THE HALF THAT IS ARCHITECTURE IS CLOSED AND DEMONSTRATED. The half that is test
scaffolding is scoped, its dependencies are mapped test-by-test, and it is NOT built.**

**It was never a rebind problem.** The original proposal -- require `veda.rebind` to refuse an
untagged destination -- was refuted here already. `cgettype c0` on a reset machine returned 0x0000 on
Sail and 0xFFFF on the RTL: one instruction, no rebind.

**The defect is that zero is a legitimate seal type.** `isSealedCap` is `otype != UNSEALED_OTYPE`
with `UNSEALED_OTYPE = 0xFFFF`, so every untouched Sail register read as **sealed with type zero** --
a type CSeal really can mint, since the otype it produces is just the sealing authority's Offset.
An unwritten register was indistinguishable from one a program had deliberately sealed.

**And one enforcement decision reads sealedness with no tag conjunct.** Rebind soft-fails on
`isSealedCap(destination)` alone. So `rebind` into a never-written register silently refused on Sail
and succeeded on the RTL. Same rule on both layers -- `$veda_rebind_sealed` is likewise
`otype != 16'hFFFF` with no tag term. **Only the reset value differed, and it changed what the
instruction did.**

The RTL is correct and Sail moved. `ext_reset()` now calls `veda_reset_crf()` before the seeding.
The value it writes is `zero_capability` from `veda_types.sail` -- every field zero, otype =
UNSEALED_OTYPE -- **a constant that already existed and had no callers.** The right answer had been
written down and never applied.

Verification: `vc_r24_crf_reset.S` / `veda_smoke_r24_crf_reset.S` pin the reset value directly, then
prove the consequence, with a control that seals a register for real and shows rebind onto it still
soft-fails. Sail mutant (remove the call): 98/99, this test alone dies. RTL mutant (reset otype
0xFFFF -> 0x0000): reproduces the Sail bug exactly. **Cross-layer divergence 16/16 -> 5/16.**

**THE OPEN HALF, and its dependencies are now mapped rather than guessed.** The five remaining
registers are the slots where BOTH layers seed test fixtures inside the architectural reset, at
different indices with different contents. A mechanical operand-role scan -- every `encdec` clause
parsed, then all 890 `.insn r` and 251 `.insn i` lines in both corpora resolved to cap-read /
cap-write / GPR -- found exactly nine cold readers:

| reg | consumer | what the fixture buys |
|-----|----------|----------------------|
| c10, c11 | `vc_r10_ocinvoke_region_fault_neg.S` | sealed region-2 code+data, built to pass all nine OCInvoke checks so the region gate is the FIRST failure. Without them the trap is TAG_VIOLATION and the R10 call-side closure loses its only test. |
| c12 | `vc_residency_deref_neg.S`, `vc_check_order.S` phase B | the only test of the DEREFERENCE-side residency gate; the other residency tests fault at Bind and never reach a dereference. Pairs with ODT entry 600. |
| c13 | `vc_r10_ocreturn_region_fault_neg.S` | region-2 sentry, the RETURN half of the R10 closure. |
| c14 | `vc_r10_rt_valid_gate_neg.S` | region-3 sentry plus a deliberately contradictory table slot (`rt_valid = false, resident = TRUE`). **`rt_valid` has exactly one consumer in the whole model and this is it** -- drop the fail-closed conjunct anywhere else and nothing notices. |

Plus three RTL cold readers and one difftest probe.

**The decision, taken from three independently-designed options and then attacked from three angles.**
Ranked: gate the fixtures behind an explicit layer-parallel test-only switch that is OFF by default,
so the architectural reset is clean and identical and the differential harness measures architecture
rather than scaffolding. Making the fixture states reachable through a new instruction was **rejected
by its own author**: the states are unreachable by design, and a mechanism to construct them is a
mechanism to construct the attack the defence exists for. Making the two layers byte-identical while
leaving the fixtures in reset ranked last -- it buys byte-identity without architectural identity,
and makes reset hand the running program five TAGGED capabilities, two carrying Execute|Invoke, as a
normative claim. **On a machine whose thesis is that authority is derived, reset-with-authority is
the one state where nothing derived it.**

**Two of the three adversarial lenses landed, and neither hit the reset fix.** The security lens
confirmed the flag itself is strictly authority-reducing and could build no attack on it -- but broke
a region-pager idea that had been bundled in, on the ground that `veda_crbr_restore_on_xret` is
infallible *because* "the Region Table is immutable after reset (no RT-write instruction exists)".
The drift lens broke the winner's policing story, and it was right: the harness that was supposed to
police the two switches was R31 above. **The anti-drift mechanism has to exist before the thing it
polices ships**, which is why R31 was fixed first and the flag is not built yet.

### R29. The RTL suite could not be rebuilt, and five tests were passing on images nobody could reproduce

**Status: FIXED. 93 images now built from source on every run; RTL 87/87 with every one of them
freshly assembled.**

Found while wiring the R26 demonstrator in: `sim/*.hex` is gitignored (`.gitignore:38`) and
**nothing in the repository rebuilt it.** The whole RTL suite ran only on a machine where those
images happened to survive from a hand-typed `gcc` invocation -- one that reached into a DIFFERENT
project's tree for its toolchain, `rva23-core/toolchain`, which is frozen and is not a dependency
this line is entitled to have. On a fresh clone every `vvp` would have failed for want of an input
the tree cannot produce. **For a security corpus, 87 tests nobody else can run is not far from not
having them.**

The runner now assembles every test from source before simulating, using the project's OWN toolchain,
resolved exactly the way `sail_tests/run_veda_selfcheck_tests.sh` resolves it.

**Building them for the first time immediately found three things, each measured rather than
reasoned about, and the second and third are the interesting ones.**

**The preprocessor is load-bearing, in both directions.** With cpp ON, three tests fail: prose in
their headers parses as C -- an `# if Offset would land >= Length` read as a directive, and two
headers naming `rtl/sim/*.S`, where `sim/*` opens a comment that never closes. The tempting fix is
to turn cpp off. With cpp OFF, **41** tests fail, because the corpus writes its comments with `//`
and only the preprocessor strips those. So cpp stays on and three comment lines were reworded. Had
either setting been chosen by reasoning instead of by running both, the answer would have been wrong
in one direction or the other.

**And a linker script was sitting in the tree, referenced by nothing.** `sim/veda_smoke_test.ld`
places `.data` immediately after `.text`. A bare `-Ttext=0x80000000` instead lets the linker
page-align `.data`, landing it a full 0x1000 past the end of `.text`. **Five tests fail with that gap
and pass without it** -- paging, scheduler, cross-thread and the two syscall0 tests, which are
exactly the five in this corpus with a non-empty `.data`. Every other test has no `.data` at all,
which is why the gap was invisible for as long as the images were never rebuilt.

**The lesson is the same one the mutation census taught, arriving from the other side.** The census
asked "is any test watching this check?" This asks the prior question: **is the artifact under test
the one the source describes?** A green suite answers neither by itself. The census found 22 checks
nobody was watching; this found five tests whose inputs could not be regenerated from the repository
at all, and the correct build turned out to be recoverable only because someone had committed the
linker script years-of-commits ago and then never referenced it.

### R26. Six security gates infer "not in a compartment" from a value software chooses

**Status: CLOSED ON BOTH LAYERS AND DEMONSTRATED. The escape is real; the obvious fix is REFUTED
by the corpus; the fix that shipped needed no new architectural state at all, because the state it
needs was already there. Sail 98/98, RTL 87/87, and the demonstrator kills a mutant at every one of
the six sites individually.**

This began as a proposal to make purecap a one-way latch, because `veda_mode` is clear at reset and
any code with unbounded PCC in Machine mode can clear it again -- and a trap handler has both by
construction. **The latch was rejected on two independent grounds, and the refutation found something
much worse.**

**Why the latch is dead.** `write_CSR(0x7C5)` gates SET and CLEAR on the *identical* expression, so
there is no asymmetry to build a latch on. And the marginal authority it would deny is empty:
`{can clear purecap}` is a strict subset of `{can mint a tagged capability over arbitrary physical
memory}` via `POPULATE_FAST`, which needs only `Machine | ODA` and validates no Base. Worse, the door
the latch closes is the only one that provably **cannot forge a capability** -- plain stores clear the
granule tag -- while Populate-Fast plus Bind yields a *tagged* capability that is sealable, storable
with its tag, and inheritable across OCInvoke. **It closes the visible door and leaves the laundering
door open.** It is also not free: purecap is a total prohibition, not a check, and MMIO is reachable
only through the ordinary path, so a latch thrown before the timer is armed is a permanent
machine-wide denial of service in one instruction.

**THE REAL FINDING.** `veda_pcc_length != VEDA_PCC_UNBOUNDED` is the second disjunct of the purecap
hook -- and of five Veda CSR escape gates, the mtvec gate, fetch bounding, and the second arm of
`veda_bind_domain_ok`. **Six independent security gates use "PCC Length is all-ones" as a proxy for
"we are not inside a compartment".**

That proxy is forgeable, and this codebase already wrote the collision down and never acted on it:
*"an object may legitimately have Length == VEDA_PCC_UNBOUNDED ... the collision is reachable, not
theoretical."* OCInvoke and OCReturn assign `veda_pcc_length = cs1.Length` verbatim, so entering a
compartment on a sentinel-Length object makes all six gates read false at once. That compartment can
then widen its own PCC through CSRs 0x7C0/0x7C1, **which carry no privilege gate at all**, forge
mepcc, fetch anywhere, and use ordinary loads and stores freely. **Reachable at any privilege.**

**AND THE OBVIOUS FIX IS WRONG.** Reserving the sentinel -- refusing `Length == 0xFFFFFFFFFF` at
Populate-Fast, the only write path that can produce it -- was implemented, typechecked clean, and
**broke 13 Sail tests and 6 RTL tests**. The reason is the finding underneath the finding:
**22 Sail tests and 14 RTL tests construct exactly that object on purpose**, because *returning to
unbounded PCC* requires a max-Length code object and OCReturn takes its bounds from the sentry's
Length. DESIGN_01 already recorded this as a wart -- *"an awkward requirement for something as
ordinary as leaving a compartment"* -- without connecting it to a security consequence.

**The escape construction and the legitimate return path are the same object.** No refusal at the
mint site can tell them apart, because there is nothing to tell apart.

**What that means, and it is the whole lesson: a security state is being INFERRED from a data value
rather than TRACKED.** "Am I in a compartment" is a property of the machine, not of a number the
entered object happened to carry. The fix is to stop inferring -- an explicit in-compartment state
set by OCInvoke, cleared by OCReturn and by the trap PCC reset, with the six gates reading that
instead of comparing a Length. Then the sentinel Length becomes an ordinary large number, the return
path keeps working unchanged, and the forgery has nothing to forge.

**And then the increment turned out to be already built.** The specification above asks for a state
set by OCInvoke, cleared by OCReturn and by the trap PCC reset. `veda_pcc_object` is exactly that
state and has been since R11(b): OCInvoke sets it to the entered code object, OCReturn restores it,
and trap entry clears it to `VEDA_OBJECT_NONE`. So no new register, no new nesting question, no new
trap interaction -- **the six gates simply stop asking for the Length and ask for the name instead.**

That substitution is what makes the forgery impossible rather than merely harder. A Length is a
number Populate-Fast will write for anyone; `VEDA_OBJECT_NONE` is not a number software can arrive
at, because it is not an object, and the only way to acquire a PCC bearing it is to not have crossed
a boundary. **The predicate stopped being a comparison against a value and became a question about
provenance.**

Applied as an ADDED conjunct, never a substitution: the Length term stays. If some future path ever
does narrow the PCC without setting an object, the old term still refuses. Six sites in Sail
(`write_CSR` for 0x7C0, 0x7C1, 0x7C2, 0x7C3 and 0x7C5, plus mtvec in the access predicate) and one
fused OR-list in the RTL, which carries all six CSRs in a single expression.

**THE DEMONSTRATOR, which was owed and is now paid.** `vc_r26_authority_neg.S` and
`veda_smoke_r26_authority.S` enter a real compartment on a code object whose Length IS the sentinel,
then attempt the escape from inside.

The construction rests on one property, and everything else in the test exists to protect it:
**inside that compartment `veda_pcc_length` reads 0xFFFFFFFFFF -- byte-identical to its value at
boot.** The length term therefore evaluates the SAME in both halves of the test and cannot be what
refuses. Only the object differs: NONE outside, 30 inside. Both tests pin that equality explicitly,
because without it a test would still pass if the compartment had merely narrowed its own bounds,
which proves nothing about this finding at all.

Two anti-vacuity pins, both earned rather than anticipated. The first draft of the RTL test FELL
THROUGH: the OCInvoke trapped, the handler stepped over it, and execution reached the landing pad in
a straight line having never entered a compartment -- where the saved-bounds CSR legitimately still
holds the sentinel, so it would have reported PASS. Both tests now assert entry as a fact. And both
assert that OUTSIDE, the very same write LANDS, so a CSR wired permanently shut could not pass either.

Getting OCInvoke to succeed took reading `$veda_ocinvoke_violation` term by term rather than
guessing at it, twice. It demands two capabilities, both tagged and sealed under the SAME otype,
both carrying PERM_INVOKE, with EXECUTE on the code side and NOT on the data side. Passing one
capability twice fails on the data-side EXECUTE term alone. And the seal authority needs a NON-ZERO
Length, because CSeal requires `cs2.Offset < cs2.Length` -- an authority may only mint otypes inside
its own range. That failure is quiet in an instructive way: CSeal writes every other field and takes
only the TAG from the authorisation result, so an unauthorised seal yields a capability that looks
correct in every field and is simply untagged.

**Mutation results, which are the actual proof.** RTL: delete the single `pcc_object` comparator and
the compartment rewrites its own execution bounds (`mepcc_length` becomes 0x40) and captures the trap
vector (`mtvec` becomes the hijacked address). Sail: each of the six sites was reverted
INDIVIDUALLY, with a full model rebuild per site, and **all six were killed -- and every one of them
left the other 97 tests green.** Nothing else in either corpus was watching any of these gates.

That last number is the more uncomfortable one. The three escape tests that already existed
(`vc_pcc_csr_escape_neg.S`, `vc_pcc_csr_escape_mepcc_neg.S`, `vc_pcc_mtvec_escape_neg.S`) all build
their code object with `Length = 0x0040`, a NARROW compartment, so the OLD length predicate alone
refuses them and they pass unchanged on the unfixed model. They could not have been written any
other way: they use the packed-descriptor form of Populate, whose Length field is 16 bits and cannot
express a 40-bit sentinel. **The corpus had three tests aimed at this exact gate and none of them
could see the hole, because the encoding they used could not reach it.**

**What DID ship: the privilege half of the `veda_mode` write, which the RTL was missing.** Sail's
`write_CSR(0x7C5)` requires `cur_privilege == Machine`; the RTL checked only the PCC-bounds half. So a
post-`droppriv`, unbounded-PCC principal could clear purecap on hardware while being refused at
Populate, which does carry the privilege term. One AND term, gating the write-enable rather than
raising a violation, because Sail's non-Machine write is a silent no-op that neither traps nor
writes. Sail 97/97, RTL 85/85.

**On the reset default, which was the original question: it stays OFF, and now for a real reason
rather than by accident.** It was never a decision -- the specification does not define CSR 0x7C5 at
all, and the only recorded rationale was test-corpus compatibility. But four independent capability
systems were checked and not one boots with enforcement on; all four start at maximal authority and
narrow monotonically. Veda-Core's genuine outlier property is not the default: it is that there is no
root-capability analogue, so "off" means *unchecked* rather than *checked against a root you still
hold*. That gap deserves its own design pass. A sticky bit over a total prohibition was not the way in.

**Also corrected, because it was load-bearing for the rejected proposal: the bootstrap justification
is false.** `ext_reset()` seeds the ODT before the first instruction, and even from an empty ODT,
Populate takes everything from GPRs and touches no memory, Bind reads no memory, and OCS.D writes
through the capability path. **Object construction under purecap needs zero ordinary loads or
stores.** The genuine bootstrap blocker is device MMIO, not object construction.

### R20. WITHDRAWN before it was acted on -- "the memory-tier timing leaks physical addresses"

**Status: NOT A FINDING. Recorded because the refutation is more useful than the claim was.**

The claim: Milestone 24's TCM tier charges a DRAM stall only on a miss, and for OCL.C/OCS.C the hit test is
`$veda_capmem_tcm_hit = ($veda_real_addr[31:0] >= TCM_SCRATCH_BASE) && (< BASE+SIZE)` where
`$veda_real_addr = $veda_rs1cap_base + $rs2_data` -- a secret physical Base plus an attacker-controlled offset.
Sweep the offset, find the timing flip, recover the Base. A timing breach of the address-less pillar.

It was filed for adversarial refutation before being recorded as real. Six independent angles attacked it. It died,
and two of its numbers were wrong as well:

- **The premise is false. `cgetbase` already returns the Base to any capability holder, unprivileged and untrapped,
  on both layers** -- RTL `veda_core.tlv:3205` returns the identical signal via the identical operand field as the
  alleged channel, `$reg_write` at :4717 carries a bare `$is_veda_capquery ||` with no violation, tag, seal, or
  privilege term, and the code says so on purpose at :1518 ("No permission or bounds checks on the query family at
  all -- deliberately"). Sail matches at `veda_cap_insts.sail:149`. A channel that recovers a value one instruction
  already hands over leaks nothing. **Information gain: zero.**
- **Recoverability was overstated by 24 bits.** The comparison at :3118 is on `$veda_real_addr[31:0]`; Base is [55:0].
- **Cost was understated by five orders of magnitude.** Membership in a 4 KiB window is not monotone, so there is no
  binary search -- a strided linear scan of ~2^20 probes, not ~32.

**What this cost, and what it bought.** The claim was wrong, and stating it as a finding would have sent real work
after a phantom. What the refutation produced instead -- because three of the six angles kept reading after their
assigned target died -- is R21 below, which is worse, needs no clock, and had been sitting in the same expression.

### R21. The Milestone 24 stall swallows its own trap, fail-open

**Status: CLOSED, and the recorded premise below was WRONG. FIX 1 closed R21 completely. FIX 2 has NO
REACHABLE TRIGGER -- proven by construction and then measured at DRAM_EXTRA_CYCLES = 10. It is
deliberately NOT built; a tripwire fires if it ever becomes reachable. The stall path is now
script-verifiable at nonzero E: 88/88 at E = 0 and 88/88 at E = 10.**

At `DRAM_EXTRA_CYCLES != 0`, an OCL.C/OCS.C (or a bind) that BOTH violates AND misses the TCM tier:

1. `$veda_dram_stall_req` (:1447) fires. Its only trap term was `!$veda_pcc_violation` -- a **fetch-side** check.
   It never referenced `$veda_oclc_violation`, `$veda_ocsc_violation`, or any bind refusal.
2. Simultaneously `$veda_trap_taken` = 1, `$pc_src` = 1, `$alt_pc` = `$mtvec`.
3. The `$pc` mux (:1039) ranks `>>1$veda_dram_busy` **above** `>>1$pc_src`, so the PC freezes and **the mtvec
   redirect is discarded**. There is no pending-trap latch.
4. `$instr` is forced to NOP for every stall cycle (:1101), so `$pc_src` reads 0 out of all of them. When busy
   clears, the mux falls through to `>>1$pc + 4`. **The handler is never entered.**
5. But every trap **state** effect, gated on `>>1$veda_trap_taken`, still fires:
   `$veda_pcc_length := 40'hFFFFFFFFFF` (**unbounded**), `$veda_pcc_base := 0`, `$veda_current_region := 0`,
   `$veda_pcc_object := VEDA_OBJECT_NONE`, `trap_depth++`.

**An attacker deliberately faults one OCL.C on a DRAM-tier address and keeps running its own instruction stream at
pc+4 with the compartment PCC bound removed and the region reset to 0.** That is a compartment escape, not an
information leak. No clock, no sweep, no statistics.

~~The same mux also silently swallows ordinary taken branches, JAL/JALR, OCInvoke/OCReturn and mret --
a separate functional-correctness bug at the same place.~~ **THIS IS FALSE AND THE CORRECTION IS THE
MAIN RESULT OF THE INCREMENT.**

A redirect is lost only if `$pc_src` and `$veda_dram_busy` are true in the SAME cycle. This is a
single-stage machine -- `|cpu @0`, and there is no `@1` -- so both are functions of ONE `$instr`.
Every instruction that can request a stall is **custom-0** (`0001011`): the three Bind modes and
OCL.C/OCS.C. Every non-trap redirect lives in a different opcode -- branch `1100011`, jalr `1100111`,
jal `1101111`, system/mret `1110011`, and the OC* jumps in custom-2 `1011011`. **One instruction
cannot be both**, and during continuation cycles `$instr` is a forced NOP so nothing executes there
either.

The only redirect a custom-0 instruction can raise is its own trap, and FIX 1 excludes every trapping
condition on exactly those five instructions. **So FIX 1 closed R21 completely and FIX 2 has no
reachable trigger.** Two independent enumerations reached this before I did, and I verified it at
source rather than taking it: the opcode constants, the single-stage structure and the stall-request
term list.

**The most instructive detail: the author had already found this hazard, on the other side.** The comment at
:1436 states the `!$veda_pcc_violation` guard exists precisely so "a faulting fetch must not spuriously start a
stall that would then eat into the trap-handling flow." The guard was correct and was simply never extended to the
data side. A known hazard class, incompletely applied -- an oversight, not a decision.

**FIX 1, applied.** Gate the stall on the trapping conditions. The bind arm needs **all four** of its refusal terms,
not just `$veda_bind_trap`: `$bind_wr_en` (~:2424) gates on bind_trap, domain_violation, region_fault AND
residency_fault, while `$veda_bind_trap` alone is only owner||notfound (:1974). The reviewing judgement recommended
`!$veda_bind_trap` alone; applied verbatim that would have left three of the four escape paths open. Checked against
`$bind_wr_en`'s own term list rather than taken on trust.

The edit is **strictly monotone** -- it only ever removes stalls, and only on paths that trap anyway. It cannot
create a stall that did not exist, so it cannot open a new escape.

**FIX 2: STILL NOT APPLIED, and now for a better reason than sequencing.** It restructures the `$pc`
mux -- the most safety-critical expression in the core -- and unlike FIX 1 it is **not monotone**: it
can *create* a redirect where none happened. Taking that risk for **zero present benefit**, against a
hazard that only appears if someone later widens the stall scope, is not hardening; it is churn on
the one expression that must not churn.

**So the hazard got a tripwire instead.** `$veda_redirect_during_stall_start = $veda_dram_stall_req &&
$pc_src` drives nothing and gates nothing -- it cannot change behaviour -- but a `$fatal` fires the
moment the precondition for FIX 2 becomes reachable, naming FIX 2 in the message. That converts a
comment about future work into something that **fires**. Widen the stall scope past bind/OCL.C/OCS.C,
as this file already flags as planned, and the first simulation to hit the co-occurrence stops and
says so instead of silently discarding a redirect the way R21 originally did.

**Measured, not just argued: at E = 10 the tripwire never fired across the whole suite.** FIX 2 is
unreachable with a real stall running, not merely on paper.

**THE PROVING RUN, which was the other half of this item.** `rtl/run_dram_stall_test.sh` edits the
localparam, transpiles, runs the suite and **always restores on a trap** so an interrupted run cannot
leave the tree at nonzero E. Its most important property is the one the finding demanded: **it
REFUSES to run at E = 0**, with a nonzero exit and a message saying why, rather than passing
vacuously. That is enforced by the script rather than by an assertion inside a testbench, which could
itself be satisfied vacuously.

Getting to a clean run took two rounds of measurement rather than one. The first E = 10 run gave
**15 failures**, all with the unwritten-register signature of a cycle-budget overrun -- each stall
adds E cycles and the testbench windows were sized for E = 0. Widening every budget fourfold is
monotone at E = 0 (the program is already spinning in its halt loop) and took it to **3**.

**Those last three were the interesting ones, and they were not budgets.** They are the Milestone 24
stall tests, and their own headers said it: the permanent check was `busy_cycles == 0` at the shipped
default, while *"the OTHER half of this feature ... was verified **manually** this same session"*.
**A manual verification is exactly the gap this document has spent the increment closing everywhere
else.** They now compute their expectation as `DRAM_EXTRA_CYCLES * VEDA_DRAM_ACCESSES`, so one
testbench covers both configurations and neither is checked by hand.

The access counts were **measured, and the first attempt guessed them wrong**: a regex put 4 in all
three, and the real counts read off a run at E = 10 are **2, 1 and 5**. The number is a structural
property of each test program, and taking it from the hardware is how it stays true when the test
changes.

**Reachability, stated plainly and NOT counted as a defence.** `DRAM_EXTRA_CYCLES = 0` (:188) plus the
`!= 0` guard make `$veda_dram_busy` a structural constant 0, so the bug is unreachable in the shipped
build. **That blocker is now lifted**: the budgets are widened, the three E-dependent testbenches are
E-aware, and nonzero E is a supported, script-verified configuration rather than a manual exercise.

**Why the existing suite could not catch it.** M24 verified the stall with a **positive latency test only** -- a
faulting access during a stall was never exercised. Identical in shape to the CAndPerm defect: *tested as
bookkeeping, never as enforcement.* The most important mutant for the new test is therefore not a code mutation at
all but `DRAM_EXTRA_CYCLES = 0`, which must make the test **error or skip, never silently pass** -- otherwise the
whole bug class hides behind E=0 forever, which is exactly how it survived M24.

**Layer note.** This is RTL-only and has no Sail counterpart: Sail has no TCM, no stall, and no timing domain at
all (`mcycle` ticks once per instruction step). That is itself a hazard worth naming -- **this class of bug cannot
be caught by Sail-versus-RTL parity review, because the layer that would catch it does not model the mechanism.**

### R22 / R9. The address-less pillar, the timing rule, and the per-access ODT read -- ALL THREE RESOLVED

**Status: DECIDED AND ENFORCED. The throughput "tension" does not exist, and the reason is structural.
Both specification questions are answered, and the coupling between them is now a check that fails,
not a paragraph. Mutation-tested both ways.**

**FIRST, THE THROUGHPUT ITEM, because it dissolves rather than resolves.** The worry was that every
dereference must read an ODT entry: from DRAM each time and throughput collapses, from a cache and the
cache-less pillar dies. **Neither happens.** Verified at source, both tier tests are pure combinational
functions of values software itself chose at Populate time:

    $veda_odt_tcm_hit    = $veda_intra_region && ($veda_local < TCM_ODT_ENTRIES)
    $veda_capmem_tcm_hit = (real_addr >= TCM_SCRATCH_BASE) && (real_addr < TCM_SCRATCH_BASE + SIZE)

No tag array, no valid bits, no fill-on-miss, no replacement policy, no history. The **same object hits
or misses forever**, and what decides it is where software put it. All twelve mentions of
eviction/replacement in the RTL are comments about the *software* pager (`page.out`/`page.in`), which
is an instruction software issues, not a hardware policy. The file already states the property for the
CRBR in its own words: *"NOT a cache and NOT a TLB: one base, no tags, no fill-on-miss, no eviction,
no access history."*

**So this is not a cache, it is a static placement decode -- and that is the whole point. A cache buys
throughput with ACCESS HISTORY, and history is the channel. This buys throughput with PLACEMENT,
which the accessor already knows.** The cache-less pillar and per-access enforcement are not in
tension; the tier is what makes them compatible.

**SECOND, THE TIMING RULE. Adopted: the second bullet** -- *"tier selection must not depend on any
value software cannot already read architecturally."* Not the first. Declaring no timing claim at all
would discard a property this architecture can genuinely make, and R5 already elevates
non-speculation to a pillar on exactly that reasoning; giving up the neighbouring guarantee in the
same document would be incoherent.

**THIRD, THE PILLAR WORDING. Amended to the invariant actually built:** *"software cannot REACH memory
by a raw address."* R16's stronger sentence -- that software cannot **see** one -- was never built.
Milestone 19 made a leaked address unusable, not unlearnable, and `cgetbase` ships returning a raw
physical Base by design. **The two sentences could not both be true, and the one that goes is the one
nothing implements.**

**AND THE COUPLING IS NOW A CHECK.** R22 predicted that tier selection is conformant *"only because
`cgetbase` is open"*, and said the narrowing must land *"in the same commit"*. A comment cannot enforce
"in the same commit". `veda-core/check_timing_coupling.sh` can, and runs first in the RTL suite. It
fails the build if the capability-query family ever grows an authority gate while tier selection still
reads Base or the local ID -- so whoever gates `cgetbase` is told by a red suite that they owe the
other half. It also fails if a replacement policy ever appears in the RTL, because hit/miss would then
depend on access history, which is precisely the channel the pillar exists to remove.

It makes **no performance claim and takes no measurement** -- it is a structural invariant over the
source. That is deliberate: this document's own rule is that **a throughput measurement must never be
allowed to decide a security question**, so the enforcement of a security rule must not be a benchmark.

**Mutation-tested both ways, and the first draft failed.** Gating the query family: caught. Adding a
replacement policy: **SURVIVED** the first version, because the detector used `\b` word boundaries and
`_` is a word character -- so `\blru\b` does not match inside `$veda_odt_lru_victim`, which is exactly
how such a signal would be named here. **The check passed on a design that had just grown a
replacement policy.** Widened to substring matching; both mutants now die and the clean tree passes.
Found by mutating the check rather than trusting it -- the same lesson this document keeps recording,
this time about a check written to enforce the lesson.

R16 in this document states "Software is not supposed to be able to see a physical address at all." Meanwhile
`cgetbase` ships returning a raw physical Base and `cgetaddr` returns Base+Offset resolved, both unit-tested to
exact physical values (`veda_smoke_m11.S:34` expects 0x80011000). Milestone 19 made a leaked address **unusable**
(the purecap violation) but never made it **unlearnable**. Both sentences cannot be true.

Resolve it one way or the other -- either amend the pillar's wording to the invariant actually built ("software
cannot REACH memory by a raw address"), or gate `cgetbase` in a hardened profile. Do not leave both standing.

There is also a **specification gap** underneath: nothing in the corpus states a timing non-interference
requirement at all. Pillar 3's wording is worst-case-execution-time shaped, which is a jitter property, not a
secret-independence property. That silence is what allowed R20 to be filed as a pillar breach. Write down one of:

- *"Veda-Core makes no timing non-interference claim; tier selection may depend on physical placement, which is
  allocation-time and software-declared."* -- in which case :3118 is fine as written and R20 is permanently moot; or
- *"Tier selection must not depend on any value software cannot already read architecturally."* -- in which case
  :3118 is conformant **only because `cgetbase` is open**, and must be narrowed in the same commit that ever gates it.

The dependency runs R22 -> the timing rule -> whether :3118 needs narrowing. It should be decided deliberately,
not settled by whichever way `cgetbase` happens to drift.

### R19. Copy-on-write needs a copier, and a copier needs universal read authority

**Status: SUPERSEDED -- see "R19 DECIDED" earlier in this document. THIS ENTRY IS THE ORIGINAL
FRAMING AND ITS PREMISE IS FALSE. It is kept because the six corrections to it are worth more than
the decision was, but its status line said OPEN for long enough to mislead a later reader of this
very document into re-opening a settled question. A stale status is not a harmless leftover: it is
the only part of an entry a reader trusts without reading the rest.**

The short version of what replaced it: `veda_bind_perms` clears **bit 3 only**, and PERM_LOAD is
bit 2 -- so a COW-attenuated capability **is a read capability**, which is why the fault is a STORE
fault. The principal that takes the fault already holds read on the object it needs copied. That is
option **(d), self-service**, which this entry did not list, and options (a), (b) and (c) were all
payments to avoid granting an authority the right party already holds.

*Original framing follows, preserved for its corrections:*

The `fork` hardware chain is now complete on both layers: policy write path, per-object bind
authority, the `cow` bit, Bind attenuation, the COW fault on all five write paths, and
CGetObjectID so a handler can identify the faulting object. The remaining piece is the **copy
itself**, and the obvious plan is "the handler does it in software". That plan has a consequence
nobody has decided to accept.

**A COW handler must be able to read ANY object**, because any object may be marked copy-on-write.
So it needs universal read authority. Three verified facts make that concrete:

- `veda.bind`'s destination capability index lives in the **instruction encoding**
  (`encdec_vcap(rd)`), not in a register, so a handler cannot rebind "whichever register faulted"
  without a 16-way dispatch.
- `veda.odt.populate` requires Machine privilege or the ODA, which the handler already holds.
- **There is no object-copy mechanism in hardware at all** -- grep finds none in either layer.

And the handler runs with `veda_pcc_object == VEDA_OBJECT_NONE`, so it passes the per-object bind
gate built this session **by design**. That exemption is correct -- it is the bootstrap and the
pager -- but combined with a copier it means: *to support `fork`, this architecture must contain one
piece of code that can read every object in the machine.*

**Why that is a problem HERE specifically.** In a conventional system this is unremarkable; the
kernel reads everything. But the thesis of this design is that security should not rest on one
trusted component behaving correctly. A universal copier reintroduces exactly that, and it arrives
by accident rather than by decision.

**The options, none chosen yet:**

- **(a) Software copier, accepted.** Simple, needs no new hardware, and honestly concedes a trusted
  component. It should then be named as one in the pillar accounting rather than left implicit.
- **(b) A hardware copy instruction** -- `veda.odt.cow.split` or similar -- where hardware performs
  the copy and clears the bit, so no software ever needs read authority over the source. This is the
  hardware-first answer and matches the standing rule. Its cost is a multi-cycle memory operation
  inside an instruction, which lands in the same bucket DESIGN_02 already put paging in
  ("inherently non-deterministic ... pageable objects are best-effort"), so it does not breach the
  determinism pillar so much as extend an existing, already-recorded concession.
- **(c) A narrow copy capability** -- authority to copy *one named object* into *one named object*,
  granted per fault rather than standing. Keeps the copier in software but removes the universal
  authority, at the cost of a new authority type.

**What settles it is a measurement, not an argument:** how long a hardware copy of a realistic
object takes, against how much of the machine's security surface a universal software copier adds.
Neither number exists yet. Recorded now, before "the handler does it" becomes the answer by default.


### R11. The domain crossings never revalidate the code object -- execute-after-free

**Status: confirmed by execution, fixed in Sail, RTL mirror pending.**

Enumerate every consumer of an object's `Base` and ask which of them re-reads the ODT:

| Consumer | Rechecks {valid, generation, resident}? |
|---|---|
| `veda_check_access` -- OCL.D / OCS.D / OCL.C / OCS.C / Veda-Atomic | yes |
| `veda_check_nmc_access` -- NMC_ADD.W / .D | yes |
| OCInvoke / OCReturn / OCJALR | **no** |
| instruction fetch (PC against PCC) | **no** |

`odt_lookup` has exactly eight call sites in the model: Bind, the two dereference checkers, and
the five table-mutating instructions. **Not one crossing.**

DESIGN_02 Phase 2 added object residency to Bind and to all six data-dereference families. The
three crossings are the only Base-consumers it was never added to. So a sealed **code** capability
survived an eviction that a **data** capability to the very same object did not.

**Reproduced, with a control that isolates the asymmetry.** Page out an object, then: `veda.bind`
of that Object_ID correctly traps 0x0A (asserted on `mcause` 0x18, `mtval` 0xCA, and a resumable
`mepc`), while `ocinvoke` through a sealed code capability naming it **took the jump**. Same
eviction, opposite answers.

**This is not a paging bug -- it predates paging.** The same sequence with `veda.odt.destroy`
instead of page-out also entered the destroyed object. That falsifies this project's own stated
reason for CAndPerm existing, quoted from the model source: *"so a later ODT-Destroy still revokes
every view."* It does not revoke the execute view. Paging did not create the hole; it made the
state reachable on a routine path and placed it directly under the mechanism DESIGN_02 was
building.

It also weakens R10's own soundness note -- *"unforgeable, because only a residency-gated Bind ever
mints a capability with a given Object_ID"* -- which is residency-gated at **mint** and was never
rechecked at **use**.

**The sharpest detail:** OCInvoke *already* checks **region** residency. That is R10, added two
increments ago. It asks whether the target domain's table is paged in, and never whether the target
object is. The region-versus-object distinction DESIGN_02 draws was carried to the crossings for
regions and never for objects.

#### The fix, in two halves, because neither alone is sufficient

| | closes | does not close |
|---|---|---|
| **(a) revalidate at the crossing** | entering an object evicted while you were not running it | eviction of an object while you **are** running it -- fetch never rechecks |
| **(b) PCC carries an object identity, and eviction refuses on it** | evicting the running code object (live PCC **and** saved MEPCC) | later entry through a sealed capability held in a register |

**(a) is built.** One helper, `veda_code_object_check`, added to all three crossings: one ODT read,
two verdicts -- generation/valid first (the permanent verdict), residency last (the serviceable
one), matching both dereference checkers term for term. Placed after the region check, because a
non-resident region means the object's entry was never legitimately readable, and before any
commit, so a faulting crossing leaves nothing behind.

**(b) is the next increment.** PCC and MEPCC gain `{Object_ID, generation}`; page-out and Destroy
refuse when the target backs the live PCC or the saved MEPCC -- one 44-bit compare on a cold path.
This puts the cost at the rare event rather than at every fetch, which is the same principle
DESIGN_02's cached-Base decision already settled. It is also the object-level twin of an obligation
already written down for regions: *"the future RT-write instruction must refuse to clear residency
on the CURRENT region and on any SAVED region."* Same sentence, object for region.

#### What a crossing actually reports, and why it is not 0x0A

The first version of the regression test asserted RESIDENCY (0x0A) for a crossing after page-out
and was **wrong** -- the model was right. Page-out **bumps the generation**, so any capability held
across it fails the generation check before residency is consulted, and reports 0x02.

That is the Option-A contract working as chosen, not a defect. The **capability** is permanently
dead, because its generation is gone forever; the **object** is still serviceable, and software
learns that by re-Binding, which reports 0x0A. Held capability gets the permanent verdict, fresh
Bind gets the serviceable one. Both correct; they answer different questions.

A consequence worth stating: the residency arm of the crossing check is **unreachable through the
ISA today**, exactly as the dereference-side residency term is, and for the same reason -- page-out
is the only producer of {valid, non-resident} and it always bumps. It is kept anyway. That
soundness argument is a property of the current producer set, not of the checker, and DESIGN_02
still has `cow` and `backing` to add.

#### IMPLEMENTATION BLOCKER found before editing -- nine call sites, not one

The fix was scoped as "add an out-of-band validity bit and a nesting guard". Enumerating the real
call sites of `veda_pcc_save_and_reset()` before touching anything shows why that scoping is wrong:

| site | kind |
|---|---|
| `postlude/step_ext.sail:248` | the trap chokepoint `handle_trap_extension`, **guarded** |
| `postlude/step_ext.sail:94` | fetch-check error path |
| `postlude/step_ext.sail:174` | data-check error path |
| `extensions/Veda/veda_bind_insts.sail:128` | inside `veda_trap()` |
| `veda_regs.sail:372, 376, 380, 384, 409` | **five CSR-escape write gates** |

**Nine, and the last five are different in kind.** They read
`if veda_pcc_length != VEDA_PCC_UNBOUNDED then { veda_pcc_save_and_reset(); Err(()) }` -- they are
not trap-entry hooks, they are *inline traps*: a compartment attempting a CSR escape is saved,
reset, and then errored out, and the `Err` subsequently raises a real exception that reaches the
chokepoint too.

**Two separate hazards follow, and they pull in opposite directions.**

1. **Double-accounting.** One logical trap can reach the save twice -- once inline at a CSR gate,
   once at the chokepoint. Today the chokepoint's guard
   (`pcc_length != UNBOUNDED | current_region != 0`) accidentally prevents this, because the first
   call has already reset both. Any design that makes the second call unconditional -- which a depth
   counter requires, since it must count every trap -- **breaks that accident** and counts one trap
   as two.

2. **Undetectable nesting.** The mirror problem. On a genuinely nested trap the live state is
   *already* reset (PCC unbounded, region 0), so the same guard is **false** and no save is
   attempted -- meaning the nesting is never observed at all. A design that only acts where the
   guard fires therefore cannot see the case it exists to catch.

So the trigger question ("is a compartment live, and does its context need saving?") and the validity
question ("is a save already outstanding?") are **genuinely different predicates that must be tested
at different places**. The in-band sentinel is sound for the first and unsound for the second, which
is the root cause restated precisely. Conflating them is what produced R12 in the first place, and a
naive validity bit would reproduce it in a new shape.

**Consequence for the fix.** Either the chokepoint becomes the sole caller -- deleting the other
eight, which needs the Milestone 20 ordering rationale for the inline CSR-gate saves to be
re-derived and disproved first -- or the nesting detection is split out of the save entirely and
placed where it fires exactly once per trap. Neither is a small edit, and choosing wrongly converts
a silent escape into a spurious fail-closed on ordinary CSR traps, which the corpus would surface as
a wave of unexplained failures.

**Status: not implemented.** Recorded at the boundary deliberately rather than half-edited. The
grounding that scoped this increment described three redundant call sites; there are eight, five of
them structurally different from what was assumed, and building on that scoping would have produced
a fix that passed its own tests and was wrong.

#### STATUS after the fix landed -- partially verified, with one UNRESOLVED behaviour

**Landed (Sail, commit e1660aec):** 86/86, and the confirmed proof-of-concept now fails, so the
escape it demonstrated is gone. The chokepoint is the sole caller (eight inline saves removed);
occupancy moved out of band to a depth counter; poison marks an unreconstructible chain; a poisoned
unwind installs a zero-length PCC.

**A Veda-specific case found only because the fix broke two tests.** A depth counter assumes a trap
is left by an xret. This architecture has a second exit -- the trusted switcher leaves a handler by
OCRETURN, and cannot do otherwise, because narrowing PCC with `csrw` then falling through to a
separate `mret` requires fetching that `mret`, by then outside the narrowed bounds. Depth therefore
incremented and never decremented. OCRETURN now abandons the frame, which follows from its already
installing PCC from its own operand. That restored 86/86.

**UNRESOLVED, and it may be a real defect in the fix rather than in the test.** A regression test
written to pin the *lossless* property -- compartment bounded 0x0100, trap, nested trap, inner xret,
outer xret, bounds expected intact -- observes the restored `veda_pcc_length` as **0**, the deny
value, not 0x0100.

Measured, not inferred: the trap count is exactly 3 as designed, and bisection confirms every stage
is reached (compartment entered bounded, nested trap taken, outer handler resumed, compartment
resumed and its ecall reached the verdict). So the flow is right and **the implementation is denying
a case it was designed to reconstruct**.

By the intended semantics the nested level carries no context -- PCC is unbounded and the region is
root at that point -- so `veda_trap_level_has_context()` should be false and no poison should be
set. Something makes it true, or the deny fires from the other branch. **Not diagnosed.**

Consequences, stated plainly:

- The **security** property holds either way: denying is fail-closed, and the escape is
  demonstrably gone. Nothing is more permissive than before.
- The **losslessness** claim is currently **unsupported**. A compartment that survives a nested trap
  may be denied rather than resumed, which is a usability regression and would surface as a
  compartment that cannot continue after any nested fault.
- Therefore **no mutation sweep has been run**, because a sweep against a behaviour that is not yet
  understood would measure the wrong thing and produce verdicts that look authoritative.

The test is retained out of the globbed corpus as `poc_r12_nested_lossless_UNRESOLVED.S` so the
suite reads an honest 86/86 rather than carrying a red test, and so the evidence is not lost.

**R12 IS NOW COMPLETE IN SAIL AND VERIFIED IN BOTH HALVES (2026-08-13).** Sail 88/88.

| mutant | verdict |
|---|---|
| capture unconditionally -- recreates R12 exactly | KILLED |
| OCRETURN stops abandoning the trap frame | KILLED |
| poison never set on an unreconstructible level | KILLED |
| poisoned unwind reconstructs instead of denying | KILLED |
| saturation does not poison | SURVIVED -- equivalent by construction |

The last is reported as equivalent rather than chased: reaching saturation needs 255 nested traps,
which is not reachable through the ISA. The saturating branch stays, because that argument is a
property of what software can currently do, not of the checker.

**The fail-closed half was initially unverified, and that is the finding worth keeping.** The first
sweep killed the mutant that recreates the defect itself but left poison and saturation untouched --
the mechanism was proven to WORK while nothing tested what it REFUSES. That is the same shape found
at every layer of this work: Sail paging left four survivors, all refusals or preservations; RTL-6b
left four of seven dereference families untested; R11 missed OCReturn on one layer and OCJALR on the
other. **A refusal that no test can distinguish from its own absence is not verified, however
correct it happens to be.**

The mutant that mattered most on the second pass was the one making a poisoned unwind reconstruct
instead of deny -- that hands unbounded authority to a level that had been narrowed, which is R12
itself reproduced one level up. Killing it shows the test catches the defect in its new shape, not
only its original one.

**A real property of self-narrowing, found while building the test.** Narrowing PCC to a 0x0080
window from inside a handler puts the very next instruction outside that window, so the narrowing
itself fetch-faults and the trap depth runs away. Any software that narrows its own PCC must size
and place the window to still contain the code that continues executing. That is a genuine
constraint, not a test artifact, and it is recorded in the test.

**RTL MIRROR ATTEMPTED -- and it surfaced a CONTRACT QUESTION that must be decided first.**

The fix was applied to `veda_core.tlv` (depth, poison, capture/consume keyed on depth, four-way
restore, OCRETURN abandon) and the suite ran **69/70**. The single failure is
`tb_veda_smoke_m21_restore`, and it fails in exactly two of its three phases:

| phase | result | what it asserts |
|---|---|---|
| 1 -- positive restore + enforcement | **PASS** | ordinary restore, preserved by the fix |
| 2 -- explicit override honored | **FAIL** | software writes mepcc via CSR, then mret restores it |
| 3 -- nested-trap staleness + repeat | **FAIL** | **the pre-R12 self-consuming behaviour itself** |

**This is not a regression. Phase 3 asserts the defect.** It encodes the old contract, in which the
restore is keyed on the in-band sentinel and any mret consumes the slot -- which is precisely what
R12 changes. A test asserting the old behaviour must fail when the behaviour is corrected, and
"fixing" it to pass without deciding would silently re-enshrine the defect.

**Phase 2 is the real question, and it is a genuine design decision.** With no trap outstanding
(depth 0), the old design restored PCC from a software-written mepcc; the new one does not, because
occupancy is now out of band and depth 0 means no frame is owed. Two readings:

- **It was a feature.** Software deliberately stages an mepcc and returns into it. Note this grants
  no new authority -- software able to write 0x7C2/0x7C3 while unbounded can already write PCC
  directly via 0x7C0/0x7C1 -- so honouring it is not an escalation.
- **It was an accident of the sentinel.** The restore fired because `mepcc_length != UNBOUNDED`
  happened to be true, not because anything was actually saved. That is the same conflation that
  produced R12, and preserving it preserves the root cause in a second place.

**DECIDED 2026-08-13: it was an artifact of the sentinel.** Software-staged restore-on-mret is NOT
a supported architectural feature. It fired because `mepcc_length != UNBOUNDED` happened to be true,
not because a frame was owed -- the same conflation that produced R12, and keeping it would preserve
the root cause in a second place.

**Consequence: `veda_smoke_pcc_restore_on_mret.S` phases 2 and 3 must be rewritten to the post-R12
contract.** This is a specification change, not a test adjustment, and the two phases encode the old
contract explicitly in their own words:

- **Phase 2** has the handler write `0xFFFFFFFFFF` into `mepcc_length` before mret -- literally
  clearing the in-band sentinel to suppress the restore, so that execution resumes unbounded. Under
  the decision above that mechanism no longer exists: occupancy is out of band, and software cannot
  suppress a restore by writing a value. **Rewrite to:** software may still influence WHAT is
  restored by writing `0x7C2`/`0x7C3`, because that grants no authority it does not already have via
  `0x7C0`/`0x7C1` -- but it may not influence WHETHER a restore happens. Assert that a
  software-written mepcc IS restored at the outermost unwind, and that writing the sentinel no
  longer suppresses it.
- **Phase 3**'s own comment states it is validating *"the new conditional-capture guard correctly
  skips it"* -- i.e. it exists to test the guarded capture that came from the false comment.
  **Rewrite to:** a nested trap must leave the outer save intact (now because depth != 0, not
  because a value comparison skipped the capture), the inner unwind must reconstruct the reset
  context, and the outer unwind must restore the real bounds. That is the same property the Sail
  test `vc_r12_nested_lossless` already pins, so the two layers end up asserting one contract.

**R12 IS NOW COMPLETE IN BOTH LAYERS (2026-08-13).** Sail 88/88, RTL 71/71. The comment-caused
divergence is closed and the two layers enforce one contract for nested traps.

RTL sweep: unguarding the capture (the Sail half of the defect), consuming on any mret (the RTL
half), OCRETURN no longer abandoning the frame, and poison never being set are all KILLED.

**One survivor, and analysing it produced a design property rather than a test gap.** The mutant
targeting the OUTERMOST poisoned unwind survives because that arm is unreachable by construction:
once poisoned, every unwind installs a zero-length PCC, which cannot fetch, so the next fetch traps
and pushes the depth back up. Depth oscillates between 1 and 2 and never reaches 0.

**Stated plainly, because it is a consequence and not an artifact: a poisoned chain never fully
unwinds, and the compartment is permanently unresumable.** That is fail-closed behaving as intended
-- the handler still runs, since a trap resets PCC to unbounded -- but **software must detect poison
via 0x7C8 and tear the compartment down rather than retry the return.** Reasoned from the mechanism,
not executed, and recorded as reasoning.

**Two stale-artifact near-misses in this increment, same class both times.** A grounding agent read
the Sail tree mid-mutation and produced a rigorous, well-evidenced, entirely spurious finding. And
the M21 phase-2 rewrite was reported as failing when it was actually passing -- its `.hex` had been
built with `gcc`, which fails on that file because a comment contains `/*`, so the binary never held
the rewrite; assembled with `as` it passes. **A stale artifact does not fail, it lies.**

**M21 REWRITE PROGRESS -- phase 3 done and it validated the fix; phase 2 still open.**

**Phase 3 is the substantive one, and rewriting it confirmed R12 independently.** Its handler
contained an explicit software workaround whose own comment states the defect exactly:

> *"mepcc is a single, global pair -- it cannot by itself distinguish 'the OUTER's own eventual real
> mret, which SHOULD auto-restore' from 'the INNER's own mret, which should NOT' (both see the
> identical mepcc_length != UNBOUNDED condition). h_phase3_inner therefore explicitly hides mepcc
> (saves it into s0/s1, clears it) before its own mret."*

So the author had **found R12, judged it a hardware limitation, and cooperated around it in
software** -- calling that cooperation "not a workaround". That is independent confirmation of the
defect from before it was named, and it is exactly the kind of software discipline a hardware-native
design exists to remove. The hide/clear/restore dance is deleted: occupancy is now out of band, so
an inner unwind and the outermost unwind are distinguishable by construction. **If that dance is
ever needed again, the depth mechanism has regressed** -- which makes its absence a live assertion,
not a simplification.

**Phase 2 still fails and is NOT diagnosed.** Its handler now writes both `0x7C2` and `0x7C3` --
expressing "resume unbounded" honestly as a frame to restore, rather than by clearing a sentinel to
suppress the restore. Phase 1 passes, so ordinary capture/restore is intact. Leading suspicion,
unverified: depth accounting across phase 1's own deliberate post-check boundary violation, which
takes an extra trap. **Recorded as a suspicion, not a conclusion.**

Both patches are preserved and apply cleanly:
`scratchpad/rtl8_r12_mirror.patch` (the RTL fix) and `scratchpad/m21_rewrite.patch` (the test
rewrite). The RTL tree is reverted to green at 70/70 rather than left red.

**State at handover:** the RTL patch is complete and preserved at
`scratchpad/rtl8_r12_mirror.patch` (103 lines, applies cleanly). The RTL tree is reverted to green
at 70/70 so nothing is left red or half-applied. The remaining work is the test rewrite above, then
re-apply the patch and re-run -- at which point the expected result is 70/70 with phases 2 and 3
asserting the new contract.

**Historical note (the question, before it was decided):**

**Not decided here, deliberately.** The RTL change is reverted so the suite stays green at 70/70,
and the complete patch is preserved at `scratchpad/rtl8_r12_mirror.patch` so no work is lost. What
must be settled first: **is a software-staged mepcc restore-on-mret a supported architectural
feature, or an artifact of the in-band sentinel?** If supported, it needs its own out-of-band
expression (e.g. a software-settable "frame owed" that is distinct from the hardware depth) rather
than riding on a value comparison. If not, the M21 test's phase 2 and phase 3 must be rewritten to
the post-R12 contract, and that rewrite is a specification change worth recording as such.

**Still outstanding for R12:** the RTL mirror. The RTL holds the OPPOSITE half of the original
defect -- guarded capture, self-consuming restore -- so the two layers still disagree about nested
traps, and that divergence was itself caused by a comment. R12 must not be described as fixed in
hardware until that lands.

**RESOLVED -- the defect was in the TEST, and the retraction is recorded in full because the
reasoning that produced it was wrong twice over.**

Final measurement: a sentinel written into x23 *before* entering the compartment is **still present**
at the verdict. So the compartment **never resumed** after the outer mret, and every reading of x23
and x17 was of a register that was never written -- `0` was simply their reset value.

Two conclusions follow, and both were previously stated with more confidence than they deserved:

1. **"The implementation denies a case it was designed to reconstruct" was WRONG.** It rested on
   x23 == 0, which was not a measurement. The deny path never fired; the readings that WERE real --
   depth 1 -> 2 -> 0 across the nesting, and `veda_mepcc_length` holding 0x0100 intact immediately
   before the outer mret -- all show the mechanism behaving exactly as designed.
2. **The "contradiction" that appeared to localise a fault in the restore was not a contradiction.**
   Three facts appeared to conflict; two of them were not facts.

**The lesson, which is the durable part.** `0` was simultaneously the reset value of the observing
register, the deny value of the mechanism under test, and therefore indistinguishable from "this
instruction never executed". A probe whose failure value collides with its own meaningful value
cannot report anything. The sentinel should have been written first -- that is one instruction, and
it would have prevented an entire diagnostic detour built on top of a non-measurement.

This is the same shape as two earlier findings this session, and the third instance of it: the dead
`odt_mem[16*5+9]` conjunct in tb_veda_smoke_m4_neg that read an always-zero spare byte, and the
`rd = 0` assertion that passed because rd's reset value was already 0. **Ask not whether a probe
returns the right answer, but whether it could return a wrong one.**

**What remains genuinely open** is narrower and different from what was recorded before: the
compartment does not resume after the outer mret, and the third trap was therefore not its ecall.
That is a question about mepc handling across a nested trap in the test, or about the resume path --
not about the depth/poison mechanism, which is now measurement-verified.

**Historical note (superseded, kept so the reasoning is auditable):**

**DIAGNOSIS PROGRESS (measured via the new read-only CSR 0x7C8, not inferred).**

State sampled at every stage of the reproduction:

| point | depth | poison | veda_mepcc_length |
|---|---|---|---|
| trap 1, entering the outer handler | 1 | 0 | -- |
| trap 2, entering the nested handler | 2 | 0 | -- |
| **immediately before the outer mret** | **1** | **0** | **0x0100 -- CORRECT** |
| in the compartment, after both unwinds | 0 | 0 | -- |

**This eliminates every hypothesis held so far.** The saved value is NOT clobbered. Poison is NEVER
set. The depth counter is exactly right at all four points. So the novel part of the fix -- the
depth and poison mechanism -- is verified correct **by measurement**, not by argument.

And it produces a contradiction that localises the remaining defect precisely. At the outer mret
`depth` goes 1 -> 0 and `poison` is false, so the restore must take its else branch and execute
`veda_pcc_length = veda_mepcc_length`, which is measured to be 0x0100. Yet the compartment then
reads `veda_pcc_length` as **0**.

Both facts are measured. Therefore the fault lies in **the restore's write of PCC, or in something
between that write and the compartment's read** -- not in the save, not in poison, not in the
counter. Remaining suspects, in order: a second consumer of the xret path that overwrites PCC after
the restore; the interaction with `veda_crbr_restore_on_xret` called at the tail of the same
function; or the compartment's own CSR read being answered from somewhere other than the live
register.

Note that 0 is not a value any branch other than the deny path writes, and the deny path is now
excluded by measurement -- so a fourth possibility is that PCC is being written by a path outside
these two functions entirely.

**Next step is diagnosis, not implementation:** instrument or expose depth/poison (0x7C8 is free in
both layers) and determine which branch produces the zero-length PCC. The RTL mirror must not be
started until this is settled -- mirroring a behaviour that is not understood would propagate it.

#### Residuals, stated rather than closed

- **Multi-hart.** "Refuse on the live PCC" is a single-hart answer; another hart's PCC is invisible.
  This is the identical residual R10 already recorded for regions and joins the same Phase 6
  checklist.
- **The PoCs prove architectural permission, not a completed exploit.** The model's page-out does
  not scrub or reassign the frame, so what was demonstrated is that entering a freed or moved object
  is *permitted* -- not that attacker-controlled bytes execute.
- **OCJALR's cross-domain behaviour is untouched here.** It carries no region check by design
  ("OCJALR cannot cross a compartment boundary"), and this increment only adds the object check.
  Whether that design intent is actually enforced was not investigated.

### R11(b). PCC carries an object identity, and eviction refuses on it

**Status: built and verified on the Sail model.** This is the second half of the R11 fix, and it
closes the window R11(a) structurally could not reach: eviction of the object you are *currently
executing*. Instruction fetch compares the PC against PCC's cached Base and Length and never
re-reads the table, so no amount of checking at the crossings can help once you are already inside.
Before this increment PCC held bounds and no name, so the hardware could not even say which object
backed the running compartment.

The shape of the fix is the one the table above committed to: give PCC a name, and let page-out and
Destroy **refuse** on it. One 44-bit compare on a cold path. The cost lands on the rare event -- an
eviction -- rather than on every fetch, which is the same trade DESIGN_02's cached-Base decision
already settled.

#### R12 is what made the documented design implementable

Mid-increment I had talked myself out of pinning the saved MEPCC, for a reason that was correct at
the time: a scheduler that permanently abandons a compartment would pin its code object forever,
with nothing left to release it -- a denial of revocation. I had planned to revalidate at mret
instead, treating mret as a fourth crossing.

R12 removed the objection rather than answering it. `veda_trap_frame_abandon` -- added so OCRETURN
out of a handler drops the trap frame -- clears the saved slot at depth 0. So a switcher that walks
away from a compartment releases the pin *by the act of walking away*, which is exactly the event
that should release it. The original design (pin both) is therefore the one that shipped. Recorded
because the sequencing matters: R12 was not a detour on the way to R11(b), it was a precondition.

#### DECISION -- the identity is `Object_ID` alone, NOT `{Object_ID, generation}`

The table above specified both fields. Only `Object_ID` was built, deliberately.

A generation is what makes a *stored, later-reused* name safe -- it detects that the slot moved on
while you were holding the name. The pin does not hold a name for later; it holds one for exactly
as long as the object is running, and the only instructions that could recycle the identifier
underneath it -- page-out and Destroy -- are precisely the two the pin refuses. **The name cannot go
stale while it is pinned, by construction.** Carrying a generation next to it would be state that no
check can ever read differently.

This is a real consequence of choosing refusal over revalidation. Had the mret-revalidation design
survived, the generation would have been mandatory, because a revalidating check *does* hold a name
across an interval it does not control. The two halves of R11 differ the same way: R11(a) checks a
capability handed to it from outside and needs the full `valid`/`generation`/`resident` triple;
R11(b) checks state it created itself and needs only the name.

#### The handler belongs to no object -- an edit that silently did not apply

The trap-entry clear (`veda_pcc_object = VEDA_OBJECT_NONE` alongside the PCC reset) was written and
did not land: the anchor assumed `veda_crbr_save_and_reset()` followed the reset directly, and an
R10 comment block sits between them. The replacement matched nothing and was not asserted, so it
failed silently.

What that cost is worth recording, because it is not the missing line:

- The handler kept the callee's name. Harmless on its own -- a stale name only ever causes *extra*
  refusals, never fewer -- so no security property was weakened, and the suite stayed green.
- **But the test that claims to prove the MEPCC pin was passing through the live-PCC term instead.**
  With the compartment's name still in PCC, PART B refused for the wrong reason. The assertion was
  true, the mechanism it named was untested, and the mutant that deletes the saved-name term would
  have survived with a full green suite.

The lesson is the one this project keeps re-learning in new clothes: a passing negative test proves
that *something* refused, not that the thing you named refused. Here the two candidate mechanisms
were one line apart. Every replacement in the increment is now assertion-guarded, and the sweep
validates all anchors for an exactly-once match before it builds anything -- four earlier sweeps in
this project tested nothing because a mis-anchored mutation was a silent no-op.

#### An eviction cannot be placed after the capability it invalidates

The first version of the test paged 180 out and back in as a control (*"evictable when nobody is
running it"*) and then entered it -- and the OCInvoke trapped 0x02. Page-out **bumps generation** by
the Option A contract, so the sealed capability minted before the round-trip was already dead. The
control is sound; only its placement was wrong, and it now runs ahead of the binds. Worth keeping
because it is the same fact from the other side: R11(a) reports a *permanent* verdict for a
capability held across an eviction, and that verdict does not care that the eviction was benign or
that the object came straight back.

#### THE REFUSAL WAS BYPASSABLE -- Populate is a third eviction path

Found while mapping the RTL for the mirror, not while writing the Sail fix. `veda_core.tlv:2101`
computes the post-instruction generation as bumped when `$is_veda_odt_destroy || $veda_odt_valid`,
and the comment above it names the source: *"Sail's own real rule: repopulating a still-valid slot
bumps generation too, not just Destroy."*

So **Populate on a live slot does everything Destroy does and more** -- it bumps the generation,
killing every outstanding capability, *and* repoints Base/Length/Perms. Refusing Destroy and
page-out on the executing object while leaving Populate open is therefore not a partial fix, it is a
**bypassable** one: an ODA-authorized actor that cannot destroy the running compartment's code
object can simply re-populate it. PCC keeps executing the cached old Base, which is now backing
nothing the object owns and is free to be handed to someone else. Execute-after-free, reached by the
one door left open.

The fix extends the same predicate to Populate and Populate-Fast. What is worth recording is not the
missing site but the pattern: this is the **third** time in this one increment that a fix spanning
several sites was implemented at all but one -- OCReturn on the Sail side of R11(a), OCJALR on the
RTL side, and now Populate. Each was found by a different accident (a mutation survivor, a second
mutation survivor, and reading the other layer's source for an unrelated reason). The common cause
is choosing sites by example -- fixing the ones that come to mind while writing -- instead of
enumerating the complete set of consumers first and discharging them one by one. For this predicate
the complete set is answerable exactly: *every instruction that can change an ODT entry's identity
or backing.* That is Destroy, page-out, Populate, and Populate-Fast; page-in is excluded because it
already refuses on a live object for an independent reason, which is the very refusal recorded in
R11(a)'s own test file.

#### VERIFICATION -- 89/89, and 7 of 10 mutants killed

The corpus is 89/89 with one new test, `vc_r11b_executing_pin_neg.S`, covering: refusal of page-out,
Destroy, Populate-Fast and plain Populate on the running object; the same four refused again from a
trap handler where PCC belongs to no object and only the SAVED name pins; the release after
OCRETURN abandons the frame; and an over-refusal control proving an unrelated live object stays
evictable while a compartment runs.

Ten mutants, **7 killed**. The three survivors are the interesting part, and two of them are not
what they first look like.

**M8 -- "abandoning the frame does not release the pin" -- is a TRUE equivalent mutant.** PART C was
written specifically to kill it and cannot, because the depth guard masks it: the abandon sets depth
to 0 in the same step, and the saved term is gated on `depth != 0`, so the stale name is unreadable.
Verified against source rather than argued: `veda_mepcc_object` has exactly two readers -- the
predicate (gated) and the mret restore. The restore is reachable only at depth 1, and every path
from depth 0 back to depth 1 passes through a trap, whose capture overwrites the stale value first.
It cannot be observed.

**M4 -- "depth guard dropped" -- is NOT strictly equivalent, and my first claim that it was
provably redundant was too strong.** The invariant it relies on does hold, and was checked on every
path: `mepcc_object` has four writers (reset, capture at depth 0, restore, abandon), depth decrements
only inside restore and abandon, and both clear the name when the decrement reaches 0 -- so
**depth == 0 implies mepcc_object == NONE**. But software may pass the sentinel itself as an operand.
Outside a compartment the LIVE term catches it, so both versions refuse; INSIDE a compartment at
depth 0 the mutant refuses and the original does not. No test supplies that input, and the mutant's
behaviour is the safer of the two, so it is left alive deliberately rather than chased with a test
that would enshrine "a nonsense Object_ID succeeds" as expected behaviour.

**M7 -- "trap entry does not clear the identity" -- survives, but is load-bearing anyway,** which is
the most useful thing this sweep produced. Applied alone, all 89 pass. Applied alone, M3 (dropping
the saved-name term) FAILS. Applied together, all 89 pass again. The clear has no directly
observable behaviour of its own; what it does is make a *different* mechanism observable, because
without it the live term silently answers in the saved term's place and PART B refuses for the wrong
reason. It is killable -- an outer handler that OCInvokes into an object and then faults leaves that
object pinned forever without the clear, and correctly reclaimable with it, since that level is
poisoned and permanently unresumable -- and that test is not yet written.

The general shape, worth carrying: **a passing negative test proves that something refused, not that
the named thing refused.** Here the two candidate mechanisms were one line apart in the same
predicate.

#### THE RTL MIRROR IS NOT A TRANSCRIPTION -- the pin changes currency

An adversarial hunt over the RTL and the design records (five lenses, each finding
independently verified by three sceptics briefed to refute it) returned the same bypass from three
separate lenses, and it is one no amount of Sail work could have found.

**The pin compares NAMES; this core's ODT writes commit to a SLOT.** Sail resolves an entry as
`base(region) + the FULL 24-bit local`, so name and slot are in bijection and a name compare *is* a
slot compare. The RTL models 256 locals per region and resolves with `local[7:0]` only, so many
names share one slot: Object_ID 436 and Object_ID 180 land on the same 32 bytes. The `id_hi` tag
exists precisely to catch that, but it is consulted on the two READ paths only -- neither ODT write
arm looks at it. So `veda.odt.destroy 436` while the core executes object 180 passed the pin
(436 != 180) and cleared the running object's descriptor in one instruction.

The fix is not to make Sail slot-addressed, and not to leave the RTL name-addressed. **Each layer
must express the predicate in whatever uniquely identifies a descriptor in that layer** -- the name
in Sail, the resolved slot here. Same region and same `local[7:0]` means the same entry, and full-name
equality implies it, so the slot compare strictly subsumes the name compare rather than trading one
guarantee for another. Sail is unchanged and correct as it stands.

One sceptic refuted the finding on the grounds that 436 is "a genuinely distinct architectural
object" and refusing it is over-refusal. That objection is right about the architecture and wrong
about this model: in a table where 436 and 180 cannot coexist, an operation naming 436 that lands on
180's storage *is* an operation on the running object's storage. Recorded because the disagreement
is the useful part -- the two layers legitimately differ, and saying so is more honest than forcing
a false uniformity.

#### The pin traps; the gates it sits beside do not

Found by the same review, verified directly: `$veda_odt_populate_violation` and
`$veda_odt_destroy_violation` reach only three places -- their definitions, the `$reg_write`
suppression, and the two `odt_mem` write gates. Neither is in `$veda_trap_taken` or
`$veda_illegal_instr`. **Populate and Destroy refuse SILENTLY in the RTL**, while Sail raises
`Illegal_Instruction` for the identical gates. `veda_smoke_m4_neg.S` and `veda_smoke_m11_neg.S` both
depend on the silence -- they drop privilege, populate, and keep executing.

So the pre-existing divergence is real, is load-bearing for two shipped tests, and is NOT this
increment's to change. What this increment does is refuse to inherit it: the pin refusal is its own
signal, `$veda_executing_pin_refusal`, and it joins the trap chain and the illegal-instruction
umbrella exactly as the page-out and page-in refusals already do.

The security argument decides it. A silent refusal tells a pager that an eviction succeeded when it
did not, and the pager then reuses memory it does not own -- worse than either trapping or
succeeding. Software has to LEARN it may not evict the running object, because the correct response
is specific: abandon the frame first, then retry.

**Recorded as an open item, not fixed here:** the RTL's silent Populate/Destroy refusal diverges
from Sail for the privilege, authority and retired gates too, and the aliasing write path means
`destroy 436` still clobbers slot 180 whenever nothing is executing it. Both are RTL-model issues
that predate R11(b) and both deserve their own increment with their own tests.

#### One wart found in passing, not fixed here

`veda_odt_index` returns `None` for an unresolvable Object_ID, and `odt_write` then does nothing --
so Destroy on a nonsense identifier returns RETIRE_SUCCESS having changed no state. A pager could
read that as "the object was destroyed". Pre-existing, outside this increment's scope, recorded so
it is not re-discovered.

#### Residuals, stated rather than closed

- **Cross-hart revocation is refused, not solved.** On this hart, revocation is never actually
  blocked: a trap clears the live name, so a handler can always abandon the frame and then evict.
  What the pin forces is a *deliberate* act -- "I am not returning to this compartment" -- stated
  before the object dies. On another hart the refusal is real: an object being executed elsewhere
  cannot be evicted until that hart is stopped. That is the bargain a conventional machine already
  strikes when it cannot unmap a page another core is running from without interrupting it, and it
  is preferred here over the alternative, which is letting the other hart keep executing freed
  memory. Joins R10's and R11(a)'s multi-hart residual on the same Phase 6 checklist.
- **A poisoned chain pins forever.** Once R12 poison is set the compartment is permanently
  unresumable, and its name is never restored or cleared, so its code object stays pinned. Consistent
  with the already-recorded consequence that software must detect poison via 0x7C8 and tear the
  compartment down; the teardown path must be able to release the pin, and that path is not yet
  specified.

### R17. veda.bind had no authority gate -- a name WAS the authority

> **RETRACTED THE SAME DAY IT WAS BUILT, and the retraction is the finding.**
>
> The rule below -- *a compartment may bind only within its own domain* -- passed all 77 RTL tests
> and then sent the Sail test `vc_r10_crbr_invoke_trap_return` into an infinite loop. Investigating
> that loop produced the real result, which is more valuable than the rule was:
>
> **A compartment's RETURN PATH is, by construction, in another domain.** That test builds a
> region-1 compartment and, from inside it, binds three region-0 objects: its return code object,
> its return data object, and the type authority. It has to. The caller lives in another domain --
> that is what "another domain" means. So a rule that forbids cross-domain Bind does not merely
> refuse an attack; **it makes compartments one-way. Nothing can ever return.** The livelock was the
> architecture saying so: bind refused, trap, handler, mret, same bind, forever.
>
> I had reasoned carefully about "who may be given authority" and not at all about "how does anyone
> get back". The design panel, three judges and an adversarial reviewer all missed it too; the
> corpus caught it, and only because one test exercises a genuine cross-domain return.
>
> **What this rules out, and what it points at.** Region-granular authority is the wrong shape: the
> unit that needs permission is the OBJECT, not the domain, because legitimate sharing is
> per-object and crosses domains by design. The panel's Proposal D (generalise the existing
> per-object `owner` from a HART to a DOMAIN) survives this argument intact -- an object can then be
> marked shareable while its neighbours are not. That is the direction to take, and it needs the
> ODT field-write path that DESIGN_02 already lists as missing.
>
> **Also fixed as a direct consequence:** the Sail runner now passes `--inst-limit 2000000`. A
> livelocking test used to hang the whole suite instead of failing -- this one consumed two and a
> half hours in silence. That mitigation had been recommended in the record for a long time and
> never applied. It is applied now, on both runners.
>
> Kept below in full, because the reasoning about SUBJECT SELECTION is still correct and will be
> needed by whatever replaces it.

### R17. veda.bind had no authority gate -- a name WAS the authority

**Status: fixed on both layers. RTL 76/76 smoke, 51/51 ACT4, 2/2 mutants killed. Sail mirror
built; corpus result pending at time of writing.**

This is the largest security decision taken in this design so far, so the reasoning is recorded in
full rather than summarised.

#### The hole

`veda.bind` took a 44-bit Object_ID from an **ordinary GPR** and, if the entry existed, minted a
**tagged, unsealed capability carrying the table's full permissions**. Its only gates were region
residency (paging state, not membership), `e.valid`, and `owner_hart` (a claim, vacuous on one
hart). No privilege test. No authority operand. No membership check.

So a name in a register plus one instruction produced full authority over the named object, from any
privilege level, from inside any compartment. Three consequences, all verified:

- **CSeal protected nothing against a recipient.** Given the name, they re-bind and get it unsealed
  with full permissions.
- **Region was not a protection boundary for Bind.**
- **DESIGN_00's isolation claim was true and irrelevant.** It says domain A "cannot forge" a
  capability to B's object. A never needed to forge one -- the hardware minted it on request.

An identifier that both names a thing and grants it is not a capability. The system had, quietly,
stopped being capability-based at its most important instruction, while listing "capability-based"
as a pillar.

#### The rule

**A compartment may bind only within its own domain. Code running in no compartment -- boot and trap
handlers -- is unrestricted.**

#### DECISION 1 -- the subject is PCC's object name, NOT the current-region register

An authority rule needs to know who is asking, and this design has two candidate answers.

`veda_current_region` looks like the obvious one and is **wrong**. It is zero at reset and reset
again on every trap, and **region zero is also a real domain** -- so "no domain" and "domain 0" are
the same value. A rule built on it would hand every trap handler domain 0's authority while looking
exactly like a lock. This project has already paid once for a value that meant two things at once.

`veda_pcc_object` has `VEDA_OBJECT_NONE`, out of band by construction (its region field is
`VEDA_REGION_NONE`, which no region-table window resolves), so the two states are genuinely
distinct. It is also already mutation-tested, by R11(b).

Worth recording: **the subject this rule needs did not exist six months ago.** R10 built the current
region and R11(b) built PCC's object identity, both to close unrelated bugs. Together they made the
hardware able to answer "who am I", which is the precondition for any authority check at all.

#### DECISION 2 -- the check runs FIRST, ahead of existence

Order is a security property here. If the table were consulted first, the cause returned would still
tell a compartment whether a foreign object **exists** -- and `veda.bind.notrap` makes that a silent
oracle. Refusing on identity before reading anything closes the oracle and the escape with one
check.

#### DECISION 3 -- its own cause (0x0B), not a reuse

`OWNER_VIOLATION` (0x06) means another **hart** holds it: release it. `REGION_FAULT` (0x09) means
that domain's table is paged out: page it in. This is a third thing -- **you were never entitled to
it, and there is nothing to repair.** Conflating them sends software to fix what is not broken. Same
argument that gave residency its own cause rather than reusing the region fault.

#### DECISION 4 -- boot and handlers stay unrestricted, deliberately

This is not a loophole left open. It is the bootstrap, the pager, and the only code that can
legitimately hand objects between domains. Narrowing it requires a delegation mechanism that does
not exist yet, and inventing one here would be building the second half of a bridge before the
first. **The mutation sweep quantified how load-bearing it is: removing the exemption fails 69 of 76
tests** -- the machine does not boot without it.

#### Cost: zero additional table reads

One comparison of two 20-bit fields already sitting in registers. No ODT read, no region-table read.
On a machine deliberately built without caches, an extra table read would be permanent added latency
on every Bind, not a rounding error -- which is precisely why the C-list designs were rejected in
favour of a subject the hardware already holds.

#### What this does NOT close, stated plainly

- **Intra-region isolation.** Many objects share a region, and a compartment may still bind any of
  them. This closes cross-domain minting, not per-object membership. The per-domain capability table
  DESIGN_00 and DESIGN_05 describe remains unbuilt.
- **Anything boot or a trap handler does.** By design, above.
- **The namespace oracle within your own region.** Enumeration inside your own domain is still free.

### R16. A failed Bind handed back the slot's real Base -- an address leak through the silent probe

**Status: fixed and verified in RTL (75/75 smoke, 51/51 ACT4, 2/2 mutants killed). Sail was already
correct; this was a divergence, and the model was the safe side.**

`veda.bind.notrap` is the deliberately SILENT probe -- it soft-fails rather than trapping. On
failure this core wrote the resolved slot's Base, Length, Perms and Object_ID into the destination
register and cleared only the Tag. The comment at that mux called those fields *"dead either way
once Tag=0"*.

They are not dead. **The capability query family is deliberately not tag-gated** on either layer, so
`cgetbase` after a failed probe returned the **raw physical Base of whatever live object occupies
that slot**. Sail writes `zero_capability` on the identical failure.

Three things make this worse than an ordinary information leak:

1. **It breaches the address-less pillar directly.** Software is not supposed to be able to see a
   physical address at all. This handed one over for an object the caller does not own.
2. **It is silent by design.** The leak is through the one Bind mode that deliberately does not
   trap, so nothing anywhere observes the probe. A noisy leak leaves evidence; this one does not.
3. **It needs no secret.** Guess a number. The namespace is enumerable, and R11(b)'s own analysis
   already established that `veda.bind.notrap` + `CGetTag` is a free existence oracle -- this
   upgraded it to a metadata oracle, and metadata here means addresses.

**Fix:** one named predicate, `$veda_bind_ok = $veda_odt_valid && $veda_owner_ok`, now gates the
DATA fields as well as the Tag, zeroing them on failure exactly as the model does. Found by an
adversarial panel convened for a different question entirely.

This is the fourth comment in this session that asserted something the code did not do. The pattern
is stable enough to name: **a comment explaining why a check is unnecessary is itself a finding to
verify, not a reason to skip verifying.**

### R15. NMC_ADD writes memory and asked for no store permission -- on both layers

**Status: fixed and verified on both layers (Sail 89/89, RTL 74/74, 51/51 ACT4, all mutants killed).**

Found by an adversarial panel convened to choose a fault-identification channel, which instead
reported that the channel was sixth of six blockers and that this one was live.

`veda_check_nmc_access` gated NMC_ADD on **`Permit_NMC_Compute` alone**. The clause it guards calls
`read_ram`, returns the loaded value in `rd`, and calls `write_ram`. The seeded fixture's
`Perms = 0x100C` carries `Load|Store|NMC_Compute` together, so a capability with `Permit_Store`
deliberately attenuated away **keeps bit 12 and the write lands**.

That makes every store-side attenuation in the architecture advisory -- including the one DESIGN_02's
copy-on-write is specified to be built on. It would have been a total COW bypass, on both layers,
under a mechanism that had just been declared verified.

**The decisive evidence was internal, not external.** Veda-Atomic is the identical
read-modify-write shape, and `veda_atomic_insts.sail:34` says in as many words *"Permission: reuses
Permit_Load + Permit_Store"*, passing `(true, true)` to the shared checker. Two read-modify-write
families in one model, answering the same question two different ways. No document ever argued for
the NMC exemption; it was simply never asked about. DESIGN_07's own consumer table two sections up
lists `veda_check_nmc_access` with a "yes" -- for a *different* property (does it recheck
valid/generation/resident), which is exactly the kind of adjacent green tick that makes an unasked
question look answered.

**Fix:** NMC_ADD now requires `Permit_Load` and `Permit_Store` in addition to
`Permit_NMC_Compute`. The principle, stated so the next instruction that reads and writes inherits
it: **a value reaching software from memory is a load, and a value reaching memory is a store,
whatever single instruction performs them.** `Permit_NMC_Compute` remains an additional gate ("this
object may be computed on near memory"), never a substitute.

#### What this says about the enumeration one increment earlier

RTL-12 claimed to have enumerated the store paths from the decoder. It found three -- OCS.D, OCS.C,
Veda-Atomic -- and missed this one, because the question asked was *"where is the store-permission
signal used?"* **A question phrased over the existing checks can never surface a path that has no
check.** The question that finds NMC_ADD immediately is *"where is memory written?"*

The sweep then made the same point a second time within this fix: the `.D` mutant died and the `.W`
mutant lived, because the new test exercised only `.D`. Two widths are two decodes, two violation
expressions and two cause muxes -- two sites, exactly as three store paths were three. Both variants
are now covered and both mutants die.

### R14. Populate and Destroy refused SILENTLY -- the RTL never told anyone

**Status: fixed and verified in RTL (73/73 smoke, 51/51 ACT4, 3/3 mutants killed). Sail was already
correct and is unchanged.**

`$veda_odt_populate_violation` and `$veda_odt_destroy_violation` reached exactly three places: their
definitions, the register-write suppression, and the two ODT write gates. Neither was in
`$veda_trap_taken` or `$veda_illegal_instr`. So both instructions **suppressed the write and raised
nothing** -- an unprivileged program could execute a privileged instruction and be told absolutely
nothing had happened.

Four independent reasons this is wrong, and none of them is "the model says so" alone:

1. Sail raises `Illegal_Instruction` for all three gates -- privilege/authority, the executing-object
   pin, and retired.
2. **The same file already disagreed with itself.** `veda.odt.page.out` and `veda.odt.page.in` trap
   on the identical authority gate. Two instruction families, one authority check, two answers.
3. RISC-V's own convention for an instruction the current privilege may not execute is precisely
   this trap.
4. Silence is the actively dangerous answer for a refusal. A component that asked to create or
   destroy an object and got no signal proceeds as though it succeeded.

The silence was never argued for anywhere -- no design note defends it. It was simply what the file
did, and three tests had grown around it.

#### What this cost, and why the tests got stronger rather than weaker

`veda_smoke_m4_neg.S` and `veda_smoke_m11_neg.S` installed **no trap handler at all** and had been
deliberately moved onto `veda.bind.notrap` to stay out of the trap path entirely;
`veda_smoke_m16_neg.S` installed `mtvec` only *after* its refused re-populate. All three would have
jumped to address 0 -- the exact Milestone-9 failure mode already on record.

Their subject was never the silence. Each says "the write must be suppressed", and each still checks
exactly that. What was added is the other half: that the refusal was **observable**, with the right
cause. A negative test that only checks "nothing happened" cannot distinguish a refusal from an
instruction that was never decoded.

`$veda_executing_pin_refusal`, added by R11(b) precisely because the gates beside it were silent, is
now fully subsumed and was deleted rather than left as a second route computing the same condition.

#### Verification, and one honest coverage note

Mutation: removing the populate arm from the trap chain is caught by both privilege-gate tests and
by the R11(b) pin test; removing the destroy arm is caught by the R11(b) pin test **only**; making
both trap with the wrong cause is caught by the mcause assertions.

That "only" is worth stating plainly: **nothing in the corpus performs an unprivileged Destroy.**
Destroy's authority gate is covered transitively, through the executing-object pin, and not
directly. It is symmetric with Populate's gate, which is directly covered, so the risk is low -- but
it is coverage by adjacency, not by test, and should be closed when Destroy's own negative test is
next touched.

### R13. Destroy clears a slot it does not own -- Milestone 15's fix covered reads only

**Status: found while mirroring R11(b), fixed and verified in RTL (73/73 smoke, 51/51 ACT4, 2/2
mutants killed). Sail needs no change and cannot express the bug.**

Milestone 15 found real low-byte aliasing in this core's 256-entry ODT model: Object_ID 32 and
Object_ID 288 share a slot, and a Bind for 32 issued after 288 was populated silently returned 288's
object. The fix stores the full Object_ID in the slot and requires it to match. **It was applied to
the two read paths and to neither write path.**

Destroy is an access too. `veda.odt.destroy 288` resolves to slot 32 and clears the valid and
resident bits and bumps the generation of **object 32** -- a different, live object the caller never
named. An authorized actor can therefore kill any object by naming any alias of it.

Sail cannot express this. It indexes with the full 24-bit local (`VEDA_LOCAL_MODELED` = 2^20), so 32
and 288 are genuinely different entries and destroying one cannot touch the other. This is the
second finding in two increments where **a correct mechanism in the model is wrong in the hardware
with no transcription error anywhere**, because the two layers identify a descriptor differently.
That is now a class worth checking for deliberately rather than meeting twice by accident.

**The fix is one term: Destroy's ODT write is gated on the identity tag.** If the slot's tag is not
ours, the object we named is not in the table and Destroy has nothing here to do -- which is exactly
what Sail does with it.

Two things deliberately NOT changed:

- **Gated on the tag, not on validity.** Sail's Destroy bumps the generation of an already-invalid
  entry, and that must keep working. Only the identity is in question, never the liveness.
- **Populate keeps its slot takeover.** That is Milestone 15's own deliberate semantics for a
  256-slot model, and the displaced object then reads not-found rather than reading someone else's
  data. Taking a free-able slot is reuse; clearing a slot you do not own is not. The two are
  different acts and only one of them is a bug.

Verified by `veda_smoke_r13_alias_destroy_neg.S`: after destroying the alias, object 32 still
re-Binds, still reads its own data, and the capability minted *before* the aliased Destroy still
works -- so no generation was bumped underneath it. The control matters as much: destroying 32 by
its own name must still work, or a core that ignored every Destroy would pass the first half
trivially. Mutation confirms both directions -- removing the tag gate is caught only by this test,
and refusing every Destroy is caught by this test and by the Milestone 4 positive together.

### R12. Veda's trap save/restore is not nesting-safe, and the PCC half fails OPEN

**Status: confirmed by execution. Not yet fixed -- the obvious fix introduces a mirror bug, so
the shape of the real fix is an open design question, recorded here rather than guessed at.**

Found while re-grounding after R11, by noticing that `veda_pcc_save_and_reset` performs **two**
captures in one function and guards only one of them:

```
function veda_pcc_save_and_reset() -> unit = {
  veda_mepcc_base   = veda_pcc_base;        // NO guard
  veda_mepcc_length = veda_pcc_length;      // NO guard
  veda_pcc_base   = zeros();
  veda_pcc_length = VEDA_PCC_UNBOUNDED;
  veda_crbr_save_and_reset();               // guarded: if current_region != 0
}
```

**Reproduced.** Enter a compartment with PCC narrowed to `{compartment, 0x0100}`, take an ordinary
capability violation, and inside that handler take a second one. Observed directly on the
architectural CSR: `veda_mepcc_length` reads `0x0100` before the nested trap and `0xFFFFFFFFFF`
after. The nested capture copies the already-reset live PCC over the outer save.

The restore is guarded on `veda_mepcc_length != VEDA_PCC_UNBOUNDED`, which reads that clobbered
value as *"nothing was ever saved"* -- so it restores **nothing**, and the compartment resumes with
**unbounded PCC**.

**The failure DIRECTION is the finding, not the nesting-unsafety itself.** Base RISC-V clobbers
`mepc`/`mcause`/`mstatus.MPP` on a nested M-mode trap too, and its answer is that handlers must
manage that themselves. Veda following the same model is defensible. But a clobbered `mepc` fails
LOUDLY -- the handler returns to the wrong address. A clobbered `mepcc` fails SILENTLY and OPEN: the
compartment keeps running with its bounds removed. A privilege boundary that dissolves quietly is
categorically different from a return address that goes wrong noisily.

#### Why the obvious fix is wrong, worked out before writing any code

Copying the CRBR guard onto the PCC half -- skip the capture when PCC is already the reset value --
does stop the clobber. It also creates the mirror bug: with the outer save now intact, the **inner**
mret's restore fires, consumes it, and installs the compartment's bounds into the still-running
handler. The outer mret then finds the sentinel and restores nothing. Same escape, one level up.

Checking `veda_crbr_restore_on_xret` shows the CRBR half **already has that second half of the
problem**: its save is guarded, but its restore is not nesting-aware and self-consumes on the first
xret. So the two halves are broken in opposite directions:

| | save | restore |
|---|---|---|
| PCC | unguarded -- outer save destroyed | guarded, but nothing left to restore |
| CRBR | guarded -- outer save survives | unguarded -- inner xret consumes it |

Neither is a missing line. Both are the same underlying gap: **a one-deep save slot with no notion
of nesting.**

#### GROUNDED IN THE OFFICIAL SPECIFICATIONS -- and both settle it

Read from the documents on disk, quoted and independently re-verified rather than recalled.

**RISC-V.** *The RISC-V Instruction Set Manual, Version 20260715: Intermediate Release*, combined
volumes; Privileged Architecture v1.13, ratified.

- **A one-deep save slot is NORMATIVE, not a defect.** mepc/mcause/mtval have no stack at all and
  are written unconditionally on every trap (SS 3.1.14-3.1.16). Only mstatus.xPIE/xPP have a
  two-level stack. So R12's defect is **not** that Veda-Core has one slot -- RISC-V has one too and
  calls it sufficient.
- The architecture assigns the hazard to software explicitly (SS 3.1.6.1): *"Trap handlers must be
  designed to neither enable interrupts nor cause exceptions during the phase of handling where the
  trap handler preserves the critical state information required to handle and resume from the
  trap."*
- **There IS a ratified mechanism for exactly this: the `Smdbltrp` Double Trap Extension v1.0**
  (SS 3.1.6.2). An `MDT` bit in `mstatus` is set on trap entry; *"if MDT is already set to 1, then
  this is an unexpected trap"*, and the hart *"enters a critical-error state **without updating any
  architectural state, including the pc**"*. MRET clears MDT. Exception code 16 is allocated to it
  and `medeleg[16]` is read-only zero.
- Caveat established by searching Volume III in full: `Smdbltrp` appears in **no profile**
  (RVA20/22/23, RVB23). Ratified, but optional.

**CHERI.** *CHERI Instruction-Set Architecture*. `MEPCC` is a Special Capability Register -- a full
capability, therefore **tagged**. And decisively: *"NULL Does Not Have the Tag Bit Set"* (SS 9.14)
while *"The length of NULL is MAXINT"* (SS 9.15).

So CHERI's null capability carries the same max length our sentinel uses, and is distinguished by an
**out-of-band tag**. CHERI deliberately does not let length be the discriminator. **Veda-Core's bug
is precisely the thing CHERI's design avoids**, and that was derived here before the spec was read,
which is why it is stated as confirmation rather than discovery.

#### A FALSE COMMENT CAUSED A REAL DIVERGENCE BETWEEN THE TWO LAYERS

Found while grounding the fix, and it changes the shape of the problem.

`veda_regs.sail` states, as justification for the restore guard: *"veda_pcc_save_and_reset()'s own
capture is itself conditional, for the identical reason."* **The function has no guard.** The
capture is unconditional, and always has been.

`veda_core.tlv` then **guards its capture** -- `>>1$veda_trap_taken && (>>1$veda_pcc_length !=
40'hFFFFFFFFFF)` -- citing that comment: *"mirroring the Sail side's own already-adversarially-
reviewed conditional-capture design."*

So the RTL implemented what the comment **said** and the Sail model does what its code **does**, and
the two layers now hold **opposite halves of the same defect**:

| layer | capture | consequence of a nested trap |
|---|---|---|
| Sail | unguarded | outer save destroyed; restore reads the sentinel as "nothing saved"; compartment resumes **UNBOUNDED** -- fails open |
| RTL | guarded | outer save survives, but the self-consuming restore fires on the **INNER** mret; the handler is narrowed to compartment bounds mid-flight |

The RTL's direction is reasoned from the source, not yet executed, and is recorded as such. It
appears to fail closed-ish (the narrowed handler faults on its next fetch) rather than open -- which
would make the RTL accidentally safer than the model it mirrors.

**The lesson is the finding.** A comment that misdescribed its own function was treated as
specification by the next layer down. Every cross-layer mirror in this project is written by reading
the other layer's comments; this is the first proven case of one being load-bearing and wrong.

#### Candidate directions, none chosen yet

1. **Fail closed instead of open.** Keep the one-deep slot and RISC-V's "handlers manage nesting"
   model, but make an unrestorable state deny rather than permit -- restore to a zero-length PCC, or
   fault, so software must explicitly re-establish bounds. Smallest change; converts a silent escape
   into a loud failure. Does not make nesting *work*, only make its failure safe.
2. **A shallow hardware save stack.** Makes nesting genuinely work; costs real state and needs a
   depth policy plus an overflow behaviour, which is itself a fail-closed decision.
3. **Software discipline.** `mepcc` and the CRBR pair are already CSR-visible, so a handler can save
   and restore them. Cheapest, and the most consistent with base RISC-V -- but this project's stated
   philosophy is that hardware gets priority whenever it can solve a security problem, and it can
   here.

Direction 1 is the likely answer and 2 is the honest one; the choice deserves its own increment
rather than a rider on R11.

#### What is NOT yet established

- The CRBR consumption half is reasoned, not executed. It needs its own reproduction before being
  claimed with the same confidence as the PCC half.
- Whether a nested trap is reachable **without** M-mode privilege has not been tested. The
  reproduction takes both traps from the handler's own context.
- The RTL mirror was not inspected for this. The Sail model is where it was found.

### R46. The verification entry point could not fail, and the cross-layer differential suite had not run

**Status: MEASURED, THEN FIXED AND VERIFIED. Found while establishing a baseline before R47, which
is the only reason it was found at all.**

`./verification.sh` printed three green numbers, a fourth line reading `Cross-layer diff : 0/21 as
expected`, and **exited 0**. The 21 differential probes had not run.

**R46(a) -- the harness took its toolchain from the caller's shell.** `difftest/rundiff.sh` invoked
`iverilog` off ambient `PATH`. Both of its siblings do not: `rtl/run_veda_smoke_test.sh` and
`run_security_trap.sh` each self-activate conda when it is missing. So the **only suite that compares
the two layers against each other** ran only when a human had already activated conda by hand, and
returned `IVERILOG-FAIL` / exit 2 on every probe otherwise. That file is meticulously hardened
against every *other* staleness channel -- it refuses to run against a `veda_core.sv` older than
`veda_core.tlv`, it rebuilds `sim_diff.vvp` every run because a committed binary once let it compare
two vintages, and R29 stopped it reaching into the frozen `rva23-core` tree for the assembler. It
then hardwired `SIM=` and `RTLSIM=` to absolute paths **three lines below its own comment** saying
paths are resolved from the file's location. Both are resolved now too: a second clone measured the
first clone's simulator and RTL.

**R46(b) -- the aggregator discarded every verdict.** `verification.sh` captured each suite's output
into a variable and never read an exit code. `run_difftests.sh` **does** exit 1 on mismatch; that
answer went nowhere. This is the same defect `rundiff.sh` has a comment about one level down --
*"a comparator that cannot fail"* -- reappearing in the layer above it.

Fixed the same way, **the exit code is the verdict**, plus a second guard the exit code cannot give:
every suite must report a **nonzero total**. A suite that dies before running anything can still exit
0, and `0 programs run` reads as a clean line rather than an outage.

**The lesson is not about conda.** A green summary is a claim, and this one was assembled from four
numbers scraped out of text with no failure path. Every result this project has published since the
differential suite was added was produced by a human who happened to have the right shell.

### R47 (flagship-adjacent). The ODA is a capability whose window neither layer ever read

**Status: MEASURED, THEN FIXED AND VERIFIED ON BOTH LAYERS. Sail 104/104, RTL 90/90, ACT4 51/51,
differential 22/22. The measurement was a shipped test that had been passing for eleven milestones.**

`veda_oda_authorized()` is the whole of the delegated authority to write the Object Descriptor
Table, and it is **three terms wide** -- identically on both layers:

```
Sail  veda_ocl_insts.sail   veda_oda_tag & not(isSealedCap(veda_oda))
                            & permBit(veda_oda.Perms, PERM_ACCESS_SYSTEM_REGISTERS)
RTL   veda_core.tlv         $veda_oda_tag && !$veda_oda_sealed && $veda_oda_perms[7]
```

Tag, otype, one permission bit. **`Base`, `Length`, `Offset` and `Object_ID` -- 196 of the ODA's 256
bits -- were consulted by NONE of the seven instructions this predicate authorizes.** They were
registered, maintained across every OSpecialRW, preserved across every trap, and read by nothing.

So delegated ODT-write authority was a **bearer token over all of memory**: any holder of any ODA
could mint a descriptor naming any Base, any Length and any Perms, Bind it, and dereference it. That
is the entire memory-safety claim, handed away by the one register this design made a capability
*specifically* so that it could carry a window -- `veda_regs.sail` says so in as many words: the ODA
*"must carry Base/Length/Perms/Tag, none of which a 64-bit CSR can hold."* **The design stated the
window and the implementation never read it.**

**THE MEASUREMENT WAS ALREADY IN THE SUITE, GREEN.** `rtl/sim/veda_smoke_m11.S` mints authority
object 40 at Base `0x80011000` Length `0x40`, installs it as the ODA, drops to User, and from User
mints object 41 at Base `0x80012000` -- **four kilobytes outside its own authority's window** -- with
`Perms 0x0300`, then Binds it and reads back its Base as proof. Its own comment calls that *"the real
proof"* the ODA path works. It is exactly that. It is **also** the escape, and by passing it pinned
the escape as the contract. That is the sixth time on this project a green test has named a weakness
and then frozen it: **counting a refusal is not checking it, and neither is counting a success.**

Reproduced independently first, on the specification layer, in `sail_tests/vc_r47_oda_scope_neg.S`:
trap count **0** where the architecture owes 1.

**THE RULE ADOPTED, uniform across all seven ODA-gated instructions.** On the **delegated path only**,
the memory a descriptor names must lie inside the ODA's window -- **both what the entry names now and
what it will name after**. Machine privilege is deliberately untouched: it takes the other half of the
`Machine | oda_authorized()` OR, needs no ODA, and already owns the machine, so scoping it would be
theatre. **Delegation is the thing that must be narrower than the delegator.**

| instruction | old window | new window |
|---|---|---|
| Populate, Populate-Fast | if `valid` | yes |
| Destroy | **always** | -- |
| set.cow, set.domain, page-out | yes | -- |
| page-in | yes | yes |

Three of those cells were forced by an attack rather than chosen:

- **Populate's old window.** Without it a delegated actor hijacks *any* descriptor in the machine by
  aiming its new Base into its own window -- the repopulate bumps the victim's generation, killing
  every capability its real owner holds, and repoints it. Gating the old half on `valid` is
  **required**, not cosmetic: a free slot reads `Base 0, Length 0`, and an ungated test would make
  every unused slot unmintable by any ODA that does not cover address zero, deleting the mechanism
  rather than scoping it.
- **Destroy's ungated old window.** Destroy bumps the generation of an *invalid* slot too and can
  retire it permanently, so an unscoped delegate could burn the 24-bit temporal-safety counter of
  every object in the machine. This is the one cell that deliberately does **not** gate on `valid`.
- **Page-in's new window.** It is the only instruction that *chooses where an object lands*. Without
  the new half a delegated actor pages a foreign object into its own window and owns it outright.

**WIDTH IS THE R18 LESSON, NOT A STYLE CHOICE.** `Base` is 56 bits and `Length` is 40, so
`Base + Length` fits neither -- a containment test computed at the operands' own width wraps and
reports the whole machine as contained. Sail computes over unbounded `int`; the RTL uses 57-bit
comparators, the same width R45's pin uses, for the same reason.
`vc_r47_oda_scope_neg.S` ATTACK 3 drives it with a saturating `veda_attr` Length -- reachable from
User precisely because Populate-Fast reads `veda_attr` as an internal register rather than through a
CSR access, so User consumes a value it could never have written.

**THE REFUSAL IS `Illegal_Instruction`, AND THAT IS A SECURITY DECISION, NOT A CONVENTION.** It
matches all seven sibling refusals on these instructions -- and a distinct cause code would let
unprivileged code **binary-search its own ODA's window by trap cause**. That is the oracle shape D-7
found on `owner_domain` in the R1 design pass, arriving on a different field.

**MY OWN TEST FELL INTO THE TRAP THIS FINDING IS ABOUT.** Its first draft wrote `veda.odt.destroy` as
an I-type encoding. That is not Destroy -- it is an encoding the architecture never allocated, so the
attack "passed" by being refused by **R30's undefined-encoding trap**, proving nothing about R47.
What caught it was the **over-refusal control demanding the same instruction succeed one line later**.
Every negative in that file now has one.

#### Open halves, stated rather than left to be discovered

- **The ODA is one global register, and only Machine can install one.** `VEDA_OSPECIALRW` is
  Machine-only for read *and* write, so a delegated allocator gets exactly one window and cannot
  narrow its own authority further. There is no monotone self-attenuation for the ODA the way
  CSetBounds/CAndPerm give one for ordinary capabilities. That asymmetry is now the interesting
  design question, and it did not exist while the window was inert.
- **The ODA survives compartment crossings.** `veda_regs.sail` records that ODA and TSC are
  deliberately *not* cleared by OCInvoke/OCReturn (the SSC comment states this as the contrast that
  motivated SSC's own clearing). So a compartment invoked while an allocator's ODA is live inherits
  its mint authority. Scoping the window bounds the damage to that window; it does not end the
  inheritance.

#### What this does to R1 (SLAB-CARVE), and it changes the question again

The R1 design pass concluded with two shapes: **Variant C**, a new carve instruction, and **Variant
S**, deletion-shaped -- *"add P2-style containment to Populate/Populate-Fast against a range the
authority holds, and scope the ODA"* -- which it could not recommend because *"it needs an ODA-scoping
design that does not exist."*

**It exists now, and it is built and verified on both layers.** With Populate contained inside the
minter's own window, *carving a child inside a parent arena is what Populate already does*: hold an
ODA whose window **is** the arena, and mint children inside it. The synthesis pass's P2 (containment
against the authority's window) and P6 (child IDs derived, never GPR-supplied) were the two
load-bearing halves; **P2 is now shipped hardware**, and the "carve-only parent Permit" that pass
refuted (D4) is unnecessary for a reason it did not reach: the authority to mint is a **separate
capability**, not a permission bit on the arena capability, so it needs no split.

What R1 still owes is the **namespace** half -- per-element Object_IDs and where they come from --
not the **authority** half. That is a strictly smaller question than the one the design pass faced.

### R48. A callee compartment inherits the caller's ODA across every crossing -- and the caller cannot drop it

**Status: MEASURED, THEN FIXED AND VERIFIED ON BOTH LAYERS. This was recorded as an R47 open half
before it was measured; it is now closed. The successor is named below, not implied.**

`OCInvoke` narrows PCC to the callee's bounds, installs a fresh IDC, reloads the CRBR for the entered
domain, and **clears the SSC**. Every authority the crossing touches is narrowed or dropped. It left
`veda_oda` and `veda_tsc` untouched -- and **the argument against that was already written down, for
the SSC, inside the OCInvoke clause itself**:

> *"applying **ODA/TSC's own 'untouched by OCInvoke' convention** to SSC would have left the caller's
> entire stack region reachable from the callee."*

Nobody turned that argument back on the ODA. **Before R47 it was moot** -- an unscoped ODA reached all
of memory from anywhere, so a crossing changed nothing. R47 gave it a window, and **inheriting a
window is inheriting mint authority over the caller's memory.**

**MEASURED, on the specification layer, before a line was changed.** A User compartment entered via
OCInvoke holding nothing but a code capability and a data capability:

| | measured |
|---|---|
| caller's object, after the callee ran | **destroyed** |
| a fresh descriptor over the caller's window | **minted** |
| traps taken by the callee | **0** |
| `mcause` | **0x00** |

**AND THE CALLER CANNOT DEFEND ITSELF -- this is what removes "software discipline" as an answer.**
`VEDA_OSPECIALRW` is `cur_privilege != Machine -> Illegal_Instruction`, for **read and write**, on
**all three SCRs**, on **both layers**. A User caller holding a delegated ODA has **no instruction**
with which to drop it before calling. If this closes anywhere, it closes in hardware.

**THE FIX: `veda_oda_tag = false` at OCInvoke and OCReturn. Tag only, never the value** -- every
consumer routes through `veda_oda_authorized()`, whose first term is the tag, and that is the same
discipline the SSC clear already uses.

**OCReturn carries the arm too, and on this machine that is not the direction people assume.** The
shipped switcher enters threads **downward** through OCRETURN -- a thread is resumed by
`OCA + CSealEntry + OCRETURN`, never by OCInvoke -- and `CSealEntry` mints sentries with no
authorizing operand and no privilege gate. An OCInvoke-only clear would have left the project's own
**primary domain-entry path** wide open.

#### Three things this deliberately does NOT do, each on the record rather than left to be found

- **The TSC is not cleared.** It has **zero consumers on either layer** -- no instruction's behaviour
  changes because the TSC is tagged -- so clearing closes nothing, while the shipped switcher installs
  the TSC one instruction before entering a thread through OCRETURN. Clearing would falsify that
  contract **while every round-trip assertion stayed green**, because they read the value field and
  never the tag. The TSC's boundary semantics belong to the increment that gives the TSC a consumer.
- **`mret` is not touched**, and it *is* a fourth compartment entry (it restores PCC and the CRBR
  pair). It is also the **only** instruction that lowers privilege, and therefore the sole vehicle by
  which Machine delegates an ODA downward at all. Clearing there would delete the delegated half of
  all seven ODA-gated instructions.
- **OCJALR is not touched**: it does not cross a compartment boundary (Milestone 22), installs no PCC
  and no CRBR. A clear there would be new policy, not a mirror.

#### The refuted alternative, and the named successor

**Auto-attenuation -- "narrow the ODA to the invoked compartment's own bounds" -- is REFUTED in the
reading that sounds best.** Narrowing to `cs1` (the code capability) is *unsafe*: a callee whose ODA
window is its own code object could mint a **fresh** Object_ID aliasing its own executing code, and
the executing pin cannot stop it, because R45 deliberately decided that *"creation is free; the alias
is useless as an eviction handle"* -- `veda_object_is_executing` requires `e.valid`, and a
never-populated id is not valid. W^X falls out. Narrowing to `cs2` is sound, and once you take it,
auto-attenuation **is** the delegated handoff below.

**The successor: a monotone delegated handoff.** OCInvoke installs the ODA from `cs2` when `cs2`
carries `PERM_ACCESS_SYSTEM_REGISTERS` **and** lies inside the caller's own ODA window; clears it
otherwise. **That design's default branch is exactly the line shipped here**, so the clear is a strict
prefix of it and nothing is discarded. It cannot land yet: it needs a sweep proving no existing `cs2`
carries bit 7 (which would *silently gain* an ODA -- the one way that option can widen authority), and
its ordering against the R10 region check and the R11 code-object check must be settled, because both
must fault before any commit.

**Availability cost, stated rather than hidden.** A User caller that crosses loses its ODA and must
trap to Machine to be re-delegated one. The corpus's own recovery claim was **false** and is corrected
in the same increment -- see R49.

### R49. Seven test programs were built and never simulated -- and one of them had been asserting the opposite of the architecture since the generation counter was widened

**Status: MEASURED, THEN FIXED AND VERIFIED. RTL corpus 90 -> 97.**

`rtl/run_veda_smoke_test.sh` assembles **every** `veda_smoke_*.S` in `sim/`, printed *"96 images
built"*, and then simulated **90**. Nobody compared the two numbers. Five of the missing seven had
complete, committed testbenches and **no reference in any runner**; two more were referenced only by
the security demo, never by the regression.

These are not scratch files. **Milestone 15 is the copy-on-write RTL mirror, Milestone 16 is
CGetObjectID plus the end-to-end COW repair, Milestone 17 is the OCJALR stack-frame work** -- every
one a security mechanism, dark across roughly twenty subsequent increments including R30, R33, R36/R39,
R38, R40, R41, R45 and R47.

**AND ONE OF THEM WAS RED.** `veda_smoke_m16_neg` destroyed an Object_ID **256 times**, because the
generation counter was **8 bits** and 256 destroys wrapped it exactly onto a stale capability's cached
value. Increment 3 widened generation to **24 bits**. 256 destroys now reach `0x000100` -- nowhere near
the `0xFFFFFF` ceiling -- so the re-populate **succeeded**, the stale access did **not** trap, and the
file asserted the opposite of what the machine does.

> **The widening silently orphaned its own regression test, and the widening looked free precisely
> because that test had gone dark in the same era.**

**Re-aimed rather than deleted.** The RTL already seeds two near-saturated fixtures for the paging
work (Object_ID 106 at generation `0xFFFFFE`, 108 at `0xFFFFFD`). Two Destroys on 106 reach the ceiling
and retire the slot, so the property is now measured in **two instructions instead of 256** -- and at
the real 24-bit width rather than at a width the architecture no longer has. Same fixture-injection
discipline Sail already uses for the identical property. Its pre-exhaustion sanity marker is now
**checked by the testbench** rather than merely set, so a machine on which the capability never worked
at all can no longer satisfy the two trap assertions for the wrong reason.

**Two guards, because a count a human compares is not a check.**
- **Coverage guard**: every assembled image must appear in a `+elf_hex=` line of the script itself, or
  the run fails. (Its own first draft failed open -- it read `$0` after a `cd "$(dirname "$0")"`, so a
  relative path no longer resolved and it reported all 96 unrun. A check that fails open reads exactly
  like a check that fails closed until you look at the number.)
- **Exit code**: this runner's verdicts are strings printed by 96 separate testbenches; its own exit
  code was whatever the last `vvp` returned, which is 0 even with a red testbench. **Measured doing
  exactly that.** Same defect as R46 one level down; `verification.sh` would have caught it at the
  aggregator, but every RTL increment on this project invokes this script directly.

**A third false claim, corrected here.** Both layers state that a compartment whose SSC was cleared
*"re-establishes its own SSC via an explicit OSpecialRW."* **OSpecialRW is Machine-only**, so a User
compartment cannot. Measured: inside a User, PCC-bounded compartment an ordinary `sd` traps (the
purecap rule -- the reason the SSC exists) **and** an `ospecialrw SSC` traps (privilege).
**The first version of this note overstated it and was corrected by measurement:** the compartment is
*not* unable to spill -- an `OCS.D` through the IDC works and adds no trap. The true statement is
narrower: **the SSC mechanism has no reachable user in the privilege configuration this design ships.**

### R50. The capability register file crosses a compartment boundary intact, and the dereference checker asks no domain question

**Status: MEASURED. NOT FIXED -- recorded deliberately, because the fix is a design decision about
what a crossing owes, not a defect repair. This is larger than R48.**

`OCInvoke`'s only capability-register write is the IDC install -- **c15 alone**. `OCReturn` and
`OCJALR` write none. And the dereference checker has **zero** domain terms: `veda_pcc_object` and
`veda_current_region` appear **0 times** in the whole access-check file.

So a callee needs no authority at all -- it simply uses a register the caller left bound.

**MEASURED.** The caller bound its own object into `c10`, wrote `0xC0FFEE` through it, and crossed
without clearing anything, because **no instruction on this machine clears capability registers at a
crossing.** Inside the callee:

```
ocl.d  s4, t1, c10        →  s4 = 0xC0FFEE,  traps taken: 0
```

**R48 closed the mint channel and left the possession channel wide open.** This must not be recorded
as "the compartment boundary is now clean." It is not.

The shipped switcher makes it concrete rather than theoretical: it holds save-area capabilities with
Load|Store, a thread-index capability and a globals table-base capability across both crossings, so a
resumed thread begins execution holding read/write capabilities into another thread's register save
area.

**Why it is not fixed in this increment.** The candidate answers -- clear all but the IDC, clear all
but an argument window, or a CHERI-style register-clearing mask on the crossing -- each define an ABI,
not just a check. Argument passing across compartments has to be designed before the boundary can
clear registers, or every cross-compartment call becomes a trap to Machine. It needs its own
increment, and it should come before any claim that this architecture provides compartment
confidentiality.

---

### R50 increment 2 -- THE ABI IS NOW DECIDED AND THE COST IS MEASURED. NOT LANDED.

**Status: SUPERSEDED BY R71 -- LANDED ON BOTH LAYERS, but with a DIFFERENT ABI. The GPR-sourced mask
decided below was refuted at the RTL for a reason no Sail prototype could surface (see R71). This
entry is kept verbatim, not rewritten: it is the record of a decision that was correct on the
evidence available and wrong on evidence that only the other layer had.**

**Original status: DESIGNED, PROTOTYPED IN SAIL, COST MEASURED, THEN REVERTED DELIBERATELY. The tree
is green at Sail 118/118. This entry exists so the next pass starts from a settled ABI and a real
number rather than an estimate.**

#### The ABI, decided

The crossing takes a **RETAIN mask** from a GPR named by a field that is reserved-zero today. Bit `i`
set means capability register `i` **survives**; everything else is cleared.

**Retain rather than clear, and that choice is the entire safety argument.** A reserved-zero field
decodes to `x0`, `X(x0)` is zero, and a zero mask retains **nothing** -- so R30(b)'s existing
reserved-zero pin becomes the fail-safe default *for free*. Every crossing written before the
increment clears everything, and a caller that wants to pass capability arguments must say so. The
opposite convention would have made silence mean **leak**.

The mask is sourced from a GPR **exactly as `VEDA_OCLEAR` sources its mask** (increment 1), so the
machine ends with one mask convention rather than two.

#### The encoding, verified available rather than recalled

- **OCInvoke's `rd`** is `0b0 @ 0b0000` -- five reserved-zero bits. `p8_reserved_bits.S` pins
  OCInvoke's **bit 24** (the top bit of the `rs2` field), not `rd`. **Available.**
- **OCReturn's `rs2`** is `0b00000` -- five reserved-zero bits. `p8_reserved_bits.S` pins OCReturn's
  **`rd`**, not `rs2`. **Available.**

#### Two placement rules that fall out of the mechanism

- **OCInvoke clears BEFORE the IDC install**, so `c15` survives by construction and needs no special
  case in the mask.
- **OCReturn does NOT exempt `c15`.** It installs no IDC, so a surviving one hands the callee's own
  data capability back to the caller.

#### The measured cost

Prototyped in Sail and run against the corpus: **15 of 118 self-check tests fail** --
`vc_ocinvoke`, `vc_ocreturn_basic`, `vc_pcc_bounds`, `vc_ocjalr_compartment_boundary_neg`,
`vc_d5_crbr_shadow_leak`, `vc_r11b_executing_pin_neg`, `vc_r52_creation_domain`,
`vc_r58_domain_writers`, `vc_r67_frame_owner_neg`, `vc_scheduler_cooperative_yield`,
`vc_ssc_cross_thread_isolation`, `vc_ssc_spill_reload`, `vc_switcher_register_clear`,
`vc_switcher_register_clear_fast_return`, `vc_syscall0_step0_spike`.

That is not breakage -- it is **the corpus declaring, one file at a time, what it had been passing
across a boundary without saying so.** Each re-aiming is a design statement, not a mechanical edit.

#### Why it was reverted rather than half-landed

Completing it means: 15 Sail tests re-aimed, the RTL encoding changed and its clear logic added, the
RTL twins re-aimed, the differential probes checked against two changed encodings, and the shipped
switcher's four crossings given masks. **A Sail-only landing is exactly the "half a fix is worse than
none" state R67 recorded one increment earlier** -- there the RTL would have held a depth while
releasing a frame, a state neither layer models. The same trap, one layer up.

So: reverted clean, tree green, ABI settled, cost known. What the next pass owes is execution, not
design.

#### Residual that this does NOT close, stated now so it is not discovered later

Clearing the registers closes the **possession** channel. It does **not** give the dereference
checker a domain question -- `veda_pcc_object` and `veda_current_region` still appear **zero** times
in the access-check file. A capability that a callee legitimately receives in the retain mask is
still usable by anyone who later obtains that register by any means. Possession and authority remain
the same thing on the dereference path.

### R51. The region table has no software write path, so the compartment crossing has never been differentially tested

**Status: MEASURED, RECORDED. Not fixed -- the fix is a new instruction, and it should be designed,
not improvised.**

Found by writing the R48 differential probe and then **reading its signature instead of trusting its
verdict**. `p21_oda_crossing.S` reported **AGREE** -- and both layers had written **eight zero words.**
Neither ever reached its stores.

**Why -- AND THIS EXPLANATION WAS WRONG. The correction matters more than the finding did.**

The paragraph first written here said: *"the region table is written by exactly one thing in the
entire model, `veda_test_seed_odt()`, the test fixture function... the differential harness runs with
`test_fixtures = false`, so no region is ever valid or resident there, and every OCInvoke
REGION_FAULTs."*

**`test_fixtures = false` does not disable region seeding.** The region writes are at
`veda_regs.sail:1231-1242`; the `if veda_test_fixtures then {` guard does not open until **:1530**,
*after* them -- and the file states the scope itself: the switch covers the **capability register**
seeding, and *"the ODT seeding above is left alone -- that is a separate question and a separate
increment."* Regions 0 and 1 are valid and resident in the differential harness, as everywhere else.

**The real cause was one immediate in my own probe.** `callee_entry` lands at `0x8000010c`, the code
object declared `Length 0x40`, and the compartment's terminating `ecall` sits at `0x8000014c` --
**exactly one word past the end of the PCC window `OCInvoke` installs.** It could never be fetched,
so the probe never reached its stores. Its sibling `vc_r10_crbr_invoke_trap_return.S` sizes its
compartment `0x200` and says why. **Corrected to `0x200`, `p21_oda_crossing.S` runs, agrees on all
seven words, and is back in `probes/`. `difftest/blocked/` is empty and gone.**

**What survives, exactly.** There is still no RT-write instruction, and RTL-5's mutant **M3 survives
for want of one** -- that part was and is true. And the compartment crossing really had never been
differentially tested. But that was true for the mundane reason that **nobody had written a probe
that crossed**, not for the architectural reason recorded beside it.

> **A finding whose headline is right and whose stated cause is wrong is worse than no finding**,
> because the stated cause is what the next increment gets scheduled against. This one nearly bought
> a new instruction.

**The consequence is bigger than the probe.** `p21` is the **first probe in the suite's history to
attempt an OCInvoke** -- verified by grepping every probe for the encoding. **The architecture's
central isolation mechanism has no cross-layer coverage**, and could not have any until the region
table becomes writable by something other than a fixture.

**What was done.** The probe is **kept, not deleted** -- moved to `difftest/blocked/` with the reason
in its header, ready for the day that changes. And `run_difftests.sh` now **refuses to run** if any
file in `probes/` is missing from its expected-verdict table, because the quieter successor failure
would have been to drop it from the table and leave the file where it sits: a test nobody runs and
nobody misses, which is R49 in a different directory.

**R48's evidence therefore lives in two fixture-enabled suites instead**:
`sail_tests/vc_r48_oda_inherit_neg.S` and `rtl/sim/veda_smoke_r48_oda_crossing.S`, each carrying the
same controls.

**This is the seventh instance on this project of a green result that measured nothing**, and the only
reason it was caught is a rule this register keeps re-learning: **a suite's verdict is a claim; read
the values.**

### R50 increment 1 (OCLEAR). The architecture assigned a duty and shipped no tool for it

**Status: BUILT AND VERIFIED ON BOTH LAYERS. Sail 106/106, RTL 98/98, ACT4 51/51, differential 24/24.
The crossing rule itself is increment 2 and is deliberately NOT in this increment -- see the
sequencing below.**

R50 measured that the capability register file crosses a compartment boundary intact. The
conventional answer, and real CHERI's, is that a **trusted switcher clears the registers it is not
passing**.

**THIS MACHINE COULD NOT DO THAT.** There was **no instruction that reliably zeroes a capability
register's value.** Every soft-fail in the derivation family -- OCA, CSetBounds, CAndPerm,
Rebind-on-sealed -- clears the **tag** and carries the source's fields **verbatim**. The only writes
of `zero_capability` outside reset are Bind's two *miss* arms, and reaching them requires the ODT
lookup to miss or be wrong-hart; on a **valid, resident, openly-bindable** slot that instruction
**succeeds and installs a fully-permissioned capability instead of clearing.** `veda.bind.notrap` is
a probe whose failure mode happens to look like a clear.

> **The architecture had assigned a duty and shipped no tool for it.**

**OCLEAR**: Custom-2, funct3 `001`, funct7 `0011000` (next free, verified by enumerating every
`0b001` encdec). A 16-bit mask in an ordinary GPR; bit *i* clears capability register *i*.
**Unprivileged** -- dropping authority you already hold is monotone, and requiring privilege to give
something up is exactly what made R48 unclosable in software.

#### Two decisions that look like details and are not

- **It clears the VALUE, not just the tag** -- and this **deliberately overrides R48's own
  "tag only, never the value" discipline.** R48's justification was that every ODA consumer routes
  through `veda_oda_authorized()`, whose first term is the tag. **That is true of the ODA and false
  of the capability register file**: the query family is deliberately un-gated -- no tag check, no
  seal check, no bounds check -- so an *untagged* register still answers `CGetBase` with the **raw
  physical Base**, the disclosure this codebase says must never reach software. **This project
  already paid for that once, as RTL-14.**
- **The cleared `otype` is `0xFFFF`, not zero.** `isSealedCap` tests `otype != UNSEALED_OTYPE`, and
  **Rebind tests `isSealedCap` on its DESTINATION with no tag conjunct** -- so an all-zeros clear
  would leave every cleared register **permanently un-Rebindable**, while its tag read 0 either way
  and every tag assertion in the corpus stayed green. **That is R24 re-created**, and it is the exact
  shape of failure this register keeps recording. Bind's own miss arms already write
  `zero_capability` for this reason; the test asserts a successful Rebind after a clear.

#### Why an instruction, and not just a rule at the crossing

The crossing rule is increment 2. This one is **independently necessary**, for a reason no crossing
rule can ever cover: **the trap path is a fourth compartment entry that no crossing rule reaches.**
The shipped switcher points `mtvec` at itself, is entered by a thread's `ecall`, and then
**dereferences capabilities bound before any crossing from inside its own handler.** Capability
registers surviving a trap is **load-bearing shipped behaviour**. On the one entry hardware cannot
police, an explicit clear is the only tool there is.

#### The GPR question, decided

**Hardware does not clear general-purpose registers at either crossing.** R48's rule is not
"hardware beats software" -- it is a **capability-of-the-caller** argument, and its premise is
falsifiable per channel. For the ODA it holds (`OSpecialRW` is Machine-only). For the capability
register file it held until this increment (no clearing instruction existed). **For GPRs it is
false**: `mv xN, x0` is one unprivileged, always-available base-ISA instruction, and the shipped
switcher already executes exactly that. A hardware GPR clear is also **structurally impossible**, not
merely expensive: inside a live compartment every ordinary load and store hard-traps under the
purecap rule, so a compartment entered with cleared GPRs, a cleared SSC and a cleared ODA would have
**no input channel in either direction**. The asymmetry is R48's rule working, not being abandoned.

#### Sequencing, and what increment 2 owes

**OCLEAR → R52 → the implicit crossing clear.** R52 must come in between, because increment 2's
cost is only honest once re-binding by name is gated -- **R52 measured that a callee needs only the
Object_ID, so clearing registers without it is theatre.** And increment 2 needs a **caller-supplied
retain mask**: the corpus's need is not a fixed window -- ten programs need exactly `c2`, six need
exactly one sentry -- and **no register subset exists that can be cleared while breaking nothing.**

**Candidate (D), retention as a property of the entered code capability, was my own proposal and is
REFUTED in both forms.** In `flags`: `odt_entry` has **no flags member**, Bind mints `flags = zeros()`
unconditionally, and **the RTL zeroes flags on every derivation while Sail carries it** -- so a retain
bit there would be alive on the specification layer and dead on the implementation, on the exact
instruction pair that mints and consumes a sentry. In `Perms`: Populate writes Perms **unmasked** from
a GPR under an authority R47 scopes to **memory only**, so any delegated ODA holder mints the retain
right on every object in its window.

### R53. CSetBounds was computed at the pre-widening widths, and the window check validated the truncated request

**Status: MEASURED, THEN FIXED AND VERIFIED. Cross-layer, and the differential suite had missed it
for twenty increments because no probe had ever exercised CSetBounds above 16 bits.**

Three sites in the RTL, not two:

```
$veda_csetbounds_new_base[31:0]   = base + offset          -- operands are 56 and 40 bits
$veda_csetbounds_new_length[15:0] = $rs2_data[15:0]        -- Sail takes new_length[39..0]
$veda_csetbounds_window_ok        = ... {48'b0, $rs2_data[15:0]} ...   -- checks the TRUNCATED request
```

The operands beside them were already wide and the results are consumed into `$base[55:0]` and
`$length[39:0]`, so the narrowing happened **here and nowhere else** -- a site increment 3's
capability-format widening missed. **The comment directly above the third site knows the widths
changed** ("Offset/Length are 40 bits now while rs2_data is 64") and fixes the *comparison* domain
while still slicing the *operand* to 16.

**MEASURED across the layers**: a CSetBounds requesting `Length 0x10000` on an unbounded parent gave
**`0x00010000` on Sail and `0x00000000` on the RTL.** Both controls -- a request of `0x40`, and the
parent's own Length read before any derivation -- **agreed on both layers throughout**, so the probe
measures the width and not a broken CSetBounds.

**Severity, split honestly.** The Length half was **fail-closed** (a truncated-to-zero Length grants
nothing), so it is a correctness divergence rather than an escape -- a program correct against the
specification failed on the hardware. **The Base half is not fail-closed**: above 4 GiB the sum wraps
and the capability names different memory. That half is **UNMEASURED** -- this testbench's memory map
cannot reach 2^32 -- and is recorded as unmeasured rather than claimed.

**The third site is the interesting one.** Because the check validated the truncated request, a
request above `0xFFFF` **passed as zero and stored zero** -- silently minting a useless capability
instead of refusing. It is now computed **65 bits wide**, because offset is 40 and the request is 64
and at 64 bits a huge request **wraps to a small sum and passes**. That is R18 for the fourth time.

### R52. A name is still full authority -- the bind gate's default is open, and that makes clearing registers at the crossing theatre

**Status: MEASURED, THEN DECIDED, BUILT AND VERIFIED ON BOTH LAYERS -- with one half deliberately
left open and named. Sail 108/108, RTL 98/98, ACT4 51/51, differential 25/25.**

**THE POLICY, TAKEN:** *an object created **inside a compartment** belongs to that compartment's
domain; an object created in the **ambient** context stays `VEDA_DOMAIN_ANY`.* Two lines per layer,
no new instruction, no new field, no encoding.

**THE AMBIENT ARM IS WHAT KEEPS R17 CLOSED, and it is the load-bearing half.** R17 forbade
cross-domain Bind outright and was retracted the same day because a compartment's **return path is by
construction in another domain**, so compartments became one-way. Here the boot/loader context builds
the return paths, the type authorities and the shared services, and those stay open. Demonstrated
rather than argued -- `sail_tests/vc_r52_creation_domain.S`:

| | tag | |
|---|---|---|
| CONTROL 1: compartment A (region 1) binds **its own** object | **1** | its own domain still works |
| **THE FINDING: compartment B (region 0) binds A's object by name** | **0** | **refused, `DOMAIN_VIOLATION`, exactly one trap** |
| CONTROL 3: B binds an **ambient-created** object | **1** | **R17's return path intact** |

**Measured before the decision was taken, not after:** the change was applied and the **whole corpus
run** -- 107/107 Sail and 98/98 RTL, nothing broken. That is what told me the ambient arm was
sufficient, and it is a stronger answer than reasoning about which tests might break.

**WHAT IT DOES NOT CLOSE, and this is stated rather than discovered later.** The gate compares
`owner_domain` against `veda_pcc_object[43 .. 24]` -- **the region** -- so two compartments in one
region are **one principal**. That is R10's design, not an oversight: the region field of a code
capability's Object_ID *is* the unforgeable domain identity. So this closes cross-**domain** naming,
not cross-**compartment** naming inside a domain. Re-graining the subject from region to object needs
a field wider than `owner_domain`'s 20 bits to hold a 44-bit identity, and that is a separate
decision. `sail_tests/pending/vc_r52_bind_by_name_neg.S` is **still red on purpose** and now waits on
exactly that, with its README saying so.

**AND THE MIRROR HAD A BUG THAT WAS ACCIDENTALLY CORRECT, which is why it is recorded rather than
quietly amended.** The RTL arm was first written `($veda_pcc_object == 44'b0) ? VEDA_DOMAIN_ANY : ...`
-- testing the sentinel against **zero**. `VEDA_OBJECT_NONE` is `44'hFFFFFFFFFFF`, all ones. The wrong
test still produced the right answer in every existing test, **by coincidence**: the all-ones
sentinel's top 20 bits are exactly `VEDA_DOMAIN_ANY`, so the else-branch returned the value the
then-branch was supposed to. It diverged from Sail for exactly one input the coincidence does not
cover -- a compartment whose code object is Object_ID `{region 0, local 0}`, a perfectly legal id --
where the RTL would have written `ANY` (**fail-open**) while Sail wrote domain 0.

**No test in the corpus could have caught it**, and it was found by checking the sentinel's value at
source rather than assuming it. A mirror that is right by coincidence is the same hazard as a green
test that measures nothing, one layer down.

---

**The original finding, kept because it is what forced the decision:**

R50's obvious fix is to clear the capability register file at the crossing. **That fix would achieve
nothing**, and the measurement says so directly. In the reproduction the caller does **more** than any
such fix would do for it -- it untags its own capability register **before** calling:

| | traps | value the callee read |
|---|---|---|
| `owner_domain = VEDA_DOMAIN_ANY` -- **what every Populate writes** | **0** | **`0xC0FFEE`** |
| `owner_domain` actually set with `veda.odt.set.domain` | **2** | `0x0` |

The callee did not need the register. It needed **the name** -- and an Object_ID is a small integer
it can enumerate. **The gate is sound; its default is open.**

```
veda_bind_domain_ok(owner_domain) =
     owner_domain == VEDA_DOMAIN_ANY      -> true    <-- every Populate writes ANY (R41)
     veda_pcc_object == VEDA_OBJECT_NONE  -> true    <-- the ambient context (R34)
     otherwise: owner_domain == veda_pcc_object[43 .. 24]
```

Three arms, **two fail-open**. The gate bites only on an object somebody deliberately narrowed.

**THIS WAS A DELIBERATE DEFERRAL, AND THE SOURCE SAYS SO** -- the `odt_entry` comment: *"Every object
is created that way, so this field changes nothing until software deliberately narrows an object --
**mechanism first, policy second**. The retracted R17 proved why that order matters: a rule applied by
default broke the return path and made compartments one-way."* **The mechanism was built. The policy
has never been taken**, and R50's measurement is what makes taking it urgent: without it, compartment
isolation for data objects does not exist, and the R50 fix cannot buy anything.

**R17's retraction already named the replacement**, and it is now buildable: *"the unit that needs
permission is the OBJECT, not the domain, because legitimate sharing is per-object and crosses domains
by design... an object can then be marked shareable while its neighbours are not. That is the
direction to take, and it needs the ODT field-write path."* **That path was built** --
`veda.odt.set.domain`, and the control above is exactly it working.

**Candidate policy, checked against the very test that killed R17** (`vc_r10_crbr_invoke_trap_return.S`):
objects populated **inside** a compartment default to that compartment's domain; objects populated in
the **ambient** context default to ANY. That test passes under it for **two different and correct
reasons** -- its objects 41/42 are created inside region 1 and bound from region 1, and its type
authority 40 was created ambient and stays shareable.

**Two things it does not fix, stated rather than discovered later.** Ambient-created objects --
including type authorities -- stay bindable by any compartment. And the gate is **region-grained**
(`veda_pcc_object[43 .. 24]`) while the compartment identity is the full **44-bit object**, so two
compartments in one region are one principal; with no region-table write path (R51) essentially
everything lives in region 0. **Re-graining the subject from region to object is a prerequisite the
title of this finding does not mention.**

**Must be measured against the whole corpus before shipping.** R17 passed all 77 RTL tests and then
sent one Sail test into an infinite loop.

### R54. Two verification runs at once silently corrupt each other's results -- and R46 is what caught it

**Status: MEASURED (on myself, this session). FIXED with a lock.**

Two `verification.sh` runs were started concurrently by mistake. They share `rtl/sim/` and the
`difftest/` artifact directory, so they overwrite each other's `.vvp`, `.hex` and `.sig` files
mid-flight. One of them reported:

```
  Sail self-check   : 106/106 passed
  RTL milestones    :  51/51  passed      <-- the true number is 98
  Cross-layer diff  :   5/24  as expected <-- the true number is 24
  VERDICT: NOT VERIFIED
```

while the other, at the same moment, reported the true 106/98/51/24 and passed.

**Before R46 this would have printed a smaller number and exited 0.** The whole failure would have
been a count nobody compared -- which is the exact shape R46 and R49 were about. So the first thing
to record is that **the fix worked**: the entry point refused to certify a run it had corrupted.

But *visible* is weaker than *impossible*. The suites write into fixed paths with no interlock, so a
second run is not a slow run -- it is a **wrong** run, in either direction. `verification.sh` now
takes an exclusive lock and **refuses to start** while another run holds it, naming the holder.

**And the deeper point, which is mine and not the harness's:** this is my own recorded rule
(*"while a sweep runs, that tree is not a source of truth for any reader"*) applied from the
writer's side and violated by me. A measurement taken while another process is mutating the same
tree is not a measurement. The lock makes that unavailable rather than merely discouraged.

### R55. veda.bind minted a capability out of a region that had never been configured

**Status: MEASURED, THEN FIXED AND VERIFIED. A Sail-only divergence in which the SPECIFICATION was
more permissive than the hardware -- the worse direction on a Sail-first project.**

The model carries **two** region-residency predicates, and they did not agree:

```
veda_region_rt_resident(r) = rt_valid & region_resident      <- OCInvoke, OCReturn
veda_region_is_resident(r) =            region_resident      <- veda.bind
```

The comment on the first one says `rt_valid` *"gains its first-ever consumer here: a slot that has
never been configured must fail closed even if its resident bit were somehow set."* **It gained that
consumer at the crossings and not on the minting path** -- and minting is where a missing gate turns
into a capability.

**Region 3 is R10's own gate fixture**, `{rt_valid = false, region_resident = true}`, built precisely
to catch this. Measured, with its control:

| | traps | tag |
|---|---|---|
| bind into region 3 `{rt_valid=0, resident=1}` | **0** | **1 -- minted** |
| control: bind into region 2 `{rt_valid=1, resident=0}` | 1 | 0 -- refused |

So the predicate consulted `region_resident` and not `rt_valid`.

**THE RTL WAS ALREADY RIGHT.** `$veda_region_resident` reads `rt_valid[..] && rt_resident[..]`. Closed
in the RTL's direction, which is also what the architecture's own comment says it intends.

**THREE OF MY OWN MEASUREMENTS OF THIS WERE VACUOUS BEFORE ONE WAS SOUND, and each was caught by a
control rather than by inspection.** The first read `cgettag` on `c10`/`c11` -- **the fixture seeds
`c10..c14`** -- so it measured the seed and reported both the finding and its control as tag 1. The
second lacked per-step trap counts, so a refusal that trapped was indistinguishable from a soft-fail.
The third asserted **zero** traps for the refusals, when a region fault is a **hard trap for every
bind mode including `.notrap`**, which the source states outright. The shipped test therefore counts
traps exactly at four points and carries four controls, including the one that matters most: **a bind
into a properly configured resident region must still SUCCEED**, or a machine that refused every
cross-region bind would pass the whole file.

### R56. RT-Populate: DECIDED AGAINST as the next increment, and the reasons are worth more than the instruction

**Status: DESIGNED, ADVERSARIALLY REFUTED, NOT BUILT. Two of the three justifications for it turned
out to be false at source, and the third is defence-in-depth.**

The case for an RT-Populate was: (i) R51 said the differential harness has no resident region;
(ii) R52's policy is inert because everything is region 0; (iii) RTL-5's mutant M3 survives for want
of an RT-write. **(i) is false** -- see R51's correction above. **(ii) does not follow**: RT-Populate
would multiply domains from 2 to 8 and **not move the bind gate's comparison by one bit**; R52's
prerequisite is re-graining the subject from region to object, which no new instruction supplies.
**(iii) is real and non-substitutable** -- and by its own author's words it is defence-in-depth, and a
**create-only** RT-Populate would not kill M3 anyway, because M3 needs *revocation*.

**AND THE MINIMAL VERSION IS A COMPARTMENT ESCAPE ON ITS FIRST EXECUTION.** Verified on both layers:

```
empty_region_entry.region_odt_base = zeros()        installed into regions 4..7
region 0's region_odt_base         = zeros()        <- the same value
RTL: the reset loop sets rt_odt_base[r] = 32'b0 for all, and rt_odt_base[0] = 32'd0
```

**Four regions already alias region 0's entire descriptor namespace at reset**, and the only thing
between a foreign compartment and every unnarrowed descriptor in region 0 is one bit --
`rt_resident[4] == false`. Setting that bit is exactly what an RT-Populate does. **"No base operand"
and "derived base" are different designs, and only the second is sound.**

**THE REGION LAYOUT IS DISJOINT ONLY BECAUSE THE MODEL TRUNCATES.** `region_entry` holds
`rt_valid, region_odt_base, region_resident, region_backing, region_generation` -- and **no length**.
A region's extent is unbounded by construction; the index is `region_odt_base + local`. Exact
constants: `VEDA_LOCAL_MODELED = 2^20` (a **modeling** bound enforced by `veda_odt_index`'s
`lu >= VEDA_LOCAL_MODELED -> None()` guard), fixture bases `0, 2^20, 2^21`. Under the model each
region spans exactly `2^20` and the three are exactly disjoint. **At the architected 24-bit local
width they are not** -- region 0 would span `[0, 2^24)` and swallow region 1's base entirely. **The
shipped layout is safe because of a modeling artifact, not an architectural invariant.**

So if RT-Populate is ever built: the base must be **derived, never defaulted and never
caller-chosen** (R10 makes the region field the unforgeable domain identity, so choosing it is
forging a domain), `region_entry` needs a **length** or a fixed stride, and the containment
arithmetic must be computed wider than its operands -- **R18 for the fifth time**. The region table
is 8 entries, so unlike the ODT's `2^23` an all-pairs disjointness check **is** a real hardware
operation here.

**The precedent supports the static reading.** seL4's `KernelNumDomains` is a compile-time constant
and the only runtime authority moves a thread between existing domains; CHERIoT's compartments are
established by a loader that then erases its own authority. A machine whose domains are fixed at load
time is a shipped architecture, not an unfinished one -- so the reset seeding is a **legitimate loader
stand-in**, and this project already recorded that as a deliberate scope decision when it left the
ODT seeding outside the fixture switch.

### R57. Is the REGION the right grain for a domain? -- VERDICT (B), and the entry that was missing

**Status: DECIDED (B). AND THIS ENTRY DID NOT EXIST UNTIL NOW.** R57 was cited four times in this
document -- *"the R57 adversarial pass"*, *"carried in the R57 residue as D5"*, *"the R57 residue as
D6"*, *"promoted, not created, by R57's verdict (B)"* -- while `### R57` had no heading anywhere in
any of the three repositories. Its three residue items were each measured, fixed and written up
(R60, R61, R62), all of them describing themselves as residue **of a finding the register did not
contain**. Second occurrence of the class the 2026-08-18 register-integrity audit caught, and the
first one that is mine.

#### The question

R10 made the region field of an Object_ID the domain identity. R52 then found that the bind gate
compares `owner_domain` against `veda_pcc_object[43 .. 24]` -- **the region** -- so two compartments
that share a region are one principal, and no amount of register-clearing at the crossing changes
that. R57 asked the architectural question directly: **is the region the right grain, or must the
domain identity be re-grained to the object?**

Two answers were possible:

- **(A) Re-grain to the object.** `owner_domain` would have to hold a 44-bit identity in a 20-bit
  field, so this is a format change, not a check. Every compartment becomes its own principal.
- **(B) The region IS the architecture.** Domains are established at load time by a trusted loader,
  compartments within a region are deliberately one principal, and the grain is a decision rather
  than a limitation.

#### The verdict: (B), on precedent and on cost

**(B).** The precedent is strong and was checked rather than recalled: seL4's `KernelNumDomains` is a
compile-time constant and the only runtime authority moves a thread between *existing* domains;
CHERIoT's compartments are established by a loader that then erases its own authority. **A machine
whose domains are fixed at load time is a shipped architecture, not an unfinished one.** (A) costs a
capability-format change for a property (B) obtains by convention plus one loader.

#### But (B)'s escape hatch is false on the shipped machine, and that is what the residue was

(B) is only sound if the loader's region grants are real. R57 recorded three premises to check and
they became this register's next four entries:

| premise | outcome |
|---|---|
| the CRBR shadow is released by every exit | **FALSE** -- R60 (D5), measured on both layers, fixed |
| `set.domain` names a principal that exists | **FALSE** -- R62 (D6), measured, fixed |
| `pending/`'s routing and citations are sound | mostly true; R61 (D7) corrected a fabricated control |
| **region grants are enforced somewhere** | **FALSE, and worst of the four** -- R63 below |

**R63 is the one that decides whether (B) can be written down at all.** A domain grant that no
instruction checks is not a grant; and until R63 there was no point in the machine where naming a
region cost anything on the write path.

#### What (B) still owes, stated as a contract

1. **A named holder.** The loader owns region creation. Today the region table is seeded at reset,
   which R56 correctly defends as a legitimate loader stand-in -- but the contract has to say so
   rather than leave it implicit in an `initial` block.
2. **Region 0 is reserved for the ambient context.** Verified as already true by construction, not
   by rule: `veda_crbr_save_and_reset` resets the current region to 0 unconditionally on every trap,
   `veda_region_table[0]` is seeded `{rt_valid, region_resident, base 0}` on both layers, and
   `veda_creating_domain` returns `VEDA_DOMAIN_ANY` when `veda_pcc_object == VEDA_OBJECT_NONE`. The
   contract must state it so a future RT-write cannot quietly repurpose region 0.
3. **`region_entry` has no length.** Verified at source, both layers: the struct is
   `rt_valid, region_odt_base, region_resident, region_backing, region_generation` and nothing else.
   A region's ODT extent is bounded only by `VEDA_LOCAL_MODELED`, a **modeling** constant. At the
   architected 24-bit local width region 0 would span `[0, 2^24)` and swallow region 1 entirely.
   **The shipped layout is disjoint because of a modeling artifact, not an architectural invariant**
   -- R56 found this and it remains the single largest unclosed premise under (B).
4. **Region-grant authority at Populate** -- closed by R63 in its minimal form (you may not name a
   region that does not exist). Its strong form -- *you may only populate into your own region,
   unless you hold an explicit grant* -- is **NOT built**, because it needs the grant object in
   premise 1, and the ambient loader legitimately populates into region 1 today.

**Recorded as still owed, not as done.** Premises 1 and 3 are open; premise 2 is verified-true but
unwritten; premise 4 is half-closed.

### R58. My own R52 landing hit the wrong two clauses, and 108/108 did not notice

**Status: SELF-INFLICTED, FOUND BY AN ADVERSARIAL PASS AND NOT BY THE SUITE, THEN CORRECTED AND
COVERED. Sail 109/109, RTL 98/98, ACT4 51/51, differential 25/25.**

R52's creation-policy edit was applied by a script that replaced *"the first two occurrences"* of
`owner_domain = VEDA_DOMAIN_ANY` in `veda_ocl_insts.sail`. **In file order the three
creation/destroy sites are Populate, DESTROY, Populate-Fast** -- so the edit hit Populate (right) and
**DESTROY** (wrong), and **missed Populate-Fast entirely.**

| | consequence |
|---|---|
| **Destroy** took `veda_creating_domain()` | a destroyed slot inherited the **destroyer's** domain -- **R41 broken**, whose whole point is that the previous occupant's policy has no claim |
| **Populate-Fast** still wrote `ANY` | and **the shipped C allocator uses exactly that encoding**, so **R52 was void for every heap object** while being reported closed |

**Both suites stayed green throughout -- 108/108 and 98/98, before and after.** Nothing in either
corpus checked the `owner_domain` of a destroyed slot or of a `populate.fast`-created object.
**Eighth instance on this project of a green result that measured nothing, and the first one that was
mine, in shipped code.**

**The RTL was right on both counts** -- its Populate arm is shared by `populate` and `populate_fast`,
and its Destroy arm did not write `owner_domain` at all. So the correction was Sail-only.

#### And verifying it turned up a pre-existing divergence, which is now closed too

The RTL's Destroy arm writing nothing to `owner_domain` was itself a **Sail/RTL divergence** -- Sail
resets to `VEDA_DOMAIN_ANY` (R41), the RTL **preserved**. It is observable, through the channel this
register keeps finding: **`veda_bind_domain_ok` is evaluated BEFORE `e.valid`**, so a Bind against a
**destroyed** slot still consults its `owner_domain`, and the trap **cause** reports which way it
went:

```
reset to ANY   ->  gate passes  ->  OBJECT_NOT_FOUND  0x05
left as N      ->  gate fails   ->  DOMAIN_VIOLATION  0x0B
```

**So the RTL's stale value was an oracle for the destroyed slot's previous owner** -- the same
refusal-cause class R44 closed for bind mode `0b11`. Closed in Sail's direction, for both reasons.
**Source-derived, not measured**: the RTL half was found by reading the arm's field list, not by
running it.

#### The test that can finally see any of this

`sail_tests/vc_r58_domain_writers.S`, and three of its details are the point:

- **A plain Bind, not `.notrap`.** Under `.notrap` a not-found object **soft-fails with no trap**, so
  the cause -- the only thing that distinguishes the two outcomes -- never exists. A plain Bind
  hard-traps on both paths and the **cause** separates them. The first draft used `.notrap` and
  measured nothing.
- **Compartment A's window is `0x40`, not `0x200`.** With `0x200` the window swallowed `arena` in
  `.data`, and **R45's memory-scoped executing pin correctly refused** to populate an object
  overlapping the code the compartment was running. *The pin was working; the scaffold was wrong.*
  Its sibling constraint is R51's: the window must still reach the compartment's last instruction.
- **`c0`/`c1`/`c2` only.** `c10..c14` are fixture-seeded and a trapping Bind never writes its
  destination, which is how four consecutive measurements earlier in this same session read a seed
  and reported a finding and its control as identical.

### R59. A re-minted object inherited the previous occupant's owner, and a domain-violating Bind still claimed it

**Status: BOTH VERIFIED AT SOURCE, THEN FIXED AND COVERED ON BOTH LAYERS. Sail 110/110, RTL 99/99,
ACT4 51/51, differential 25/25. Found by the R57 adversarial pass -- the design question it was asked
came back (B), and these came back with it.**

#### The owner byte nothing reset

Sail resets `owner_hart = VEDA_OWNER_UNOWNED` on **Populate, Populate-Fast and Destroy**. The RTL's
**only** dynamic write to that byte anywhere in the file was the owner **claim**. It never reset. So
on the hardware a slot's owner **survived Destroy and re-Populate**, and a freshly minted object was
born owned by whoever last held the slot.

**Benign at `MHARTID = 0` and permanent above it.** With one hart a stale `0x00` still passes
`owner_ok`, so nothing shows. With a real second hart **no instruction in the ISA can clear the
byte** -- the claim is its only writer -- so hart A could never reclaim a slot hart B once bound,
*even after destroying and re-minting it*.

**This is R41's class applied to the third carried field.** R41 closed `cow` and `owner_domain` on
exactly this argument -- a Populate mints a **new** object and the previous occupant has no claim on
it. `owner_hart` was left behind, and the RTL had even written the absence down as deliberate.

#### The claim that fired on a refusal

`$veda_owner_claim_en` carried `!region_fault` and `!residency_fault` and **not**
`!domain_violation` -- and the comment directly above it explains exactly why the other two terms
exist: *"a residency-faulting Bind takes ownership of an object it was just refused... ownership is
the thing page-in is specified to PRESERVE."* The same argument, unapplied to the third gate. The two
predicates are independent rather than exclusive, so both held for a valid, unowned object narrowed
to another domain, and **the owner byte was written by a trapping instruction.** Sail cannot do this:
its `veda_trap` returns before any `odt_write`.

**Third instance of a class this one signal had already closed twice** -- and combined with the byte
nothing resets, it was a **permanent, unrecoverable claim** on multi-hart.

#### The test, and why it needs two files

**This property cannot be tested fixture-free.** Nothing software can do on one hart sets
`owner_hart` to a third value -- that is what the byte means. It is observable only because Milestone
12 seeded slots at `0x63` ("hart 99"), a value `owner_ok` refuses, precisely as a stand-in for a
second hart.

**And the two layers seed different slots** -- Sail objects 5 and 615, RTL entries 60, 105, 109 --
so this needs one test per layer rather than one shared file. Writing the RTL's ids into the Sail
test produced a trap with the **wrong cause**, and it would have passed for the wrong reason had the
cause not been asserted **as a value** rather than as "it trapped".

Each file carries the control that matters: **an untouched `0x63` slot must still be refused**, so a
machine that simply stopped checking `owner_ok` cannot pass by refusing nothing.

**D4's own discriminator is described and NOT built**: bind a `0x63` object narrowed to a foreign
domain from inside a compartment (domain violation), then bind it again from the ambient context --
under the bug the first, *trapping* bind rewrote the owner to `MHARTID` and the second succeeds. It
needs a compartment scaffold; recorded as **unmeasured** rather than claimed.

### R60 (D5). The CRBR saved shadow was released by no exit OCRETURN takes, and installed by any later xret

**Status: MEASURED ON BOTH LAYERS BEFORE THE FIX, THEN FIXED AND COVERED ON BOTH. Sail 111/111,
RTL 100/100, ACT4 51/51, differential 25/25. A design gap, not
a divergence -- the two layers agreed, and agreed on the wrong thing. Carried in the R57 residue as
D5, described there as "currently UNREACHABLE"; it is reachable, and this entry replaces that
assessment with a measurement.**

#### Three facts that only compose into a bug

Each is correct on its own and each is deliberate, with a written reason:

1. `veda_crbr_save_and_reset` captures **only** when `veda_current_region != 0`. Region 0 needs no
   save because the reset target *is* region 0, so a restore-to-0 would be the identity.
2. `veda_trap_frame_abandon` -- which **OCRETURN** calls, and which nothing else calls -- releases
   `veda_trap_depth`, `veda_mepcc_base`, `veda_mepcc_length`, `veda_mepcc_object` and
   `veda_trap_poison`. It does **not** release `veda_saved_region`.
3. `veda_crbr_restore_on_xret` fires on the **sentinel alone**: no depth term, no owner term, and it
   is called **outside** the mepcc depth guard -- deliberately, so the two disciplines stay
   individually self-consuming.

Compose them and the machine has a slot that **one exit fills and only the other exit empties.**
OCRETURN is not an obscure path: it is the architecture's *second* exit from a trap handler and the
**only** one the shipped switcher takes (`runtime/veda_sched_asm.S`), because narrowing PCC with
`csrw` and then falling through to an `mret` requires *fetching* that `mret`, which by then lies
outside the just-narrowed bounds. The design comment for `veda_trap_frame_abandon` says exactly this,
and the frame was abandoned on that reasoning while the shadow beside it was not.

#### What it does, measured

A region-1 compartment traps. The handler leaves by OCRETURN. `saved_region` stays 1. Then **any
later `mret` -- taken by unrelated region-0 code, for an unrelated reason -- installs region 1.**
Sail instruction trace on the unfixed model:

```
[60] ocinvoke c3, c4   CSR veda_current_region -> 1        entered the compartment
[64] ecall             CSR veda_current_region -> 0        handler in the root domain
                       CSR veda_saved_region   -> 1        captured
[72] ocreturn c8       CSR veda_current_region -> 0        frame abandoned...
                       CSR veda_saved_region   -> 1        ...shadow was NOT
[77] ecall                                                 unrelated region-0 trap: no capture
[83] mret              CSR veda_current_region -> 1        <-- STALE REGION INSTALLED
```

The RTL is the same machine: `$veda_saved_region` had reset, trap-capture and `mret` arms and **no
OCRETURN arm**. Measured on the unfixed hardware, with the intermediate assertion lifted so the run
reaches the second half: `after the OCRETURN exit: saved=0x1` and `after an unrelated mret:
region=1`. Identical failure, identical fix.

#### What leaks

`veda_region_is_resident` **exempts the current region** -- the CRBR is loaded only through validated
paths, so the region it names is resident by construction. With a stale CRBR that construction is
false, and the exemption grants the stranded region unconditional residency, bypassing both
`region_resident` and the `rt_valid` check **R55 put on `veda.bind`'s minting path**. So this
directly weakens the gate R55 closed one increment earlier.

It is **not** an authority escape by itself: the bind gate's subject is `veda_pcc_object`, which the
stale CRBR does not change. Recorded as an **R10 residual** -- promoted, not created, by R57's
verdict (B).

#### The fix, and why it sits where it does

A new `veda_crbr_release()` beside `veda_crbr_restore_on_xret`, called by OCRETURN immediately after
`veda_crbr_load`. Two choices were available and the reasoning picked the second:

- Fold it into `veda_trap_frame_abandon`'s depth-zero guard, alongside the mepcc release.
- Put it on the **CRBR side, unconditional**.

**Unconditional, on the CRBR side.** The justification is *supersession by the operand* -- OCRETURN
calls `veda_crbr_load` and installs the region from `cs1`, so a saved region is superseded by
definition, which is verbatim the argument `veda_trap_frame_abandon`'s own comment already makes for
PCC -- and that argument **does not depend on the depth bookkeeping being right**. Folding it into
the depth guard would have made a CRBR property contingent on the mepcc frame's counter, which is
precisely the coupling the restore path is deliberately written to avoid.

#### Coverage

`sail_tests/vc_d5_crbr_shadow_leak.S` and `rtl/sim/veda_smoke_d5_crbr_shadow_leak.S` + testbench,
both built from the passing R10 round-trip scaffold with **exactly one change**: the handler leaves
by OCRETURN instead of `mret`, and an ordinary region-0 `ecall`/`mret` pair follows. Both assert the
release *and* the consequence, both carry the entry controls (start in region 0 with an empty
shadow; the shadow really did capture in the handler), and the RTL half was **shown to fail with the
fix stripped from a copy of the generated Verilog** -- the finding half directly, and the consequence
half on a variant with the masking assertion lifted.

**A note on the scaffold, because it cost most of the time.** Four hand-built harnesses produced
values that were not measurements: an HTIF payload packed past 47 bits, a `report` block a patch
script had mangled, and two runs whose disagreeing numbers were my own bit-packing rather than the
model. The finding was only nailed down by `--trace-instr --trace-csr`, which reads the machine
instead of my arithmetic. **Building from a known-passing scaffold and reading the CSR trace should
have been the first move, not the fifth** -- and the fourth of these was the exit choice itself:
the first working version left the handler by **OCInvoke**, which calls `veda_crbr_load` but *not*
`veda_trap_frame_abandon`, so the second trap nested and R12's poison stopped the machine. The bug
needs OCRETURN specifically, and reading which crossing calls what came before the harness worked.

### R61 (D7). A control asserted as a measurement, in a file that names a sibling that never existed

**Status: RECORD DEFECT, CORRECTED. And D7's own two claims were both wrong about where and what --
recorded that way, because a finding whose headline is right and whose stated cause is wrong is worse
than no finding (R51's lesson, applied to a finding of mine).**

#### What D7 said, and what was actually there

D7 said `sail_tests/pending/README.md` routes the file to the **wrong decision** and cites
`vc_r52_bind_domain_default_ctl.S`, which does not exist. Checked at source:

- **The routing is correct.** The README says the file waits on re-graining the bind gate's subject
  from region to object. Both of the file's compartments live in region 0, `veda_bind_domain_ok`
  compares `veda_pcc_object[43 .. 24]`, and two compartments in one region are one principal by R10's
  design. That is exactly right. **Refuted.**
- **The phantom citation is not in the README.** It is inside
  `pending/vc_r52_bind_by_name_neg.S:203`, which calls it a *sibling file*. **Misplaced -- and the
  real defect is worse than the one reported.**

#### The real defect

The comment did not merely cite a missing file. It **reported that file's result in the past tense**:

> *"PART C is the control that decides what the finding IS. It lives in the sibling file
> `vc_r52_bind_domain_default_ctl.S`: with `veda.odt.set.domain` giving object 121 a real
> `owner_domain`, the identical PART B **takes 2 traps and reads 0. The gate works.**"*

The file does not exist anywhere in any of the three repositories, so **that measurement was never
made**. This is the ninth instance of this register's most persistent class -- a green claim that
measured nothing -- and it is the worst placement yet, because the sentence says outright that this
is *the control that decides what the finding is*. A fabricated control does not merely fail to
support a finding; it makes the finding unfalsifiable by the reader.

#### What the control actually is

It exists, twice, and both are landed and green:

| file | what it proves |
|---|---|
| `sail_tests/vc_bind_domain_neg.S` | the **explicit** path: `veda.odt.set.domain` narrows object 2 to domain 7; a bind from inside a region-0 compartment traps `0x0B` and the destination comes back **untagged** |
| `sail_tests/vc_r52_creation_domain.S` | the **creation-time default** (R52): a compartment's own object binds, a foreign compartment's is refused in exactly one trap, and the ambient object still binds -- R17's return path intact |

So `veda_bind_domain_ok` is enforced and is not bypassable, and the phantom sibling was never needed:
its job was already done by a test written earlier. The claim was not just unmeasured, it was
**redundant**, which is why nothing ever noticed it was missing.

#### Two more defects in the same file, found while verifying the first

- **Wrong identity.** The header opens `R48 -- DOES A CALLEE COMPARTMENT INHERIT THE CALLER'S ODA?`
  while the file is filed as the R52 pending test. It is a hybrid grown from the R48 scaffold; now
  says so in its first lines instead of announcing the wrong finding.
- **`120..106`** as an Object_ID range -- descending, impossible. The file uses 120..124.

Corrected in place, all three. The file still assembles and is still **red on purpose**
(`FAILURE: 1`), which is the contract `pending/` exists to hold.

**The rule this adds:** `pending/` was created because R49 measured what happens to a test nobody
runs. It now needs the second half of that discipline -- **nobody reads an unrun file either**, so a
claim inside one is never contradicted by a suite. Every cross-reference in `pending/` must name a
file that exists, and any result quoted there must name the test that produced it.

### R62 (D6). `veda.odt.set.domain` wrote an unvalidated principal -- and every use of it in the corpus named one that did not exist

**Status: FIXED AND COVERED ON BOTH LAYERS, with the gate measured on the shipped binary using the
corpus's own file as the probe. Sail 112/112, RTL 101/101, ACT4 51/51, differential 25/25. Carried in
the R57 residue as D6.**

#### The refusal was already in the same function, one term away

`VEDA_ODT_SET_DOMAIN` took `new_domain` straight from `rs2[19 .. 0]` and wrote it into `owner_domain`
with no validation of any kind. Three lines above it, for the *object* half, sits this:

> *"Refuse on a slot that holds nothing: a policy on a non-existent object is meaningless, and
> allowing it would let software **pre-stage rules on slots it does not own yet, to take effect when
> someone else populates them.**"*

The identical argument for the **domain** half was never applied, and it is the stronger of the two.
A domain **is** a region (R10). A policy naming a region that has never been configured takes effect
when someone else is **given** that region -- so it is **authority that outlives its author.** An
early-boot component holding a delegated ODA can stamp a future principal and then be dismissed;
dropping its ODA unstamps nothing. That is this architecture's own temporal-safety thesis, applied to
policy rather than to code, and it was the one place it had not been applied.

#### Write-time, not read-time, and the difference is the whole finding

The obvious alternative is to validate on the **read** side, in `veda_bind_domain_ok`. It does not
work, and seeing why is what settles the design:

- A read-time check makes the object **unbindable while the region is unconfigured, and bindable the
  moment it is configured.** That is precisely the attack, arriving on schedule.
- Only refusing the **write** prevents the stamp from being applied at all.

So the check lands in `veda_domain_nameable`, called by `VEDA_ODT_SET_DOMAIN` before `odt_write`, and
mirrored in the RTL as `$veda_domain_not_nameable` inside `$veda_odt_set_domain_violation`.

`VEDA_DOMAIN_ANY` is exempt because it is **not a principal** -- it is the absence of a restriction,
and it is what R41 and R58 reset the field to, so gating it would have broken object destruction. The
check reads `rt_valid`, **not** `region_resident`: region 3 is seeded `{rt_valid = false,
region_resident = true}` by R10 precisely so a check on the wrong bit cannot pass, and both tests
name region 3 for that reason.

**Machine is deliberately NOT exempt,** and this is the one arguable choice. R47's `veda_oda_denies`
exempts Machine because that is an **authority** question and Machine holds all authority. This is a
**well-formedness** question, like the `valid` check beside it -- which does not exempt Machine
either -- and the ordering it imposes on a loader (configure a region before assigning objects to it)
is one line of sequencing, not a capability anyone loses.

#### What the corpus was doing

Every single use of `set.domain` in the entire corpus, on both layers, **named a principal that does
not exist**:

| file | named | region state |
|---|---|---|
| `sail_tests/vc_bind_domain_neg.S` | domain 7 | `rt_valid = false`, never configured |
| `rtl/sim/veda_smoke_bind_domain_neg.S` | domain 7 | same |
| `rtl/sim/veda_smoke_odt_set_domain.S` | domain 5 | same |
| `sail_tests/vc_odt_set_domain.S` | domain 5 | same |

**Four** tests, four nonexistent principals, **not one correct usage anywhere on either layer**, and
one of them is described in its own header as *"the test the gate did not have."* That is why the
missing check was invisible: there was nothing to contrast against.

The fourth was found by the suite rather than by me. Having re-aimed the RTL twin I recorded the
count as three and moved on; `vc_odt_set_domain.S` came back **111/112** on the next full run. The
count in this entry was wrong for exactly as long as it took the harness R46 fixed to disagree with
it -- which is the argument for R46 in one line. All four are re-aimed at region 1, which is real,
configured and resident, and each now asserts what it always meant: the executing domain is not the
object's domain, therefore the bind traps.

#### The measurement, without a rebuild

The gate was measured on the **shipped** binary by taking the corpus's own canonical file and
restoring the one immediate:

```
vc_bind_domain_neg.S naming domain 7 (never configured)  ->  FAILURE   refused
vc_bind_domain_neg.S naming domain 1 (real principal)    ->  SUCCESS   accepted
```

Same file, same instruction, one operand apart. New tests
`sail_tests/vc_r62_domain_nameable_neg.S` and `rtl/sim/veda_smoke_r62_domain_nameable.S` carry three
controls each -- a real principal is accepted, the open sentinel is accepted, and a **refused write
wrote nothing** (an ambient bind still mints, so the field still holds `ANY` and not 3) -- so a
machine that simply refused every `set.domain` cannot pass either.

On the RTL the gate was additionally measured by **stripping its term from a copy of the generated
Verilog**: with `CPU_veda_domain_not_nameable_a0` removed from
`$veda_odt_set_domain_violation`, the region-3 write is **accepted** and the test's sentinel is never
set. (The two later sentinels also read zero in that run, but those are **unwritten registers, not
measurements** -- the first failing check jumps to the end. Stated because the identical masking in
the D5 run needed a second variant to see past, and a zero that means "never ran" reads exactly like
a zero that means "measured zero".)

**The first attempt at this check measured nothing at all**, and is recorded because the failure mode
is specific to this toolchain: the strip targeted `CPU_veda_domain_not_nameable_a1`, the pipeline
stage the source signal is *consumed* in, which does not appear in the generated file. The edit
silently changed nothing and the run passed, looking exactly like a successful control. **A vacuity
check that itself does nothing is the worst possible artefact**, because it manufactures confidence
in both directions -- the strip must be confirmed to have landed before its result means anything.

**And my own first draft was vacuous, in the register's most familiar way.** The trap-count
assertions read `li t4, N` / `bne x29, t4, fail` with `x29` as the trap counter -- and **`t4` IS
`x29`**, so every one of them compared the counter against itself. It surfaced only because a wrong
`cgettag` encoding trapped and the trace showed `addi x29, x0, 0x2` where the source said `t4`.
Tenth instance of a green check that measured nothing, and the first caused by an ABI-name alias.

#### Residual, stated and not closed

This stops a policy naming a region that has **never existed**. It does **not** stop one naming a
region that existed, was torn down, and was re-issued to a different principal -- the region-level
twin of the object generation counter. `region_generation` is already in the region table and is the
mechanism that would close it, but `owner_domain` has 20 bits and no room to carry one, so it needs a
**field change rather than a check**. Recorded as **UNMEASURED**: no RT-teardown instruction exists
yet, so the case is currently unreachable, and R56 decided against adding one.

### R63. The region half of an Object_ID was an identity on the read path and a bare index on the write path

**Status: MEASURED ON THE SHIPPED MODEL, THEN FIXED AND COVERED ON BOTH LAYERS. Sail 113/113, RTL
102/102, ACT4 51/51, differential 25/25. Found while verifying R57's premises in order to write R57
down -- the register repair produced the finding.**

#### The asymmetry

R10 states that the region field of an Object_ID is *"the unforgeable domain identity"*. R55 made
that true on the **read** path: `veda.bind` checks `veda_region_is_resident` (`rt_valid &
region_resident`) before it looks anything up. Nothing ever made it true on the **write** path.
`VEDA_ODT_POPULATE`'s gates are, in full: Machine-or-ODA, the executing pin, the ODA window, and
`retired`. **Not one of them reads either RT bit.** So `veda_odt_index` resolved any in-window region
number, configured or not, straight through `veda_odt_base_of` -- which also does not consult
`rt_valid`.

Regions 4..7 are reset to `region_odt_base = 0` on both layers, and **that is region 0's base**, so
the `local` half alone picked the slot.

#### Measured, by instruction trace, before the fix

```
populate {region 5, local 200}   ->  0 traps, ACCEPTED
bind     {region 0, local 200}   ->  tag 1, CGetBase = 0x80000100 = the prober's own arena
bind     {region 5, local 200}   ->  trap, cause 0x09 REGION_FAULT
```

**A live descriptor written under a name the machine then refused to let its own author read.** After
the fix the same probe returns tag 0 and Base 0, and the populate traps.

#### This corrects R56

R56 recorded the aliasing -- *"Four regions already alias region 0's entire descriptor namespace at
reset"* -- and named the barrier: *"the only thing between a foreign compartment and every unnarrowed
descriptor in region 0 is one bit -- `rt_resident[4] == false`. Setting that bit is exactly what an
RT-Populate does."*

**The Populate path reads neither RT bit, so that bit was never the barrier and no new instruction
was ever required.** R56's *conclusion* (do not build a naive RT-Populate) stands and is if anything
strengthened. Its *mechanism* was wrong, and a mechanism claim that names the wrong bit sends the
next reader to guard the wrong thing.

#### What it is, and what it is not -- stated plainly

**Not an authority escalation.** Every ODT writer is already bounded by the ODA window (R47), and an
actor that can write `{5, L}` can write `{0, L}` with the identical check, so it gains no memory it
did not already have. What it breaks is **namespace integrity**: one slot with several
legitimate-looking names, and the two halves of the architecture disagreeing about whether the region
field means anything. It also **falsifies R10's headline claim as stated** -- the region field was
unforgeable only at use, never at creation.

It is recorded and fixed rather than deferred because it is a landmine under everything queued next:
the `backing` field, any RT-write instruction, and R57's verdict (B), whose entire soundness rests on
region grants being real.

#### The fix, in two halves, and why the first one alone was wrong

**Half one, the choke point.** `veda_odt_index` -- which every ODT access of either direction passes
through -- now requires `rt_valid` for any non-current region. The intra-region fast path is
deliberately exempt: a crossing has already validated the current region (R10/R55), and re-reading
the RT for it would be circular by `veda_crbr_load`'s own argument.

**Half one alone was a bug, and it was measured as one.** `odt_write`'s `None()` arm is `()`, so a
gated write became a **silent no-op**: the instruction retired reporting success while nothing
happened. That is exactly R14's class (*"Populate and Destroy refused SILENTLY -- the RTL never told
anyone"*). The first R63 test failed for precisely this reason, and the trace showed the populate
retiring normally.

**Half two, the refusal.** All **seven** ODT writers -- Populate, Populate-Fast, Destroy, Set-COW,
Set-Domain, Page-Out, Page-In -- now ask `veda_region_nameable(object_id)` directly and raise
`Illegal_Instruction`. Illegal rather than a `REGION_FAULT` via `veda_trap`, for a concrete reason:
`veda_trap` packs a **capability** index into `mtval`, and these instructions' `rd` is a plain GPR,
so the cause would arrive with a meaningless register field. Every other refusal these seven raise is
already `Illegal_Instruction`, so this keeps one shape. On the RTL, five of the seven inherit the
term through `$veda_odt_valid`; **Destroy does not**, because it is deliberately ungated on validity
(an invalid slot's generation still needs protecting), so it carries the term itself.

Each of the seven Sail edits was anchored **on its own clause by name**, not by ordinal -- R58 is why.

#### What the corpus was doing, again

`vc_r55_bind_rt_valid_neg.S` **wrote the gap down and then depended on it**, one increment before it
was found:

> *"Populate does not consult the region table at all -- only `veda_odt_index`'s window bounds -- so
> all three of these succeed regardless of `rt_valid` or residency, and that is what makes the Bind
> results below attributable to the Bind gate alone."*

True, load-bearing, and a finding. The file is re-aimed: its region-3 seed is now expected to be
refused, and its four trap-count assertions are bumped -- each edit anchored on the `li t4, N` whose
**next line compares the trap counter**, because the same literal also appears before tag compares.

#### Residual, recorded rather than dropped

R55's finding was that a bind into region 3 **minted a live capability**, and that demonstration
needed a real entry in region 3's ODT space. **R63 has made that state unreachable by software.** The
test can still prove the bind is refused; it can no longer prove what it would otherwise have minted.
That is a fix working, not coverage lost -- the bind gate is now defence-in-depth against a state
only a corrupt or half-torn ODT could produce, which is exactly the state R10 seeded region 3 into
and exactly why it did. Restoring the severity demonstration needs a **reset fixture**, the technique
R59 had to use for `owner_hart` for the identical reason. Recorded as **UNMEASURED**.

**Also open, and now sharper:** R63 closes the minimal form of region-grant authority -- *you may not
name a region that does not exist*. The strong form -- *you may populate only into your own region
unless you hold an explicit grant* -- is **not built**, because the grant object does not exist and
the ambient loader legitimately populates into region 1 today. See R57, premise 4.

### R64. `backing` is DECIDED AGAINST -- and the prerequisite DESIGN_02 named is built instead

**Status: DECIDED AGAINST (the field), BUILT AND VERIFIED ON BOTH LAYERS (the prerequisite). The
decision came from a 19-agent adversarial design pass: four independent architects, each attacked
from three lenses -- confused-deputy, temporal-safety, and unobservable-mechanism.
Sail 114/114, RTL 103/103, ACT4 51/51, differential 25/25.**

#### The question

Phase 2's one unbuilt item was the ODT entry's `backing` field. DESIGN_02 says `mmap(file)` is *"an
object whose backing is the file"*, and the entry carries no such field, so `mmap(file)` has no
mechanism. The pass asked what `backing` should be: an opaque software handle, a capability, a
structured `(device, offset)` tuple -- or nothing at all.

#### The verdict: build no field

**Do not add `backing` to `odt_entry` on either layer.** Three positions were designed and attacked;
the fourth agent died on a schema retry cap and its design was never seen, which the synthesis
recorded as a stated gap rather than papering over. What killed the two field-bearing positions:

- **Opaque handle** -- killed by a **stale-base window inversion**, found independently by all three
  of its attackers. Its only scoping guard was `veda_oda_denies(old_entry.Base, old_entry.Length)`,
  and it is evaluable only when the entry is **non-resident** -- but page-out preserves `Base` as an
  explicitly dead value (`veda_ocl_insts.sail:1314`, whose own comment says *"stale, and
  unreachable"*), and freeing that frame is the entire point of eviction. So in every reachable case
  the authorization test compares the ODA against a physical range the object no longer occupies.
  **It authorizes whoever inherited the corpse.**
- **Capability-valued backing** -- killed three ways. Its `xchg.backing` returns exactly the value
  its own read gate exists to withhold; it transplants `VEDA_OSPECIALRW`'s read-then-write semantics
  onto an instruction gated `Machine | oda_authorized()` while the original is **Machine-only**
  (`veda_cap_insts.sail:978`), creating the machine's first ODT-to-CRF authority channel; and 257
  bits do not fit in the 16 free bits of a 32-byte entry.

And what killed the "no field" position's own *alternative* -- representing a lazy mapping as an
**absent** entry -- is the sharpest result of the pass: that is the one ODT state in which per-object
bind authority is **structurally disabled on both layers**. `empty_odt_entry` carries `owner_domain =
VEDA_DOMAIN_ANY`, `veda_bind_domain_ok` returns true on its first line for ANY, and the RTL's
`$veda_domain_violation` carries a `$veda_odt_valid` conjunct that makes the gate literally
unreachable on an invalid slot. Its *thesis* -- do not store a field nothing can read -- survived
every attack untouched.

**The decisive argument is `region_backing`.** The region table has carried a 56-bit `region_backing`
field for five increments. Nothing reads it. It is write-only storage, and it is precisely what an
object-level `backing` would become, because **there is no instruction that reads an ODT entry field
into a GPR at all** -- verified: all seven ODT instructions end `X(rd) = zeros()`.

#### What was built instead, and why it is the right increment

DESIGN_02 itself names the prerequisite and says where it belongs in the order of work:

> *"The handler cannot identify which object faulted. `mtval` carries {cap_idx, cause}, not an
> Object_ID ... That is a software workaround for a missing architectural channel, and **it should be
> resolved before `backing` is designed rather than after**."*

Verified still open. `CGetObjectID` closed it for the **copy-on-write** fault, where a live
capability exists to interrogate -- and the Sail source cites DESIGN_02's open item as its motivation.
It does **not** close it on the **bind** side: the residency trap passes `rd`, the destination
register of a Bind that never completed (`veda_bind_insts.sail:317`; the RTL agrees at
`veda_core.tlv:5339`). **No capability names the faulting object, so nothing can recover it.**

So this increment builds **`veda_mfaultobj`, read-only CSR `0x7C9`** -- verified unallocated on both
layers -- carrying the faulting Object_ID.

#### Fail-closed by construction, which is the design decision worth stating

The obvious implementation threads the Object_ID through `veda_trap`, which has **fifty-three call
sites**. A scripted mass-edit across near-identical sites is exactly what produced R58. So `veda_trap`
is left untouched and a **second entry point** `veda_trap_obj` carries the name; the single trap
chokepoint (`veda_pcc_save_and_reset`, where R10 and R12 both landed, and whose own comment says
*"per-site additions miss paths"*) writes `VEDA_OBJECT_NONE` whenever nothing was staged.

**An unconverted site can only ever cost information. There is no edit anywhere that makes this
register report the wrong object.** Five bind-side entry-derived traps are converted, each anchored
on its own line: REGION_FAULT, DOMAIN_VIOLATION, RESIDENCY_FAULT, OWNER_VIOLATION, OBJECT_NOT_FOUND.

Sail needs two registers (the name, plus a "was anything staged" flag) because its trap helper runs
before the chokepoint and cannot see the outcome. **The RTL sees both facts in the same cycle, so one
mux expresses the whole discipline** -- a difference between the layers that is real rather than a
divergence, and is written down as such.

#### Measured, on both layers

```
reset                          -> 0xFFFFFFFFFFF   sentinel
bind object 400 (never populated) -> 0x190 = 400  OBJECT_NOT_FOUND
ecall (no descriptor consulted)   -> 0xFFFFFFFFFFF   fail-closed
bind object 401 (paged out)       -> 0x191 = 401  RESIDENCY_FAULT, nothing minted
csrw 0x7C9 (illegal)              -> 0xFFFFFFFFFFF   fail-closed on a NON-Veda trap
```

**The reset is the sentinel and not zero, and the first version got that wrong.** Object 0 is a legal
name, so a zero reset makes *"nothing faulted"* and *"object 0 faulted"* the same reading -- R10's
argument for the CRBR's out-of-window sentinel, applied a second time. Its own CONTROL 1 caught it.

#### And a third ABI-alias collision, recorded because the pattern is now undeniable

The first draft of the Sail test wrote `li s11, <sentinel>` while using `x27` as the trap counter --
**`s11` IS `x27`** -- and `li t3, N` against `x28`. R62 was `t4` versus `x29`. Three collisions in one
session, each turning a check into a comparison of a value with itself. Both R64 tests now name
**every register by number**, and say why in their headers.

#### Residuals, stated

- **NOT CLOSED -- `mmap(file)` still has no mechanism.** DESIGN_02's *"an object whose backing is the
  file"* remains unimplementable as written. It needs a **second producer** of `{valid, not
  resident}`, and page-in's safety currently rests on an enumeration argument (*"page-out is the sole
  producer"*) rather than on the property behind it (*every producer must first kill every
  outstanding capability to that object*). That rewrite is owed whether or not `backing` is ever
  built.
- **NOT CLOSED -- content preservation across a paging cycle is a software obligation with no
  hardware precondition.** Page-out moves no bytes, frees nothing and scrubs nothing.
- **NOT CLOSED -- the no-scrub disclosure on the ordinary eviction path.** Page-out leaves the old
  frame fully populated at a known address; a pager that evicts A and then Populates B at that Base
  hands B's first binder every byte of A, and R45 established there is no disjointness check.
- **REOPENING CONDITION for `backing`, written into the decision so it is a decision and not a
  silence:** it may be reconsidered only when (a) an ODT-entry **read** primitive exists -- DESIGN_02
  calls this *"the pillar-sensitive half"*, and it would be the first channel from the table to the
  program that is not a capability -- **and** (b) a real pager exists to consume it, **and** (c) the
  writer is the **evictor**, so its authorization runs against a live `Base`. Storage and delivery
  must ship in **one** commit; a commit that adds the field without the reader produces
  `region_backing`, byte for byte.

#### A LEAD, deliberately NOT recorded as a finding

The adversarial pass surfaced this and refused to number it, correctly, under this register's own
rule that findings must be refuted before they are recorded:

> `veda.odt.set.cow` and `veda.odt.set.domain` both gate on
> `veda_oda_denies(old_entry.Base, old_entry.Length)` and **neither requires the entry to be
> resident, and neither carries an owner check** -- verified at source. Against a **paged-out**
> object, whoever legitimately inherits the reclaimed frame passes the window test on the previous
> occupant's dead descriptor, and can retarget its `owner_domain` to their own. After page-in the
> object binds to the thief.

I verified both premises at source: page-out does preserve `Base` as explicitly stale, and
`set.domain`'s gate list is privilege, `region_nameable | oda_denies`, `valid`, `domain_nameable` --
with **no residency and no ownership term**. I did **not** execute the sequence and did **not**
attempt to refute it. It is a **lead requiring its own pass**, not R65. Note also that its
end-to-end form needs a real allocator that reuses frames, which the shipped model does not have --
so the primitive is measurable but the exploitation is architectural.

### R65. An authority test against a Base the object has left -- the ODA's window in TIME

**Status: MEASURED END TO END ON THE SHIPPED MODEL, THEN FIXED AND COVERED ON BOTH LAYERS. It began
as a LEAD the R64 design pass surfaced and deliberately refused to number, under this register's own
rule that a finding must be refuted before it is recorded. It survived the refutation.
Sail 115/115, RTL 104/104, ACT4 51/51, differential 25/25.**

#### The gate, and the value it tests

`veda.odt.set.cow` and `veda.odt.set.domain` authorize a **delegated** actor with
`veda_oda_denies(old_entry.Base, old_entry.Length)`, and neither required the entry to be **resident**.
Page-out preserves `Base` as an explicitly dead value -- the model's own comment on that very line
reads *"stale, and unreachable"* -- because freeing the frame is the entire point of eviction.

So for a paged-out object the gate asks about **the frame the object has left**, and grants authority
over **the object it is**.

#### Measured, by instruction trace, on the shipped model

From User, holding an ODA covering **only** `victim_frame`:

```
[53] [U] set.domain on the PAGED-OUT victim  ->  retired.  ACCEPTED
[57] [U] set.domain on an out-of-window obj  ->  TRAPPED             <- control
[84] [M] page.in the victim at new_frame     ->  succeeded
[88] [M] cgetbase                            ->  0x80000240 = new_frame
```

The attacker's ODA covered `0x800001c0` and **never** covered `0x80000240`. `veda.bind` consults no
ODA at all, so the capability at the new frame is mintable. After the fix, the same binary:

```
[53] [U] set.domain  ->  [54] [M] trap_handler+0
```

#### Why the obvious refutations fail

- **"The actor gains nothing -- it could Destroy and Populate instead."** No. `Destroy` clears
  `valid`, and `page_in` refuses unless `old_entry.valid`. The victim's **restored contents** are
  reachable only through this path.
- **"This is R47's residual."** No. R47 gave the ODA a window in **space**. This is the same window in
  **time**: correct when written, meaningless the instant the object is evicted, and **nothing marks
  the transition**.
- **"The frame is not really reused on the shipped model."** True -- and it does not matter, because
  the escalation does not depend on frame reuse. It depends on `page_in` installing a **new** Base
  (`rs2`), which is shipped behaviour, so the object moves to memory the attacker never had authority
  over while the attacker's policy write persists.
- **"An ambient actor could bind it anyway."** Only from ambient, where `veda_bind_domain_ok` short-
  circuits on `veda_pcc_object == VEDA_OBJECT_NONE`. The attack matters exactly where that
  short-circuit does not apply.

#### The fix, and one deliberate asymmetry with R62

**While an object is not resident its `Base` describes nothing, so it may not authorize anything.**
`veda_stale_authority(e) = (cur_privilege != Machine) & e.valid & not(e.resident)`, added as the first
term of both policy writers' gates on both layers.

**Machine is EXEMPT, deliberately -- the opposite of the R62 decision, for a stated reason.** R62
gated a **well-formedness** question (*does this principal exist?*), which applies to every caller
including Machine. This gates the **validity of an authority test**, and Machine takes the
`cur_privilege == Machine` half of the OR and is never window-tested at all -- so gating it would
remove a real capability from the loader for no security gain. Two similar-looking checks, opposite
answers, and the difference is which question the gate is asking.

`page_in` is untouched: its first conjunct tests the same stale Base, but its **second** tests the
live destination, so a delegate can only pull an object into memory it already controls.

#### Coverage

`sail_tests/vc_r65_stale_base_authority_neg.S` and `rtl/sim/veda_smoke_r65_stale_base.S` + testbench.
Both carry the control that decides what the finding is -- **the same actor, the same instruction, an
object outside the window, still refused** -- so a fix that simply broke `set.domain` for delegates
cannot pass. The RTL half was shown to fail with the term stripped from a copy of the generated
Verilog (`x19 = 0`, the write accepted), and **the strip was asserted to have landed before the run
was believed**, per the R62 lesson.

#### Residuals

- **NOT CLOSED, and architectural rather than measurable:** `page_in`'s first conjunct still tests a
  stale Base. A delegate holding the dead frame *and* a frame of its own can page a victim in at its
  own address before a real pager does. On the shipped model this gains nothing -- page-in moves no
  bytes, so it reads its own memory -- so it is a **denial/confusion primitive against a pager that
  does not exist yet**. Recorded as **UNMEASURED**.
- **NOT CLOSED:** `set.cow` and `set.domain` still carry **no owner check at all**. The ODA window is
  the only authority test, so any delegate whose window covers a **resident** object's memory may
  rewrite that object's policy. That is arguably R47's design rather than a defect -- but it is
  written down here so the next reader decides it deliberately rather than inheriting it.

### R66. The retirement lands one Populate too late, and two incarnations share one generation

**Status: MEASURED END TO END ON THE SHIPPED MODEL, THEN FIXED AND COVERED ON BOTH LAYERS. Found by
a 32-agent stale-authority audit -- every authorization gate in the machine enumerated, then swept
for values that can be stale at the moment the gate reads them. Two survivors; this is the first.
A temporal-safety break, which is this architecture's central claim.
Sail 116/116, RTL 105/105, ACT4 51/51, differential 25/25.**

#### The one-instruction lag

`retired` is computed from the **old** generation:

```
new_generation = if old.valid then (if old.generation == 0xffffff then 0xffffff else old.generation + 1)
                 else old.generation
new_retired    = old.valid & (old.generation == 0xffffff)
```

and the only gate is `if old_entry.retired then Illegal_Instruction()`, which also reads the **old**
value. So from `{valid, 0xfffffe, retired false}`:

1. **Populate #1** -- a legal increment. Writes `{valid, 0xffffff, retired STILL FALSE}`.
2. **Bind** mints a capability carrying generation `0xffffff`.
3. **Populate #2 at a different Base** -- the gate reads `retired = false` and **passes**. The bump
   cannot run (saturating no-op), `retired` becomes true, **and the new incarnation is written in the
   same instruction**.

Two distinct incarnations now hold generation `0xffffff`, and the first one's capabilities are live.

**The dereference does not catch it.** Its only temporal arm is
`not(entry.valid) | entry.generation != cap.generation` -- `valid` is true and the generations match.
The address is formed from the capability's **cached** `Base`, so the access lands on the abandoned
frame. **`retired` is read by no dereference arm on either layer** -- its only consumers are the two
Populate gates, write-backs, and pure carry-overs.

#### Measured, by instruction trace, over the seeded `0xFFFFFE` fixture

```
[12] populate #1 at arena1              ->  accepted
[15] bind, [20] ocs.d 0xABCD            ->  written into arena1
[29] populate #2 at arena2              ->  ACCEPTED, no trap
[33] ocl.d through the OLD capability   ->  0xABCD, read out of arena1
```

`arena2` stayed zero. After the fix the same binary shows `[29] populate -> [30] trap_handler+0`.

#### The source already knew -- one instruction away

Page-out's own comment describes this exact state and accepts this exact argument:

> *"That state is genuinely reachable, not theoretical: a Destroy from 0xfffffe leaves generation
> 0xffffff with retired STILL false (its retired rule tests the OLD generation), and a following
> Populate is then permitted and leaves the slot valid, resident, saturated and un-retired. So
> `retired` does not intercept it."*

and names the consequence -- *"each would read and write the freed frame, now owned by another
object. That is a full use-after-free"* -- and then **fails closed**, with the principle stated
outright: *"if the invalidation mechanism cannot run, the operation that depends on it must not
proceed. FAIL CLOSED."*

**Populate depends on the bump to invalidate the previous incarnation, and had no such term.** The
defence was written for the instruction that **observes** the state and not for the one that
**creates** it. This is a new shape for the register: not a missing check, but a check placed on the
wrong instruction while its own justification was written down correctly.

`veda_types.sail` states the intent outright -- *"once generation WOULD WRAP, the slot is permanently
retired instead."* The implementation retired exactly one Populate later than that sentence.

#### The fix

Both Populate clauses, both layers, refuse when the bump cannot deliver a fresh generation:
`old_entry.retired | (old_entry.valid & old_entry.generation == 0xffffff)`. Populate #1 is still
allowed -- `0xfffffe -> 0xffffff` is a genuine increment -- so the refusal lands exactly where the
guarantee cannot be met and nowhere earlier.

**The Destroy route is covered by the same term.** `Destroy` from `0xfffffe` leaves
`{invalid, 0xffffff, retired false}`; the following Populate takes the `else old.generation` branch
and is permitted, because `old.valid` is false -- correctly, since a capability from before the
Destroy carries a generation `<= 0xfffffe` and already mismatches. The Populate **after** that one
finds `{valid, 0xffffff}` and is refused. Both entry paths converge on one term.

#### Why no existing test caught it

`vc_gen_retire_neg.S` drives **two Destroys** -- its own comment says so -- and the RTL twin
`veda_smoke_m16_neg` was re-aimed at the same route. **The Populate-over-a-valid-saturated-slot route
is measured by no test on either layer.** The saturation mechanism had coverage; the instruction that
can defeat it did not.

#### Coverage

`sail_tests/vc_r66_generation_collision_neg.S` and `rtl/sim/veda_smoke_r66_gen_collision.S` +
testbench, over the seeded `0xFFFFFE` fixtures (Sail object 55, RTL entry 106 -- the layers seed
different slots, as R59 also had to handle). Both carry three controls: Populate #1 must still be
**accepted**, the bind must mint, and after the refusal the old capability must **still work** --
so a fix that simply broke Populate near the ceiling cannot pass. The RTL half was shown to fail with
the term stripped from a copy of the generated Verilog, and the strip was **asserted to have landed**
before the run was believed.

#### Standing, stated plainly

Software alone cannot reach generation `0xfffffe` -- that is 16.7M populates -- so this needs the
reset fixture, the same standing R59's `owner_hart = 0x63` fixture has and for the same reason. The
window is exactly **one** re-mint: after the colliding Populate `retired` is true and the next is
refused. Calling it cross-principal needs the abandoned frame handed to another object, which is one
more ordinary Populate and no new mechanism -- the same standing R65 was accepted under.

#### The audit's second survivor, recorded as a LEAD and NOT numbered

The same pass surfaced a second candidate that survived two independent refuters, and it is recorded
here **unverified by me** so it is not lost and not overstated:

> `veda_trap_frame_abandon` asks *"is a frame outstanding"* -- a **count** -- and never *"does this
> sentry own that frame"* -- an **identity**. `veda_trap_depth` is incremented at exactly one site
> (trap entry) and decremented at two (`restore_on_xret` and `abandon`); OCInvoke touches it nowhere.
> So an OCRETURN that returns **into** a handler pops a counter nothing pushed, and the frame it
> consumes belongs to a third principal. At depth 0 the restore body is skipped entirely, so a
> following `mret` restores privilege while the bounds belonging to it are gone.

**Now closed as R67 below** -- verified at source, refuted unsuccessfully, measured, and fixed on
both layers. The lead was right.

### R67. The trap frame has an owner, not just a count -- and a callee could consume it

**Status: MEASURED END TO END ON THE SHIPPED MODEL, THEN FIXED AND COVERED ON BOTH LAYERS. This was
the stale-authority audit's SECOND survivor, recorded under R66 as an unnumbered lead that I had
explicitly not verified. I verified it, tried to refute it, and it held.
Sail 117/117, RTL 106/106, ACT4 51/51, differential 25/25.**

#### One push, two pops, and no identity

`veda_trap_frame_abandon` asks *"is a frame outstanding"* -- a **count** -- and never *"is this frame
mine to abandon"* -- an **identity**. Verified at source: `veda_trap_depth` is written at exactly
three places -- incremented once at trap entry, decremented at `restore_on_xret` and at `abandon` --
and **OCInvoke touches it zero times**. So an OCRETURN executed by a principal that never trapped
pops a frame it did not push.

#### Measured, by instruction trace

```
compartment C traps            ->  veda_trap_status 1,  mepcc_length 0x40   (C's window)
the handler OCInvokes into D   ->  veda_trap_status 1   (D never trapped)
D executes OCRETURN            ->  veda_trap_status 0,  mepcc_length 0xFFFFFFFFFF
```

**C's frame is gone.** Any later `mret` then finds depth 0, skips the entire restore body, and C is
never reinstated with its own bounds -- it resumes with whatever PCC and whatever `veda_pcc_object`
are current, which is the compartment-escape shape R26 established the name predicate to prevent.

After the fix the same binary reads `veda_trap_status 1` and `mepcc_length 0x40` at the landing.

**R12's poison does not catch it.** Poison arms on a nested **trap**, and no trap occurred inside the
handler. And the handler narrowing itself by OCInvoke is not an exotic case -- it is the case R12's
own comment names as real.

#### Refutations attempted, and why they fail

- **"The handler chose to call D, so this is a handler bug."** The frame is not the handler's to give
  away -- **it belongs to C**. A handler calling out must not be able to destroy a third principal's
  right to be resumed. That is a confused deputy, and hardware-first says hardware closes it.
- **"Is the outcome actually harmful?"** After the abandon nothing is restored, so C resumes with the
  bounds and the **name** the last crossing installed rather than its own. R26 established that the
  name is the trustworthy compartment predicate; this hands C a different one.

#### The fix sharpens R12 rather than contradicting it

R12 abandons the frame because OCRETURN *"installs PCC from its own operand, so any saved context is
superseded by definition."* **That is true of the handler's EXIT and false of an OCRETURN that merely
returns from a callee the handler invoked** -- there the handler is still running and the saved
context is still owed. `veda_invoke_since_trap` is exactly that distinction and nothing more: OCInvoke
increments it while a frame is outstanding, and OCRETURN decrements it **instead of** abandoning the
frame whenever it is non-zero.

**A counter, not an owner check, and the reason is the shipped switcher.** The switcher deliberately
OCRETURNs to a **different** principal than the one that trapped -- that is what a scheduler does --
so requiring the target to equal `veda_mepcc_object` would break the one path R12 was written for.
The counter distinguishes *leaving* from *unwinding* without ever asking who the target is. Saturating
at 0xFF, so a runaway cannot alias zero and turn the next OCRETURN back into an abandon. Reset to zero
whenever the trap level ends, on **both** pop paths, and at the architectural reset.

#### An RTL half-fix that would have been worse than none

Gating only the depth arm left the **four frame-release arms** (`mepcc_base`, `mepcc_length`,
`mepcc_object`, `trap_poison`) still keyed directly on `is_veda_ocreturn && depth == 1`. The RTL would
have kept the depth at 1 while releasing the frame anyway -- a state neither layer models and a
divergence that no existing test would have shown. All five sites now consult the counter, and the
vacuity check strips all five.

#### Coverage

`sail_tests/vc_r67_frame_owner_neg.S` and `rtl/sim/veda_smoke_r67_frame_owner.S` + testbench. Both
carry four controls before the finding -- the depth starts at zero, C really is narrow (`0x40`), the
trap really pushed a frame, and that frame really is C's window -- so a machine that simply stopped
tracking frames cannot pass. **The whole corpus passing is itself the load-bearing control**: the
switcher's legitimate OCRETURN exit must still abandon its frame, and the scheduler tests would fail
if it did not. The RTL half was shown to fail with the counter ungated at all five sites, and the
strip was asserted to have landed before the run was believed.

### R68. R65's rule reached two sites out of seven, and I shipped it that way

**Status: MEASURED, FIXED AND COVERED ON BOTH LAYERS. Found by a 33-agent sweep of two classes this
register names but had never swept systematically -- justifications that expired, and tests that pin
a weakness as the contract. This is my own incomplete fix, one increment old.
Sail 119/119, RTL 108/108, ACT4 51/51, differential 25/25.**

#### The gap

`veda_oda_denies(old_entry.Base, old_entry.Length)` is an **authority test at seven sites**. R65
established that for a non-resident object that test asks about the frame the object has **left**, and
installed `veda_stale_authority` at **two** of them -- `set.cow` and `set.domain`. Populate, Destroy,
Populate-Fast, page-out and page-in kept the unguarded form.

**This is R58's shape a second time**: a fix that landed in too few places while the suite stayed
green. R58 was three clauses and I hit the wrong two; here it was seven sites and I closed two.

#### Measured, by instruction trace, before the fix

From User, holding an ODA covering **only the frame the victim had left**:

```
[53] [U] veda.odt.populate on the PAGED-OUT victim   ->  ACCEPTED, retired normally
[56] [U] the same instruction, out-of-window object  ->  REFUSED            (control)
```

After the fix the same binary shows `[53] [U] populate -> [54] [M] trap_handler+0`.

**The harm is worse in kind than R65's.** R65 rewrites a victim's **policy**; this retargets the
victim's **identity** into attacker memory with attacker `Perms` -- and because `page.in` refuses a
resident entry, the victim's evicted contents can then **never be restored**.

#### Populate-Fast is not exempt, and the sentence that would have exempted it had expired

The natural objection is that Populate-Fast is the residency-**repair** path, which by definition runs
on a `{valid, not resident}` entry, so gating it trades a hole for a lockout. The sweep's own agent
raised exactly that, citing DESIGN_02's mechanism-1 sketch: *"the handler fetches contents from
`backing`, allocates physical Base (ODT-Populate-Fast), sets `resident`, and resumes."*

**That sentence is superseded by its own document.** DESIGN_02's cached-Base decision says outright:
*"Page-in therefore **cannot be plain ODT-Populate** ... A distinct, generation-preserving page-in
path is required, gated on `valid & not resident`."* The repair path is `veda.odt.page.in`. So
Populate-Fast carries the term with the other two.

**The objection was itself an instance of the class the sweep was hunting** -- a justification that
was true when written and false when relied on. It surfaced inside the pass that was looking for
exactly that, which is the best evidence the sweep was worth running.

#### Scope, and what is deliberately left

Three of the five unguarded sites are closed: **Populate, Populate-Fast, Destroy**. **`page.in` and
`page.out` are left**, because for them the question is genuinely open and is being decided in its
own pass: *what should authorize a write to a non-resident entry, given that the stale-Base window
test is meaningless there?* Candidates under adversarial review are `owner_domain`, the destination
window alone, a distinct pager capability, and Machine-only. Recorded as **NOT CLOSED**.

**Standing, stated plainly:** the delta requires the window over the freed frame to be acquired
**after** the eviction. While the victim was resident under that window the attacker already held
descriptor authority -- that is R47's design. This is the same standing R65 and R66 were accepted
under, and it is stated rather than inherited.

#### Coverage

`sail_tests/vc_r68_populate_stale_base_neg.S` and `rtl/sim/veda_smoke_r68_populate_stale.S` +
testbench, both carrying the control that decides what the finding is -- **the same actor, the same
instruction, an object whose old Base is outside the window, still refused** -- so a fix that simply
broke Populate for delegated actors cannot pass. Zero corpus damage: no existing test relied on
minting over a paged-out object.

### R69. Page-in is Machine-only -- an evictor test implemented by proxy through an address

**Status: DECIDED AND CLOSED ON BOTH LAYERS. Sail 120/120, RTL 109/109, ACT4 51/51, differential
25/25. Decided by a 21-agent adversarial pass on the question R68 left open, then verified at source
before landing. This closes the last two of the seven ODA authority sites.**

#### The rule, stated once and applied uniformly

> **A delegated actor may write an ODT entry only while the object still occupies memory that actor
> demonstrably holds. An object that is not resident occupies nothing, so no delegated actor may
> write its entry. Machine is exempt, because it is never window-tested.**

**At `page.in` the rule collapses to Machine-only, and that is a consequence rather than a special
case:** the clause's own gate already refuses `not(valid) | resident`, so **every** delegated
execution of page-in was a non-resident one. There was no delegated case left to authorize.

#### The defect is sharper than R65's framing, and that is what decides the fix

Page-out is the **sole producer** of `{valid, not resident}`, and its own gate refuses a non-resident
entry -- verified at source: `else if not(old_entry.valid) | not(old_entry.resident) then
Illegal_Instruction()`. So page-out's window test **always ran against a live `Base`**, and the
`Base` it then preserves is **the record of the eviction authority**.

Page-in's first ODA conjunct was therefore not merely *"a test against a dead value"* -- R65's
framing -- but an **evictor test implemented by proxy through an address**. Right in shape, unsound
in mechanism: **the proxy decays the instant the frame becomes reallocatable, which is the instant the
eviction completes.**

#### Why no substitute predicate can work

The legitimate delegated pager and the R68-standing attacker present **identical evidence**. The
pager evicted the victim, so it holds the freed frame and a destination frame in the same pool. The
attacker acquired a window over the freed frame *after* the eviction -- exactly R68's own standing
clause -- and holds a destination frame. Both satisfy *ODA covers old Base* **and** *ODA covers new
base*. The only differentiating fact is **who evicted**, and page-out records nothing about it: its
write changes exactly `generation` and `resident`.

They are not hard to tell apart. **They are indistinguishable given the state this machine keeps.**

#### "You may repair what you evicted" is the right rule and does not fit -- measured, not assumed

`ODT_ENTRY_BYTES` is 32 with offsets running 0..29, so **16 spare bits** -- not the 20 a domain needs,
nor the 44 an Object_ID needs. It would hold an 8-bit hart, and a hart is not a principal: page-in
preserves `owner_hart` *precisely* so a pager cannot claim ownership. And the entry cannot be widened
by changing a localparam: the 32-byte stride is baked into **107 hard-coded seed offsets across 11
entry bases**. So: fail closed.

#### The lockout costs nothing constructible, and that was verified rather than argued

A delegated pager **cannot learn which object faulted**:

- the residency trap **does** stage the name -- `veda_trap_obj` sets `veda_mfaultobj`, the R64 channel;
- but **CSR 0x7C9 is Machine-only by its address**: `csrPriv(csr) = csr[9 .. 8]`, and `0x7C9` gives
  `0b11`. Verified at source in `sys/sys_control.sail`;
- and `mtval` carries only `{cap_idx, cause}`.

**So delegated demand paging was never constructible on this machine -- and not because page-in
refused it.** This also kills the strongest rival rule outright: keying page-in on `object_id ==
veda_mfaultobj` would authorize a delegate by a value it cannot read, on a fault it cannot observe.

**Zero corpus damage confirmed that empirically** -- not one of 120 tests relied on a delegated
page-in.

#### The ODA constructs are deleted, not left standing

The refusal is an unconditional `cur_privilege != Machine` placed **first**, and the three ODA
constructs it makes unreachable are **removed**. Two reasons, both load-bearing:

- `veda_stale_authority` would have been the **wrong term** here: it requires `e.valid`, so pasting it
  verbatim would leave an invalid entry uncovered if the gate below were ever relaxed -- and Destroy
  preserves `Base` and `Length` on an invalidated slot, which is exactly that entry. An unconditional
  privilege refusal depends on nothing.
- Leaving terms that read as tests and cannot fail **is** the expired-justification defect this
  register keeps paying for.

#### Rejected on the way, recorded so it is not re-raised

**Writing the evictor's identity into the provably dead `Base` field.** It fits in 56 bits and needs
no new state. Rejected: a record field whose *type* depends on `resident` is the R41/R59 shape, better
hidden -- and it would break the RTL's seeded `{valid, not resident}` fixtures.

#### Coverage

`sail_tests/vc_r69_pagein_machine_only_neg.S` and `rtl/sim/veda_smoke_r69_pagein_machine_only.S` +
testbench. The delegated actor is given **an ODA covering both frames** -- the strongest window a
delegate could hold -- so the refusal cannot be attributed to a narrow window. And the
**anti-lockout control is the load-bearing one**: Machine's page-in must still succeed and the object
must come back usable at the new frame. A rule that stranded data would be a bug, not a fix, and this
test would catch it.

### R70. DESIGN_01 decision 7 was recorded, cited six times, and never built

**Status: MEASURED, FIXED AND VERIFIED. Sail 120/120, RTL 109/109, ACT4 51/51, differential 25/25.
The second finding from the expired-justifications sweep, verified at source by me before acting.
A fail-open CONFIGURATION gate, not a capability escape -- the severity is stated rather than
inflated.**

#### The decision, and the gap

DESIGN_01 decision 7 says outright:

> *"**Gate `Ext_Veda` on `xlen == 64`** (reverses the earlier xlen-generic decisions; drops NMC_ADD.W
> on RV32) ... This is a **prerequisite that lands before any width edit**."*

**The width edit landed. The gate did not.** And **six comments** across the extension cite that
decision as settled fact -- three of them adding *"but that gate is invisible to the type checker
here"*, which is the tell: the author knew it was not structural and assumed it existed elsewhere.

#### Measured before the fix

- `currentlyEnabled(Ext_Veda) = hartSupports(Ext_Veda)` -- **no xlen term.**
- Of **28** `mapping clause encdec = VEDA_*` clauses, **12 carry `xlen == 64` and 16 do not.**
- `postlude/validate_config.sail` contains **zero** occurrences of "Veda".
- `sail_riscv_sim --rv32 --validate-config` reported **"The default configuration is valid."**

So an RV32 build ran an **incoherent half-extension nobody specified**: the capability-query,
derivation and sealing family, the three domain crossings, Destroy, OCLEAR and `veda.bind` decoded,
while OCL/OCS, the ODT write path, the paging pair and the atomics did not.

**It is not a capability escape.** Every bounds and permission check lives on the dereference path,
and that is exactly the half that did not decode.

#### The fix, at three levels, and why all three

1. **Structural** -- `currentlyEnabled(Ext_Veda) = hartSupports(Ext_Veda) & (xlen == 64)`. **One line
   closes all twenty-eight**, because every clause guards on it -- verified by counting before
   landing. The twelve that also carry `xlen == 64` become redundant rather than wrong and are left
   alone: they document the same fact at the site that needs it.
2. **Declarative** -- the generated config now says `"supported": false` at xlen 32, so the
   configuration states the truth instead of claiming support the model then has to refuse.
3. **Loud** -- a `validate_config` arm mirroring the existing Zcf one, so a **hand-written** config
   that claims Veda on RV32 is refused with a message rather than silently producing a Veda-less
   core. That is R14's rule -- refusals must be visible -- applied one layer up.

Level 1 alone would have been fail-safe but silent. Level 2 alone could be overridden by hand.
Level 3 alone would not stop anything.

#### Measured after the fix

```
generated rv32 config          ->  Veda.supported = false
generated rv64 config          ->  Veda.supported = true      (unchanged)
hand-written rv32 claiming Veda ->  "The configuration is invalid.
                                    The Veda extension is enabled: Ext_Veda is RV64-only."
CGetObjectID executed on rv32   ->  illegal 0xe00055b
```

That last line is the finding closing: before the fix that encoding decoded and wrote `rd`.

#### No RTL mirror, and that is verified rather than assumed

`veda_core.tlv` contains **three** occurrences of `rv32`/`xlen`, and all three are **comments** --
there is no xlen parameter and no 32-bit datapath. The RTL is RV64 by construction, so there is
genuinely nothing to mirror.

#### The class this belongs to

A justification that was **true when written and false when relied on** -- the class the sweep that
found it was hunting, and the same shape as R36, where a custom instruction was justified by *"this
core has no trap to return from"* and Milestone 9 built the traps twenty-seven milestones before
anyone re-read the sentence. Here the sentence was a **decision** rather than an observation, which
makes it worse: repairing only the six comments would have left the reachable half-extension in
place, and that is the test that separates a finding from documentation rot.

### R71. The crossing now clears the capability register file -- and the ABI that got there is not the ABI that was decided

**Status: MEASURED, FIXED AND VERIFIED ON BOTH LAYERS. Sail 121/121, RTL 110/110, ACT4 51/51,
differential 25/25. This closes R50's possession channel, which had been open since R50 was first
recorded, and it closes the last of the three channels a compartment crossing leaves behind
(R48 mint, R50i1 tooling, R50i2 possession).**

#### What was still open

R50 measured it and named it precisely: OCInvoke's only capability write is the IDC, OCReturn writes
none, and the dereference checker has **zero** domain terms. So a callee needs no authority at all --
it uses a register the caller left bound. R48 closed the **mint** channel; increment 1 (OCLEAR) built
the **tool** and, in doing so, recorded that until then *nothing in the machine could clear a
capability register.* Increment 2 decided the ABI and deliberately reverted rather than half-land it.

#### The decided ABI was refuted -- by the RTL, on a fact Sail cannot express

Increment 2 chose a **RETAIN mask sourced from a GPR named by a reserved-zero instruction field**,
and verified the fields were available. That verification was correct. What it could not see is that
**OCInvoke's two operand fields both name CAPABILITY registers.** In Sail that costs nothing: `X(r)`
is a function call. In the RTL it is a **third integer read port on the whole register file**, paid
by every instruction, to carry a mask consumed by two.

The attempt was made and abandoned on that measurement, not on taste. **A field being architecturally
available does not make it economically readable**, and only the implementation layer knows which.

> This is the second time this project has had a Sail-side design refuted by an RTL cost that the
> Sail layer is structurally incapable of showing. It is an argument for the two-layer discipline
> itself, not an argument against Sail-first.

#### The ABI that landed: CSR 0x8CA `veda_xretain`

- **Retain, not clear.** Bit `i` set means capability register `i` **survives** the next crossing.
  Never written means zero means retain **nothing** -- so **silence means clear, and silence can
  never leak.** That was increment 2's central safety argument and it survives the ABI change intact.
- **Read-write**, so a compartment can read back what it is about to spend.
- **SELF-CONSUMING.** The crossing zeroes it. A mask cannot survive to apply to a later crossing.
- **Cleared on trap entry**, and reset to zeros architecturally. A trap is not a crossing; leaving a
  mask armed across one would let a handler's resumption spend authority the interrupted code
  intended for somewhere else.
- **Both placement rules from increment 2 are preserved unchanged**: OCInvoke clears **before** the
  IDC install, so `c15` survives by construction and needs no mask bit; OCReturn **does not exempt**
  `c15`, because it installs no IDC and a surviving one hands the callee's own data capability back
  to the caller. The RTL twin asserts that second rule directly (`cgettag c15` must read 0 after the
  return leg).

A CSR rather than an instruction field also means the mask is **not** part of the crossing encoding,
so the reserved-zero pins R30(b) placed on OCInvoke and OCReturn stay pinned.

#### What self-consuming actually costs, measured rather than asserted

It costs a **PCC window**. `vc_r58_domain_writers.S` broke, and the reason is the mechanism working
as designed: a compartment that wants to pass capabilities onward must set the CSR **itself, from
inside its own PCC window**, because the caller's mask was already spent getting it there. Its
compartment window had to widen from `0x40` to `0x80` to hold two more instructions.

> **AND THAT SENTENCE NAMED AN INSTRUCTION THE COMPARTMENT COULD NOT EXECUTE.** At `0x7CA` the mask
> was Machine-only by its address, so the software this paragraph addresses would have trapped on it.
> Found the same day, measured, and closed as **R74** -- the register now lives at `0x8CA`, in the
> only Custom read/write **User** range the RISC-V Privileged specification allocates. The paragraph
> above is true as written only from R74 onward.

That is the honest price. **Delegation is no longer free and no longer silent** -- it costs two
instructions and it costs them *inside the compartment that is delegating*, which is exactly where
the decision belongs.

#### How much of the corpus was living off the leak

| | files carrying a crossing | needed a retain mask | needed none |
|---|---|---|---|
| Sail | 44 | 15 (37 declarations) | 29 |
| RTL | 30 | 29 (50 declarations) | 1 |

The Sail row is the encouraging one: **29 of 44 files crossed a compartment boundary and never
depended on anything surviving it.** Most were already using only the IDC the crossing installs.
The RTL row is the opposite because its tests are integration-shaped and carry state across.

**Every one of those 87 declarations is RETAIN ALL, and that makes all 87 vacuous with respect to
this mechanism** -- delete the clear and every one still passes. That is stated here rather than
discovered later, and it is why the discrimination is carried by exactly one dedicated file per
layer (`vc_r50i2_crossing_clear.S`, `veda_smoke_r50i2_crossing_clear.S`), each running **two rounds**:

- **Round 1** retains only the sentry. The callee's dereference of the caller's `c10` must trap.
- **Round 2** retains the sentry **and** `c10`. The same dereference must now return `0xC0FFEE`.

Round 2 is not decoration. **Without it, a core that simply wiped the whole file at every crossing --
ignoring the mask entirely -- would pass round 1 for entirely the wrong reason.** That is the shape
this project has now caught **twelve** times.

#### The RTL vacuity proof, with the strip asserted before it was believed

`assign L1_xclear_wr_en_a0` was replaced with `1'b0` in a copy of the generated Verilog. **The
mutation was asserted to have landed before the run** -- 228 bytes removed, replacement text
confirmed present -- because this project has already been fooled once by a strip that silently
matched nothing and then "passed".

On the mutant, with the clear disabled:

```
round 1 trap count            x20 = 0        (must be 1)
round 1 value read            x22 = 0xC0FFEE (must be 0)  <-- the caller's secret
callee IDC survived return    x25 = 1        (must be 0)
round 2 value read            x24 = 0xC0FFEE (passes -- correctly, it is the over-refusal guard)
```

**That middle line is R50's possession channel executing on real hardware**: a compartment holding
nothing but its own code and data capabilities read the caller's private object, with **zero traps**,
and carried the callee's own IDC back across the return. On the fixed core the same instruction
traps with `mtval = 0x142` -- `cap_idx = 10`, cause `0x02` TAG -- so the refusal **names the register
it refused**, which is the difference between a refusal and a crash.

#### A test-harness lesson worth more than the finding

Inserting the two mask instructions into `veda_smoke_m10_neg.S` broke it, and the reason was not the
mechanism. That file's handler compares `mepc` **exactly** against a label, and the insertion landed
**between the label and the trapping instruction** -- so the label stopped naming the thing it was
pinning. Every displaced label in the corpus was then found by script and each was **classified, not
mass-edited**: two were genuine breaks (re-pinned onto the crossing), and four were jump or resume
targets where having the mask write *inside* the label is not merely harmless but **required**, since
a self-consuming mask must be re-armed on every entry.

> **An inserted instruction can move a label off the instruction it was pinning.** A sweep that
> "adds two lines before every crossing" is not a mechanical edit in a corpus where addresses are
> assertions.

#### Residual, carried forward unchanged from increment 2

Clearing the registers closes **possession**. It still does **not** give the dereference checker a
domain question -- `veda_pcc_object` and `veda_current_region` remain **zero** occurrences in the
access-check file. A capability a callee legitimately receives in the retain mask is still usable by
anyone who later obtains that register by any means. **Possession and authority remain the same thing
on the dereference path**, and that is now the largest single open item on the crossing.

### R72. The machine refuses an object by NAME and hands over the same object through MEMORY

**Status: MEASURED ON BOTH LAYERS BY THE LEAD, INDEPENDENTLY CONFIRMED BY A SEPARATE CHANNEL CENSUS.
OPEN -- the mechanism is being designed and this entry exists so the register has no gap and the
measurement is not carried in a task list. Sail 123/123 and RTL 112/112 are green WITH THE HOLE
PRESENT, which is the point: no suite in the corpus asks this question.**

#### The experiment, and why it is built the way it is

R71 closed the register channel at the crossing. This asks whether that closed the leak or moved it.

The decisive move is the **control**: object 200 is locked to domain 0 with `veda.odt.set.domain`, so
compartment B -- executing from a **region 1** code object -- may not bind it by name at all. Without
that lock the finding would be vacuous, because `owner_domain` defaults to `VEDA_DOMAIN_ANY` and B
could simply re-Bind the name (R52). **The hole only exists in the configuration where the policy was
actually applied, so the experiment applies it.**

```
veda.odt.set.domain 200 -> 0        # the caller narrows its own object
veda.bind  c1, 200 ; ocs.d c1 <- 0xC0FFEE
veda.bind  c2, 201 ; ocs.c  mem=c2, src=c1     # PUBLISH the capability
csrw 0x8CA, 0x2000 ; ocinvoke                  # retain ONLY the sentry: R71 clears c1 and c2
--- inside compartment B, region 1 ---
veda.bind.notrap c5, 200  ->  REFUSED   mtval 0xAB = cap_idx 5, cause 0x0B DOMAIN
veda.bind  c6, 201        ->  allowed   (201 is open)
ocl.c c7, c6              ->  allowed
cgettag c7                ->  1        A TAGGED, VALID CAPABILITY
ocl.d  c7                 ->  0xC0FFEE THE SECRET
```

**One trap in the entire run, and it is the control's refusal. The attack itself takes zero.**
The RTL reproduces every value identically.

#### What it actually says

**`veda.bind` and `ocl.c` are both capability-ACQUISITION instructions, and only one of them asks
the ODT's ownership question.** The hardware refused B the object by NAME with a named cause, then
handed B the same object through MEMORY without asking anything. The policy the machine accepts at
`set.domain` is not the policy the machine enforces.

Confirmed structurally by a separate census: `VEDA_OCS_C` is the **only** instruction in the model
that writes a tagged capability to memory, `VEDA_OCL_C` the **only** one that reads one back, and
both are authorised solely by `veda_check_access`, **whose eleven arms contain zero domain terms**.

#### The strongest argument against it, conceded where it is right

*Both parties already held capabilities to the shared object, so what leaks is authority to a THIRD
object -- and that is what a capability system is for.*

**It narrows the finding and does not defeat it.** Where it is right: at the default
`VEDA_DOMAIN_ANY` the memory channel adds nothing, because B reads the name with `CGetObjectID` and
Binds it. **Where it fails:** the moment software uses the policy field the architecture provides,
the machine enforces it on the mint path and not on the transfer path. A policy that a single
`ocs.c` erases is not defence in depth; it is a suggestion. And the leak does not require a
malicious A -- A publishing a capability intended for a trusted peer C leaks it to every domain that
can read the same object.

#### Adjacent channels the census turned up, recorded so they are not lost

- **The trap frame and `mret`.** `veda_crossing_clear` has exactly two call sites, OCInvoke and
  OCReturn. **Neither trap entry nor `xret` touches the capability register file**, so every
  capability survives a trap in both directions. R50 increment 1 already named the trap path "a
  fourth compartment entry no crossing rule can reach"; R71 did not reach it either.
- **Sentries through the memory channel.** `CSealEntry` requires no authorising capability and no
  privilege, so a sentry placed in a shared object is a call gate for whoever can read it.
- **The TSC** crosses both crossings intact in tag and value, deliberately -- Machine-only today.
- **The dereference path consults none of the three region predicates**, though `veda.bind` uses
  `veda_region_is_resident` and both crossings use `veda_region_rt_resident`.

#### What is NOT yet decided

Whether the governor is CHERI's Global / StoreLocalCapability pair (the two bits **R42** records as
allocated and enforced by neither layer), an ODT containment rule that uses the table CHERI does not
have, a domain stamp in the capability's own `flags`, or none of them. The hardware cost is the
gate: the container's ODT entry is already looked up by `veda_check_access`, but the **referent's**
is not, and a second ODT lookup in the same instruction is exactly the class of cost that refuted
R50 increment 2's ABI. **That cost is being priced before the mechanism is chosen, not after.**

### R73. A domain refusal trapped for all three bind modes, and nothing anywhere said why

**Status: MEASURED ON BOTH LAYERS BEFORE CHANGING ANYTHING, FIXED AND VERIFIED. Sail 122/122,
RTL 111/111, ACT4 51/51, differential 25/25. NOT a capability escape and NOT a cross-layer
divergence -- a contract defect, and the severity is stated rather than inflated. Found while
refuting a suspicion raised by a trace taken for an unrelated finding.**

#### What was measured, before any edit

A `veda.bind.notrap` issued from a region-1 compartment against an object narrowed to domain 0
**trapped**, with `mtval = 0xAB` -- `cap_idx = 5`, cause `0x0B` DOMAIN_VIOLATION -- and left the
destination register untouched. The RTL agreed **exactly**. So both layers implement the same rule,
and the defect is that the rule is not the one written down.

#### The rule that is written down, in three places, and contradicted in the code

`rtl/MILESTONE_12_RESULTS.md` states it outright for ownership refusals:

> *"**Bind-NoTrap and Rebind both always soft-fail** (Tag cleared, no trap) -- Rebind joins 'sealed
> rd' and 'ODT miss' as a third soft-fail reason, **never a fourth hard-trap reason**, matching its
> own established 'never traps for any reason' rule from Milestone 8."*

`veda_bind_insts.sail` still says it verbatim above the Rebind arm -- *"Rebind never traps for ANY
failure reason, **owner mismatch included**"* -- and the `owner_hart` arm forty lines below **still
implements it**, with its own comment: *"Bind-NoTrap still soft-fails here too, matching its own
established convention for every other failure reason."*

The `owner_domain` gate added later by R13/R52 was the one exception, and it was silent.

#### How it got there -- a policy inherited without its argument

The gate was written **beside the residency gate**, and adopted residency's all-modes trap policy.
Residency and region **trap for every mode deliberately**, and both say so at length. The Sail:

> *"If Bind-NoTrap or Rebind merely cleared Tag here, the caller would be told 'no such object' and
> the pager would never be invoked -- a live object would look permanently destroyed."*

The RTL enumerates the exceptions one at a time -- *"a region fault is the **FIRST** condition under
which it must hard-trap"*, then *"RTL-6: the object residency fault is the **SECOND** condition ever
to make Rebind hard-trap, and it needs its own exclusion for the same reason"*. **The domain
violation arrived as a silent third in the same exclusion list.**

**That argument does not transfer.** Region and residency traps exist so the holder goes and
**services** something -- "your object is paged out, retry". **There is nothing to service on a
domain refusal.** The object is not yours and will not become yours by running a pager.

#### Why this is worse than tidiness: R43 was justified by a sentence the code made false

R43 chose a soft-fail for its new Rebind refusal and said so explicitly: *"SOFT-FAIL, NOT A TRAP,
deliberately: the comment directly above records that Rebind never traps for ANY failure reason, so
a refusal that trapped would change the instruction's contract far beyond this finding."*

**That sentence was false at source when R43 relied on it.** A decision was justified by a property
the machine did not have. This is the R70 class -- a justification true when written and false when
relied on -- with the difference that here the falsity was **already present** at the moment of
reliance, not introduced later.

#### The decision, and the argument that nearly went the other way

**DECIDED: honour the mode.** Plain Bind traps `0x0B`; Bind-NoTrap and Rebind soft-fail.

The strongest case for keeping the trap is that `owner_hart` is a **transient contention** condition
("another hart holds it") while `owner_domain` is a **permanent policy** ("not yours, ever"), and a
permanent refusal deserves to be loud so a bug is caught early. It does not survive: **choosing mode
`0b01` IS the software's declaration that it wants the quiet answer.** An instruction whose entire
purpose is to ask without faulting cannot have a failure reason that faults -- and code that is not
deliberately probing uses plain Bind, which still traps loudly, so the early-bug case is unharmed.

R14's rule that refusals must be visible is satisfied: **the cleared tag is the visible refusal**,
and it is the mechanism Bind-NoTrap was given for exactly this purpose. Security does not decide it
in either direction -- a soft-fail grants nothing, so both forms are fail-closed.

#### The hazard the fix itself creates, closed in the same edit

`$veda_owner_claim_en` carries `!$veda_domain_violation`, added by **R59** because a Bind refused for
a domain must not take ownership of what it was just refused. R73 narrows `$veda_domain_violation`
to plain Bind -- **so that guard stops covering Bind-NoTrap** -- and `$veda_bind_claim_en` never
consulted the domain gate itself. Left alone, a NoTrap soft-failing on a domain refusal would have
silently written `MHARTID` into the owner byte of an object it was just refused: **R59's bug,
reopened by R59's own successor.** `$veda_bind_domain_ok` was therefore added to
`$veda_bind_claim_en` in the same edit.

Found by reading the consumer before landing. **No suite would have caught it**: the owner byte is
invisible to every assertion in the corpus and `MHARTID` is 0 on this core -- the same two facts
that let the original R59 bug live.

#### Two soft-fail shapes, and a test that can tell them apart

They are genuinely different and a tag-only check cannot distinguish them. Measured, both layers:

```
Rebind      : Base before 0x80011100 -> Tag 0, Base after 0x80011100   (fields PRESERVED)
Bind-NoTrap : Base before 0x80011100 -> Tag 0, Base after 0x0          (register ZEROED)
plain Bind  : traps once, mtval 0x6B = cap_idx 3, cause 0x0B
```

`vc_r73_bind_mode_refusal.S` and its RTL twin assert all three rows. **The plain-Bind row is the
anti-vacuity control**: without it, a core that simply DELETED the domain gate would satisfy both
soft-fail rows.

#### The corpus damage, and why re-aiming it made two tests stronger

Two Sail tests failed, both of which encode the old behaviour: `vc_r52_creation_domain.S` and
`vc_r58_domain_writers.S`.

**R52's entry in this register contains ZERO occurrences of "notrap", "soft-fail" or "Rebind" in
6702 characters.** The trapping behaviour was recorded there as a **measurement** -- *"refused,
DOMAIN_VIOLATION, exactly one trap"* -- and never argued as a decision. The test then froze the
measurement into a contract.

And **R52's tag assertion could not fail.** The bind trapped, a trap leaves `rd` untouched, and `c1`
was never bound to anything -- so `cgettag c1` read the architectural reset value and asserted 0
against a register that was already 0 for reasons having nothing to do with the gate. Only the trap
count was load-bearing. Re-aimed, the file now loads a **real tagged capability first**, so a cleared
tag is evidence the soft-fail genuinely wrote. It also gained the loud row it never had.

**R58 had already written the reasoning down for the wrong row.** Its row (2) comment says: *"PLAIN
Bind, not .notrap, and the distinction is the whole discriminator. Under .notrap a not-found object
SOFT-FAILS with no trap, so the cause -- the only thing that says which way owner_domain went --
never exists."* Row (1) then used `.notrap` and asserted a trap. **One author, one file, two
understandings.** Row (1) is now the loud form, which is what its own verdict block always needed:
it asserts the CAUSE, and a cause requires a trap.

#### A search bug worth more than the finding

The scan that concluded *"no test uses NoTrap or Rebind AND narrows a domain"* was wrong, and the
pattern was the reason: it matched `x[0-9]*` and the failing tests write the operand as **`a1`**.
**The ABI-alias hazard this project has already been bitten by three times in code extends to
searches.** A grep that names registers numerically will silently miss every file that names them by
ABI alias, and it fails as a **clean negative result** -- the most convincing kind of wrong answer.

### R74. R71's retain mask was Machine-only, so the only software that needs it could not write it

**Status: MEASURED, FIXED AND VERIFIED ON BOTH LAYERS. Sail 123/123, RTL 112/112, ACT4 51/51,
differential 25/25. A defect in work landed the same day, found by refuting my own increment rather
than by a suite. Fail-closed throughout -- the mask stayed zero and the crossing cleared everything,
so nothing leaked. What was lost was the mechanism's usefulness, not its safety.**

#### The defect

Privilege on this machine is derived from the **CSR address**: `csrPriv(csr) = csr[9..8]`
(`sys/sys_control.sail:19`), and the RTL computes the identical thing
(`$csr_priv_violation = $is_csr_access && ($csr_priv_bits < $csr_addr[9:8])`). `0x7CA[9..8]` is
`0b11`. **The retain mask was Machine-only on both layers.**

R71's own write-up says: *"a compartment that wants to pass capabilities onward must set the CSR
**itself**, from inside its own PCC window."* **Compartments are unprivileged by definition.** The
instruction that sentence prescribes would trap.

#### Measured, not deduced

`veda_smoke_r48_oda_crossing.S` writes the mask **after** its architected drop to User. Its own trap
counter read **2**, not 1 -- the mask write trapped, the mask stayed zero, the crossing cleared
everything, and **the RTL suite passed 110/110 with nobody noticing**. The thirteenth green on this
project that measured nothing. After the fix the same counter reads **1**.

A scan of both corpora found this was the **only** such site: 96 of the 97 mask writes are at
Machine. So the blast radius was one dead instruction -- and an architecture that could not do the
thing it was designed for.

#### Why it is worse than a dead write, and why it connects to R72

With the register channel shut to unprivileged code and the memory channel (R72, open) asking no
questions, **R71 pushed every User-mode delegation onto the one path with no governance.** A defect
that makes the safe route unusable is a defect that routes traffic to the unsafe one.

#### The fix, decided from the official specification rather than from convention

The RISC-V Instruction Set Manual Volume II (Privileged Architecture), chapter *Control and Status
Registers*, table *Allocation of RISC-V CSR address ranges*, was read in full. `csr[11:10]` encodes
read/write versus read-only; `csr[9:8]` encodes the lowest privilege that may access the register.

**`0x800`-`0x8FF` is the only Custom, read/write, User-level range in the entire table**, and unlike
the Supervisor, Hypervisor and Machine custom ranges -- which are only the `11XX` quarter of their
block -- its `csr[7:4]` field is unconstrained, so all 256 addresses are available. The
specification also states that *"the CSR addresses designated for custom uses will not be redefined
by future standard extensions"*, which is the collision guarantee this needs.

**Chosen: `0x8CA`**, keeping the low byte of `0x7CA` so logs, traces and prose stay readable across
the move. `csrPriv(0x8CA) = 0b00` (User) and `csrAccess(0x8CA) = 0b10` (not read-only), so
**no privilege-check logic changed on either layer -- only the address constant**, at 115 sites
across 57 files, verified by counting residual occurrences of the old address to zero.

**`0xCC0`-`0xCFF` was rejected**: it is Custom **read-only**, and a write to a read-only CSR must
raise an illegal instruction -- which is the one thing a retain mask may not do.

#### The invariant this makes load-bearing, and it is a test rather than a comment

Making a security register unprivileged deserves the obvious objection, and it was put in its
strongest form: *letting the untrusted side write the boundary's policy inverts the trust
relationship -- a compromised compartment writes `0xFFFF` and the crossing scrubs nothing.*

**It fails as an argument about authority.** The mask is consumed as **retain-only**: a set bit
suppresses a clear of a register the writer **already holds**. `0xFFFF` yields exactly the
pre-crossing set -- the identity function, which is the state the machine was in before R71 existed.
It cannot mint, widen or import anything, and a never-written mask is zero, so User-writability can
only move the machine **from maximal scrubbing toward less scrubbing, never past it into new
authority**. The attacker's best move is a hygiene regression, not an escalation. The alternative is
incoherent: an M-only mask means the mechanism can never be exercised by the only software that has
a reason to.

**It survives, narrowed, as an obligation**: *retain must never become grant.* If any future path
ever reads a set bit as "materialize this register" rather than "do not clear it", User-writability
becomes escalation **on the spot**. So it is asserted, not asserted-in-prose:
`vc_r74_umode_retain_mask.S` and its RTL twin retain `c9` **while it holds nothing**, and require
that after the crossing it is still untagged AND that dereferencing it traps `0x02` TAG. Measured on
both layers, and the RTL's `mtval = 0x122` names `cap_idx = 9` -- the refusal identifies the very
register the mask retained.

#### What the fix proves that could not be proved before

```
csrrw x0, veda_xretain, x31   at [U]   -> no trap          (it used to trap)
ocl.d x21, c10                at [U]   -> 0xC0FFEE         (delegation from User, impossible before)
cgettag x22, c9               at [U]   -> 0                (retained, still empty)
ocl.d x25, c9                 at [U]   -> trap 0x02 TAG    (retained, still unusable)
```

The compartment also re-arms the mask **itself, from inside its own window**, before returning --
the exact behaviour R71's text described and the machine could not perform.

#### A new obligation, recorded now rather than discovered later

The Smstateen extension's `mstateen0` register defines **bit 0 = C**, which *"controls access to any
and all custom state"*. **That obligation did not exist while the mask was Machine-only and it exists
from this increment onward**: if Veda-Core ever implements Smstateen, U-mode access to
`veda_xretain` must be gated by the C bit. Nothing to build today -- the model implements no
`stateen` -- but it is now a precondition on that work rather than a surprise inside it.

### R75. The return path is an entry path, and it has no admission control -- domain identity is forgeable from a name

**Status: MEASURED ON BOTH LAYERS, IDENTICAL VALUES. OPEN, AND IT BLOCKS R72. Every claim below was
re-read at source by me before it was written down; the lead came from an adversarial security lens
that constructed the chain, and constructing a chain is not measuring one. This is the largest open
finding in the register.**

#### What it says

`veda_pcc_object` is the machine's **domain identity**. Every domain question asked anywhere is asked
of it: the R52 bind gate (`veda_regs.sail:1165-1168`), the creating domain a Populate records
(`veda_ocl_insts.sail:715-717`), R62's nameable check, R73's mode-dependent refusal.

**That register can be installed by a principal that was never given the identity, in three
instructions, whose only input is a NAME.**

#### CORRECTION, SAME DAY, BY MEASUREMENT -- THE ASYMMETRY BELOW IS FALSE

**The paragraph that followed is kept because it is what I believed and acted on, and because the
correction is worth more than the claim.** I wrote that `OCInvoke` demands evidence of delegation and
`OCReturn` does not, and I proposed making the return path symmetric with the call path. **I then
tested my own hypothesis instead of building on it, and it failed.**

`poc_r75b_forged_sealed_pair.S`: the same compartment B, refused the same object, binds the **type
authority object by name** -- because it too is created ambiently with `owner_domain = ANY` -- mints
its **own** matching sealed pair from A's code object and an INVOKE-only data object, and executes

```
veda.bind c7, TYPEAUTH ; veda.bind c8, CODE_A ; veda.bind c9, DATA
cseal c10, c8, c7      ; cseal c11, c9, c7    ; ocinvoke c10, c11
```

**It succeeds.** `cgettag` on the previously-refused object reads **1**, the secret reads
**0xC0FFEE**, and the run takes **one trap in total** -- the final `ecall` that reaches the verdict.

**So BOTH crossings are forgeable, and a sealed pair is evidence of nothing while the seal authority
is itself bindable by name.** Every "make OCReturn symmetric with OCInvoke" proposal -- including the
one this entry originally advanced -- is therefore worthless: it would make the return path as strong
as a call path that is already broken.

**WHAT THIS DOES TO THE DIAGNOSIS.** R75 is not an instruction-level defect in OCReturn. It is
**R52's remaining half arriving at the identity**: R52 recorded that *a name is still full authority*
and narrowed the creation default only for objects created **inside** a compartment. Every object
made in the ambient boot context -- every code object, every data object, and **every type
authority** -- stays open, and the machine's domain identity is assembled out of them. The fix
therefore belongs where authority is **granted**, not where it is **spent**, and any mechanism that
adds a test to a crossing while the ingredients stay open is decoration.

The original paragraph, kept verbatim:

#### The asymmetry, which I believed and which is FALSE in the default configuration

`OCInvoke` demands a **sealed pair** -- `cs1` code and `cs2` data with matching `otype`. A matching
pair can only be minted with a capability carrying `PERM_SEAL`, so the pair is **evidence that the
owning domain minted and handed over an entry**. That is real admission control.

`OCReturn` demands only a **sentry**. And `CSealEntry`'s complete authorisation, read at
`veda_cap_insts.sail:413`, is:

```
let ok : bool = CTag(cs1idx) & not(isSealedCap(cs1));
```

**No operand, no permission, no privilege.** Any holder of any tagged unsealed capability mints a
sentry from it.

OCReturn's guard chain (`veda_cap_insts.sail:887-905`) asks tag, sealed, `otype == SENTRY`,
`PERM_EXECUTE`, region rt-resident, and then `veda_code_object_check` -- **whose entire body
(`:535-545`) is `valid`, `generation`, `resident`**. There is no domain term and no owner term.
Then `:924` executes `veda_pcc_object = cs1.Object_ID;`.

**So the instruction that RETURNS from a compartment is an unauthenticated ENTRY into one.**

#### Measured, with a control, on both layers

The probe locks an object to domain 0 and enters a region-1 compartment carrying nothing.

```
BEFORE  veda.bind.notrap c5, 300   ->  cgettag 0    REFUSED     (0 traps -- R73's quiet form)
FORGE   veda.bind c9, 301              (A's code object, owner_domain ANY -- the default)
        csealentry c9, c9              (authorised by the tag alone)
        ocreturn c9                    (installs A's Object_ID as the identity)
AFTER   veda.bind.notrap c6, 300   ->  cgettag 1    SUCCEEDED
        ocl.d x23, c6             ->  0xC0FFEE     the secret
                                       ZERO TRAPS along the entire chain
```

**The same instruction, on the same object, refused before and permitted after.** The RTL reproduces
every value. The control is load-bearing: without the refusal first, a machine on which everything
binds would satisfy the attack rows for entirely the wrong reason.

#### Why the default configuration is the vulnerable one

The forge needs a capability to **A's code object**, and it gets one because
`owner_domain = VEDA_DOMAIN_ANY` is the value every object is created with, and
`veda_bind_perms(e) = e.Perms`, so the binder receives `PERM_EXECUTE` verbatim. **Every code fixture
in this corpus is created that way.** R52 narrowed the *creation* default for objects made inside a
compartment; objects made in the ambient boot context -- which is where every code object is made --
stay open, deliberately, because R17's retraction proved that closing them breaks the return path.

#### This blocks R72, and that is the reason it is recorded before R72's mechanism is chosen

R72's design pass produced four candidate mechanisms. **Three of them are defeated by this chain
without touching the memory channel at all**, because each asks "which domain am I" and this makes
that question forgeable:

- a `flags`-borne mint-domain stamp is stamped from the forged register, so it validates;
- an ODT containment rule never runs, because the attacker stores nothing;
- and the argument that `owner_domain` is a sound mint-time gate is simply false.

**A mechanism keyed on domain identity cannot be chosen until the identity is sound.** Building one
first would be the R43 shape again -- a design justified by a property the machine does not have.

#### Directions, none chosen, and the constraint each must satisfy

The binding constraint is **R17's retraction**: a compartment's caller is by construction in another
domain, so OCReturn may not simply demand a matching domain -- that made compartments one-way and
livelocked a test.

1. **Authenticate the sentry.** `VEDA_OTYPE_SENTRY` is a single fixed value, so every sentry is
   interchangeable and provenance is unrepresentable. Giving sentries a minting authority would
   mirror `CSeal`'s -- but CHERI's `CSealEntry` is deliberately unprivileged, and the reason that is
   safe there is that a CHERI sentry does **not** change compartment identity. **The asymmetry is in
   OCReturn, not in CSealEntry**, and a fix that taxes CSealEntry is taxing the wrong instruction.
2. **Return to where you came from.** The machine already saves caller state -- `veda_saved_region`,
   the CRBR shadow R60 releases, and R67's trap-frame ownership. A return that must match the saved
   caller is precise, uses state that already exists, and is R17-safe by construction, because the
   saved value IS the other domain.
3. **Separate the two duties of `veda_pcc_object`.** It is simultaneously "which code am I running"
   (a bounds and provenance fact) and "which domain may I name" (an authority fact). OCReturn has a
   legitimate need for the first and no business granting the second.

**ALL THREE DIRECTIONS ARE DOWNGRADED BY THE CORRECTION ABOVE.** They each add a test to a crossing,
and the correction shows the crossing is not where the authority is acquired. They are kept as
material for the mechanism pass, not as the shortlist they were when written.

**What the correction promotes instead**: the creation default. `owner_domain = VEDA_DOMAIN_ANY` is
what makes the code object, the data object AND the seal authority all acquirable by name, and it is
the single value every one of the four attack steps depends on. The counter-argument is R17's
retraction and R52's own ambient arm -- the boot context's objects are left open **deliberately**, so
that return paths, type authorities and shared services stay bindable from anywhere, and closing them
made compartments one-way. **That tension is the real open question, and it is not resolved here.**

A second framing the correction makes available: the machine has **no principal that is trusted to
enter other domains**. The shipped switcher needs exactly the powers the attacker used -- it binds
thread code objects by name at `runtime/veda_sched_asm.S:296` and `:307` and mints its own sentries
at `:331` -- so the two cannot be told apart by instruction, only by authority the machine does not
currently represent.

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

**R10 (added after RTL-4) attaches to Phase 1's tail**: it must be Sail-respec'd before any
domain-entry CRBR load lands in either model, and its multi-hart half joins the Phase 6 checklist.

**R12 (added alongside R11) blocks the purecap process model in DESIGN_05**: a compartment boundary
that dissolves on a nested trap is not a boundary. It attaches to Phase 2's tail beside R11.

**R11 (added after RTL-6) attaches to Phase 2's tail** and blocks calling DESIGN_02's paging work
safe: half (a) is built in Sail and owes an RTL mirror, half (b) is the next increment, and its
multi-hart half joins the Phase 6 checklist beside R10's.
