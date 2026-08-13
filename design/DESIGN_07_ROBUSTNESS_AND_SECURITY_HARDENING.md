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
