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

**Status: FIX 1 APPLIED (security). FIX 2 SPECIFIED, NOT APPLIED (correctness). Unreachable in the shipped build.**

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

The same mux also silently swallows ordinary taken branches, JAL/JALR, OCInvoke/OCReturn and mret -- a separate
functional-correctness bug at the same place.

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

**FIX 2, specified but deliberately NOT applied.** Latch a redirect that coincides with the start of a stall and
replay it when busy clears, ahead of the pc+4 fallthrough. This is what fixes the swallowed branches, jumps and
mret. It is **not** applied in the same increment because it restructures the `$pc` mux -- the most safety-critical
expression in the core -- and unlike FIX 1 it is not monotone. It goes in on its own, with its own test.

**Reachability, stated plainly and NOT counted as a defence.** `DRAM_EXTRA_CYCLES = 0` (:188) plus the
`!= 0` guard make `$veda_dram_busy` a structural constant 0, so neither bug is reachable in the shipped build.
But the nonzero default is named in the file itself as planned follow-up work, and E was swept {0, 10, 50} during
verification. **Widening the 46 test budgets to enable nonzero E is now blocked on FIX 2 and its test**, and that
follow-up must not be treated as mechanical.

**Why the existing suite could not catch it.** M24 verified the stall with a **positive latency test only** -- a
faulting access during a stall was never exercised. Identical in shape to the CAndPerm defect: *tested as
bookkeeping, never as enforcement.* The most important mutant for the new test is therefore not a code mutation at
all but `DRAM_EXTRA_CYCLES = 0`, which must make the test **error or skip, never silently pass** -- otherwise the
whole bug class hides behind E=0 forever, which is exactly how it survived M24.

**Layer note.** This is RTL-only and has no Sail counterpart: Sail has no TCM, no stall, and no timing domain at
all (`mcycle` ticks once per instruction step). That is itself a hazard worth naming -- **this class of bug cannot
be caught by Sail-versus-RTL parity review, because the layer that would catch it does not model the mechanism.**

### R22. The corpus contradicts itself on the address-less pillar

**Status: OPEN. Pre-existing, independent of Milestone 24, surfaced by R20's refutation.**

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

**Status: OPEN. Not a bug in anything built -- a consequence of what was just completed, noticed
before it hardened into a convention.**

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
