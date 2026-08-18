# Documentation staleness sweep -- 2026-08-18

**Preserved here because the standing rule on this project is that no work may be lost, and this
list lived only in a scratchpad.** It is the raw output of a six-way parallel sweep over every
document in all three repositories, hunting claims falsified by the R36..R43 hardening work.

**71 distinct stale claims in 46 files.** Categories used by the sweep: **(A)** a current claim now
false -- 28; **(B)** an instruction that would mislead a reader -- 22; **(C)** a gap recorded as open
that is now closed -- 21; **(D)** correct as history, leave alone -- 14 sites.

**TIER 1 IS ALREADY FIXED** (commits `bbd8183`, `72d8674`, `d78019d`, `30523a2`): `veda_core.tlv`'s
eight stale comments, `run_security_trap.sh`'s frozen root, `veda-core/README.md`,
`difftest/README.md`, `VEDA_CORE_SPEC.md`, `rtl/MILESTONE_PLAN.md`, the `MILESTONE_4/11_RESULTS`
forward-pointers, `PCC_COMPARTMENT_DESIGN.md`, `EVIDENCE_INDEX.md`, `NEXT_STEPS_ROADMAP.md`,
`ROADMAP.md` and `verification.sh`. Everything below tier 1 is still open -- see the task list.

**METHOD THAT MUST BE KEPT WHEN WORKING THIS LIST.** Re-verify every claim at its line before
editing: several hits are correctly-quoted history and must NOT be rewritten. A
`MILESTONE_*_RESULTS.md` records what was true at that milestone and gets a forward-pointer, never
an edit. Living documents that make CURRENT claims are corrected in place, with the correction
stating what changed and why rather than silently deleting.

---

{
  "summary": "Find every document claim falsified by this session, excluding the files being edited concurrently",
  "agentCount": 7,
  "logs": [],
  "result": {
    "collated": "# CONSOLIDATED STALENESS FIX LIST -- grouped by file, ranked by reader harm\n\nSix sweeps merged; duplicates collapsed; conflicts adjudicated in section X at the end. Categories: **(A)** current claim now false, **(B)** instruction that would mislead, **(C)** gap recorded open but closed, **(D)** correct history, leave alone. Every quote is verbatim from the file. The eleven already-being-edited files are excluded throughout.\n\n**Totals:** 71 distinct fixes in 46 files (A: 28, B: 22, C: 21), plus 14 files/sites judged correct-as-history. Three cross-sweep conflicts, all resolved below.\n\n---\n\n## TIER 1 -- a reader acting on this today gets a wrong machine, a wrong build, or a wrong measurement\n\n### 1. `/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv` -- the live shipping source, 8 fixes\nThe single worst file in the corpus, because it is not a record of anything: it is the code, and four of these comments are contradicted by lines within one screen of themselves.\n\n**(A) Must fix**\n- `:11` -- \"violations suppress writes rather than trap, since this core has no privileged/trap infrastructure at all yet\"\n  File header. The file now carries mtvec/mepc/mcause/mtval/mscratch/mstatus, a real trap redirect, `$priv`, and trapping Populate/Destroy violations. Fix: date the parenthetical to Milestone 1 and name Milestone 9 (traps) and R36/R39 (privilege).\n- `:1372` -- \"This core has no privilege-level stack to restore (it's always effectively M-mode, matching $priv's own existing one-way-drop model) -- MRET here means exactly \"PC = mepc\", not a full mstatus.MPP/MPIE restore.\"\n  **Highest-value single fix in the whole sweep.** All three claims false; `$mret_ok` at :1384 and `$priv` at :1097 do exactly the restore this denies, and the R36 block at :1377-1383 immediately below already says so. This comment is also the cited authority for two doc hits (item 12 and item 13 below) -- **fix this one first and those two become mechanical.**\n  Fix: \"MRET's PC redirect and every other effect hang off `$mret_ok` below, not off `$is_mret` -- R36 made this a real trap return: privilege = mstatus.MPP, and an MRET below Machine is an illegal instruction.\"\n- `:1396` -- \"EBREAK remains deferred -- not added here.\"\n  Contradicted 23 lines later by the R33d block defining `$is_ebreak = ($instr == 32'h00100073)` at :1419.\n- `:18` -- \"Milestone 23, ECALL; EBREAK still excl./deferred) plus the 12\"\n  Same defect in the header instruction inventory. Fix: \"ECALL and, as of R33d, EBREAK\".\n- `:2574` -- \"veda_smoke_m4_neg.S and veda_smoke_m11_neg.S both depend on exactly that -- they droppriv, populate, and keep executing.\"\n  Both tests were migrated to `VEDA_DROP_TO_USER` (m4_neg:26, m11_neg:23). Neither contains a droppriv.\n- `:5630` -- \"Measured before editing: NO test in the corpus writes 0x7C4 after veda.droppriv, so the privilege half costs nothing.\"\n  Stale twice: the instruction is gone, and the statement is now inverted -- `veda_smoke_r35_attr_priv.S:44-49` drops to User and then deliberately writes 0x7C4 as the negative test for this exact gate. A reader trusting this concludes the gate is untested.\n\n**(B) Must fix -- names a retired instruction in a live gate's threat model**\n- `:5605` -- \"But a principal after veda.droppriv -- holding neither privilege nor a tagged ODA -- could CHOOSE THE LENGTH AND PERMS OF AN OBJECT A LATER PRIVILEGED POPULATE-FAST WILL MINT.\"\n  Reasoning still correct; the principal should be described as \"running below Machine\". Every Custom-3 encoding now raises Illegal_Instruction, so the named encoding does not decode.\n- `:5654` -- \"post-droppriv, unbounded-PCC principal could clear purecap here\"\n  Same defect in the R26 Lever B comment. The gate itself (`$priv` on the 0x7C5 write, :5658) is current and correct.\n\n**(D) Leave alone**\n- `:1946` -- \"`veda.droppriv` lives in Custom-3 -- explicitly \"Reserved, unallocated\"...\" Present tense, but superseded in place by the R36 block at :1952-1960; a reader cannot see the old text without the correction. Optional: prefix with \"Milestone 4 wrote:\" so the two paragraphs read as a dated pair.\n\n---\n\n### 2. `/home/prabhu/veda-core-sindhu/veda-core/run_security_trap.sh` -- measures the wrong core\n\n**(B) Must fix**\n- `:19` -- `ROOT=/home/prabhu/makerchip/rva23-core`\n  Not merely a borrowed toolchain. Lines 74-75 then `strip_viz \"$ROOT/veda-core/rtl/veda_core.tlv\"`, so the RTL actually transpiled, compiled and demonstrated is the **frozen** tree's copy -- missing every RTL-mirror increment through R41/R38(b). The header at :6-7 names the paths in a way a reader reads as this repo, and :15 says \"run this yourself to reproduce it\". Fix: `ROOT=\"$(cd \"$(dirname \"$0\")/../..\" && pwd)\"` and `TC=\"$ROOT/toolchain/riscv-collab-gcc/riscv/bin\"` -- the layout matches, only line 19 needs to change.\n\n---\n\n### 3. `/home/prabhu/veda-core/README.md` -- design-repo front door, every current number wrong\n\n**(A) Must fix**\n- `:12` -- \"**Sail (formal model)** -- `Veda-Core-sail-riscv` fork, branch `phase1-respec`: **76/76**\" -> 102/102, and widen the parenthetical to include Phase 2 (residency/paging/COW).\n- `:15` -- \"**RTL (hardware)** -- `veda-core-sindhu`, branch `sindhu`: **64/64** smoke tests through\" -> 90/90, and \"through increment RTL-5\" -> through the Phase-2 mirrors.\n- `:62` -- \"findings R1-R10 + a proposed 6th pillar\" -> R1..R43 (no gaps).\n- `:60` -- \"| 05 | ... | OCL.C/OCS.C, tag memory, ODA, droppriv |\"\n  Column heading is **\"Builds on (verified)\"**, so this asserts droppriv is currently verified. Replace with \"mstatus.MPP/mret\".\n- `:70` -- \"**-- DONE, both layers (Sail 72/72, RTL 62/62).**\" The DONE verdict stays; the numbers read as current totals. Reword to \"(Sail 72/72 and RTL 62/62 at the time; suites now 102/102 and 90/90)\".\n\n**(C) Must fix**\n- `:73` -- \"3. **ODT as unified mm** (02) -- residency/COW/backing, Sail-first. **-- next (Phase 2).**\"\n  Residency, page-out/page-in and COW are all built and mirrored on both layers. Mark DONE; if `backing` is still partial, say so explicitly rather than leaving the whole item as \"next\".\n\n---\n\n### 4. `/home/prabhu/veda-core-sindhu/veda-core/difftest/README.md` -- the weakest document in the sweep\n\n**(A) Must fix**\n- `:28` -- \"It asserts nothing. **Divergence is the finding, not failure.**\"\n  `rundiff.sh:7-12` now says the opposite: \"EXIT CODE IS THE VERDICT... 0 = agree, 1 = diverge, 2 = infrastructure failure.\" Worse, this README never mentions `run_difftests.sh` at all, so **the 20/20 cross-layer figure has no documented entry point** and the file holding the expected verdicts is invisible.\n\n**(B) Must fix**\n- `:39` -- \"**The two layers seed DIFFERENT capability registers at reset.** Sail seeds c10-c14; the RTL seeds a different set with different contents. ... treat any divergence involving c10-c14 as suspect until the fixtures are reconciled.\"\n  This is the README's one stated hard constraint for probe authors, and R24 closed it on both layers: `veda_reset_crf()` (veda_regs.sail:772-790) zeroes all sixteen registers and clears crTags; both layers gate their fixtures off the architectural reset (Sail config key, RTL `+veda_fixtures`), both OFF by default, and the harness passes neither. `run_difftests.sh:35` records \"p_reset_crf.S AGREE R24 CLOSED\". The section now tells probe authors to discount exactly the class of divergence that would today be a real defect.\n- `:32` -- \"    iverilog -g2012 -I ../rtl/sim -o sim_diff.vvp ../rtl/sim/veda_core.sv tb_diff.sv\"\n  `rundiff.sh:56` rebuilds `sim_diff.vvp` on every run and `:40-48` hard-refuses with FATAL if `veda_core.sv` is missing or older than `veda_core.tlv`. Hand-building is work the harness undoes, and a reader may take it as a substitute for re-running the smoke runner -- the exact staleness the guard exists to prevent.\n\n**(C) Must fix**\n- `:46` -- \"Reconciling those fixtures is worth doing on its own: two layers that do not agree on their reset state cannot be compared on any test that touches it.\"\n  Done by R24. Replace with a pointer to R24 and `p_reset_crf.S`.\n\n---\n\n### 5. The capability-table permission set -- one wrong value in two docs and one source file\n\nThis is a real build instruction that now traps, not a wording drift. `0x000C` = bits 2,3 only. R40 made PERM_LOAD_CAPABILITY (bit 4) and PERM_STORE_CAPABILITY (bit 5) enforced at OCL.C/OCS.C on both layers, and this object exists solely to hold capabilities -- so the documented bootstrap raises 0x15 on the first store and 0x14 on every read. The RTL already made this exact correction for its own scratch fixture (`veda_core.tlv:320-325`: 16'h103C not 16'h100C); the toolchain's CAP_TABLE_REGION never got it.\n\n**(B) Must fix**\n- `TOOLCHAIN_MILESTONE_13_DESIGN.md:201` -- \"bound over the whole in-memory table (read-write, `Perms = 0x000C`, its own dedicated small `Object_ID`\" -> `0x003C`, with a clause stating bits 4/5 are required, not optional. (The per-global capabilities *stored* in the table, lines 108-118, are unaffected -- the checked permission is the table capability's.)\n- `TOOLCHAIN_MILESTONE_15_RESULTS.md:37` -- \"into the descriptor's Length field and OR'd with the unchanged `Perms=0x000C` (Load|Store).\" The word \"unchanged\" makes a reader take it as current. Append the R40 correction beside the sentence rather than silently rewriting the recorded edit.\n- **Code follow-up, not a doc fix:** `compiler/veda_struct_array_global_entry.S:63` still ORs `0x000C`. Doc and code agree with each other and both now disagree with the architecture. Worth its own task.\n\n---\n\n## TIER 2 -- live design documents resting on premises that are now false\n\n### 6. `/home/prabhu/veda-core-sindhu/veda-core/MINIMAL_OS_KERNEL_DESIGN.md`\nThree sweeps hit this; it is a live design doc, not a record.\n\n**(A)**\n- `:3` -- Status header quotes \"44/44 self-check regression\" and stops at Milestones A/B. Sail is 102/102 and Milestone C (scheduler + full GPR context save) is done on both layers.\n- `:67` -- \"that Veda-Core's existing M-mode-only design can and should use `PERMIT_ACCESS_SYSTEM_REGISTERS` ... as the actual privilege boundary\"\n  Load-bearing premise of Finding 3, which drives the Section 3 privilege decision at :126. The CHERI quote it leans on is explicitly conditioned on \"a ring-free design ... without ... kernel/supervisor/user modes\", which no longer describes this machine. Fix: date the premise and add one sentence noting the ring-free precondition no longer holds unmodified.\n\n**(C)**\n- `:12` -- \"RTL mirrors for both Milestone A and Milestone B remain explicit, separate, not-yet-started\" -- all three mirrors exist (`rtl/MILESTONE_A_RESULTS.md`, `_B_`, `_C_`).\n- `:236` -- \"(holding TSC-authorizing capabilities, making dispatch decisions) is the next, not-yet-started\" -- built by Milestone C on both layers. Keep preemption / >2 threads / allocator named as still open.\n- `:238` -- \"**S/U-mode privilege transitions** — unchanged from this project's own already-documented limitation (`MILESTONE_11_RESULTS.md`)\" -- **closed twice over**: the Sail config has S/U `\"supported\": true`, and privilege drops via mstatus.MPP + mret on both layers. Keep the design point (the model is ring-independent by design), drop the \"unchanged limitation\" framing and the M11 pointer.\n\n### 7. `/home/prabhu/veda-core/design/DESIGN_05_PURECAP_PRIVILEGE_PROCESS.md` **(A, both)**\n- `:5` -- \"OSpecialRW, droppriv, the MOS switcher.\" -- a \"Builds on:\" header naming a retired mechanism as verified.\n- `:35` -- \"(1-bit $priv + one-way droppriv + ODA authority). Extend to a real OS:\" -- Part B's ring-free premise. Fix to \"(standard mstatus.MPP/mret privilege + ODA authority)\" **and re-read the rest of Part B**, which reasons from the premise.\n\n### 8. `/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_13_CRF_EXHAUSTION_DECISION.md` **(B)**\n- `:66-67` -- \"need M-mode or a carve-out, untested anywhere in the corpus, possibly unverifiable given the / S/U-mode-disabled Sail config.\"\n  A decision record written to be reopened, pricing the rejected \"4th SCR (GDC)\" option partly on a dead premise. Strike the clause and add a dated correction: S/U are `\"supported\": true` (since 2026-08-10), so a U-mode carve-out **is** verifiable; the untested-M-mode-requirement cost stands on its own.\n\n### 9. `/home/prabhu/veda-core/design/DESIGN_01_CAPABILITY_FORMAT_RESPEC.md`\n**(A)** `:39` -- \"| Perms | 16 | CHERI-aligned set + Permit_NMC_Compute + Permit_Attenuate + spare |\"\n`PERM_ATTENUATE` exists in neither layer and was explicitly refused (PHASE1_SAIL_RESPEC_256BIT_RESULTS.md:78-80 -- CAndPerm is monotonic). The rest of this table shipped, so the row reads as the built permission budget, and the doc's own \"Resolved implementation decisions\" (:191) overrides three other lines but not this one.\n**(B)** `:184` -- \"- Re-run: Sail self-check (65/65 today), 51/51 ACT4\" -> 102/102 today (ACT4 51/51 is still right), or drop the number and point at the runner.\n\n### 10. `/home/prabhu/veda-core/design/DESIGN_06_BUILD_ORDER_AND_OPEN_QUESTIONS.md`\n**(B)** `:8` -- \"Sail types -> RTL -> re-pass 63/51/49.\" A reader following build-order step 1 re-passes the wrong triple. Current: 102 Sail / 51 ACT4 / 90 RTL.\n\n### 11. `/home/prabhu/veda-core/design/DESIGN_08_OBJECT_NAMESPACE_SCALE.md`\n**(C)** `:213` -- \"## 10. The Sail experiment that validates this (next step, before RTL)\" -- built and passed (PHASE1_SAIL_DESIGN08_REGION_EXPERIMENT_RESULTS.md), and the RTL mirror landed (rtl/RTL_MIRROR_04). Retitle \"...that validated this -- DONE\" with pointers; keep the experiment design as the record of what was run.\n\n---\n\n## TIER 3 -- the pre-R36 privilege trio (fix in this order)\n\n### 12. `rtl/MILESTONE_9_RESULTS.md` **(A)**\n- `:71` -- \"this core has no privilege-level stack to restore (it's always effectively M-mode, matching `$priv`'s own existing one-way-drop model since Milestone 4), so `MRET` here means exactly \"PC = mepc\", not a full `mstatus.MPP`/`MPIE` restore.\"\n  Phrased as a standing architectural property, not as \"at Milestone 9 we did X\". Make it past-tense and append the R36/R39 pointer. This is the text `veda_core.tlv:1372` and `rtl/MILESTONE_19:25` both point readers at.\n\n### 13. `rtl/MILESTONE_19_RESULTS.md` **(A)**\n- `:25-27` -- \"no privilege check needed beyond what already exists (this core has no S/U-mode / concept yet; every CSR write in this file is implicitly M-mode-only / for the identical, already-stated reason MRET's own comment gives).\"\n  Two false present-tense claims plus a forward-pointer to the stale MRET comment. R39 added the generic `csrPriv = csr[9..8]` check, enforced on **reads as well as writes**. A reader adding a CSR on this rationale today ships an unchecked one.\n  **(C)** `:85` -- \"RTL mirrors for Milestones 20 (compartment-state CSR self-escape\" -- both mirrors exist.\n\n### 14. `rtl/MILESTONE_23_RESULTS.md`\n**(A)** `:30` -- \"`0x0B` (11) is the real, standard RISC-V mcause ... and the only possible value since this core only ever runs M-mode.\"\nThe trailing clause is a standing claim, now false twice: the core runs below Machine, and `veda_core.tlv:5228` is now `>>1$is_ecall ? (>>1$priv ? 64'h0B : 64'h08) : 64'h18`. **This is the only ECALL-prong hit in the entire corpus** -- every other mcause==11 reference (MILESTONE_21, MILESTONE_C's switcher guard) describes an M-mode ecall and is still correct.\n**(C)** `:108` -- \"EBREAK, general illegal-instruction trapping, and misaligned-access detection remain explicitly\" -- EBREAK closed by R33d, illegal-instruction by R33b; only misaligned-access is still open.\n**(C)** `:110` -- names the RTL mirror of Milestone C as the next not-yet-started piece; built (rtl/MILESTONE_C_RESULTS.md, rtl/MILESTONE_25_RESULTS.md).\n\n---\n\n## TIER 4 -- outward-facing documents and the live Sail model\n\n### 15. `/home/prabhu/veda-core-sindhu/veda-core/TECHNICAL_BRIEF.md` (researcher-facing, undated)\n**(A)** `:38` \"50/50 RV64I base + Custom-0/1/2/3 Veda-Core extension\" -> Custom-0/1/2 (Custom-3 deliberately unallocated). `:67` \"30/30 self-checking positive/negative tests pass.\" -> 102/102. `:70` \"27/27 milestone regression tests pass.\" -> 90/90. Add ACT4 51/51 and cross-layer 20/20.\n**(A/C -- see conflict X2)** `:85` -- \"- No compiler or toolchain ecosystem exists — every test program is / hand-assembled.\"\nFalse today: LLVM/clang fork with 36 Veda-Core instructions and a capability register class, `VedaShadowPropagation` pass, C runtime (`runtime/veda_rt.{h,c}`, `crt0.S`), GDB stub, twenty TOOLCHAIN_MILESTONE docs, and an end-to-end \"write your own C program\" guide. Replace with the real remaining scope limits (capability memcpy/struct copy, unions, VLAs, general C/C++ library and ABI interop), not an absence.\n\n### 16. `/home/prabhu/veda-core-sindhu/veda-core/VEDA_CORE_TECHREPORT.md`\n**(A)** `:73` \"30/30\" -> 102/102; `:75` \"27/27 milestone regression tests pass.\" -> 90/90 and update \"Eighteen sequential milestones\" (the RTL line reached Milestone 25 plus the RTL_MIRROR increments).\n**(C)** `:176` \"- **No compiler or software toolchain.** Every test program in this report is hand-assembled.\" -- same closure as above.\n**(C)** `:180` \"- **The 16-bit `Length` field caps a single object at 65,536 bytes**\" -- the DESIGN_01 respec closed this: 256-bit capability with Base(56)/Length(40)/Object_ID(44)/generation(24). §1's \"128-bit hardware capability\" and §7's \"8-bit generation counter\" are stale for the same reason.\n**(D)** `:37` -- \"Custom-3 deliberately left unallocated\" -- **now correct again.** It was arguably wrong while droppriv occupied the opcode; R36 made it true. No action; recorded so the Custom-3 prong is closed.\n\n### 17. `/home/prabhu/veda-core-sail-riscv/model/postlude/step_ext.sail` **(A)**\n- `:229` -- \"// alike -- the only real privilege-delegation path in this project's own / // test config, S/U-mode being disabled).\"\n  Live model source, directly above the `handle_trap_extension` body it justifies. Note for the architect: I checked whether the **conclusion** survives, and it does, but not for the stated reason -- `trap_handler()` calls the hook in **both** arms (`sys_control.sail:222` Machine, `:248` Supervisor) and `medeleg.delegatable_bits.value` is `0x0` in the config. Fix by substituting the reason that actually holds. (Strictly outside the `extensions/Veda/*.sail` glob, but it carries the identical claim, so fixing only the milestone doc would leave the model asserting it.)\n\n### 18. `/home/prabhu/veda-core-sail-riscv/model/extensions/Veda/veda_regs.sail` **(A)**\n- `:1212` -- \"(a real, distinct limitation named in / MILESTONE_11_RESULTS.md for an unrelated reason, S/U-mode being / disabled there)\"\n  Only the parenthetical is wrong. The surrounding multi-hart claim is correct and must survive: delete the clause and the now-misleading cross-reference.\n  **Note:** the rest of `model/extensions/Veda/*.sail` is clean on the privilege prong -- zero mentions of droppriv or Custom-3, consistent with the model never having had them.\n\n### 19. `/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_21_RESULTS.md`\n**(A)** `:17` -- \"the only real privilege-delegation path in this project's own test config, S/U-mode being disabled).\" Twin of the step_ext.sail hit; same fix.\n**(C)** `:41` -- \"**RTL mirror** — deliberately not attempted this pass ... combined with Milestones 19 and 20's own still-pending RTL work\". The two sibling bullets in this same section already carry dated CLOSED notes; this one was missed. All three mirrors exist.\n\n### 20. `/home/prabhu/veda-core-sindhu/veda-core/difftest/MUTATION_CENSUS_DEREF.md`\n**(A)** `:50` \"| `oclc` (capability load) | 4/7 |\" -> the expression now has **8** terms (`veda_core.tlv:3531` gained `!perm_loadcap_ok` under R40). `:47` \"| `ocsc` (capability store) | 3/8 |\" -> **9** terms (`!$veda_perm_storecap_ok`). These rows are the document's only statement of what OCL.C/OCS.C enforce, so a reader concludes no capability-flow permission is checked on those paths.\n**(C -- see conflict X1)** `:3` \"**22 of 54 mutants SURVIVED. 41% of the trap-decision layer is unverified.**\" All 22 closed: `veda_smoke_uaf.S` (6 gen_stale) + `veda_smoke_deref_guards.S` (6 sealed + 3 bounds) + `veda_smoke_perm_cow_align.S` (\"the last seven census survivors\") = 22 exactly. The denominator is also now 56, not 54.\n**(C)** `:74` \"## The work list, in priority order\" and `:79` \"3. `!$veda_perm_load_ok` on oclc, nmc_add_w, nmc_add_d.\" -- all six items executed. A reader working this list rebuilds coverage that exists. Mark COMPLETE with the closing test named per item, and note that `!perm_loadcap_ok`/`!perm_storecap_ok` post-date the census and need their own coverage judgement.\n**Recommended shape:** one dated banner at the top (\"Superseded: all 22 survivors closed; layer is now 56 terms, R40 added one permission term to each of oclc and ocsc, both uncensused\") and keep the body as the historical measurement it is.\n**(D)** `:31` and `:65` -- both verified correct and current; see section D.\n\n### 21. `/home/prabhu/veda-core-sindhu/veda-core/DEVELOPER_WORKFLOW_GUIDE.md` **(A)**\n- `:146` -- \"real, live 128-bit packed capability and its out-of-band tag bit, verified against an independent second read path (`cgetbase`/`cgetlen`/`cgetperm`/`cgettag`) matching byte-for-byte.\"\n  The format is 256-bit (`veda_types.sail:77-82`), so this describes at most half a capability. **Separate task for whoever owns the gdbstub:** it appears never to have been widened -- `riscv_model_impl.h:116` still declares `pack_veda_capability_reg(int index, uint8_t out_bytes[16])` and `gdbstub.cpp:341-343` still advertise `bitsize=\"128\"` -- so the byte-for-byte agreement this sentence promises cannot hold at the new field widths. Until then, warn that the GDB view is truncated and cgetbase/cgetlen/cgetperm are authoritative.\n\n### 22. `/home/prabhu/veda-core-sindhu/veda-core/FORMAL_VERIFICATION_PLAN.md`\n**(A)** `:3` -- \"**Status**: Design-stage. No Sail code written yet.\" Contradicted by its own §5, which records V-A/V-B/V-C done.\n**(C)** `:97` ODT entry-creation/destruction encoding \"not decided\" -- the whole ODT-write family is encoded and implemented on both layers, and Populate's policy-field reset is pinned. `:99` Veda-Atomic op-select values -- finalized in `veda_atomic_insts.sail`, mirrored in RTL. `:100` Tag array representation -- decided (per-capability, plus the RTL's separate tcm_scratch_tag array).\n\n### 23. `/home/prabhu/veda-core-sindhu/veda-core/SECURITY_COMPARISON_STUDY.md` **(A)**\n- `:88` -- \"Veda-Core's other four `veda_check_access` checks\" (glossed \"(Tag, generation-staleness, Seal, Permission)\"). Not four, and the lumped \"Permission\" now hides two separately-caused capability-flow checks (0x14, 0x15) guarding a distinct class -- whether **authority** may move through memory. Honest note: the count was already understated pre-R40 (cow, residency, capability alignment are also in that function), so this is drifted enumeration, not a single-cause error. Best fix: drop the count, name the classes.\n\n---\n\n## TIER 5 -- runners and paths (frozen-tree dependencies first)\n\nThe conversion off `/home/prabhu/makerchip/rva23-core` was done thoroughly but incompletely. Already converted and correct: `rtl/run_veda_smoke_test.sh:80`, `sail_tests/run_veda_selfcheck_tests.sh:14`, `difftest/rundiff.sh:18` (TC only). Missed:\n\n### 24. `rtl/run_act4_tests.sh` **(B, two)**\n- `:17` -- `GCC_BIN=/home/prabhu/makerchip/rva23-core/toolchain/riscv-collab-gcc/riscv/bin`\n  This line has its own toolchain at `/home/prabhu/veda-core-sindhu/toolchain/riscv-collab-gcc/riscv/bin` (objcopy and readelf both confirmed present). Even the frozen tree's own copy of this script has a local-first fallback.\n- `:20` -- `ELF_DIR=\"${1:-/home/prabhu/makerchip/rva23-core/act4-verify/work/rva23-base-rv64i/elfs/rv64i/I}\"`\n  **Structural.** The ACT4 corpus exists only in the frozen tree; `/home/prabhu/veda-core-sindhu/act4-verify` does not exist and `act4-verify/` is gitignored here. **The 51/51 figure quoted across this line cannot be reproduced from a clean clone at all.** Make the \"No .elf files found\" guard say how to obtain or regenerate the corpus.\n\n### 25. `compiler/run_veda_shadow_prop_tests.sh` **(B)**\n- `:25` -- `MY_LLVM_BUILD=/home/prabhu/makerchip/rva23-core/toolchain/llvm-project/build`\n  The only script in that directory still hardwired; siblings (`run_veda_demo_tests.sh:10-14`, `run_veda_global_protect_test.sh:24-28`, `run_veda_alloca_protect_test.sh:28-32`) all derive LLVM from `$REPO_ROOT`. **Fixing this one line also fixes two docs for free:** `TOOLCHAIN_MILESTONE_8_RESULTS.md:78` and `TOOLCHAIN_MILESTONE_9_RESULTS.md:265`, both \"## Reproducing this\" blocks that invoke it. If the script is not fixed, both blocks need an explicit frozen-tree prerequisite line.\n\n### 26. `difftest/rundiff.sh` **(A)**\n- `:19` -- `SIM=/home/prabhu/veda-core-sindhu/toolchain/sail-riscv/build/c_emulator/sail_riscv_sim` and `:27` `RTLSIM=/home/prabhu/veda-core-sindhu/veda-core/rtl/sim`\n  Directly contradicted by the comment at :15-18 claiming R29 fixed exactly this (\"the hand-wired path this replaced ... so this harness only ran on one machine\"). Only TC was converted, so the harness still runs on one machine and the comment overstates the fix. The file already computes `D=\"$(cd \"$(dirname \"$0\")\" && pwd)\"` at :13.\n\n### 27. `check_timing_coupling.sh` **(B)**\n- `:32` -- `SAIL=/home/prabhu/veda-core-sail-riscv/model/extensions/Veda/veda_cap_insts.sail`\n  The only absolute path in an otherwise fully relative script, and the repo already carries `toolchain/sail-riscv` as a symlink to that tree. As written, a build-failing invariant check degrades into an infrastructure failure (\"FAIL: cannot find VEDA_CAPQUERY\") on any other machine -- the wrong failure mode for a check whose purpose is to fail loudly at the right moment.\n\n### 28. `/home/prabhu/veda-core-sindhu/toolchain/setup.sh` and `/home/prabhu/veda-core-sindhu/README.md`\n*(Both sit one level above the `veda-core/**/*.md` glob; included because they are the only quickstart this line has.)*\n**(B)** `setup.sh:58` -- `BRANCH=veda-core` drives **both** fork clones (:142, :166), but this line's Sail model is on `phase1-respec` (confirmed against the local checkout's branch and its only remote-tracking heads, master and phase1-respec). A veda-core branch, if it still exists upstream, predates the entire Phase-1 respec and Phase-2 work, so `./toolchain/setup.sh` builds a simulator that cannot pass 102/102. Split into per-fork variables. The LLVM half is **unconfirmed** (no local clone) -- leave it until checked.\n**(B)** `README.md:266` -- \"git clone --branch veda-core https://github.com/prabhu-euro20/Veda-Core-sail-riscv.git toolchain/sail-riscv\", and the table row at :219 repeats it while describing pre-respec scope. Same fix.\n**(A)** `README.md:224` -- \"git clone https://github.com/prabhu-euro20/Veda-Core.git\"\nThe \"One-command setup\" for the repo this file lives in clones a **different** repo: origin here is `veda-core-sindhu`; `prabhu-euro20/Veda-Core` is the frozen upstream the design README:122 calls \"read-only reference only\". A reader following this quickstart clones the frozen line and runs setup.sh inside it. The `:217` \"This repo\" table row repeats the misidentification.\n\n---\n\n## TIER 6 -- Phase 2 / mirror results docs that state a **current** contract\n\n### 29. `sail_tests/PHASE2_SAIL_RESIDENCY_RESULTS.md`\n**(A)** `:28` -- \"A page-out leaves `valid` true (the object still exists) and does not bump `generation` (only Populate and Destroy do). So **nothing existing would notice**\"\nTruth item 6's forbidden claim almost verbatim, and it is the premise of section 2.1's whole design argument. `veda_ocl_insts.sail:1171` sets `generation = old_entry.generation + 1`. The document now **contradicts its own RTL mirror** (RTL_MIRROR_06:192-194 already says the dereference-side residency term is unreachable through the ISA because page-out bumps generation). Fix by dating it to increment 1 and stating that the residency gate is retained on the soundness argument, not on reachability.\n**(C)** `:185` -- \"**COW is bypassable as DESIGN_02 currently describes it** ... a domain that can name a COW object's Object_ID can simply re-Bind it and get a writable capability. COW must be enforced by hardware attenuation at Bind\" -- built: `veda_bind_perms` masks a cow entry with `0xFFF7` (veda_regs.sail:983) and the RTL masks on **both** the Bind and Rebind arms (veda_core.tlv:3137, :3152, the latter added by R23b). The bullet now reads as an open demand for work already done.\n**(C)** `:178` -- \"**There is no evict instruction**, so a non-resident object can only be reached by reset seeding.\" Closed by increment 2; `vc_paging_full_cycle` is exactly the bind-evict-dereference test the follow-on sentence says cannot yet be written.\n\n### 30. `sail_tests/PHASE2_SAIL_PAGING_RESULTS.md` **(A)**\n- `:37` -- \"| gate | `valid & resident & generation != 0xFFFFFF` | `valid & not resident` |\"\n  Missing the R38(b) conjunct: `else if old_entry.cow then Illegal_Instruction()` (veda_ocl_insts.sail:1158). Add `& not cow` with a footnote: paging bumps the generation, which would destroy the copy-on-write split right that lives only in the capabilities minted before `set.cow`.\n\n### 31. `rtl/RTL_MIRROR_06_PAGING_RESULTS.md` **(A)**\n- `:160` -- \"| gate | authority & valid & resident & gen != 0xFFFFFF | authority & valid & not resident |\"\n  Same defect, under the heading \"## 5. The paging contract, as built\" -- so it reads as the current contract. The RTL's real refusal (`veda_core.tlv:2634-2646`) carries the cow conjunct. Suggested cell: `authority & not executing & valid & resident & not cow & gen != 0xFFFFFF`.\n  **Out-of-scope note routed here:** `:36` and `:114` speak of \"a future `cow` at +26\"; cow is built and sits at `ODT_OFF_COW = 29`. Belongs to a built-vs-unbuilt sweep, not this one.\n\n### 32. `TOOLCHAIN_MILESTONE_7_RESULTS.md`\n**(A)** `:20` -- \"Every existing test program in this project runs entirely in M-mode with no privilege drop; this runtime does the same\" -- false corpus-wide (`vc_umode_compartment_basic.S`, `vc_r39_csr_priv.S`, six RTL tests using `VEDA_DROP_TO_USER`). The conclusion about the runtime is unaffected: just narrow the claim to this runtime.\n**(B)** `:30` -- \"**The generation-counter retirement threshold is exactly 256 real Destroy calls** ... (`new_generation` bumps unconditionally every call...)\"\nLoad-bearing, not cosmetic: the very next bullet (:36-42) turns it into a standing obligation on live runtime code -- `g_destroy_count[]` \"must exactly replicate hardware's own per-call bump rule\". Page-out also bumps, so a mirror counting only Destroys silently under-counts for any paged object. (The 8-bit/256 figures are separately superseded by the widen to 24 bits, but that is the ceiling, not the bump rule.)\n\n### 33. `MILESTONE_22_RESULTS.md`\n**(A)** `:29` -- \"staleness can only arise the intended way (destroy-then-repopulate after a capability was already bound elsewhere)\" -- an \"only\" claim in the general present tense, inside an audit concluding \"No gap found\". Page-out is a second, entirely intended producer.\n**(C)** `:50` -- \"Broader subsystem-by-subsystem review (Veda-Atomic's own `aq`/`rl` ..., `OSpecialRW`'s privilege-only gating, RTL mirrors for Milestones 19-22) explicitly deferred\" -- all three discharged (ATOMIC_AQRL_SAFETY_ANALYSIS.md, OSPECIALRW_PRIVILEGE_GATING_AUDIT.md, rtl/MILESTONE_19..22).\n\n### 34. `rtl/RTL_MIRROR_04_DESIGN08_REGION_RESULTS.md` **(A)**\n- `:243` -- \"- **The CRBR is reset-only in both models**, so the domain-entry load remains prose-only in Sail and\" -- a present-tense divergence claim about both layers, closed by R10 (loaded and validated at OCInvoke, OCReturn, trap entry and mret on both layers).\n\n---\n\n## TIER 7 -- (C) one-line dated CLOSED annotations on milestone gap lists\n\nThese are legitimate history whose *remaining-gap* clauses have since closed. Low risk individually; each needs one appended sentence, not a rewrite.\n\n| File:line | Stale clause | Closed by |\n|---|---|---|\n| `MILESTONE_19_RESULTS.md:48` | \"A true non-M-mode negative case can't be exercised in this project's own Sail test config (S/U-mode both `\"supported\": false`)\" | config flipped 2026-08-10; DESIGN_07 R39 ran the U-mode probe. Keep the M19 record, append a dated closure. |\n| `MILESTONE_19_RESULTS.md:55` | RTL mirror \"deliberately not attempted this pass\" + design sketch | `rtl/MILESTONE_19_RESULTS.md`. Keep the sketch -- the prediction was right. |\n| `MILESTONE_20_RESULTS.md:41` | \"this exact same CSR-write escape exists unfixed in RTL too\" | mirrors + `veda_smoke_mtvec_escape_neg.S` + R39. The \"not attempted this pass\" scoping is fine; the \"exists unfixed\" clause is what must go. |\n| `MILESTONE_27_MTVEC_CSR_GATE_RESULTS.md:71` | \"this exact same class of gap ... likely exists there too\" | `rtl/MILESTONE_21_27_RESTORE_MTVEC_GATE_RTL_RESULTS.md` + R39. |\n| `TOOLCHAIN_MILESTONE_19_SCOPE_LIMIT_AUDIT_RESULTS.md:153` | \"## What this means for the project (not yet acted on -- reporting only)\" -- four numbered candidates | all four acted on across the Milestone-20 parts. |\n| `rtl/MILESTONE_5_RESULTS.md:130` | \"Real trap/exception infrastructure and any privilege-raising mechanism remain out of scope\" | traps at M9, privilege-raising-on-trap at R36. |\n| `rtl/MILESTONE_6_RESULTS.md:130` | \"any privilege-raising or `CInvoke`-equivalent domain-transition mechanism (explicitly out of scope per `VEDA_CORE_SPEC.md` Section 6 item 7)\" | R36. **Also re-check the Section 6 pointer after the spec edit lands** -- it can go stale a second way. |\n| `rtl/MILESTONE_20_RESULTS.md:96` | \"RTL mirror for Milestone 21 (universal PCC reset on any trap,\" | `rtl/MILESTONE_21_RESULTS.md` + the mtvec-gate doc. |\n| `rtl/MILESTONE_21_RESULTS.md:99` | \"Real `ecall`/illegal-instruction/misaligned-access support does not\" exist | ecall at RTL M23, illegal-instruction at R33a-d; only misaligned-access remains. |\n| `MILESTONE_14_RESULTS.md:36` | \"`Perms`-on-PCC, S/U-mode-privilege interaction, and real multi-hart RTL all remain exactly as named\" | S/U-mode privilege closed by R36/R39; the M14 RTL mirror exists. See conflict **X3**. |\n| `rtl/ACT4_CONFORMANCE_RESULTS.md:16` | \"new Custom-0/1/2/3 decode logic\" | Custom-3 unclaimed. **Leave 51/51 -- the number is still correct.** Only the opcode clause is defective. |\n\n---\n\n## (D) CORRECT AS HISTORY -- leave alone\n\nRecorded so the architect can confirm the judgement rather than re-derive it.\n\n1. `rtl/veda_core.tlv:1946` -- droppriv/Custom-3 paragraph, superseded in place by the R36 block below it. *Forward-pointer would help:* prefix with \"Milestone 4 wrote:\".\n2. `VEDA_CORE_TECHREPORT.md:37` -- \"Custom-3 deliberately left unallocated\". Now correct again.\n3. `rtl/MILESTONE_3_RESULTS.md:13` and `rtl/MILESTONE_1_RESULTS.md:64-65` -- \"no privileged architecture at all\" / \"no privileged/trap architecture at all yet\". Both date themselves (\"yet\", and M3:27 says ODT-Populate \"become Milestone 4, once the privilege concept exists\"). Rewriting would rewrite history.\n4. `rtl/sim/veda_smoke_r36_priv_trap.S:10` -- \"`$priv` had exactly one writer -- veda.droppriv, Custom-3, one-way\". Past tense, inside R36's own explanation of what R36 changed. The model case for the judgement rule.\n5. **The eight `perms=0x100C` transcript sites** -- `rtl/MILESTONE_1_RESULTS.md:18`, `rtl/MILESTONE_2:43`, `rtl/MILESTONE_3:39`, `rtl/MILESTONE_6:76` and `:80`, `MILESTONE_V-B_RESULTS.md:95`, `TOOLCHAIN_MILESTONE_4_RESULTS.md:88` and `:114`, `rtl/RTL_MIRROR_02B_256BIT_FORMAT_RESULTS.md:73`. The seed is now `16'h103C` (R40), but every one of these is a captured simulation or CGetPerm transcript -- what the machine printed at that milestone. None asserts it as a current fixture. *(The one doc that does state it as current architecture, `rtl/MILESTONE_PLAN.md:92`, is already on the being-edited list.)*\n6. `MILESTONE_20_RESULTS.md:10` -- \"it works with only M-mode enabled, no S/U-mode needed\". The load-bearing claim (the self-escape PoC needed no S/U-mode) is still true, and strengthened by S/U now being enabled.\n7. `difftest/MUTATION_CENSUS_DEREF.md:31` -- \"an object's generation is bumped on Destroy and on page-out\". **The one place in ~110 documents that states the producer set correctly.** Do not touch.\n8. `difftest/MUTATION_CENSUS_DEREF.md:65` -- verified rather than assumed: R38 changed only the *cause chain*, not the violation OR-expressions, and the capability at `rtl/sim/veda_smoke_check_order.S:37` is bound \"(BEFORE cow: keeps store)\", so it retains PERM_STORE and still reports 0x01.\n9. `rtl/RTL_MIRROR_09_EXECUTING_PIN_RESULTS.md:38` -- consumer-set table correctly lists page.out as a generation bumper and correctly excludes page.in.\n10. `rtl/MILESTONE_C_RESULTS.md:76` -- remaining items (fault recovery, preemption, >2 threads, priorities, queues, allocator) are all genuinely still open; the one that closed (full GPR context save) is already struck through and marked Resolved.\n11. `rtl/RTL_MIRROR_02A:35` -- \"Checked after Tag/Seal/Perm and before the bounds fall-through\" is still exactly right post-R40 (alignment sits below the new 0x14/0x15 arms, above bounds).\n12. `rtl/MILESTONE_10_RESULTS.md:195` -- \"Permit_Set_CID/cause 0x1c ... not yet built\" is still true; PERM_SET_CID is genuinely unenforced and is not one of R40's four.\n13. `OSPECIALRW_PRIVILEGE_GATING_AUDIT.md` -- read end to end; surfaces on every grep but only discusses where the M-mode gate sits, never the test config. Same for the \"M-mode-only\" mentions in `MINIMAL_OS_KERNEL_DESIGN.md:65-67`, `TOOLCHAIN_MILESTONE_7_RESULTS.md:18`, `rtl/MILESTONE_3_RESULTS.md:15`, `veda_ocl_insts.sail:591`.\n14. The \"## Reproducing this\" sections pointing at `/tmp/claude-.../scratchpad` paths (ARCHITECTURE_IMPROVEMENT_FINDINGS, ATTACK_DEMO_PORTFOLIO, SECURITY_COMPARISON_STUDY, SYNTHESIS_CRITICAL_PATH_STUDY and five others) -- every one labels itself \"session-scoped, not committed\", so the document is truthful about what it is.\n\n---\n\n## SUPPLEMENTARY -- five `.S` test-file headers (scope call needed)\n\nOutside the four corpus locations in the brief, but these are unambiguous droppriv assertions a reader will hit while reading the tests. Each is a header describing what the file does; each file was migrated to `VEDA_DROP_TO_USER`. **(B)** throughout:\n\n- `rtl/sim/veda_smoke_m4_neg.S:6` -- \"# Veda-Core RTL Milestone 4 negative test: `veda.droppriv` first,\" (real drop at :26)\n- `rtl/sim/veda_smoke_m11_neg.S:5` -- \"# Veda-Core RTL Milestone 11 negative test: `veda.droppriv` first\" (real drop at :23)\n- `rtl/sim/veda_smoke_m11.S:15` -- \"RTL's own real `veda.droppriv` (Milestone 4) lets this test prove...\" (real drop at :40). **Second defect in the same comment, lines 13-15:** \"this project's own Sail test config has S/U-mode disabled, so privilege can never actually drop below Machine there\" -- false under truth item 5, and false before this session.\n- `rtl/sim/veda_smoke_paging_refusals_neg.S:36` -- \"// PART D -- BOTH REFUSE WITHOUT AUTHORITY. veda.droppriv first, then both\" (real drop at :165)\n- `rtl/sim/veda_smoke_m4.S:11` -- \"# `veda.droppriv` is exercised only by the separate negative test.\" and `veda_smoke_m6.S:39` -- \"privileged by default, no droppriv in this test\"\n\n---\n\n## X. CROSS-SWEEP CONFLICTS -- reported, not averaged\n\n**X1 -- `difftest/MUTATION_CENSUS_DEREF.md:3`.** The permissions sweep filed it **(C)** gap-since-closed; counts-and-gaps filed it **(A)** current-claim-false. Both are right about different halves of the same sentence: \"22 of 54 mutants SURVIVED\" is a closed gap (all 22 covered), and \"54\" / \"41% ... is unverified\" is a false current claim (the layer is 56 terms since R40). **Resolution: one dated banner fixes both; do not treat as two edits.**\n\n**X2 -- `TECHNICAL_BRIEF.md:85` (\"No compiler or toolchain ecosystem exists\").** counts-and-gaps filed **(C)**; entry-points filed **(A)**. Not a real disagreement -- it is a closed gap *stated as a current limitation in an undated outward-facing brief*, which makes it read as (A) to a reader. **Resolution: fix at (A) urgency, phrase as a scope narrowing.** Same for `VEDA_CORE_TECHREPORT.md:176`, which is dated by context and can stay (C).\n\n**X3 -- `MILESTONE_14_RESULTS.md:36`.** The sail-config sweep cleared it as **(D)** (it makes no config claim of its own and defers entirely to `PCC_COMPARTMENT_DESIGN.md` §7, already on the being-edited list); counts-and-gaps filed it **(C)** (two of the three named items no longer \"remain\"). **Resolution: both are correct about different clauses.** The §7 pointer needs no edit and inherits its correction -- *but verify §7 still exists under that heading after its own edit so the reference does not dangle.* The clause \"S/U-mode-privilege interaction ... remain[s] exactly as named\" **is** stale and needs the R36/R39 annotation; the M14 RTL mirror also now exists. Multi-hart and Perms-on-PCC are still genuinely open.\n\n**X4 -- line-number drift, same passage.** `rtl/MILESTONE_19_RESULTS.md` cited at :25 (privilege) and :26 (counts) -- one passage spanning 25-27. `TOOLCHAIN_MILESTONE_13_CRF_EXHAUSTION_DECISION.md` cited at :66 (sail-config) and :67 (counts) -- one sentence wrapping 66-67. Both verified against the files; one edit each, not two.\n\n---\n\n## Y. NOTABLE NEGATIVES (verified, not gaps in the sweeps)\n\n- **Truth item 4 (Populate clearing cow / resetting owner_domain to ANY): zero hits outside your excluded files.** `owner_domain`, `VEDA_DOMAIN_ANY`, `veda.odt.set.domain` and any Populate carries/preserves-policy claim appear in exactly one non-excluded line (`DESIGN_08_OBJECT_NAMESPACE_SCALE.md:53`, a proposed region-table field list saying nothing about Populate's write set). R41's subject matter is documented only inside the files you already have open.\n- **Truth item 3 is a near-negative.** `LOAD_CAPABILITY`, `STORE_CAPABILITY`, `PERMIT_GLOBAL`, `STORE_LOCAL_CAPABILITY` appear in exactly two files corpus-wide, both already yours. **Nothing outside your list claims GLOBAL or STORE_LOCAL_CAPABILITY are enforced.** What went stale was the four bits' *absence* -- the 0x000C capability table (Tier 1 item 5) and the census term counts (item 20).\n- **Copy-on-write is almost undocumented outside the excluded set:** `\\bcow\\b` matches only 13 lines corpus-wide. The R38/R38(b)/R19 reasoning lives entirely in code comments (`veda_ocl_insts.sail:100-260`, `:1118-1160`, `veda_core.tlv:4390-4470`), all verified current and correct.\n- **`model/extensions/Veda/*.sail` is clean on the privilege prong** -- zero mentions of droppriv or Custom-3, consistent with the model never having had them. Its only truth-item-5 hit is `veda_regs.sail:1212`.",
    "results": [
      {
        "hits": [
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv",
            "line": 1372,
            "quote": "This core has no privilege-level stack to restore (it's always effectively M-mode, matching $priv's own existing one-way-drop model) -- MRET here means exactly \"PC = mepc\", not a full mstatus.MPP/MPIE restore.",
            "why_stale": "This is the live RTL, and the comment is contradicted by the code three lines below it. $mret_ok = $is_mret && $priv (line 1384) makes MRET illegal below Machine, and $priv (line 1097) installs >>1$mstatus_mpp[1] on a legal MRET. mstatus (0x300) exists at line 1311 implementing MIE/MPIE/MPP. All three of the comment's claims -- no privilege-level stack, always effectively M-mode, one-way $priv -- are now false, and the R36 comment block immediately below (1377-1383) says so. Highest-value hit in the sweep: it is the surviving pre-R36 text inside the shipping source, and it is the text MILESTONE_9 and MILESTONE_19 both point readers at.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Replace the three sentences with: \"MRET's PC redirect and every other effect hang off $mret_ok below, not off $is_mret -- R36 made this a real trap return: privilege = mstatus.MPP, and an MRET below Machine is an illegal instruction.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_9_RESULTS.md",
            "line": 71,
            "quote": "than field-by-field decode — this core has no privilege-level stack to restore (it's always effectively M-mode, matching `$priv`'s own existing one-way-drop model since Milestone 4), so `MRET` here means exactly \"PC = mepc\", not a full `mstatus.MPP`/`MPIE` restore.",
            "why_stale": "Phrased in the present tense as a standing architectural property (\"this core has no...\", \"it's always...\", \"$priv's own existing one-way-drop model\"), not as \"at Milestone 9 we did X\". R36/R39 retired the one-way drop, added mstatus with MPP/MPIE, and made MRET a real privilege restore that is illegal below Machine. This is also the cited authority for the stale RTL comment and for MILESTONE_19_RESULTS.md:25-27, so fixing it unblocks both.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Make it past-tense and add one pointer: \"...at Milestone 9 this core had no privilege-level stack to restore ... so MRET here meant exactly 'PC = mepc'. R36/R39 later replaced this with the standard model: MRET restores privilege from mstatus.MPP and is illegal below Machine.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_19_RESULTS.md",
            "line": 25,
            "quote": "no privilege check needed beyond what already exists (this core has no S/U-mode concept yet; every CSR write in this file is implicitly M-mode-only for the identical, already-stated reason MRET's own comment gives).",
            "why_stale": "Two present-tense claims, both now false. The core does have a below-Machine privilege concept ($priv reaches 0 via mstatus.MPP + mret), and CSR writes are no longer implicitly M-mode-only -- R39 added the generic check keyed on csrPriv = csr[9..8], which applies to reads as well as writes. The clause also forwards the reader to the MRET comment that is itself the stale text (hit 1).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Change to \"...(at Milestone 19 this core had no S/U-mode concept and every CSR write was implicitly M-mode-only; R36/R39 added mstatus.MPP-based privilege and a generic csr[9:8] privilege check that now covers 0x7C5 too).\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_23_RESULTS.md",
            "line": 30,
            "quote": "`0x0B` (11) is the real, standard RISC-V mcause for \"Environment call from M-mode,\" not an invented code, and the only possible value since this core only ever runs M-mode.",
            "why_stale": "The trailing clause is a standing claim about the machine, not a record of the Milestone 23 edit, and it is now false twice over: the core does run below Machine, and the mcause mux is no longer the two-way branch this line describes. veda_core.tlv:5228 now reads `>>1$is_ecall ? (>>1$priv ? 64'h0B : 64'h08) : 64'h18` -- ECALL reports 0x08 from User and 0x0B from Machine.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Cut the clause after \"not an invented code\", and add: \"At Milestone 23 it was the only possible value, since the core only ran M-mode; R36 added User mode and the mux is now `$is_ecall ? ($priv ? 0x0B : 0x08) : 0x18`.\""
          },
          {
            "file": "/home/prabhu/veda-core/design/DESIGN_05_PURECAP_PRIVILEGE_PROCESS.md",
            "line": 35,
            "quote": "(1-bit $priv + one-way droppriv + ODA authority). Extend to a real OS:",
            "why_stale": "Asserts the current Veda privilege model as a live premise the rest of Part B builds on. veda.droppriv is retired, Custom-3 is unclaimed, and $priv is no longer one-way -- it is raised by a trap and restored from mstatus.MPP by mret. A design doc still resting on a retired instruction is worse than a stale results file: it is a premise for future work.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "\"(standard mstatus.MPP/mret privilege + ODA authority)\"."
          },
          {
            "file": "/home/prabhu/veda-core/design/DESIGN_05_PURECAP_PRIVILEGE_PROCESS.md",
            "line": 5,
            "quote": "OSpecialRW, droppriv, the MOS switcher. **Verification plan:** purecap-compile a",
            "why_stale": "The \"Builds on:\" header lists droppriv as an existing, verified mechanism this design proposal stands on. It no longer exists on either layer.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Drop \"droppriv\" from the list, or replace it with \"the standard mstatus.MPP/mret privilege model\"."
          },
          {
            "file": "/home/prabhu/veda-core/README.md",
            "line": 60,
            "quote": "| 05 | `design/DESIGN_05_PURECAP_PRIVILEGE_PROCESS.md` | pointer = capability; privilege = ODA possession | OCL.C/OCS.C, tag memory, ODA, droppriv |",
            "why_stale": "The column heading is \"Builds on (verified)\" -- so this row asserts droppriv is a currently verified mechanism. It is retired. This is the design repo's front-door index, the first place a new reader looks.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Replace \"droppriv\" with \"mstatus.MPP/mret\" in that cell."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MINIMAL_OS_KERNEL_DESIGN.md",
            "line": 67,
            "quote": "core spec, not just CHERIoT's specific choice — that Veda-Core's existing M-mode-only design can and should use `PERMIT_ACCESS_SYSTEM_REGISTERS` (already real, already implemented, already the exact gate `OSpecialRW`/`veda_oda` delegation already uses, `OSPECIALRW_PRIVILEGE_GATING_AUDIT.md`) as the actual privilege boundary for kernel components, rather than inventing new ring levels.",
            "why_stale": "\"Veda-Core's existing M-mode-only design\" is the load-bearing premise of Finding 3, and it is now false: both layers run User mode, a trap raises to Machine saving mstatus.MPP, and mret restores from it. The CHERI quote it leans on is explicitly conditioned on \"a ring-free design ... without ... kernel/supervisor/user modes\", which no longer describes this machine. Finding 3 then drives the doc's Section 3 privilege-model decision (line 126).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Change \"Veda-Core's existing M-mode-only design\" to \"Veda-Core's design as of this document (M-mode-only; R36 has since added the standard M/U model)\" and add one sentence noting the CHERI quote's ring-free precondition no longer holds unmodified."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MINIMAL_OS_KERNEL_DESIGN.md",
            "line": 238,
            "quote": "- **S/U-mode privilege transitions** — unchanged from this project's own already-documented limitation (`MILESTONE_11_RESULTS.md`); the capability-context-only privilege model (Finding 3) is deliberately independent of ring levels, not a workaround for their absence.",
            "why_stale": "This is a \"Not yet built\" entry naming a remaining gap that R36 closed for U-mode on both layers: mstatus.MPP + mret is exactly a privilege transition, exercised by sail_tests/vc_umode_compartment_basic.S, sail_tests/vc_r39_csr_priv.S and six RTL tests using VEDA_DROP_TO_USER. The judgement rule says a remaining gap since closed is reportable even inside a historical doc.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Append: \"CLOSED for U-mode by R36/R39 -- privilege now drops via mstatus.MPP + mret and is raised by a trap, on both layers. S-mode remains unbuilt.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv",
            "line": 2574,
            "quote": "veda_smoke_m4_neg.S and veda_smoke_m11_neg.S both depend on exactly that -- they droppriv, populate, and keep executing.",
            "why_stale": "Present-tense claim about what two live tests do. Both were migrated to VEDA_DROP_TO_USER (veda_smoke_m4_neg.S:26, veda_smoke_m11_neg.S:23, each commented \"R36: the architected drop -- mstatus.MPP=U then mret\"). Neither file contains a droppriv instruction any more. (The other half of this block -- that the gates refuse silently -- is separately stale via RTL-11/R14, but that is outside truth item 1 and is already corrected at lines 2589-2594.)",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "\"...both depend on exactly that -- they drop to User via mstatus.MPP + mret, populate, and keep executing.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv",
            "line": 5630,
            "quote": "Measured before editing: NO test in the corpus writes 0x7C4 after veda.droppriv, so the privilege half costs nothing.",
            "why_stale": "Stale twice. The instruction named no longer exists, so the measurement is not reproducible as written; and the statement is now factually inverted -- veda_smoke_r35_attr_priv.S:44-49 drops to User via VEDA_DROP_TO_USER and then deliberately writes 0x7C4, as the negative test for exactly this gate. A reader trusting this line would conclude the gate is untested.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "\"Measured before editing: no test then wrote 0x7C4 below Machine, so the privilege half cost nothing. veda_smoke_r35_attr_priv.S is now the standing negative test for it.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv",
            "line": 5605,
            "quote": "But a principal after veda.droppriv -- holding neither privilege nor a tagged ODA -- could CHOOSE THE LENGTH AND PERMS OF AN OBJECT A LATER PRIVILEGED POPULATE-FAST WILL MINT.",
            "why_stale": "The threat model for a live gate is stated in terms of a retired instruction. The reasoning is still correct -- it is the principal running below Machine that matters -- but naming veda.droppriv sends the next reader looking for an encoding that no longer decodes; every Custom-3 encoding now raises Illegal_Instruction.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Replace \"a principal after veda.droppriv\" with \"a principal running below Machine\"."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv",
            "line": 5654,
            "quote": "post-droppriv, unbounded-PCC principal could clear purecap here",
            "why_stale": "Same defect as the previous hit, in the R26 Lever B comment on the veda_mode write gate: the principal is described by an instruction that no longer exists. The gate itself ($priv on the 0x7C5 write, line 5658) is current and correct.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "\"a below-Machine, unbounded-PCC principal could clear purecap here\"."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv",
            "line": 11,
            "quote": "violations suppress writes rather than trap, since this core has no privileged/trap infrastructure at all yet",
            "why_stale": "This is the file header of the live RTL -- the first thing a reader sees -- and it asserts, with \"yet\", that no privileged or trap infrastructure exists. The file now carries mtvec/mepc/mcause/mtval/mscratch/mstatus, a real trap redirect, $priv, and Populate/Destroy violations that trap rather than suppress. Unlike the milestone docs, this text is not framed as a dated record; it reads as a description of the file it heads.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Prefix the parenthetical with its date: \"the three architectural calls Milestone 1 required (as of Milestone 1: ... violations suppressed writes rather than trapping, since the core then had no privileged/trap infrastructure -- Milestone 9 built the traps, R36/R39 the standard privilege model)\"."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_7_RESULTS.md",
            "line": 20,
            "quote": "Every existing test program in this project runs entirely in M-mode with no privilege drop; this runtime does the same, stated explicitly rather than silently assumed.",
            "why_stale": "A present-tense claim about the whole corpus, used to justify why the runtime needs no ODA path. It is now false on both layers: sail_tests/vc_umode_compartment_basic.S and vc_r39_csr_priv.S drop below Machine, and six RTL tests use VEDA_DROP_TO_USER. The conclusion about the runtime is unaffected; only the corpus-wide claim is wrong.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Narrow the claim: \"This runtime runs entirely in M-mode with no privilege drop, stated explicitly rather than silently assumed.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_5_RESULTS.md",
            "line": 130,
            "quote": "Real trap/exception infrastructure and any privilege-raising mechanism remain out of scope per earlier milestones' own decisions.",
            "why_stale": "A \"Not yet built\" gap that has since been closed: Milestone 9 built the traps, and R36 added the privilege-raising mechanism this line rules out -- a trap now sets privilege to Machine and saves the previous level in mstatus.MPP. Reported because the brief treats a since-closed remaining gap as stale even inside a milestone record; low priority, since the closure predates this session.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Append \"(both since built: traps at Milestone 9, privilege-raising-on-trap at R36)\"."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_6_RESULTS.md",
            "line": 130,
            "quote": "and any privilege-raising or `CInvoke`-equivalent domain-transition mechanism (explicitly out of scope per `VEDA_CORE_SPEC.md` Section 6 item 7)",
            "why_stale": "Same since-closed gap as the previous hit, and it anchors the claim to VEDA_CORE_SPEC.md Section 6 item 7 -- a file already on the being-edited list, so this pointer will go stale in a second way once that edit lands. R36 gives the core a real privilege-raising mechanism (trap -> Machine, MPP = previous).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Append \"(privilege-raising since built by R36: a trap raises to Machine and saves the previous level in mstatus.MPP)\", and re-check the Section 6 pointer after the spec edit."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/sim/veda_smoke_m4_neg.S",
            "line": 6,
            "quote": "# Veda-Core RTL Milestone 4 negative test: `veda.droppriv` first,",
            "why_stale": "The file's own header still says the test begins with veda.droppriv; line 26 was migrated to VEDA_DROP_TO_USER and the instruction is gone. Note: .S files are outside the four locations the brief listed as the corpus, so treat this and the four following as a supplementary group -- they are real droppriv assertions a reader will hit, but the parent may consider them out of scope.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "\"# ... negative test: drop to User (mstatus.MPP + mret) first,\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/sim/veda_smoke_m11_neg.S",
            "line": 5,
            "quote": "# Veda-Core RTL Milestone 11 negative test: `veda.droppriv` first",
            "why_stale": "Same as the m4_neg header: the file now drops via VEDA_DROP_TO_USER at line 23 and contains no droppriv.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "\"# ... negative test: drop to User (mstatus.MPP + mret) first\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/sim/veda_smoke_m11.S",
            "line": 15,
            "quote": "there) -- RTL's own real `veda.droppriv` (Milestone 4) lets this test prove the ODA authorization path works genuinely independently of ordinary privilege, not just alongside it.",
            "why_stale": "Names veda.droppriv as the mechanism this test uses; line 40 is now VEDA_DROP_TO_USER. Separately, the preceding clause on lines 13-15 (\"this project's own Sail test config has S/U-mode disabled, so privilege can never actually drop below Machine there\") is false under truth item 5 -- flagged here only so it is not lost, since it belongs to that sweep, not mine.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Replace \"RTL's own real `veda.droppriv` (Milestone 4)\" with \"the architected drop to User (mstatus.MPP + mret)\"; hand the S/U-disabled clause to the truth-item-5 sweep."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/sim/veda_smoke_paging_refusals_neg.S",
            "line": 36,
            "quote": "// PART D -- BOTH REFUSE WITHOUT AUTHORITY. veda.droppriv first, then both",
            "why_stale": "Part D's description names veda.droppriv; the file actually drops via VEDA_DROP_TO_USER at line 165.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "\"// PART D -- BOTH REFUSE WITHOUT AUTHORITY. Drop to User first, then both\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/sim/veda_smoke_m4.S",
            "line": 11,
            "quote": "# `veda.droppriv` is exercised only by the separate negative test.",
            "why_stale": "The separate negative test no longer exercises veda.droppriv -- it uses VEDA_DROP_TO_USER -- and the instruction no longer decodes anywhere. Same for veda_smoke_m6.S:39, whose inline comment ends \"privileged by default, no droppriv in this test\": harmless in effect, but it names a retired instruction as though it were still available to name.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "\"# the privilege drop is exercised only by the separate negative test.\" Same substitution in veda_smoke_m6.S:39."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv",
            "line": 1946,
            "quote": "encoding). `veda.droppriv` lives in Custom-3 -- explicitly \"Reserved, unallocated\" in this file's own ISA summary since the very first draft, exactly the room this project has repeatedly reserved for real, later growth rather than overloading an already-populated opcode.",
            "why_stale": "JUDGED NOT STALE, recorded so the parent knows it was checked. The present tense is superseded in place: the R36 block at lines 1952-1960 directly below states Custom-3 is unclaimed again and that every Custom-3 encoding now falls through to $base_undef_encoding and raises Illegal_Instruction. A reader cannot see the old text without the correction. No fix needed.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "None. Optionally prefix the older block with \"Milestone 4 wrote:\" so the two paragraphs read as a dated pair."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/VEDA_CORE_TECHREPORT.md",
            "line": 37,
            "quote": "Custom-0/1/2; Custom-3 deliberately left unallocated, following CHERI's own documented 13-year lesson of needing more encoding room than initially planned",
            "why_stale": "JUDGED NOT STALE -- in fact this is the one document that now reads correctly. It was arguably wrong while the RTL's droppriv occupied Custom-3; R36 made it true again. Flagged only to close out the Custom-3 prong of the sweep. No fix needed.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "None."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_3_RESULTS.md",
            "line": 13,
            "quote": "This core's RTL has **no privileged architecture at all** (no CSRs, no privilege-mode register) — confirmed by re-checking the base core before starting, not assumed.",
            "why_stale": "JUDGED HISTORICAL, not reported as a fix. It sits under the heading \"Real scoping decision made before writing any code\" and line 27 immediately says ODT-Populate/Destroy \"become Milestone 4, once the privilege concept exists\" -- so the text dates itself. It was already falsified by Milestones 4 and 9 long before this session, and rewriting it would rewrite history. Same judgement for MILESTONE_1_RESULTS.md:64-65 (\"This core's RTL has no privileged/trap architecture at all yet\"), where \"yet\" does the same work.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "None."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/sim/veda_smoke_r36_priv_trap.S",
            "line": 10,
            "quote": "//   * $priv had exactly one writer -- veda.droppriv, Custom-3, one-way, with no",
            "why_stale": "JUDGED CORRECT HISTORY, the model case for the brief's judgement rule. Past tense (\"had\"), inside the R36 test's own explanation of what R36 changed. Recording that droppriv once existed is exactly what this file should do.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "None."
          }
        ],
        "summary": "Swept truth item 1 (veda.droppriv, Custom-3, one-way $priv, MRET-as-PC=mepc, absent mstatus, ECALL's mcause) across all 122 impl-repo .md files, the 11 design-repo .md files, model/extensions/Veda/*.sail, and rtl/veda_core.tlv, skipping the 11 files named as already-handled. 22 stale items in 15 files, plus 4 recorded as correct history.\\n\\nThe single most valuable hit is in the live RTL, not a document: veda_core.tlv:1372-1375 still tells the reader \"this core has no privilege-level stack to restore ... MRET here means exactly 'PC = mepc', not a full mstatus.MPP/MPIE restore\" -- three lines above $mret_ok, which does exactly the restore the comment denies, and one screen below the R36 block that says so. That comment is also the cited authority for two of the doc hits (MILESTONE_9_RESULTS.md:70-74, which states the same thing in the present tense, and MILESTONE_19_RESULTS.md:25-27, which forwards to it and adds the now-false \"every CSR write in this file is implicitly M-mode-only\" -- false since R39's csr[9:8] check). Fixing the RTL comment first makes the other two mechanical.\\n\\nThe ECALL prong has exactly one hit: MILESTONE_23_RESULTS.md:30-31, \"the only possible value since this core only ever runs M-mode\". The mux is now `$is_ecall ? ($priv ? 64'h0B : 64'h08) : 64'h18` at veda_core.tlv:5228. Every other mcause==11 reference in the corpus (MILESTONE_21, MILESTONE_C's switcher guard) describes an M-mode ecall and is still correct.\\n\\nThe droppriv prong reaches into the design repo, which matters more than the results files because those are premises for unbuilt work: README.md:60 lists droppriv in a column headed \"Builds on (verified)\", and DESIGN_05 names it twice, once as a \"Builds on:\" dependency and once as the current model, \"(1-bit $priv + one-way droppriv + ODA authority)\". MINIMAL_OS_KERNEL_DESIGN.md rests its Finding 3 on \"Veda-Core's existing M-mode-only design\" and lists S/U-mode transitions as a standing limitation -- a gap R36 closed for U-mode on both layers.\\n\\nFour deliberate judgement calls. (1) I did not report the ordinary \"Not yet built\" lists in MILESTONE_5/6/8/13, except the two that name a privilege-raising mechanism as out of scope (M5:130, M6:130), since R36's trap-raises-to-Machine is exactly that; every milestone's gap list is superseded by the next milestone, and reporting them all would drown the real hits. (2) veda_core.tlv:1946 says \"veda.droppriv lives in Custom-3\" in the present tense but is corrected in place six lines later, so it is not stale. (3) VEDA_CORE_TECHREPORT.md:37 (\"Custom-3 deliberately left unallocated\") was arguably wrong while droppriv occupied the opcode and is now correct again -- no action. (4) The five .S test files with stale droppriv headers are outside the four corpus locations you listed; I included them because they are unambiguous droppriv assertions a reader will hit, but they are separable if you want to hold the line at .md/.sail/.tlv.\\n\\nTwo things I found that belong to other sweeps, flagged so they are not lost: veda_smoke_m11.S:13-15 asserts \"this project's own Sail test config has S/U-mode disabled, so privilege can never actually drop below Machine there\" (truth item 5), and MILESTONE_19_RESULTS.md:48 makes the same claim about vc_purecap_csr_privgate.S. The Sail model itself (model/extensions/Veda/*.sail) is clean -- zero mentions of droppriv or Custom-3, consistent with it never having had them."
      },
      {
        "hits": [
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_21_RESULTS.md",
            "line": 17,
            "quote": "confirmed via grep: called exactly once, unconditionally, from `sys/sys_control.sail`'s own `trap_handler()`, for every Machine-delegated exception *and* interrupt alike — the only real privilege-delegation path in this project's own test config, S/U-mode being disabled).",
            "why_stale": "Asserts as a currently-load-bearing architectural premise that S/U-mode is disabled in the Sail test config. It is not: veda_test_sail.json:481-486 sets both `\"S\": {\"supported\": true}` and `\"U\": {\"supported\": true}` (since commit 993a104, 2026-08-10). This matters beyond wording, because the premise is what the milestone offers as proof that hooking `handle_trap_extension` is exhaustive over every trap source. That conclusion happens to survive, but for two different reasons I checked directly: `trap_handler()` calls `handle_trap_extension` in BOTH arms (sys_control.sail:222 Machine, :248 Supervisor), and `medeleg.delegatable_bits.value` is `0x0` in the test config, so no trap can be delegated away regardless. A reader who audits the exhaustiveness claim today finds the stated reason false and cannot tell whether the fix is still sound.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Replace \", S/U-mode being disabled)\" with the reason that actually holds: \", and in both the Machine and Supervisor arms of `trap_handler()` (`sys_control.sail:222`, `:248`) -- so the hook is exhaustive even though the test config now enables S/U-mode, and `medeleg` has zero delegatable bits regardless).\""
          },
          {
            "file": "/home/prabhu/veda-core-sail-riscv/model/postlude/step_ext.sail",
            "line": 229,
            "quote": "// alike -- the only real privilege-delegation path in this project's own\n// test config, S/U-mode being disabled). Called after `mepc`/`mcause`/",
            "why_stale": "The live source-comment twin of the MILESTONE_21_RESULTS.md hit above -- the same sentence was copied into the model itself, directly above the `handle_trap_extension` body it justifies. Being in the Sail source rather than a .md makes it worse, not better: it is the comment a future maintainer reads before touching the hook, and it now states a false premise about the test config. (Strictly this file is `postlude/`, not the `extensions/Veda/*.sail` glob named in the scope list -- flagging it because it carries the identical claim and a fix to the milestone doc alone would leave the model asserting it.)",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Same edit as the milestone doc: replace \", S/U-mode being disabled)\" with a note that the hook fires in both the Machine and Supervisor arms of `trap_handler()` (`sys_control.sail:222`, `:248`), so the exhaustiveness holds now that S/U are enabled."
          },
          {
            "file": "/home/prabhu/veda-core-sail-riscv/model/extensions/Veda/veda_regs.sail",
            "line": 1212,
            "quote": "// project's own Sail test config genuinely cannot produce two real,\n  // concurrently-executing harts (a real, distinct limitation named in\n  // MILESTONE_11_RESULTS.md for an unrelated reason, S/U-mode being\n  // disabled there)",
            "why_stale": "Present-tense claim, in the live model, that S/U-mode is disabled in this project's Sail test config. Now false (both `\"supported\": true`). Only the parenthetical is wrong -- the surrounding claim (the single-process simulator cannot run two concurrent harts, so the owner_hart fixture is injected directly) is still correct and should survive the fix.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Delete the clause \", S/U-mode being disabled there\" and the now-misleading cross-reference, leaving: \"(a real, distinct limitation named in MILESTONE_11_RESULTS.md for an unrelated reason)\". The multi-hart limitation stands on its own without it."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MINIMAL_OS_KERNEL_DESIGN.md",
            "line": 238,
            "quote": "- **S/U-mode privilege transitions** — unchanged from this project's own already-documented\n  limitation (`MILESTONE_11_RESULTS.md`); the capability-context-only privilege model (Finding 3)\n  is deliberately independent of ring levels, not a workaround for their absence.",
            "why_stale": "This is a live out-of-scope list in a design document (not a milestone record), and it asserts as currently true that the Milestone-11 limitation is \"unchanged\". It has changed twice over: the Sail test config now has S/U `\"supported\": true`, and privilege now genuinely drops below Machine on both layers via `mstatus.MPP` + `mret`. A reader planning the kernel work would still believe ring transitions are untestable here and would scope around a barrier that no longer exists.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Rewrite the first clause only, keeping the design point: \"- **S/U-mode privilege transitions** -- no longer a test-config limitation: the Sail config now sets S/U `\\\"supported\\\": true` and privilege drops via `mstatus.MPP` + `mret` on both layers. Still deliberately out of scope here, because the capability-context-only privilege model (Finding 3) is independent of ring levels by design, not for want of them.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_13_CRF_EXHAUSTION_DECISION.md",
            "line": 66,
            "quote": "need M-mode or a carve-out, untested anywhere in the corpus, possibly unverifiable given the\n   S/U-mode-disabled Sail config. The spill/restore approach touches no privilege boundary at all.",
            "why_stale": "A standing design-decision record, whose rejection of the \"4th SCR (GDC)\" option rests partly on the claim that a U-mode carve-out would be unverifiable because the Sail config disables S/U. That reason is now false, so one of the recorded costs of the rejected option has evaporated. Anyone reopening this decision (the doc exists precisely to be reopened) would weigh it on a premise that no longer holds.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Strike \"possibly unverifiable given the S/U-mode-disabled Sail config\" and add a dated correction: \"(2026-08-10: the Sail config now sets S/U `\\\"supported\\\": true`, so a U-mode carve-out IS verifiable -- the remaining cost, an untested M-mode requirement on every compartment-body access, stands on its own.)\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_19_RESULTS.md",
            "line": 48,
            "quote": "- `vc_purecap_csr_privgate.S` — confirms `0x7C5` is read/write-able from Machine mode. A true non-M-mode negative case can't be exercised in this project's own Sail test config (S/U-mode both `\"supported\": false`) — the same real, already-documented scope limitation Milestone 11 hit for `OSpecialRW`'s own privilege gate, stated honestly here too rather than silently skipped.",
            "why_stale": "Dated 2026-08-01, when the quoted config value was genuinely `false`, so the record of what was tested at Milestone 19 is accurate history. What is stale is that it states a REMAINING TEST GAP -- \"a true non-M-mode negative case can't be exercised\" -- and that gap has since been closed: the config flipped to `\"supported\": true` on 2026-08-10, and DESIGN_07's R39 records a real probe entering U-mode and confirming `csrr x10, 0x7c1` raises Illegal_Instruction. Left as-is, it tells a future test author that a negative case for 0x7C5 is impossible when it is now both possible and already proven.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Keep the sentence as the Milestone-19 record and append a dated closure note, e.g. \" **[CLOSED 2026-08-10: the Sail test config now sets S/U both `\\\"supported\\\": true`; the non-M-mode negative case is exercisable and has since been exercised -- see DESIGN_07 R39.]**\" Do not rewrite the original finding."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_14_RESULTS.md",
            "line": 36,
            "quote": "`Perms`-on-PCC, S/U-mode-privilege interaction, and real multi-hart RTL all remain exactly as named in `PCC_COMPARTMENT_DESIGN.md`'s own \"Deliberately out of scope\" section (§7) and `MILESTONE_12_RESULTS.md`'s \"Not yet built\" — none touched or affected by this milestone.",
            "why_stale": "Reported for completeness as NOT stale on its own terms. Dated 2026-07-26, it is a \"Not yet built\" record scoped to Milestone 14 and it makes no independent claim about the Sail config -- it defers entirely to PCC_COMPARTMENT_DESIGN.md §7, which is already on the being-fixed list. Flagging only so the cross-reference is not orphaned: once §7 is corrected, this pointer inherits the correction and needs no edit.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "No change. Verify only that PCC_COMPARTMENT_DESIGN.md §7 still exists under that heading after its own edit, so this reference does not dangle."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_20_RESULTS.md",
            "line": 10,
            "quote": "This required no special preconditions — it works with only M-mode enabled, no S/U-mode needed, using only instructions and CSRs that already existed.",
            "why_stale": "Reported for completeness as NOT stale. Dated 2026-08-01, and the load-bearing claim -- the compartment self-escape PoC needed no S/U-mode -- remains true today and is if anything strengthened by S/U now being enabled. The incidental phrase \"with only M-mode enabled\" described the config at the time and reads as a property of the exploit, not an assertion about today's config. No reader is misled into a wrong action.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "No change needed. If touched for another reason, \"it needed no S/U-mode\" would be marginally cleaner than \"it works with only M-mode enabled\"."
          }
        ],
        "summary": "Six real hits plus two verified-clean-on-inspection entries, out of 122 impl-repo docs, 11 design-repo docs, and the Sail model.\n\nGround truth I established myself rather than assumed: `/home/prabhu/veda-core-sindhu/veda-core/sail_tests/veda_test_sail.json:481-486` has `\"S\": {\"supported\": true}` and `\"U\": {\"supported\": true}`. Git history of that file shows exactly when it changed -- `false` at 974ffcd (2026-07-26) and 3543e3b (2026-08-08), flipping to `true` at 993a104 (2026-08-10, \"Empirically verify Veda-Core's compartmentalization model at U-mode\"). That single date is the whole judgement axis for this sweep: text written before 2026-08-10 was accurate when written.\n\nApplying that axis, the six hits split into two genuinely different problems:\n\n(1) THREE documents assert S/U-disabled as a live premise, and all three need a real edit. `MILESTONE_21_RESULTS.md:17` and its verbatim copy in the Sail model at `postlude/step_ext.sail:229` use it as the proof that hooking `handle_trap_extension` is exhaustive over every trap source. I checked whether the conclusion survives: it does, but not for the stated reason -- `trap_handler()` calls the hook in BOTH the Machine and Supervisor arms (`sys/sys_control.sail:222` and `:248`), and `medeleg.delegatable_bits.value` is `0x0` in the config anyway. So the fix is still sound and the justification for it is now false, which is the worst combination for an auditor. `extensions/Veda/veda_regs.sail:1212` carries the claim in the live model as a present-tense parenthetical; only the parenthetical is wrong, the multi-hart limitation around it is fine.\n\n(2) THREE documents state a gap or a cost that the config flip has since dissolved. `MILESTONE_19_RESULTS.md:48` says a non-M-mode negative case for CSR 0x7C5 \"can't be exercised\" -- accurate history for 2026-08-01, but it is a remaining-gap statement, and DESIGN_07's R39 has since done exactly that test from U-mode. `MINIMAL_OS_KERNEL_DESIGN.md:238` claims the Milestone-11 limitation is \"unchanged\", in a live design doc's out-of-scope list. `TOOLCHAIN_MILESTONE_13_CRF_EXHAUSTION_DECISION.md:66` prices the rejected \"4th SCR (GDC)\" option partly on the carve-out being \"possibly unverifiable given the S/U-mode-disabled Sail config\" -- a decision record written to be reopened, now resting on a dead premise.\n\nTwo candidates I read in full and cleared rather than reporting as stale: `MILESTONE_14_RESULTS.md:36` (a Milestone-14 \"Not yet built\" entry that makes no config claim of its own and merely points at PCC_COMPARTMENT_DESIGN.md §7, already on your fix list) and `MILESTONE_20_RESULTS.md:10` (its load-bearing claim, that the self-escape PoC needed no S/U-mode, is still true). I listed both as HISTORICAL_OK so you can see they were checked, not missed.\n\nAlso checked and genuinely clean: `OSPECIALRW_PRIVILEGE_GATING_AUDIT.md` -- it surfaced on every grep, but reading it end to end shows it only discusses the M-mode-only *gate design* for OSpecialRW, and never claims anything about the test config. Same for the `M-mode-only` mentions in `MINIMAL_OS_KERNEL_DESIGN.md:65-67`, `TOOLCHAIN_MILESTONE_7_RESULTS.md:18`, `rtl/MILESTONE_3_RESULTS.md:15` and `extensions/Veda/veda_ocl_insts.sail:591`: all about where a gate sits, not about what the config supports. Design-repo `DESIGN_05`/`DESIGN_06`/`README.md` mention `droppriv` and an undecided S-mode, but that is truth item 1 territory, not item 5, so I left them alone.\n\nOne adjacent thing I found but deliberately did NOT file as a hit, since it falls under truth item 1 rather than item 5 and another sweep will likely catch it: `rtl/MILESTONE_19_RESULTS.md:25-26` says \"no privilege check needed beyond what already exists (this core has no S/U-mode concept yet; every CSR write in this file is implicitly M-mode-only...)\". The RTL's own comments at `rtl/veda_core.tlv:4879-4900` now document the opposite -- a generic `check_CSR_priv` gate landed with R39, gating reads as well as writes. Worth routing to whoever owns the privilege-model sweep."
      },
      {
        "hits": [
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/sail_tests/PHASE2_SAIL_RESIDENCY_RESULTS.md",
            "line": 28,
            "quote": "A page-out leaves `valid` true (the object still exists) and does not bump `generation` (only Populate and Destroy do).",
            "why_stale": "This is truth item 6's forbidden claim almost verbatim. `VEDA_ODT_PAGE_OUT` sets `generation = old_entry.generation + 1` (veda_ocl_insts.sail:1171) and the RTL mirrors it; page-out is a third generation bumper. The sentence is not framed as history -- it is the present-tense architectural premise for section 2.1's design argument, and the conclusion it supports (\"So **nothing existing would notice**\") is now false: a capability held across an eviction is caught by the generation-staleness term first. RTL_MIRROR_06_PAGING_RESULTS.md:192-194 already says exactly that (\"the dereference-side residency term is unreachable through the ISA, because page-out bumps generation\"), so this document now contradicts its own RTL mirror.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Date the claim to the increment: \"A page-out would leave `valid` true and, *as the design stood at this increment* (before the page-out/page-in pair of increment 2), would not bump `generation`. Increment 2 made page-out bump it, which is why the dereference term is now unreachable through the ISA -- the residency gate is retained on the soundness argument, not on reachability.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/sail_tests/PHASE2_SAIL_RESIDENCY_RESULTS.md",
            "line": 185,
            "quote": "- **COW is bypassable as DESIGN_02 currently describes it** -- found while grounding this increment, recorded for the next one. Bind mints `Perms = e.Perms` verbatim, with no attenuation, on all three bind modes; CAndPerm writes only the register and never the table. So a domain that can name a COW object's Object_ID can simply re-Bind it and get a writable capability. COW must be enforced by hardware attenuation at Bind, not by software having handed out attenuated capabilities.",
            "why_stale": "Stated remaining gap, since closed. `veda_bind_perms` is now `if e.cow then e.Perms & 0xFFF7 else e.Perms` (veda_regs.sail:983) and the RTL masks with `16'hFFF7` on BOTH the Bind arm and the Rebind arm (veda_core.tlv:3137 and :3152, the latter added by R23b). Re-Binding a cow object no longer yields a writable capability -- it yields one with PERM_STORE cleared by construction, which is exactly the \"hardware attenuation at Bind\" this bullet asks for. The bullet's last sentence now reads as an open demand for work already done on both layers.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Append one sentence: \"**Closed.** `veda_bind_perms` now masks a cow entry's Perms with `0xFFF7` (PERM_STORE, bit 3) on all three bind modes in Sail and on both the Bind and Rebind arms in the RTL, so re-Binding the name cannot escape the attenuation.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/sail_tests/PHASE2_SAIL_RESIDENCY_RESULTS.md",
            "line": 178,
            "quote": "- **There is no evict instruction**, so a non-resident object can only be reached by reset seeding.",
            "why_stale": "Stated remaining gap, since closed by increment 2. `veda.odt.page.out` exists on both layers (veda_ocl_insts.sail:1101, veda_core.tlv:1999/2634) and is the sole producer of `{valid, not resident}`, so a non-resident object is now reachable by a live transition, not only by reset seeding. The follow-on sentence (\"A test that binds while resident, evicts, then dereferences cannot be written yet\") is also superseded -- `vc_paging_full_cycle` is exactly that test.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Mark the bullet as closed: \"**There is no evict instruction *at this increment*** ... **Closed in increment 2**: `veda.odt.page.out` makes the transition live, and `vc_paging_full_cycle` is the bind-evict-dereference test this bullet said could not yet be written.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/sail_tests/PHASE2_SAIL_PAGING_RESULTS.md",
            "line": 37,
            "quote": "| gate | `valid & resident & generation != 0xFFFFFF` | `valid & not resident` |",
            "why_stale": "This row is the document's statement of what page-out accepts, and it is now incomplete in the direction that matters for truth item 2: R38(b) added `else if old_entry.cow then Illegal_Instruction()` (veda_ocl_insts.sail:1158), mirrored in the RTL's `$veda_odt_page_out_refusal` (veda_core.tlv:2634ff). A copy-on-write object is NOT pageable, because paging would bump the generation and destroy the split entitlement held by the pre-cow capabilities. As written, the table tells a reader page-out is available on any live resident object. (The same row also predates R11(b)'s executing-object pin, which is a separate finding's territory.)",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Change the page-out gate cell to `valid & resident & not cow & generation != 0xFFFFFF` and add a footnote: \"the `not cow` conjunct was added by R38(b) -- paging bumps the generation, which would destroy the copy-on-write split right that lives only in the capabilities minted before `set.cow`.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/RTL_MIRROR_06_PAGING_RESULTS.md",
            "line": 160,
            "quote": "| gate | authority & valid & resident & gen != 0xFFFFFF | authority & valid & not resident |",
            "why_stale": "Same defect as the Sail-side table, under the heading \"## 5. The paging contract, as built\", which reads as the current contract rather than as a snapshot. The RTL's actual refusal expression now also contains the R38(b) cow conjunct (veda_core.tlv:2634-2646: `... || !$veda_odt_resident || // R38(b): a copy-on-write object is not pageable`). A reader taking this table as the built contract would believe any live resident object can be evicted.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Change the page-out gate cell to `authority & not executing & valid & resident & not cow & gen != 0xFFFFFF`, or minimally insert `& not cow` and note \"R38(b): copy-on-write objects are not pageable\"."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_7_RESULTS.md",
            "line": 30,
            "quote": "- **The generation-counter retirement threshold is exactly 256 real Destroy calls**, independently re-derived from `veda_ocl_insts.sail`'s `VEDA_ODT_DESTROY` execute clause (`new_generation` bumps unconditionally every call; `new_retired` fires once `old_entry.generation == 0xff`) and cross-checked against `sail_tests/vc_gen_retire_neg.S`'s own real `.rept 256` test -- both agree exactly.",
            "why_stale": "Asserts Destroy is the sole consumer of a slot's generation budget. It is not: `veda.odt.page.out` bumps the generation on every eviction (veda_ocl_insts.sail:1171), which PHASE2_SAIL_PAGING_RESULTS.md:200 itself records as \"Each page-out consumes one of 2^24 generations for that slot\". This is load-bearing rather than cosmetic, because the very next bullet (lines 36-42) makes it a standing obligation on live runtime code: the runtime's `g_destroy_count[]` mirror \"must exactly replicate hardware's own per-call bump rule or the two states silently diverge\". A mirror that counts only Destroys now silently under-counts once any object is paged. (The `0xff` / 256 figures are separately superseded by the 8 -> 24-bit generation widen, but that is the ceiling, not the bump rule.)",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Qualify to the milestone and name the second consumer: \"**At Milestone 7, Destroy was the only generation consumer** and the threshold was 256 Destroy calls on the 8-bit counter. Both facts have since changed: the counter is 24 bits, and `veda.odt.page.out` also bumps the generation -- so a software mirror that counts Destroys alone will diverge from hardware for any object that is paged.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_22_RESULTS.md",
            "line": 29,
            "quote": "staleness can only arise the intended way (destroy-then-repopulate after a capability was already bound elsewhere)",
            "why_stale": "An 'only' claim about what makes a capability stale, written in the general present tense inside an audit that concludes \"No gap found\". Page-out is now a second, entirely intended producer of staleness -- it bumps the generation precisely so that every outstanding capability stops validating across an eviction. A reader auditing temporal safety from this paragraph would not know paging is in the producer set. The neighbouring enumeration in the same sentence (`Destroy` always bumps; `Populate` bumps only when overwriting a still-valid slot) is correct but likewise no longer the complete set.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Scope the claim to the audit's date: \"...staleness can only arise the intended ways -- **as of this milestone**, destroy-then-repopulate; `veda.odt.page.out`, added in Phase 2 increment 2, is the second intended producer and bumps the generation for the same reason.\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/MUTATION_CENSUS_DEREF.md",
            "line": 31,
            "quote": "an object's generation is bumped on Destroy and on page-out, and this term is what refuses a capability whose generation no longer matches",
            "why_stale": "NOT STALE -- reported so it is not re-flagged. This is the one place in the ~110-document corpus that states the generation-bump producer set correctly and includes paging. It matches veda_ocl_insts.sail:1171 and veda_core.tlv exactly. Leave as is.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "No change."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/MUTATION_CENSUS_DEREF.md",
            "line": 65,
            "quote": "In that test the object is **also copy-on-write**, so with the bounds term removed from the violation expression `$veda_cow_write` still fires the trap -- and the cause chain, where bounds correctly precedes cow, still reports 0x01.",
            "why_stale": "NOT STALE -- verified rather than assumed, because it looks like a pre-R38 claim. R38 changed only the CAUSE chain (the 0x13 arm is no longer gated on `!$veda_cow_write` and now sits above bounds); the violation OR-expressions are untouched, so `$veda_cow_write` does still fire the trap for any holder. And the capability P3/P4/P5 use is bound at rtl/sim/veda_smoke_check_order.S:37 with the explicit comment \"(BEFORE cow: keeps store)\", so it retains PERM_STORE, does not take the 0x13 arm, and still reports 0x01. Bounds still precedes cow in `$veda_ocs_cause` (veda_core.tlv:4475-4481).",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "No change."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/RTL_MIRROR_09_EXECUTING_PIN_RESULTS.md",
            "line": 38,
            "quote": "| `veda.odt.page.out` | yes | clears residency, bumps generation |",
            "why_stale": "NOT STALE -- reported for the same reason. This consumer-set table is correct and current for truth item 6: it lists page.out as a generation bumper alongside populate/populate.fast/destroy, and correctly excludes page.in. Consistent with veda_ocl_insts.sail:1171 and :1244.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "No change."
          }
        ],
        "summary": "Swept all ~110 non-excluded documents in /home/prabhu/veda-core-sindhu/veda-core (**/*.md), /home/prabhu/veda-core/design/*.md and /home/prabhu/veda-core/*.md for claims about COW eligibility, who may cause a split, the bind-time 0xFFF7 mask, the COW fault firing for any holder, page-out availability on a live resident object, and the generation-bump rules (truth items 2, 4, 6). Ground truth was read first from veda_ocl_insts.sail (VEDA_ODT_PAGE_OUT gate at :1101-1180, generation+1 at :1171), veda_regs.sail:983 (veda_bind_perms 0xFFF7), and veda_core.tlv ($veda_odt_page_out_refusal at :2634, bind/rebind masks at :3137/:3152, cause chains at :4468-4545).\n\nSEVEN REAL HITS, concentrated in four files.\n\nGeneration-bump rules (item 6): three. PHASE2_SAIL_RESIDENCY_RESULTS.md:28 carries truth item 6's forbidden claim almost verbatim (\"does not bump `generation` (only Populate and Destroy do)\") and it is the premise of that section's whole design argument -- it now contradicts its own RTL mirror. TOOLCHAIN_MILESTONE_7_RESULTS.md:30 asserts Destroy is the sole generation consumer and turns that into a standing obligation on live runtime code (`g_destroy_count[]` \"must exactly replicate hardware's own per-call bump rule\"), which page-out now breaks. MILESTONE_22_RESULTS.md:29 asserts staleness \"can only arise\" via destroy-then-repopulate.\n\nPage-out availability (item 2): two, and they are the same defect in the two mirrored contract tables -- PHASE2_SAIL_PAGING_RESULTS.md:37 and RTL_MIRROR_06_PAGING_RESULTS.md:160 both give the page-out gate as `valid & resident & gen != 0xFFFFFF` with no `not cow` conjunct, so both tell a reader page-out is available on any live resident object. RTL_MIRROR_06's table sits under \"The paging contract, as built\".\n\nBind-time 0xFFF7 mask (item 2): one. PHASE2_SAIL_RESIDENCY_RESULTS.md:185 still records \"COW is bypassable ... a domain that can name a COW object's Object_ID can simply re-Bind it and get a writable capability\" as an open gap and demands the hardware attenuation that R23b/R38 have since built on both layers. The adjacent line 178 (\"There is no evict instruction\") is a second closed gap in the same section.\n\nPOPULATE POLICY RESET (item 4): NOTHING FOUND, and this is a real negative, not a gap in the sweep. `owner_domain`, `VEDA_DOMAIN_ANY`, `veda.odt.set.domain` and any Populate carries/preserves-policy claim appear in exactly one non-excluded document line (DESIGN_08_OBJECT_NAMESPACE_SCALE.md:53, a proposed region-table field list, which says nothing about Populate's write set). R41's subject matter is documented only inside the files you already have open.\n\nAlso worth knowing: outside the excluded set there is almost NO copy-on-write documentation at all -- `\\bcow\\b` matches only 13 lines across the whole corpus, and the R38/R38(b)/R19 reasoning lives entirely in code comments (veda_ocl_insts.sail:100-260 and :1118-1160, veda_core.tlv:4390-4470), which I verified are current and correct. Three near-misses that a faster sweep would have mis-flagged are reported as HISTORICAL_OK with the verification that cleared them, including MUTATION_CENSUS_DEREF.md:65, which I checked against rtl/sim/veda_smoke_check_order.S:37 rather than assuming.\n\nOne thing I saw and deliberately did not report as a hit, because it falls outside items 2/4/6: RTL_MIRROR_06_PAGING_RESULTS.md:36 and :114 speak of \"a future `cow` at +26\" and \"`cow` and `backing` will add readers\". `cow` is built in the RTL and sits at ODT_OFF_COW = 29, not 26. That belongs to whoever is sweeping built-vs-unbuilt status."
      },
      {
        "hits": [
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_13_DESIGN.md",
            "line": 201,
            "quote": "bound over the whole in-memory table (read-write, `Perms = 0x000C`, its own dedicated small `Object_ID`",
            "why_stale": "This is the design's prescription for the compiler-reserved global capability TABLE object -- the one container in the toolchain whose entire job is to hold capabilities. The same document's bootstrap (lines 210-213) writes each per-global capability into it with `OCS.C` and reads it back with `OCL.C`. Post-R40, PERM_LOAD_CAPABILITY (bit 4) and PERM_STORE_CAPABILITY (bit 5) are ENFORCED at OCL.C/OCS.C on both layers, and `0x000C` = Permit_Load|Permit_Store only -- bits 2 and 3, neither 4 nor 5. Every table-slot `OCS.C` in that bootstrap now raises cause 0x15 and every table read via `OCL.C` raises 0x14. Verified against ground truth: veda_types.sail:222-223 (bit assignments), veda_ocl_insts.sail:100 and :173 (the enforcement arms), veda_core.tlv:3439-3440 and :3531-3532 (the RTL twins). The RTL made exactly this correction for its own scratch fixture -- veda_core.tlv:320-325, \"R40: 16'h103C, not 16'h100C ... several tests spill a CAPABILITY into it; once those two permissions became real, a container lacking them could no longer hold one\" -- but the toolchain's CAP_TABLE_REGION was never given the same treatment, in this doc or in compiler/veda_struct_array_global_entry.S:63, which still ORs `0x000C`. So the doc and the code agree with each other and both now disagree with the architecture.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Change `Perms = 0x000C` to `Perms = 0x003C` (Load|Store|Load_Capability|Store_Capability) and add a clause: \"bits 4 and 5 are required, not optional -- R40 made PERM_LOAD_CAPABILITY/PERM_STORE_CAPABILITY enforced at OCL.C/OCS.C, and this object exists to carry capabilities.\" The per-global capabilities STORED in the table (lines 108-118, `0x0004`/`0x000C`) are unaffected -- the checked permission is the table capability's, not the stored value's."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_15_RESULTS.md",
            "line": 37,
            "quote": "into the descriptor's Length field and OR'd with the unchanged `Perms=0x000C` (Load|Store).",
            "why_stale": "Same defect, second document, and this one names the CAP_TABLE_REGION descriptor as it stands today (\"unchanged\"), so a reader takes it as the current, correct permission set for the capability table. It is an accurate description of compiler/veda_struct_array_global_entry.S:63 -- which is precisely why it now misleads: 0x000C carries neither PERM_LOAD_CAPABILITY (bit 4) nor PERM_STORE_CAPABILITY (bit 5), and R40 made both enforced at the OCS.C/OCL.C accesses this very table depends on.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Append after \"(Load|Store)\": \"-- since R40 this must be `0x003C`; bits 4/5 (Load_Capability/Store_Capability) are now enforced at the `OCS.C`/`OCL.C` this table is accessed through.\" Do not silently rewrite the value alone; the sentence records a real edit and the correction belongs beside it."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/MUTATION_CENSUS_DEREF.md",
            "line": 50,
            "quote": "| `oclc` (capability load) | 4/7 |",
            "why_stale": "The census's unit is \"one term of the violation expression\", and it states OCL.C's expression has 7 terms. R40 added an eighth: veda_core.tlv:3531 is now `!tag || gen_stale || sealed || !perm_load_ok || !perm_loadcap_ok || !oclc_bounds_ok || capmem_misaligned || deref_nonresident`. The denominator is now 8, and more importantly the row is the doc's only statement of what OCL.C enforces -- a reader takes the 7 terms as the complete check set and concludes no capability-flow permission is checked on that path.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Either restate as `4/8 (as censused; term 8 = !$veda_perm_loadcap_ok added by R40, not covered by this run)` or add a dated banner at the top of the file saying the census predates R40 and the oclc/ocsc expressions have each gained one permission term since."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/MUTATION_CENSUS_DEREF.md",
            "line": 47,
            "quote": "| `ocsc` (capability store) | 3/8 |",
            "why_stale": "Same as the oclc row. OCS.C's violation expression now has 9 terms, not 8 -- veda_core.tlv:3532 gained `!$veda_perm_storecap_ok` under R40. The row presents 8 terms as the complete enforcement layer for the capability store path, which now omits the check that governs whether authority may be written into memory at all.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Restate as `3/9 (as censused; term 9 = !$veda_perm_storecap_ok added by R40)`, or cover it with the same file-level banner."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/MUTATION_CENSUS_DEREF.md",
            "line": 3,
            "quote": "**22 of 54 mutants SURVIVED. 41% of the trap-decision layer is unverified.**",
            "why_stale": "Two independent reasons, both post-dating the run. (1) The denominator: 54 was the total term count across the seven dereference violation expressions; R40 added one term to oclc and one to ocsc, so the layer is now 56 terms and 54 no longer names it. (2) All 22 survivors have since been closed -- veda_smoke_uaf.S (the 6 $veda_gen_stale survivors), veda_smoke_deref_guards.S (the 6 $veda_sealed survivors plus the 3 bounds-as-trap-decision ones), and veda_smoke_perm_cow_align.S, whose own header says \"The last seven census survivors\": 6+9+7 = 22. The sentence is stated in the present tense and is the first thing a reader sees.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Add a status line directly under the title: \"**Superseded.** All 22 survivors closed by veda_smoke_uaf.S, veda_smoke_deref_guards.S and veda_smoke_perm_cow_align.S. The layer is now 56 terms, not 54 -- R40 added one permission term to each of oclc and ocsc, both uncensused.\" Keep the body as the historical measurement it is."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/MUTATION_CENSUS_DEREF.md",
            "line": 79,
            "quote": "3. `!$veda_perm_load_ok` on oclc, nmc_add_w, nmc_add_d.",
            "why_stale": "This is item 3 of \"The work list, in priority order\" -- an instruction to go write tests. It has been executed: veda_smoke_perm_cow_align.S was written specifically to close the remaining permission/cow/alignment survivors and its header names them as \"the last seven census survivors\". A reader working this list today would rebuild coverage that exists. It also reads as the complete permission-coverage debt on the capability paths, which it no longer is -- R40's two new permission terms on oclc/ocsc were never censused and so appear nowhere on the list.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Mark the work list \"COMPLETE -- see veda_smoke_uaf.S, veda_smoke_deref_guards.S, veda_smoke_perm_cow_align.S\", and note that `!$veda_perm_loadcap_ok` / `!$veda_perm_storecap_ok` post-date this census and need their own coverage judgement."
          },
          {
            "file": "/home/prabhu/veda-core/design/DESIGN_01_CAPABILITY_FORMAT_RESPEC.md",
            "line": 39,
            "quote": "| Perms | 16 | CHERI-aligned set + Permit_NMC_Compute + Permit_Attenuate + spare |",
            "why_stale": "This is the Perms-bit budget row of the 256-bit format table, and `Permit_Attenuate` does not exist and was deliberately refused. Confirmed by grep: no `PERM_ATTENUATE` in any of the six veda_*.sail files or in veda_core.tlv, and PHASE1_SAIL_RESPEC_256BIT_RESULTS.md:78-80 records the decision verbatim -- \"**`PERM_ATTENUATE` was deliberately NOT added.** CAndPerm is monotonic ... Reserving a permission bit with no consumer would violate this project's own 'speculative, not grounded' rule.\" The rest of this table landed as built (the 256-bit layout is restated concretely at line 195 and mirrored in RTL_MIRROR_02B), so the row reads as the shipped permission budget. The document's own \"Resolved implementation decisions\" section (line 191) explicitly overrides three earlier lines but never this one.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Change the cell to \"CHERI-aligned set + Permit_NMC_Compute + spare\" and, if the refutation is worth preserving in place, add a footnote: \"Permit_Attenuate was proposed here and refused during increment 2 -- CAndPerm is monotonic, so a permission to give away permissions is meaningless (PHASE1_SAIL_RESPEC_256BIT_RESULTS.md).\""
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/SECURITY_COMPARISON_STUDY.md",
            "line": 88,
            "quote": "was exercised here. Veda-Core's other four `veda_check_access` checks",
            "why_stale": "The sentence continues \"(Tag, generation-staleness, Seal, Permission)\" and presents that as the exhaustive set of checks `veda_check_access` performs besides bounds. It is not four any more, and the single undifferentiated \"Permission\" entry is the part that falls inside this sweep: since R40, `veda_check_access` performs two further, separately-caused permission checks -- PERM_LOAD_CAPABILITY (cause 0x14, veda_ocl_insts.sail:100) and PERM_STORE_CAPABILITY (cause 0x15, veda_ocl_insts.sail:173) -- which guard a distinct vulnerability class the sentence's own gloss does not cover: not \"read/write-permission violations\" but whether AUTHORITY may move through memory. Stated honestly, the count was already understated before R40 as well (cow, residency and capability alignment are also in that function), so this is a drifted enumeration rather than a single-cause error.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Replace \"other four ... (Tag, generation-staleness, Seal, Permission)\" with \"other `veda_check_access` checks (Tag, generation-staleness, Seal, data permissions, capability-flow permissions, copy-on-write, residency, capability alignment)\", or drop the count and name only the classes the study actually contrasts."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_1_RESULTS.md",
            "line": 18,
            "quote": "cyc=1  bind fires  -> c0: tag=1 base=0x80010000 length=0x40 perms=0x100c otype=0xffff",
            "why_stale": "NOT STALE -- recorded here so the judgement is visible rather than silent. The reset-seeded Object_ID 1 fixture is now `16'h103C`, not `0x100C` (veda_core.tlv:320-325, mirroring veda_regs.sail:1145-1151), because R40 made bits 4/5 real and the corpus spills capabilities into that object. Seven documents still show `0x100C`: rtl/MILESTONE_1_RESULTS.md:18, rtl/MILESTONE_2_RESULTS.md:43, rtl/MILESTONE_3_RESULTS.md:39, rtl/MILESTONE_6_RESULTS.md:76 and :80, MILESTONE_V-B_RESULTS.md:95, TOOLCHAIN_MILESTONE_4_RESULTS.md:88 and :114, and rtl/RTL_MIRROR_02B_256BIT_FORMAT_RESULTS.md:73. Every one is a captured simulation or CGetPerm transcript -- what the machine actually printed at that milestone. They record history correctly and none asserts the value as a currently-true fixture or instructs anyone to build one. No change wanted. (The one document that DOES state the seed as current architecture, rtl/MILESTONE_PLAN.md:92, is on your already-being-edited list.)",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "None. Leave all eight transcript sites unchanged."
          }
        ],
        "summary": "Swept the ~110 documents outside your already-being-edited list for Perms-bit listings, cause-code tables, and enforced-permission claims, judging each against ground truth read directly from veda_types.sail:218-230, veda_bind_insts.sail:17-138 and veda_core.tlv:3421-3532 / :4483-4507 rather than from memory.\\n\\nThe headline result on truth item 3 is a near-negative, and it matches DESIGN_07's own measurement: the strings LOAD_CAPABILITY, STORE_CAPABILITY, PERMIT_GLOBAL and STORE_LOCAL_CAPABILITY appear in exactly two files in the whole corpus, and both (DESIGN_07, VEDA_CORE_SPEC) are already yours. No document outside your list calls those four bits active, unconsumed, reserved or not-yet-built, because no document outside your list ever named them at all. Nothing claims GLOBAL or STORE_LOCAL_CAPABILITY are enforced.\\n\\nWhat the sweep did turn up is the mirror image of that silence -- eight hits in six files where the four bits' absence, not their presence, is what went stale:\\n\\n1. The most consequential is a real, load-bearing build instruction, not a wording drift. TOOLCHAIN_MILESTONE_13_DESIGN.md:201 and TOOLCHAIN_MILESTONE_15_RESULTS.md:37 both specify the compiler's global capability TABLE -- the one object whose entire purpose is holding capabilities -- with Perms = 0x000C. That is bits 2 and 3 only. Its bootstrap writes every slot with OCS.C and reads them with OCL.C, so post-R40 the documented sequence traps 0x15 on the first store and 0x14 on every read. The RTL made precisely this correction for its own scratch fixture (veda_core.tlv:320-325, \\\"once those two permissions became real, a container lacking them could no longer hold one\\\"); the toolchain's CAP_TABLE_REGION never got it, and compiler/veda_struct_array_global_entry.S:63 still ORs 0x000C -- so doc and code agree with each other and both now disagree with the architecture. Worth a task, not just an edit.\\n\\n2. difftest/MUTATION_CENSUS_DEREF.md is stale on two independent axes (four hits). Its per-chain term counts, 7 for oclc and 8 for ocsc, are now 8 and 9 -- R40 added a permission term to each -- so the file's enumeration reads as the complete check set for the two capability paths while omitting the checks that govern capability flow. Separately, and I verified this rather than taking it from the task list, all 22 survivors are closed: veda_smoke_uaf.S (6 gen_stale), veda_smoke_deref_guards.S (6 sealed + 3 bounds), veda_smoke_perm_cow_align.S (\\\"the last seven census survivors\\\") = 22 exactly. The present-tense headline and the work list both need superseding banners; the body is a legitimate historical measurement.\\n\\n3. DESIGN_01:39 budgets a Permit_Attenuate bit in the Perms field. It does not exist in either layer and was explicitly refused (PHASE1_SAIL_RESPEC_256BIT_RESULTS.md:78-80). The rest of that table shipped, so the row reads as the built permission budget.\\n\\n4. SECURITY_COMPARISON_STUDY.md:88 calls the veda_check_access set \\\"other four ... (Tag, generation-staleness, Seal, Permission)\\\". The lumped \\\"Permission\\\" entry now hides two separately-caused capability-flow checks; I note honestly that this count was already understated before R40.\\n\\nDeliberately NOT reported, and I want this visible rather than silent: eight sites across seven milestone documents still show perms=0x100C for the reset-seeded Object_ID 1, which is now 0x103C. Every one is a captured simulation or CGetPerm transcript of what the machine printed at that milestone -- correct history, no current-truth assertion, no instruction. I recorded one as a HISTORICAL_OK entry listing all eight so you can confirm the judgement rather than re-derive it. I also checked and cleared two false leads: rtl/RTL_MIRROR_02A:35's \\\"Checked after Tag/Seal/Perm and before the bounds fall-through\\\" is still exactly right (alignment still sits below the new 0x14/0x15 arms and above bounds -- veda_core.tlv:4483-4507), and rtl/MILESTONE_10_RESULTS.md:195's \\\"Permit_Set_CID/cause 0x1c ... not yet built\\\" remains true, since PERM_SET_CID is genuinely still unenforced and is not one of R40's four."
      },
      {
        "hits": [
          {
            "file": "/home/prabhu/veda-core/README.md",
            "line": 12,
            "quote": "- **Sail (formal model)** -- `Veda-Core-sail-riscv` fork, branch `phase1-respec`: **76/76**",
            "why_stale": "Suite size. Sail self-check is now 102/102 (truth 7). 76/76 was the Phase-1 R10-CRBR number; Phase 2 (residency, paging, COW, R11..R41) added 26 more tests.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "76/76 -> 102/102, and widen the parenthetical to mention Phase 2 (residency/paging/COW) rather than only the Phase-1 respec items."
          },
          {
            "file": "/home/prabhu/veda-core/README.md",
            "line": 15,
            "quote": "- **RTL (hardware)** -- `veda-core-sindhu`, branch `sindhu`: **64/64** smoke tests through",
            "why_stale": "Suite size and increment marker. RTL smoke is now 90/90 (truth 7) and the line stops at increment RTL-5; RTL-6 (paging), RTL-9 (executing pin), and the R11..R41 mirrors have all landed since.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "64/64 -> 90/90 and 'through increment RTL-5' -> through the Phase-2 mirrors (paging, COW, privilege model)."
          },
          {
            "file": "/home/prabhu/veda-core/README.md",
            "line": 62,
            "quote": "| 07 | `design/DESIGN_07_ROBUSTNESS_AND_SECURITY_HARDENING.md` | Adversarial 6-lens red-team; findings R1-R10 + a proposed 6th pillar (provably non-speculative) | the whole verified base + 01/08 |",
            "why_stale": "Finding count. The DESIGN_07 register now runs R1..R43 with no gaps (truth 7); R1-R10 is the state it had when the index row was written.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "'findings R1-R10' -> 'findings R1-R43'."
          },
          {
            "file": "/home/prabhu/veda-core/README.md",
            "line": 60,
            "quote": "| 05 | `design/DESIGN_05_PURECAP_PRIVILEGE_PROCESS.md` | pointer = capability; privilege = ODA possession | OCL.C/OCS.C, tag memory, ODA, droppriv |",
            "why_stale": "The 'Builds on (verified)' column names droppriv as a verified base mechanism. R36/R39 retired veda.droppriv entirely and left the Custom-3 major opcode unclaimed (truth 1).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Replace 'droppriv' in that cell with 'mstatus.MPP + mret (standard privilege model)'."
          },
          {
            "file": "/home/prabhu/veda-core/README.md",
            "line": 73,
            "quote": "3. **ODT as unified mm** (02) -- residency/COW/backing, Sail-first. **-- next (Phase 2).**",
            "why_stale": "Status marker. Phase 2 is no longer 'next': residency, the page-out/page-in pair and copy-on-write are all built and mirrored on both layers (truths 2 and 6, plus PHASE2_SAIL_RESIDENCY/PAGING and rtl/RTL_MIRROR_06_PAGING).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Mark item 3 '-- DONE, both layers (residency, paging, COW)'; if `backing` is still partial, say so explicitly instead of leaving the whole item as 'next'."
          },
          {
            "file": "/home/prabhu/veda-core/README.md",
            "line": 70,
            "quote": "   **-- DONE, both layers (Sail 72/72, RTL 62/62).**",
            "why_stale": "Suite sizes quoted inside a 'where it stands' status list read as current totals; they are now 102/102 and 90/90 (truth 7). The DONE verdict itself is correct and should stay.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Reword to '-- DONE, both layers (Sail 72/72 and RTL 62/62 at the time; suites now 102/102 and 90/90)'."
          },
          {
            "file": "/home/prabhu/veda-core/design/DESIGN_05_PURECAP_PRIVILEGE_PROCESS.md",
            "line": 5,
            "quote": "OSpecialRW, droppriv, the MOS switcher. **Verification plan:** purecap-compile a",
            "why_stale": "The Status/'Builds on' header lists droppriv as an existing verified mechanism this design builds on. droppriv is retired on both layers and every Custom-3 encoding now raises Illegal_Instruction (truth 1).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Drop 'droppriv' from the Builds-on list and replace with the standard privilege model (trap saves mstatus.MPP, mret restores)."
          },
          {
            "file": "/home/prabhu/veda-core/design/DESIGN_05_PURECAP_PRIVILEGE_PROCESS.md",
            "line": 35,
            "quote": "(1-bit $priv + one-way droppriv + ODA authority). Extend to a real OS:",
            "why_stale": "Part B's premise -- that Veda is already ring-free via a 1-bit $priv plus a one-way droppriv -- is false. Privilege is now the standard RISC-V model on both layers (mstatus.MPP, mret, MRET-below-Machine illegal, csrPriv checked on reads as well as writes), and the Sail config has S and U supported (truths 1 and 5).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Rewrite the parenthetical as '(standard mstatus.MPP/mret privilege + ODA authority)' and re-check the rest of Part B, which reasons from the ring-free premise."
          },
          {
            "file": "/home/prabhu/veda-core/design/DESIGN_06_BUILD_ORDER_AND_OPEN_QUESTIONS.md",
            "line": 8,
            "quote": "   CAndPerm, widen ODT entry. Sail types -> RTL -> re-pass 63/51/49. *Nothing downstream",
            "why_stale": "Instruction with stale suite sizes: a reader following build-order step 1 would re-pass 63 Sail / 51 ACT4 / 49 RTL. The current triple is 102 Sail / 51 ACT4 / 90 RTL (truth 7).",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "'re-pass 63/51/49' -> 're-pass 102/51/90 (current suite sizes; check the runners rather than this number)'."
          },
          {
            "file": "/home/prabhu/veda-core/design/DESIGN_01_CAPABILITY_FORMAT_RESPEC.md",
            "line": 184,
            "quote": "- Re-run: Sail self-check (65/65 today), 51/51 ACT4 (should be untouched -- GPR datapath",
            "why_stale": "'65/65 today' is a current-tense baseline in a re-run instruction; the Sail self-check baseline is 102/102 (truth 7). ACT4 51/51 is still correct.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "'(65/65 today)' -> '(102/102 today)', or drop the number and point at run_veda_selfcheck_tests.sh."
          },
          {
            "file": "/home/prabhu/veda-core/design/DESIGN_08_OBJECT_NAMESPACE_SCALE.md",
            "line": 213,
            "quote": "## 10. The Sail experiment that validates this (next step, before RTL)",
            "why_stale": "Section header presents the validating Sail experiment as the pending next step before any RTL. It was built and passed (PHASE1_SAIL_DESIGN08_REGION_EXPERIMENT_RESULTS.md) and the RTL mirror landed too (rtl/RTL_MIRROR_04_DESIGN08_REGION_RESULTS.md, then RTL-5 for R10).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Retitle '## 10. The Sail experiment that validated this -- DONE' and add a one-line pointer to the two results docs; keep the numbered experiment design as the record of what was run."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TECHNICAL_BRIEF.md",
            "line": 67,
            "quote": "  RV64I base. 30/30 self-checking positive/negative tests pass.",
            "why_stale": "Outward-facing brief stating the current Sail suite size. It is 102/102 (truth 7).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "30/30 -> 102/102 (and '18 milestones' on the preceding line is likewise well behind)."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TECHNICAL_BRIEF.md",
            "line": 70,
            "quote": "  27/27 milestone regression tests pass.",
            "why_stale": "Outward-facing brief stating the current RTL smoke suite size. It is 90/90 (truth 7).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "27/27 -> 90/90."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TECHNICAL_BRIEF.md",
            "line": 85,
            "quote": "- No compiler or toolchain ecosystem exists — every test program is",
            "why_stale": "Honest-limitations list names a gap that is closed. A real LLVM pass (compiler/VedaShadowPropagation.cpp), a C runtime (runtime/veda_rt.c) and ~20 TOOLCHAIN_MILESTONE_* results docs exist; demo/FileCheck/runtime suites run against compiled C.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Replace with the honest current statement: a real but narrow toolchain exists (shadow-propagation pass, veda_rt, veda_compartment attribute) with named remaining scope limits, not 'no compiler exists'."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TECHNICAL_BRIEF.md",
            "line": 38,
            "quote": "50/50 RV64I base + Custom-0/1/2/3 Veda-Core extension), or from a real",
            "why_stale": "Claims the measured RTL decodes Custom-3. Custom-3 is unclaimed and every Custom-3 encoding now raises Illegal_Instruction (truth 1); VEDA_CORE_TECHREPORT.md:37 already states it correctly.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "'Custom-0/1/2/3' -> 'Custom-0/1/2 (Custom-3 deliberately unallocated)'."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/VEDA_CORE_TECHREPORT.md",
            "line": 73,
            "quote": "**30/30 self-checking positive/negative tests pass**, using the model's own real, built-in HTIF/`tohost` support",
            "why_stale": "Tech report's headline Sail verification count. It is 102/102 (truth 7).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "30/30 -> 102/102."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/VEDA_CORE_TECHREPORT.md",
            "line": 75,
            "quote": "**27/27 milestone regression tests pass.**",
            "why_stale": "Tech report's headline RTL verification count. It is 90/90 (truth 7). The same paragraph's 'Eighteen sequential milestones' is likewise well behind (the RTL line reached Milestone 25 plus the RTL_MIRROR increments).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "27/27 -> 90/90 and update the milestone count."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/VEDA_CORE_TECHREPORT.md",
            "line": 176,
            "quote": "- **No compiler or software toolchain.** Every test program in this report is hand-assembled.",
            "why_stale": "Honest-Limitations entry naming a gap that is closed: a real LLVM shadow-propagation pass, veda_rt runtime, and compiled-C demo/FileCheck suites exist (compiler/, runtime/, TOOLCHAIN_MILESTONE_1..20).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Restate as a narrow-toolchain limitation with its real remaining scope limits (memcpy/struct copy of capabilities, unions, VLAs, indirect calls), not an absence."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/VEDA_CORE_TECHREPORT.md",
            "line": 180,
            "quote": "- **The 16-bit `Length` field caps a single object at 65,536 bytes**",
            "why_stale": "Honest-Limitations entry naming a gap the DESIGN_01 respec closed on both layers: the capability is 256-bit with Base(56)/Length(40)/Object_ID(44)/generation(24) (veda_types.sail:110, 174).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Delete the entry or restate it as the 40-bit Length of the current 256-bit format; note the report's §1 '128-bit hardware capability' and §7 '8-bit generation counter' are stale for the same reason."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/MUTATION_CENSUS_DEREF.md",
            "line": 3,
            "quote": "**22 of 54 mutants SURVIVED. 41% of the trap-decision layer is unverified.**",
            "why_stale": "Headline is present tense and reads as the current coverage state. The 22 survivors were closed: veda_smoke_uaf.S (gen_stale on six chains), veda_smoke_deref_guards.S (sealed on six chains + bounds-as-trap-decision on the three NMC/atomic chains), veda_smoke_perm_cow_align.S (perm_load, cow_write, capmem_misaligned).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Add a dated status line above it -- 'CLOSED: all 22 survivors now covered, see veda_smoke_uaf.S / veda_smoke_deref_guards.S / veda_smoke_perm_cow_align.S' -- and keep the census body as the historical measurement."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/MUTATION_CENSUS_DEREF.md",
            "line": 74,
            "quote": "## The work list, in priority order",
            "why_stale": "A six-item live work list. Every item is done: 1 and 2 by veda_smoke_uaf.S and veda_smoke_deref_guards.S, 4 by deref_guards P7-P9, and 3/5/6 by veda_smoke_perm_cow_align.S.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Retitle '## The work list -- all six CLOSED' and mark each item with the test that closed it."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/README.md",
            "line": 39,
            "quote": "**The two layers seed DIFFERENT capability registers at reset.** Sail seeds",
            "why_stale": "The 'one hard constraint' for probe authors. R24's open half moved the CRF fixtures out of the architectural reset on BOTH layers behind switches that are OFF by default (Sail `extensions.Veda.test_fixtures`, RTL `+veda_fixtures` plusarg), and the differential harness passes neither -- so it now measures the same architectural reset on both sides, and p_reset_crf.S is the probe that pins it.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Rewrite the section: the harness now measures the real architectural reset because both layers gate their fixtures off by default; keep 'probes should bind what they need' as good practice, drop the c10-c14 warning."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/README.md",
            "line": 46,
            "quote": "Reconciling those fixtures is worth doing on its own: two layers that do not",
            "why_stale": "Names an outstanding task that R24 completed (both layers' test fixtures are now gated off the architectural reset; veda_core.tlv:993-1035 and veda_regs.sail's `if veda_test_fixtures` block).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Replace with a pointer to R24 and p_reset_crf.S as the probe that measures the now-common reset state."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MINIMAL_OS_KERNEL_DESIGN.md",
            "line": 12,
            "quote": "RTL mirrors for both Milestone A and Milestone B remain explicit, separate, not-yet-started",
            "why_stale": "Present-tense ('remain ... not-yet-started') claim in the Status header. Both mirrors exist: rtl/MILESTONE_A_RESULTS.md and rtl/MILESTONE_B_RESULTS.md, and Milestone C was mirrored too (rtl/MILESTONE_C_RESULTS.md, rtl/MILESTONE_25_RESULTS.md).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Replace with 'RTL mirrors for Milestones A, B and C are all complete -- see rtl/MILESTONE_A_RESULTS.md, rtl/MILESTONE_B_RESULTS.md, rtl/MILESTONE_C_RESULTS.md.'"
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MINIMAL_OS_KERNEL_DESIGN.md",
            "line": 236,
            "quote": "  (holding TSC-authorizing capabilities, making dispatch decisions) is the next, not-yet-started",
            "why_stale": "Out-of-scope list names the real scheduler compartment as not-yet-started. Milestone C built and verified the cooperative round-robin scheduler with full GPR context save on both layers (MILESTONE_C_RESULTS.md, MILESTONE_C_GPR_CONTEXT_SAVE_RESULTS.md, rtl/MILESTONE_C_RESULTS.md, rtl/MILESTONE_25_RESULTS.md).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Mark the bullet '-- CLOSED by Milestone C' with the four results-doc pointers; keep the remaining genuinely-open parts (preemption, >2 threads, allocator) named."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MINIMAL_OS_KERNEL_DESIGN.md",
            "line": 238,
            "quote": "- **S/U-mode privilege transitions** — unchanged from this project's own already-documented",
            "why_stale": "Out-of-scope list carries S/U-mode privilege transitions as a standing limitation. Privilege is now the standard model on both layers -- trap raises to Machine saving mstatus.MPP, mret restores, MRET below Machine is illegal, ECALL reports 0x08 from User -- and the Sail config has S and U supported (truths 1 and 5).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Replace the bullet with the current state (standard MPP/mret model, R36/R39) and drop the MILESTONE_11_RESULTS.md limitation pointer."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MINIMAL_OS_KERNEL_DESIGN.md",
            "line": 67,
            "quote": "core spec, not just CHERIoT's specific choice — that Veda-Core's existing M-mode-only design can",
            "why_stale": "Finding 3 reasons from 'Veda-Core's existing M-mode-only design'. The machine is no longer M-mode-only: it implements mstatus MIE/MPIE/MPP, mret, per-CSR privilege checking on reads and writes, and software drops to User by writing MPP and executing mret (truth 1).",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Add a superseded note under Finding 3: the design is no longer ring-free; PERMIT_ACCESS_SYSTEM_REGISTERS now sits alongside, not in place of, a real privilege level."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MINIMAL_OS_KERNEL_DESIGN.md",
            "line": 3,
            "quote": "**Status**: Sail-side Milestone A implemented and verified (44/44 self-check regression, zero",
            "why_stale": "Status header suite size. The Sail self-check is 102/102 (truth 7), and the header stops at Milestones A/B while Milestone C (scheduler + full GPR context save) is also done on both layers.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Rewrite the Status block to cover A/B/C done on both layers and quote 102/102, or drop the running count and point at the runner."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/FORMAL_VERIFICATION_PLAN.md",
            "line": 3,
            "quote": "**Status**: Design-stage. No Sail code written yet.",
            "why_stale": "Status header says no Sail code exists. The model has existed for a long time (model/extensions/Veda/*.sail, 102/102 self-check) -- the same document's §5 already records Milestones V-A/V-B/V-C as done, contradicting its own header.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "'Status: Design-stage. No Sail code written yet.' -> 'Status: historical plan (2026-07). The model was built; see §5 and the MILESTONE_V-* results docs. Current Sail self-check: 102/102.'"
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/FORMAL_VERIFICATION_PLAN.md",
            "line": 97,
            "quote": "- Exact `ODT` entry-creation/destruction instruction encoding (`VEDA_CORE_SPEC.md` §5.1 resolves the *authorization* — gated by `Permit_Access_System_Registers` — and the *data model*, but not the encoding itself).",
            "why_stale": "'Explicitly not decided yet' item that is decided: veda.odt.populate / populate-fast / destroy / set.domain / set.cow / page.out / page.in are all encoded and implemented on both layers, and Populate's policy-field reset semantics are pinned (truth 4).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Mark the item RESOLVED with a pointer to the ODT-write family in veda_bind_insts.sail and veda_core.tlv."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/FORMAL_VERIFICATION_PLAN.md",
            "line": 99,
            "quote": "- Exact Veda-Atomic op-select values (`VEDA_CORE_SPEC.md` §1 already notes these as \"proposed... not yet finalized\").",
            "why_stale": "'Explicitly not decided yet' item that is decided: veda_atomic_insts.sail implements the finalized nine-op family and the RTL mirrors it ($veda_atomic_violation chain).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Mark RESOLVED with a pointer to veda_atomic_insts.sail."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/FORMAL_VERIFICATION_PLAN.md",
            "line": 100,
            "quote": "- Whether the Tag array (§2.3) should be a flat 16-bit register or embedded per-capability in the `struct` — either is mechanically fine; not yet chosen since it doesn't affect any decision made so far.",
            "why_stale": "'Explicitly not decided yet' item that is decided: the tag lives per-capability and the RTL additionally carries a separate tcm_scratch_tag array for capability memory; CGetTag reads the per-register tag on both layers.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Mark RESOLVED and record which representation shipped."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_19_SCOPE_LIMIT_AUDIT_RESULTS.md",
            "line": 153,
            "quote": "## What this means for the project (not yet acted on -- reporting only)",
            "why_stale": "Section header plus its four numbered next-step candidates are all acted on: return-value shadow propagation (TOOLCHAIN_MILESTONE_20_RETURN_SHADOW_RESULTS.md), silent-bind-failure (TOOLCHAIN_MILESTONE_20_SILENT_BIND_FAILURE_FIX.md), indirect-call crash + multi-level global GEP + uintptr_t round-trip (TOOLCHAIN_MILESTONE_20_REMAINING_FIXES_RESULTS.md).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Retitle '## What this means for the project (all four acted on in Milestone 20 -- see below)' and annotate each numbered item with the M20 part that closed it."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_13_CRF_EXHAUSTION_DECISION.md",
            "line": 67,
            "quote": "   S/U-mode-disabled Sail config. The spill/restore approach touches no privilege boundary at all.",
            "why_stale": "A false premise feeding a design decision: the Sail config has S and U supported (truth 5), and that was already true when this was written. The GDC option was partly rejected on the ground that an M-mode carve-out would be 'possibly unverifiable' in this config.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Strike 'possibly unverifiable given the S/U-mode-disabled Sail config' and note that S/U are enabled, so the privilege-gating cost of the GDC option is testable if the option is ever revisited."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_20_RESULTS.md",
            "line": 41,
            "quote": "**RTL mirror** — deliberately not attempted this pass, matching this project's own established Sail-first sequencing. Confirmed via direct grep of `veda_core.tlv` that RTL has not mirrored Milestone 19 either yet, so this exact same CSR-write escape exists unfixed in RTL too — a named, combined RTL follow-up (Milestones 19+20 together) rather than two separate small RTL passes.",
            "why_stale": "Present-tense claim about the current RTL asserting a live, unfixed CSR-write compartment escape. The mirrors landed: rtl/MILESTONE_19_RESULTS.md, rtl/MILESTONE_20_RESULTS.md, rtl/MILESTONE_21_27_RESTORE_MTVEC_GATE_RTL_RESULTS.md, plus rtl/sim/veda_smoke_mtvec_escape_neg.S and R39's generic CSR privilege check.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Append a dated CLOSED note (the scoping sentence 'not attempted this pass' is legitimate history; the 'exists unfixed in RTL too' clause is what must be corrected)."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_27_MTVEC_CSR_GATE_RESULTS.md",
            "line": 71,
            "quote": "**RTL mirror** -- deliberately not attempted this pass, matching this project's established Sail-first sequencing. RTL's own `veda_core.tlv` has never mirrored Milestone 20's CSR-gating either yet, so this exact same class of gap (any CSR write ungated by compartment state) likely exists there too -- a named, combined future RTL pass (Milestones 20+21+this fix together), not scoped here.",
            "why_stale": "Asserts the class of gap 'likely exists' in the current RTL. The combined pass it names was run: rtl/MILESTONE_21_27_RESTORE_MTVEC_GATE_RTL_RESULTS.md mirrors the mtvec gate, and R39 added a generic CSR privilege check (csrPriv = csr[9:8]) on reads and writes (truth 1).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Append a dated CLOSED line pointing at rtl/MILESTONE_21_27_RESTORE_MTVEC_GATE_RTL_RESULTS.md and R39."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_22_RESULTS.md",
            "line": 50,
            "quote": "Broader subsystem-by-subsystem review (Veda-Atomic's own `aq`/`rl` semantics under real concurrency, `OSpecialRW`'s privilege-only gating, RTL mirrors for Milestones 19-22) explicitly deferred to a later pass, per the user's own stated sequencing: audit the named CHERI-pillar properties first, broaden afterward, with extra caution before any future OS/runtime work begins on top of this project.",
            "why_stale": "All three deferred items were done: ATOMIC_AQRL_SAFETY_ANALYSIS.md, OSPECIALRW_PRIVILEGE_GATING_AUDIT.md, and rtl/MILESTONE_19..22_RESULTS.md.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Append a dated CLOSED line naming the three docs that discharged it."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_21_RESULTS.md",
            "line": 41,
            "quote": "**RTL mirror** — deliberately not attempted this pass, matching this project's own established Sail-first sequencing; combined with Milestones 19 and 20's own still-pending RTL work as one named future RTL pass covering all three together.",
            "why_stale": "The two other 'Not yet built' items in this same section were updated with dated CLOSED notes; this one was not. The RTL mirrors for 19, 20 and 21 all exist (rtl/MILESTONE_19/20/21_RESULTS.md and rtl/MILESTONE_21_27_RESTORE_MTVEC_GATE_RTL_RESULTS.md), so 'still-pending RTL work' is false.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Add the same dated CLOSED annotation the sibling bullets already carry."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_19_RESULTS.md",
            "line": 55,
            "quote": "**RTL mirror** — deliberately not attempted this pass, matching this project's own established Sail-first sequencing. RTL's own version will need a genuinely new kind of check for the load/store datapath (an unconditional-every-cycle data-address gate, analogous to but distinct from Milestone 14's own fetch-time `$instr`-forcing-to-NOP mechanism), new CSR decode for `0x7C5`, and reuse of the existing `pcc_length` signal for the compartment trigger — scoped as an explicit `rtl/MILESTONE_19_RESULTS.md` follow-up.",
            "why_stale": "The follow-on it scopes exists and is complete: rtl/MILESTONE_19_RESULTS.md (CSR 0x7C5, $veda_purecap_violation). Left unannotated, this reads as outstanding RTL work.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Add 'CLOSED -- see rtl/MILESTONE_19_RESULTS.md'; the design sketch is worth keeping as the prediction that turned out right."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_14_RESULTS.md",
            "line": 36,
            "quote": "`Perms`-on-PCC, S/U-mode-privilege interaction, and real multi-hart RTL all remain exactly as named in `PCC_COMPARTMENT_DESIGN.md`'s own \"Deliberately out of scope\" section (§7) and `MILESTONE_12_RESULTS.md`'s \"Not yet built\" — none touched or affected by this milestone.",
            "why_stale": "Two of the three no longer 'remain as named': the RTL mirror of Milestone 14 exists (rtl/MILESTONE_14_RESULTS.md), and S/U-mode privilege interaction is now the standard MPP/mret model on both layers with a generic CSR privilege check (truth 1). Only multi-hart is still genuinely open.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Annotate: S/U-mode privilege closed by R36/R39; Perms-on-PCC and multi-hart still open."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_21_RESULTS.md",
            "line": 99,
            "quote": "- Real `ecall`/illegal-instruction/misaligned-access support does not",
            "why_stale": "'What remains open, honestly' claims the RTL has no ecall or illegal-instruction support at all. RTL Milestone 23 added real ECALL ($is_ecall, with mcause 0x08 from User / 0x0B from Machine per truth 1), R33d added EBREAK with mcause 3, and R33b added the fail-closed base-ISA decode catch-all ($veda_illegal_instr).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Annotate the bullet: ecall CLOSED by RTL Milestone 23, illegal-instruction CLOSED by R33a/b/c/d; only misaligned-access detection for base loads/stores is still open."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_23_RESULTS.md",
            "line": 108,
            "quote": "EBREAK, general illegal-instruction trapping, and misaligned-access detection remain explicitly",
            "why_stale": "Two of the three are built: R33d implemented EBREAK with a real mcause 3 and faulting-PC mtval (veda_core.tlv:1399-1419, probe difftest/probes/p10_ebreak.S), and R33b implemented the general fail-closed illegal-instruction catch-all (veda_core.tlv:4747+).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Annotate EBREAK and illegal-instruction as CLOSED (R33d, R33b); keep misaligned-access as still out of scope."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_23_RESULTS.md",
            "line": 110,
            "quote": "exists — the RTL mirror of Sail-side Milestone C's cooperative scheduler — is the next,",
            "why_stale": "Names the RTL mirror of Milestone C as the not-yet-started next piece of work. It was built: rtl/MILESTONE_C_RESULTS.md and rtl/MILESTONE_25_RESULTS.md (full GPR context save, mscratch CSR).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Append 'CLOSED -- see rtl/MILESTONE_C_RESULTS.md and rtl/MILESTONE_25_RESULTS.md'."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_20_RESULTS.md",
            "line": 96,
            "quote": "- RTL mirror for Milestone 21 (universal PCC reset on any trap,",
            "why_stale": "'What remains open, honestly' names the Milestone 21 RTL mirror as not-yet-attempted work. It exists: rtl/MILESTONE_21_RESULTS.md and rtl/MILESTONE_21_27_RESTORE_MTVEC_GATE_RTL_RESULTS.md, with rtl/sim/veda_smoke_mtvec_escape_neg.S as the negative test.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Add a dated CLOSED annotation with those two pointers."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_19_RESULTS.md",
            "line": 85,
            "quote": "- RTL mirrors for Milestones 20 (compartment-state CSR self-escape",
            "why_stale": "Names the Milestone 20 and 21 RTL mirrors as separate, not-yet-attempted work. Both exist (rtl/MILESTONE_20_RESULTS.md, rtl/MILESTONE_21_RESULTS.md, rtl/MILESTONE_21_27_RESTORE_MTVEC_GATE_RTL_RESULTS.md).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Add a dated CLOSED annotation with those pointers."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_19_RESULTS.md",
            "line": 26,
            "quote": "  concept yet; every CSR write in this file is implicitly M-mode-only",
            "why_stale": "Design rationale asserting the RTL has no S/U-mode concept and that all CSR writes are implicitly M-mode-only. R39 added mstatus (0x300) with MIE/MPIE/MPP and a generic per-CSR privilege check (csrPriv = csr[9:8]) enforced on reads as well as writes; a reader adding a CSR on that rationale today would ship an unchecked one.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Add a superseded note: as of R36/R39 the core has a real privilege level and a generic CSR privilege check; new CSRs must pick an address whose csrPriv encodes the intended level."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/sail_tests/PHASE2_SAIL_RESIDENCY_RESULTS.md",
            "line": 28,
            "quote": "bump `generation` (only Populate and Destroy do). So **nothing existing would notice**: a capability",
            "why_stale": "Truth 6 names exactly this claim as false: veda.odt.page.out now sets generation = old + 1. It was true for increment 1 (no page-out instruction existed yet) but is written in the present tense and reads as the current contract.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Add an inline note: 'as of the Phase-2 paging increment, page-out also bumps generation (PHASE2_SAIL_PAGING_RESULTS.md) -- the argument below is why residency was still needed at the dereference'."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/RTL_MIRROR_04_DESIGN08_REGION_RESULTS.md",
            "line": 243,
            "quote": "- **The CRBR is reset-only in both models**, so the domain-entry load remains prose-only in Sail and",
            "why_stale": "Present-tense divergence claim about both layers. R10 closed exactly this: the CRBR is loaded and validated at OCInvoke, OCReturn, trap entry and mret on both layers (sail_tests/PHASE1_SAIL_R10_CRBR_RESULTS.md, rtl/RTL_MIRROR_05_R10_CRBR_RESULTS.md).",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Append 'CLOSED in the next increment by R10' with both pointers; the increment-scoped divergence list is otherwise legitimate history."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv",
            "line": 18,
            "quote": "//  Milestone 23, ECALL; EBREAK still excl./deferred) plus the 12",
            "why_stale": "File-header instruction-inventory comment states EBREAK is still excluded. R33d implemented it at line 1419 with mcause 3 and mtval = faulting PC.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "'ECALL; EBREAK still excl./deferred' -> 'ECALL and, as of R33d, EBREAK'."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv",
            "line": 1396,
            "quote": "// EBREAK remains deferred -- not added here.",
            "why_stale": "Contradicted 23 lines later by the R33d block that defines $is_ebreak = ($instr == 32'h00100073). A reader scanning the ECALL comment would conclude EBREAK is unimplemented.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Change to 'EBREAK is added separately below -- see the R33d block.'"
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/MILESTONE_C_RESULTS.md",
            "line": 76,
            "quote": "Per the Sail-side plan's own explicit scope, unchanged here: real fault recovery for the",
            "why_stale": "NOT STALE -- reported so it is not re-flagged. The remaining items (fault recovery, preemption, >2 threads, priorities, queues, allocator) are all genuinely still open; full GPR context save, which the Sail-side twin also listed, is correctly struck through and marked Resolved in MILESTONE_C_RESULTS.md.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "No change."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/ACT4_CONFORMANCE_RESULTS.md",
            "line": 16,
            "quote": "**51/51 passed, 0 failed, 0 timed out** — `veda_core.tlv` genuinely, currently passes the exact same real ACT4 RV64I conformance suite the untouched `rv64i_core.tlv` does.",
            "why_stale": "NOT STALE as a count -- ACT4 is still 51/51 (truth 7). Flagged only because the same sentence says 'new Custom-0/1/2/3 decode logic', which is now wrong (Custom-3 is unclaimed, truth 1); that clause, not the number, is the defect.",
            "kind": "HISTORICAL_OK",
            "suggested_fix": "Leave 51/51; change 'Custom-0/1/2/3' to 'Custom-0/1/2'."
          }
        ],
        "summary": "Swept the ~110 non-excluded documents (impl repo 122 .md minus the handled list, design repo README + DESIGN_00/01/03/04/05/06/08, plus difftest and the RTL file header) for suite sizes, test counts, probe counts, and REMAINING-GAP / not-yet-built / open-item / next-step lists. 51 hits, of which 49 are real staleness.\\n\\nHighest-value cluster -- the four documents a reader would consult for CURRENT state, all wrong on counts: /home/prabhu/veda-core/README.md (Sail 76/76 and RTL 64/64, now 102/102 and 90/90; findings 'R1-R10', now R1..R43; droppriv listed as a verified base mechanism; Phase 2 still marked 'next' though residency/paging/COW are built and mirrored), TECHNICAL_BRIEF.md and VEDA_CORE_TECHREPORT.md (both still say 30/30 Sail and 27/27 RTL, both still list 'no compiler or toolchain exists' as an honest limitation though compiler/ and runtime/ exist with ~20 TOOLCHAIN_MILESTONE docs, and the techreport still caps objects at a 16-bit Length though the format is now 256-bit with Length(40)), and FORMAL_VERIFICATION_PLAN.md, whose Status header still says 'No Sail code written yet' while its own §5 records V-A/B/C done.\\n\\nTwo gap lists are wholly closed and still read as live work: difftest/MUTATION_CENSUS_DEREF.md ('22 of 54 mutants SURVIVED. 41% of the trap-decision layer is unverified' plus its six-item priority work list -- all closed by veda_smoke_uaf.S, veda_smoke_deref_guards.S and veda_smoke_perm_cow_align.S), and TOOLCHAIN_MILESTONE_19_SCOPE_LIMIT_AUDIT_RESULTS.md ('not yet acted on -- reporting only'; all four items acted on across the four Milestone-20 parts). difftest/README.md's 'one hard constraint' for probe authors is now actively misleading: R24 gated the CRF fixtures off the architectural reset on BOTH layers (Sail config key, RTL +veda_fixtures plusarg, both OFF by default), so the harness already measures a common reset.\\n\\nAgainst truths 1-5 specifically: MINIMAL_OS_KERNEL_DESIGN.md still carries 'M-mode-only design', 'S/U-mode privilege transitions' as a standing limitation, and 'RTL mirrors ... remain not-yet-started' though A/B/C are all mirrored; rtl/MILESTONE_19_RESULTS.md still tells a reader 'this core has no S/U-mode concept yet; every CSR write in this file is implicitly M-mode-only', which R39 refutes; TOOLCHAIN_MILESTONE_13_CRF_EXHAUSTION_DECISION.md rejected an option partly on the false premise of an 'S/U-mode-disabled Sail config' (truth 5). Against truth 6, PHASE2_SAIL_RESIDENCY_RESULTS.md still asserts generation is bumped 'only by Populate and Destroy'.\\n\\nI applied the historical-record rule strictly: I did NOT report the ~25 milestone 'Not yet built' sections that are correctly scoped to their own pass or already carry dated CLOSED/Resolved annotations. I reported only the ones that assert something about the CURRENT layers ('exists unfixed in RTL too', 'likely exists there too', 'remain not-yet-started', 'does not exist in RTL at all', 'the CRBR is reset-only in both models') or that a reader would act on today. Two entries are marked HISTORICAL_OK to record near-misses I judged and cleared. Two hits are in rtl/veda_core.tlv itself: the file-header inventory and the ECALL comment both still say EBREAK is deferred, 23 lines above the R33d block that implements it."
      },
      {
        "hits": [
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/run_act4_tests.sh",
            "line": 17,
            "quote": "GCC_BIN=/home/prabhu/makerchip/rva23-core/toolchain/riscv-collab-gcc/riscv/bin",
            "why_stale": "Reaches into the FROZEN rva23-core sibling for objcopy/readelf. This line has its own toolchain at /home/prabhu/veda-core-sindhu/toolchain/riscv-collab-gcc/riscv/bin -- I confirmed riscv64-unknown-elf-objcopy and -readelf both exist there. Every sibling runner was already converted off the frozen tree (rtl/run_veda_smoke_test.sh:80 uses \"$(cd ../.. && pwd)/toolchain/...\" and its comment at line 78 explicitly names rva23-core/toolchain as \"frozen and is not a dependency this line is\" entitled to; sail_tests/run_veda_selfcheck_tests.sh:14 and difftest/rundiff.sh:18 do the same). Even the frozen tree's OWN copy of this script (rva23-core/rtl/run_act4_tests.sh:20-22) has a local-first fallback. This one file was missed.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "GCC_BIN=\"$(cd \"$(dirname \"${BASH_SOURCE[0]:-$0}\")/../..\" && pwd)/toolchain/riscv-collab-gcc/riscv/bin\", with the same \"FATAL: run ./toolchain/setup.sh gnu-toolchain\" guard run_veda_smoke_test.sh:83-85 already uses."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/rtl/run_act4_tests.sh",
            "line": 20,
            "quote": "ELF_DIR=\"${1:-/home/prabhu/makerchip/rva23-core/act4-verify/work/rva23-base-rv64i/elfs/rv64i/I}\"",
            "why_stale": "The default ACT4 ELF corpus exists ONLY inside the frozen rva23-core tree. /home/prabhu/veda-core-sindhu/act4-verify does not exist, and act4-verify/ is gitignored in this repo (.gitignore line 'act4-verify/'). So the 51/51 ACT4 figure that VEDA_CORE_SPEC.md and verification.sh both quote as a current suite cannot be reproduced from this line at all without reading the frozen project. A fresh clone of veda-core-sindhu cannot run this script.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Default ELF_DIR to a path inside this repo (e.g. \"$REPO_ROOT/act4-verify/work/rva23-base-rv64i/elfs/rv64i/I\"), keep the positional override, and make the existing 'No .elf files found' guard at line 70 print how to obtain or regenerate the corpus for this line rather than silently depending on the frozen sibling."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/compiler/run_veda_shadow_prop_tests.sh",
            "line": 25,
            "quote": "MY_LLVM_BUILD=/home/prabhu/makerchip/rva23-core/toolchain/llvm-project/build",
            "why_stale": "Reaches into the FROZEN rva23-core sibling for opt/FileCheck/llvm-config. Every other script in this same directory already derives LLVM from the repo: run_veda_demo_tests.sh:10-14, run_veda_global_protect_test.sh:24-28, run_veda_alloca_protect_test.sh:28-32 etc. all compute SCRIPT_DIR/REPO_ROOT and set LLVM=$REPO_ROOT/toolchain/llvm-project/build/bin. This is the only compiler-directory script still hardwired, and it is the one two docs point readers at.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Adopt the sibling pattern verbatim: SCRIPT_DIR/REPO_ROOT via \"$(cd \"$(dirname \"${BASH_SOURCE[0]:-$0}\")/../..\" && pwd)\", then MY_LLVM_BUILD=$REPO_ROOT/toolchain/llvm-project/build."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/run_security_trap.sh",
            "line": 19,
            "quote": "ROOT=/home/prabhu/makerchip/rva23-core",
            "why_stale": "Worse than a toolchain path: lines 74-75 then do strip_viz \"$ROOT/rtl/rv64i_core.tlv\" and strip_viz \"$ROOT/veda-core/rtl/veda_core.tlv\", so the RTL actually transpiled, compiled and demonstrated is the FROZEN rva23-core tree's copy of veda_core.tlv -- not this repo's rtl/veda_core.tlv, which carries every RTL-mirror increment through R41/R38(b). The script's own header at lines 6-7 says it runs \"rtl/rv64i_core.tlv\" and \"veda-core/rtl/veda_core.tlv\", which a reader will read as this repo, and line 15 says \"run this yourself to reproduce it\". A reader who does so measures the wrong core, and silently depends on a frozen project.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "ROOT=\"$(cd \"$(dirname \"$0\")/../..\" && pwd)\" and TC=\"$ROOT/toolchain/riscv-collab-gcc/riscv/bin\" -- the layout matches ($ROOT/rtl/rv64i_core.tlv and $ROOT/veda-core/rtl/veda_core.tlv both exist in veda-core-sindhu), so only line 19 needs to change."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_8_RESULTS.md",
            "line": 78,
            "quote": "cd veda-core/compiler && ./run_veda_shadow_prop_tests.sh",
            "why_stale": "This is a '## Reproducing this' block -- a present-tense instruction, not a milestone record. The script it names still hardwires the frozen rva23-core LLVM build (run_veda_shadow_prop_tests.sh:25), so following this instruction from a clean clone of this line either fails or silently exercises the frozen sibling's compiler. TOOLCHAIN_MILESTONE_9_RESULTS.md:265 carries the identical instruction in its own '## Reproducing this' block.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "No doc edit needed if run_veda_shadow_prop_tests.sh:25 is repointed at $REPO_ROOT; the docs become correct automatically. If the script is not fixed, both blocks need a line stating the frozen-tree prerequisite."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/rundiff.sh",
            "line": 19,
            "quote": "SIM=/home/prabhu/veda-core-sindhu/toolchain/sail-riscv/build/c_emulator/sail_riscv_sim",
            "why_stale": "Directly contradicted by the comment four lines above it (lines 15-18): \"R29: the project's OWN toolchain, resolved from this file's location. The hand-wired path this replaced reached into rva23-core, a frozen sibling project, so this harness only ran on one machine.\" Only TC (line 18) was actually converted. SIM here and RTLSIM at line 27 (RTLSIM=/home/prabhu/veda-core-sindhu/veda-core/rtl/sim) are still absolute single-machine paths, so the harness STILL only runs on one machine and the comment now overstates what R29 fixed. Note the file already computes D=\"$(cd \"$(dirname \"$0\")\" && pwd)\" at line 13 and uses \"$D/../rtl\" at line 39, so the machinery is right there.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "SIM=\"$(cd \"$D/../..\" && pwd)/toolchain/sail-riscv/build/c_emulator/sail_riscv_sim\" and RTLSIM=\"$(cd \"$D/../rtl/sim\" && pwd)\"."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/check_timing_coupling.sh",
            "line": 32,
            "quote": "SAIL=/home/prabhu/veda-core-sail-riscv/model/extensions/Veda/veda_cap_insts.sail",
            "why_stale": "The only absolute path in an otherwise fully relative script (line 30 is cd \"$(dirname \"$0\")\", line 31 is the relative TLV=rtl/veda_core.tlv). The repo already carries toolchain/sail-riscv as a symlink to exactly this tree (confirmed: /home/prabhu/veda-core-sindhu/toolchain/sail-riscv -> /home/prabhu/veda-core-sail-riscv), which is the resolution path every other runner uses. As written, this build-failing invariant check silently becomes an infrastructure failure (line 38's 'FAIL: cannot find VEDA_CAPQUERY') on any other machine or clone layout -- for a check whose entire purpose is to fail loudly at the right moment, that is the wrong failure mode.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "SAIL=\"$(cd .. && pwd)/toolchain/sail-riscv/model/extensions/Veda/veda_cap_insts.sail\" (relative to the post-cd working directory)."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/README.md",
            "line": 39,
            "quote": "**The two layers seed DIFFERENT capability registers at reset.** Sail seeds c10-c14; the RTL seeds a different set with different contents. A probe that reads a seeded register is not comparing the same thing on both sides, and will report a divergence that is a fixture difference rather than a defect. Probes should bind what they need, and treat any divergence involving c10-c14 as suspect until the fixtures are reconciled.",
            "why_stale": "R24 is closed and the fixtures were reconciled. veda_regs.sail:772-790 defines veda_reset_crf() which sets ALL sixteen registers to zero_capability and clears crTags -- Sail no longer seeds c10-c14 with anything. run_difftests.sh:35 records the measurement: 'p_reset_crf.S AGREE  R24 CLOSED: all 16 capability registers agree at reset'. This section is the README's single 'one hard constraint' for anyone writing a new probe, and it now tells them to discount exactly the class of divergence that would today be a real defect.",
            "kind": "GAP_SINCE_CLOSED",
            "suggested_fix": "Replace the section with the current constraint: both layers reset all 16 capability registers to zero (veda_reset_crf), p_reset_crf.S is the standing proof, and any divergence at reset is now a defect rather than a fixture artefact."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/README.md",
            "line": 28,
            "quote": "It asserts nothing. **Divergence is the finding, not failure.**",
            "why_stale": "rundiff.sh was given a verdict exit code and now asserts. Its own header (rundiff.sh:7-12) says so: 'EXIT CODE IS THE VERDICT... Now: 0 = agree, 1 = diverge, 2 = infrastructure failure. run_difftests.sh is the thing that runs them all and holds the expected verdicts.' The README also never mentions run_difftests.sh anywhere, so the only documented entry point is the single-probe rundiff.sh -- a reader cannot reproduce the cross-layer 20/20 figure from this README at all, and the file that records which probes are EXPECTED to diverge is invisible to them.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Replace with the exit-code contract (0 agree / 1 diverge / 2 infrastructure) and add run_difftests.sh as the suite entry point that holds the expected verdicts; keep rundiff.sh documented as the single-probe form."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/difftest/README.md",
            "line": 32,
            "quote": "    iverilog -g2012 -I ../rtl/sim -o sim_diff.vvp ../rtl/sim/veda_core.sv tb_diff.sv",
            "why_stale": "This manual 'Building the RTL side' step is no longer something a reader should do. rundiff.sh:56 now rebuilds sim_diff.vvp from veda_core.sv on every single run (its comment at lines 51-55 explains why: a committed, hand-built sim_diff.vvp let the harness compare a current Sail model against a stale RTL image), and rundiff.sh:40-48 hard-refuses with FATAL if veda_core.sv is missing or older than veda_core.tlv. A reader who runs this line by hand is doing work the harness undoes, and may believe hand-building is a valid substitute for re-running run_veda_smoke_test.sh, which is exactly the staleness the guard exists to prevent.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Drop the manual iverilog command and state instead that rundiff.sh rebuilds the RTL image itself and refuses to run when ../rtl/sim/veda_core.sv is absent or older than ../rtl/veda_core.tlv -- regenerate it with ../rtl/run_veda_smoke_test.sh."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/DEVELOPER_WORKFLOW_GUIDE.md",
            "line": 146,
            "quote": "real, live 128-bit packed capability and its out-of-band tag bit, verified against an independent second read path (`cgetbase`/`cgetlen`/`cgetperm`/`cgettag`) matching byte-for-byte.",
            "why_stale": "The capability format was widened to 256 bits by the DESIGN_01 respec. veda_types.sail:77-82 states it outright: '256-bit respec ... + Perms(16) + otype(16) + generation(24) + flags(20) = 256 exactly. There is NO padding bit any more: the old 128-bit layout was 127 data bits + 1 pad'. So what this debugging section describes as 'the real, live ... capability' is at most half of one. Supporting observation, worth a separate check by whoever owns the gdbstub: the stub was apparently never widened -- riscv_model_impl.h:116 still declares pack_veda_capability_reg(int index, uint8_t out_bytes[16]) and gdbstub.cpp:341-343 still advertise bitsize=\"128\" -- so the byte-for-byte agreement with cgetbase/cgetlen this sentence promises cannot hold at the new field widths.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "State the current width (256-bit packed capability, tag out-of-band) and, until the gdbstub is widened, warn that the GDB register view is truncated and cgetbase/cgetlen/cgetperm are the authoritative read path."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/toolchain/setup.sh",
            "line": 58,
            "quote": "BRANCH=veda-core",
            "why_stale": "This single variable drives both fork clones (line 142 'git clone --branch \"$BRANCH\" \"$SAIL_RISCV_REPO\"' and line 166 the same for LLVM), and it is the one-command setup the top-level README advertises. But this line's Sail model is on branch phase1-respec, not veda-core: /home/prabhu/veda-core-sail-riscv is on phase1-respec, its origin is prabhu-euro20/Veda-Core-sail-riscv with a full fetch refspec (+refs/heads/*:refs/remotes/origin/*), and the only remote-tracking heads present are origin/master and origin/phase1-respec -- no veda-core. Even if a veda-core branch still exists upstream, it predates the entire Phase-1 respec (256-bit format, region table, CRBR) and Phase-2 work, so ./toolchain/setup.sh would build a simulator that cannot pass today's 102/102 Sail self-check. I could not verify the LLVM fork's branches (no local clone), so that half is unconfirmed.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Split the shared BRANCH into per-fork variables and set the Sail one to phase1-respec (SAIL_BRANCH=phase1-respec), leaving the LLVM branch as-is until it is checked."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/README.md",
            "line": 266,
            "quote": "git clone --branch veda-core https://github.com/prabhu-euro20/Veda-Core-sail-riscv.git toolchain/sail-riscv",
            "why_stale": "Same defect as setup.sh:58, in the hand-run version of the setup. The Sail fork branch this line actually uses is phase1-respec (confirmed against the local checkout's branch and remote-tracking refs). The table row at line 219 repeats it -- 'Sail RISC-V fork | github.com/prabhu-euro20/Veda-Core-sail-riscv (branch `veda-core`)' -- and describes its contents as 'Milestones 1-25 ... SSC Stack-Spill Capability work', which is the pre-respec scope, not the current model. Also note the local toolchain/sail-riscv is a symlink to /home/prabhu/veda-core-sail-riscv, not a clone, so this step has not been exercised on this machine in its documented form.",
            "kind": "INSTRUCTION_THAT_WOULD_MISLEAD",
            "suggested_fix": "Change --branch veda-core to --branch phase1-respec in the command and in the line-219 table row, and update that row's contents column to name the Phase-1 respec + Phase-2 work."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/README.md",
            "line": 224,
            "quote": "git clone https://github.com/prabhu-euro20/Veda-Core.git",
            "why_stale": "This is the 'One-command setup' for the repo the file actually lives in, but it clones a different repo. veda-core-sindhu's origin is git@github.com:prabhu-euro20/veda-core-sindhu.git; prabhu-euro20/Veda-Core is its UPSTREAM -- the frozen deterministic embedded line (~/makerchip/rva23-core), which the design repo's own README:122 calls 'read-only reference only'. A reader following this quickstart clones the frozen line and then runs setup.sh from inside it, landing nowhere near the pipelined/Linux line this README describes. Line 217's table row repeats the identification: 'This repo | `github.com/prabhu-euro20/Veda-Core`'.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Point both line 224's clone and line 217's 'This repo' row at github.com/prabhu-euro20/veda-core-sindhu (and the correct branch), keeping Veda-Core mentioned only as the frozen upstream if that relationship is worth stating."
          },
          {
            "file": "/home/prabhu/veda-core-sindhu/veda-core/TECHNICAL_BRIEF.md",
            "line": 85,
            "quote": "- No compiler or toolchain ecosystem exists — every test program is\n  hand-assembled.",
            "why_stale": "Stated as a current, standing limitation in an undated researcher-facing brief (not a milestone record). It is flatly false today: there is an LLVM/clang fork with 36 Veda-Core instructions and a capability register class, a VedaShadowPropagation compiler pass, a C runtime (runtime/veda_rt.h, veda_rt.c, crt0.S), a GDB stub with capability-register visibility, and twenty Toolchain Milestone results docs -- plus DEVELOPER_WORKFLOW_GUIDE.md, an end-to-end 'write your own C program' guide. The same section's suite counts are also stale as current claims: line 67 '30/30 self-checking positive/negative tests pass' and line 70 '27/27 milestone regression tests pass' against today's Sail 102/102 and RTL 90/90.",
            "kind": "CURRENT_CLAIM_NOW_FALSE",
            "suggested_fix": "Replace the bullet with the real current scope (LLVM fork + compiler pass + C runtime + GDB stub exist; general C/C++ library and ABI interop are not established) and refresh lines 67/70 to Sail 102/102 and RTL smoke 90/90, adding ACT4 51/51 and cross-layer differential 20/20."
          }
        ],
        "summary": "Swept every script and every document in the impl and design repos that tells a reader how to run or reproduce something, excluding the eleven files named as already being edited. Fifteen hits, in four clusters.\\n\\nFROZEN-TREE DEPENDENCIES (the priority you named). Four scripts still reach into /home/prabhu/makerchip/rva23-core, and two docs point readers at one of them. The conversion off the frozen tree was done thoroughly but incompletely: rtl/run_veda_smoke_test.sh, sail_tests/run_veda_selfcheck_tests.sh and difftest/rundiff.sh all resolve the toolchain from their own location and say so in comments, while rtl/run_act4_tests.sh (lines 17 and 20), compiler/run_veda_shadow_prop_tests.sh (line 25) and run_security_trap.sh (line 19) were missed. run_security_trap.sh is the worst of them: it does not merely borrow a toolchain, it transpiles and demonstrates the frozen tree's own copy of veda_core.tlv, so its \\\"run this yourself to reproduce it\\\" measures the wrong core. run_act4_tests.sh:20 is the structural one -- the ACT4 ELF corpus exists only in the frozen tree and act4-verify/ is gitignored here, so the 51/51 figure quoted across this line cannot be reproduced from a clean clone at all.\\n\\nSINGLE-MACHINE ABSOLUTE PATHS. difftest/rundiff.sh:19 and :27 are still hand-wired to /home/prabhu/veda-core-sindhu/... directly beneath a comment claiming R29 fixed exactly that, so the comment now overstates the fix. check_timing_coupling.sh:32 is the only absolute path in an otherwise relative script, and the repo already carries the symlink that would resolve it.\\n\\nSTALE HOW-TO-RUN CONTENT. difftest/README.md is the weakest document in the sweep: its one \\\"hard constraint\\\" for probe authors (Sail seeds c10-c14, treat those divergences as suspect) was closed by R24 -- veda_reset_crf() zeroes all sixteen registers and run_difftests.sh records p_reset_crf as AGREE -- its \\\"It asserts nothing\\\" is contradicted by rundiff.sh's own exit-code verdict, its manual iverilog step is now done automatically with a staleness guard, and it never mentions run_difftests.sh, so the 20/20 suite result has no documented entry point. DEVELOPER_WORKFLOW_GUIDE.md:146 still tells a debugging reader that GDB shows the real 128-bit capability, which the 256-bit respec made half a capability.\\n\\nREPO ENTRY POINT (note: /home/prabhu/veda-core-sindhu/README.md and toolchain/setup.sh sit one level above the veda-core/**/*.md glob you gave me -- I included them because they are the only quickstart this line has). setup.sh:58 pins BRANCH=veda-core for both fork clones, but the Sail model lives on phase1-respec; and README.md:224 tells a reader to clone prabhu-euro20/Veda-Core, which is this repo's frozen upstream rather than this repo.\\n\\nDeliberately NOT reported: the \\\"## Reproducing this\\\" sections in the study docs (ARCHITECTURE_IMPROVEMENT_FINDINGS, ATTACK_DEMO_PORTFOLIO, SECURITY_COMPARISON_STUDY, SYNTHESIS_CRITICAL_PATH_STUDY and five others) that point at /tmp/claude-.../scratchpad paths -- every one of them labels itself \\\"session-scoped, not committed\\\", so the document is truthful about what it is; and the \\\"## Verification\\\" blocks in the MILESTONE_*/TOOLCHAIN_MILESTONE_*/PHASE1_*/RTL_MIRROR_* results docs, which record the suite size at that milestone and are correct history, not stale current claims."
      }
    ]
  },
  "workflowProgress": [
    {
      "type": "workflow_phase",
      "index": 1,
      "title": "Audit"
    },
    {
      "type": "workflow_phase",
      "index": 2,
      "title": "Collate"
    },
    {
      "type": "workflow_agent",
      "index": 1,
      "label": "sweep:privilege",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "a5f5eedec761783b0",
      "model": "claude-opus-5",
      "state": "done",
      "startedAt": 1787035205617,
      "queuedAt": 1787035201005,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "Swept truth item 1 (veda.droppriv, Custom-3, one-way $priv,…",
      "promptPreview": "READ-ONLY. Do not modify, build, or run anything that writes. Never touch\n/home/prabhu/makerchip/rva23-core -- frozen, owned by another session.\n\n  Impl repo docs : /home/prabhu/veda-core-sindhu/veda-core/**/*.md   (~122 files)\n  Design repo    : /home/prabhu/veda-core/design/*.md, /home/prabhu/veda-core/*.md\n  Sail model     : /home/prabhu/veda-core-sail-riscv/model/extensions/Veda/*.sail\n  RTL  …",
      "lastProgressAt": 1787035896514,
      "tokens": 160456,
      "toolCalls": 49,
      "durationMs": 690222,
      "resultPreview": "{\"hits\":[{\"file\":\"/home/prabhu/veda-core-sindhu/veda-core/rtl/veda_core.tlv\",\"line\":1372,\"quote\":\"This core has no privilege-level stack to restore (it's always effectively M-mode, matching $priv's own existing one-way-drop model) -- MRET here means exactly \\\"PC = mepc\\\", not a full mstatus.MPP/MPIE restore.\",\"why_stale\":\"This is the live RTL, and the comment is contradicted by the code three line…"
    },
    {
      "type": "workflow_agent",
      "index": 2,
      "label": "sweep:sail-config",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "ab5961d5ddf61f0a2",
      "model": "claude-opus-5",
      "state": "done",
      "startedAt": 1787035205591,
      "queuedAt": 1787035201005,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "Six real hits plus two verified-clean-on-inspection entries…",
      "promptPreview": "READ-ONLY. Do not modify, build, or run anything that writes. Never touch\n/home/prabhu/makerchip/rva23-core -- frozen, owned by another session.\n\n  Impl repo docs : /home/prabhu/veda-core-sindhu/veda-core/**/*.md   (~122 files)\n  Design repo    : /home/prabhu/veda-core/design/*.md, /home/prabhu/veda-core/*.md\n  Sail model     : /home/prabhu/veda-core-sail-riscv/model/extensions/Veda/*.sail\n  RTL  …",
      "lastProgressAt": 1787035560037,
      "tokens": 113931,
      "toolCalls": 27,
      "durationMs": 353745,
      "resultPreview": "{\"hits\":[{\"file\":\"/home/prabhu/veda-core-sindhu/veda-core/MILESTONE_21_RESULTS.md\",\"line\":17,\"quote\":\"confirmed via grep: called exactly once, unconditionally, from `sys/sys_control.sail`'s own `trap_handler()`, for every Machine-delegated exception *and* interrupt alike — the only real privilege-delegation path in this project's own test config, S/U-mode being disabled).\",\"why_stale\":\"Asserts as …"
    },
    {
      "type": "workflow_agent",
      "index": 3,
      "label": "sweep:cow-paging",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "a84b8f2b408e00a73",
      "model": "claude-opus-5",
      "state": "done",
      "startedAt": 1787035205070,
      "queuedAt": 1787035201005,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "Swept all ~110 non-excluded documents in /home/prabhu/veda-…",
      "promptPreview": "READ-ONLY. Do not modify, build, or run anything that writes. Never touch\n/home/prabhu/makerchip/rva23-core -- frozen, owned by another session.\n\n  Impl repo docs : /home/prabhu/veda-core-sindhu/veda-core/**/*.md   (~122 files)\n  Design repo    : /home/prabhu/veda-core/design/*.md, /home/prabhu/veda-core/*.md\n  Sail model     : /home/prabhu/veda-core-sail-riscv/model/extensions/Veda/*.sail\n  RTL  …",
      "lastProgressAt": 1787035705992,
      "tokens": 158778,
      "toolCalls": 37,
      "durationMs": 500922,
      "resultPreview": "{\"hits\":[{\"file\":\"/home/prabhu/veda-core-sindhu/veda-core/sail_tests/PHASE2_SAIL_RESIDENCY_RESULTS.md\",\"line\":28,\"quote\":\"A page-out leaves `valid` true (the object still exists) and does not bump `generation` (only Populate and Destroy do).\",\"why_stale\":\"This is truth item 6's forbidden claim almost verbatim. `VEDA_ODT_PAGE_OUT` sets `generation = old_entry.generation + 1` (veda_ocl_insts.sail:11…"
    },
    {
      "type": "workflow_agent",
      "index": 4,
      "label": "sweep:permissions",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "ace9ede9c975244b6",
      "model": "claude-opus-5",
      "state": "done",
      "startedAt": 1787035205218,
      "queuedAt": 1787035201005,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "Swept the ~110 documents outside your already-being-edited …",
      "promptPreview": "READ-ONLY. Do not modify, build, or run anything that writes. Never touch\n/home/prabhu/makerchip/rva23-core -- frozen, owned by another session.\n\n  Impl repo docs : /home/prabhu/veda-core-sindhu/veda-core/**/*.md   (~122 files)\n  Design repo    : /home/prabhu/veda-core/design/*.md, /home/prabhu/veda-core/*.md\n  Sail model     : /home/prabhu/veda-core-sail-riscv/model/extensions/Veda/*.sail\n  RTL  …",
      "lastProgressAt": 1787036077286,
      "tokens": 199785,
      "toolCalls": 57,
      "durationMs": 870994,
      "resultPreview": "{\"hits\":[{\"file\":\"/home/prabhu/veda-core-sindhu/veda-core/TOOLCHAIN_MILESTONE_13_DESIGN.md\",\"line\":201,\"quote\":\"bound over the whole in-memory table (read-write, `Perms = 0x000C`, its own dedicated small `Object_ID`\",\"why_stale\":\"This is the design's prescription for the compiler-reserved global capability TABLE object -- the one container in the toolchain whose entire job is to hold capabilities.…"
    },
    {
      "type": "workflow_agent",
      "index": 5,
      "label": "sweep:counts-and-gaps",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "a275c1e38df7ace80",
      "model": "claude-opus-5",
      "state": "done",
      "startedAt": 1787035205584,
      "queuedAt": 1787035201005,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "Swept the ~110 non-excluded documents (impl repo 122 .md mi…",
      "promptPreview": "READ-ONLY. Do not modify, build, or run anything that writes. Never touch\n/home/prabhu/makerchip/rva23-core -- frozen, owned by another session.\n\n  Impl repo docs : /home/prabhu/veda-core-sindhu/veda-core/**/*.md   (~122 files)\n  Design repo    : /home/prabhu/veda-core/design/*.md, /home/prabhu/veda-core/*.md\n  Sail model     : /home/prabhu/veda-core-sail-riscv/model/extensions/Veda/*.sail\n  RTL  …",
      "lastProgressAt": 1787036108394,
      "tokens": 202434,
      "toolCalls": 76,
      "durationMs": 902101,
      "resultPreview": "{\"hits\":[{\"file\":\"/home/prabhu/veda-core/README.md\",\"line\":12,\"quote\":\"- **Sail (formal model)** -- `Veda-Core-sail-riscv` fork, branch `phase1-respec`: **76/76**\",\"why_stale\":\"Suite size. Sail self-check is now 102/102 (truth 7). 76/76 was the Phase-1 R10-CRBR number; Phase 2 (residency, paging, COW, R11..R41) added 26 more tests.\",\"kind\":\"CURRENT_CLAIM_NOW_FALSE\",\"suggested_fix\":\"76/76 -> 102/10…"
    },
    {
      "type": "workflow_agent",
      "index": 6,
      "label": "sweep:entry-points",
      "phaseIndex": 1,
      "phaseTitle": "Audit",
      "agentId": "a9fae966f52617523",
      "model": "claude-opus-5",
      "state": "done",
      "startedAt": 1787035205400,
      "queuedAt": 1787035201005,
      "attempt": 1,
      "lastToolName": "StructuredOutput",
      "lastToolSummary": "Swept every script and every document in the impl and desig…",
      "promptPreview": "READ-ONLY. Do not modify, build, or run anything that writes. Never touch\n/home/prabhu/makerchip/rva23-core -- frozen, owned by another session.\n\n  Impl repo docs : /home/prabhu/veda-core-sindhu/veda-core/**/*.md   (~122 files)\n  Design repo    : /home/prabhu/veda-core/design/*.md, /home/prabhu/veda-core/*.md\n  Sail model     : /home/prabhu/veda-core-sail-riscv/model/extensions/Veda/*.sail\n  RTL  …",
      "lastProgressAt": 1787035785055,
      "tokens": 177950,
      "toolCalls": 53,
      "durationMs": 578762,
      "resultPreview": "{\"hits\":[{\"file\":\"/home/prabhu/veda-core-sindhu/veda-core/rtl/run_act4_tests.sh\",\"line\":17,\"quote\":\"GCC_BIN=/home/prabhu/makerchip/rva23-core/toolchain/riscv-collab-gcc/riscv/bin\",\"why_stale\":\"Reaches into the FROZEN rva23-core sibling for objcopy/readelf. This line has its own toolchain at /home/prabhu/veda-core-sindhu/toolchain/riscv-collab-gcc/riscv/bin -- I confirmed riscv64-unknown-elf-objcop…"
    },
    {
      "type": "workflow_agent",
      "index": 7,
      "label": "collate",
      "phaseIndex": 2,
      "phaseTitle": "Collate",
      "agentId": "af693a09a7e79dc82",
      "model": "claude-opus-5",
      "state": "done",
      "startedAt": 1787036113206,
      "queuedAt": 1787036110402,
      "attempt": 1,
      "lastToolName": "Bash",
      "lastToolSummary": "set -e echo \"=== rtl/ACT4_CONFORMANCE_RESULTS.md 14-18\"; se…",
      "promptPreview": "READ-ONLY. Do not modify, build, or run anything that writes. Never touch\n/home/prabhu/makerchip/rva23-core -- frozen, owned by another session.\n\n  Impl repo docs : /home/prabhu/veda-core-sindhu/veda-core/**/*.md   (~122 files)\n  Design repo    : /home/prabhu/veda-core/design/*.md, /home/prabhu/veda-core/*.md\n  Sail model     : /home/prabhu/veda-core-sail-riscv/model/extensions/Veda/*.sail\n  RTL  …",
      "lastProgressAt": 1787036444471,
      "tokens": 94522,
      "toolCalls": 2,
      "durationMs": 331262,
      "resultPreview": "# CONSOLIDATED STALENESS FIX LIST -- grouped by file, ranked by reader harm\n\nSix sweeps merged; duplicates collapsed; conflicts adjudicated in section X at the end. Categories: **(A)** current claim now false, **(B)** instruction that would mislead, **(C)** gap recorded open but closed, **(D)** correct history, leave alone. Every quote is verbatim from the file. The eleven already-being-edited fil…"
    }
  ],
  "totalTokens": 1107856,
  "totalToolCalls": 301
}
