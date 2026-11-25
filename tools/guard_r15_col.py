#!/usr/bin/env python3
# Post-codegen guard pass for the deterministic R14 crash (hunt v1.4.6, ronda 15,
# A2-R15-01). Runs on the GENERATED tree, after tools/localize_fix_col.py and
# before the pack step, like the localize pass (same CLI: a glob of
# childoflight_recomp.*.cpp files).
#
# THE CRASH (two identical runs, deterministic):
#   SIGSEGV, fault 0x100000004 (= 0x100000000 + 4), pc
#   libmain.so+0x1520264 __imp__sub_82459F10+0x44, lr +0x28.
#   x1 = x19 = 0x100000000 exact (2^32); x0/x20 = valid host pointer with MTE tag.
#   The faulting instruction is `ldr w9, [x19, w8]` = PPC_LOAD_U32(ctx.r3.u32 + 4)
#   in sub_82459F10, and base = 0x100000000 is CORRECT (virtual_membase(),
#   xthread.cpp:630; the previous stwu executed fine, the mapping is alive).
#   Conclusion: guest NULL deref -- ctx.r3 == 0 on entry to sub_82459F10.
#   The caller, sub_8247B6D0, passes its r4 as r3; that r4 is *(this+156) of a
#   424-byte screen/state object, loaded by sub_824C5150. The base ctor
#   (sub_824C51C8, via sub_82A619B0) sets +156 = 0, and the ONLY writer of a
#   non-zero value is sub_824C4FD8 (Alloc(60, heap 66) + Ctor sub_8242EAC8),
#   reached only through the vtable init sub_82A61110. In the R14 crash +156
#   is still 0: either the init never ran for this instance before the first
#   update, or the Alloc(60) failed (guest heap exhausted/fragmented on the
#   title -> JUGAR transition). Both sub_824C5150 and sub_824C4B70 use +156
#   WITHOUT a null check; the game's own sibling sub_824C4C00 DOES check
#   +156 == 0 before calling sub_82459F10 (recomp/ppc/ppc_recomp.117.cpp,
#   __imp__sub_824C4C00: `lwz r3,156(r31)` / `cmplwi cr6,r3,0` /
#   `if (cr6.eq) goto loc_824C4C94;` -> return 0).
#
# THE FIX (this script, three sites in the SDK-syntax generated tree):
#   1. sub_824C5150 (childoflight_recomp.90.cpp): after loading r4 = *(this+156),
#      if it is 0, create the sub-object exactly as sub_824C4FD8 would
#      (Alloc(60, 66) via sub_827AE488, then Ctor sub_8242EAC8, store to +156).
#      If the Alloc fails again, skip the block (goto loc_824C5150_skip, just
#      before the epilogue): no crash. CORRECCION RONDA 18 (A2-R18-02):
#      sub_824C5150 is NOT the state-2 per-frame function -- it is the
#      state-3 ONCE-HOOK (vtable offset 48; the state-2 per-frame function
#      is sub_824C4D70 at offset 52). Proven from the XEX static data
#      (derived vtable 0x820D37D0: offset 48 = thunk 0x82A60E88 -> 5150,
#      offset 52 = thunk 0x82A60E90 -> 4D70) and sub_824C6568's source.
#      sub_824C6568 sets the once-flag (byte +52) to 1 BEFORE calling, so
#      the skip re-arms the flag (+52 = 0, r4 is already 0 on that path)
#      and the state machine retries next frame; without the re-arm the
#      one-time init would be lost forever (stall, not crash). The temp
#      at r1+80 is never touched, so its destructor is skipped too -- it
#      was never constructed on this path.
#      CORRECCION DEL COORDINADOR (ronda 15, verificacion): el Alloc/ctor
#      clobberan r3 (r3 es volatil en PPC: el Alloc devuelve el puntero en
#      r3), pero el codigo original llama a sub_8247B6D0 con r3 = el temporal
#      de r1+80. Sin restaurar r3, la guardia pasaria el sub-objeto como
#      `this` a sub_82474328 y las copias temp+4/+8 -> this+164/+168 leerian
#      del sub-objeto. Por eso el snippet restaura r3 = r1+80 al final
#      (no-op cuando +156 ya venia creado: r3 ya era r1+80).
#   2. sub_824C4B70 (childoflight_recomp.46.cpp), the +152 == 4 branch: same
#      recovery after loading r3 = *(this+156); if still 0, goto loc_824C4BE4
#      (the existing "state != 4" path, which calls sub_824C6B20 instead).
#   3. sub_824C52F8 (childoflight_recomp.99.cpp), the state-2 ONCE-HOOK
#      (ronda 19, A2-R19-01): after loading r4 = *(this+156), same
#      recovery; if the Alloc fails again, re-arm the once-flag (byte +51
#      = 0, r4 is already 0 on that path) and goto loc_824C52F8_skip, a NEW
#      label placed BEFORE the two sub_82410310 releases (r1+116, r1+108):
#      the pre-guard bctrl (vtable offset 88 -> sub_82A61000 ->
#      sub_82413FB8) already built two heap strings there (sub_82412398
#      allocates via sub_824C4CB0 -> sub_827AE110), so they must be freed
#      even on the skip path; SetState(2) then runs (state stays 2, as on
#      entry) and sub_824C6568 retries the hook next frame. 52F8 passes
#      +156 to sub_82459F10 through the wrapper sub_82488668 (mr r3,r4; bl
#      59F10, no check) -- the R17 sweep missed it because it only traced
#      DIRECT +156 loads feeding 59F10 calls, not wrapper-mediated ones.
#      No r3 restore is needed here (unlike 5150): the original code sets
#      r3 = r1+80 AFTER the +156 load, so the guard's clobber of r3 is
#      overwritten before the call.
#   A guard on sub_82459F10 ALONE is NOT enough: sub_82413AD8 does
#   r3 = *(r3+48) and sub_82474328 does r3 = *(r31+52) with r31 = the result
#   of sub_82459F10, so a NULL return from there would only move the crash.
#
# RONDA 17 (A2-R17-01 / A2-R17-02): the SAME nullable field (+156 of the same
# screen class) is used WITHOUT a null check in more places. A sweep of the
# generated tree (every `sub_82459F10(ctx, base)` call whose r3 comes from a
# `+ 156)` load) found 9 more sites, all on instances of the same class
# (proven per site in hunt-v146-round17/evidence-a2.md):
#   A2-R17-01 (BLOQUEADOR): sub_824C4D70 (childoflight_recomp.32.cpp), TWO
#   sites, `this` itself (r30 = entry r3, same +160 sub-struct, SetState via
#   sub_824C6A68, thunk sub_82A60E90 adjacent to sub_824C5150's sub_82A60E88).
#   A2-R17-02 (ALTO): seven "table element" sites -- the element is a
#   screen-class instance fetched from a global table (lwzx), passed to
#   sub_824C5FF0 (state == 4 predicate, reads element+152) and, in
#   sub_824C8940/sub_824C8018, to sub_824C4C00 itself:
#     sub_824C8940 (.129.cpp), sub_824C8018 (.86.cpp), sub_824C9A60 (.136.cpp),
#     sub_82A60450 (.184.cpp), sub_824C9DA8 (.128.cpp), sub_82A60C40 (.98.cpp),
#     sub_824C99D8 (.50.cpp).
#   The new snippets are inserted BEFORE the +156 load (mode "before"), not
#   after it like the R15 ones: the element pointer lives in a register that
#   the load itself overwrites (lwz r30,156(r30)) or in volatile r6, so an
#   after-load snippet could not store to element+156 anymore. Before-load,
#   the snippet checks the memory value, creates the sub-object, and re-tests
#   the memory value before letting the original load run. Three variants:
#     V1: the base register is non-volatile (r29/r30: sub_824C4D70,
#         sub_824C8940, sub_824C8018, sub_824C9A60, sub_82A60450) -- it
#         survives Alloc/Ctor, so the store and the re-test use it directly.
#     V2: the base is volatile r6 and the value register (r27/r28) is a
#         non-volatile that is dead at the insertion point (the load below
#         overwrites it): stash the element pointer there, restore r6 after
#         (sub_824C9DA8, sub_82A60C40).
#     V3: the base is volatile r6 and the value register is volatile r3
#         (sub_824C99D8): stash the element pointer in r1+80, proven free in
#         that frame (no other r1+80 use in the function; callees only use
#         memory below r1), restore r6 from the slot after the calls.
#   Skip targets are EXISTING labels only (no new label is created for the
#   R17 sites): the epilogue of each function, or the existing "not ready"
#   path (sub_824C4D70 -> loc_824C4DF0, i.e. SetState(1), mirroring the
#   13AD8-returns-0 failure path; sub_824C9DA8 -> loc_824C9FA0, the state!=4
#   epilogue). The script verifies each skip label exists inside the target
#   function and fails closed if it does not.
#   Liveness (verified per site against the generated code): the snippets
#   only clobber volatiles (r3, r4, lr; the Alloc trampoline also r5/r6/r10
#   and the Ctor r3-r6), which are dead across the following call by the PPC
#   ABI; the Ctor writes no FP registers; non-volatiles (r27-r31, r1) survive
#   the calls via the callees' save/rest pairs. The only volatile read
#   between each insertion point and the guarded call is the load itself,
#   whose base register the snippet preserves or restores.
#   NOT covered (deliberately): the second and third +156 uses in
#   sub_824C4C00 are dominated by its first, checked use -- no intervening
#   write to +156 exists between them, and the intervening calls take the
#   sub-object (not the screen object) as `this`. The REX_CALL_INDIRECT_FUNC
#   sites whose r3 comes from a +156 load in the 822xxxxx/82Cxxxxx ranges
#   belong to other classes; their +156 nullability was not proven.
#
# RONDA 17 (A2-R17-04): atomicity. The script used to write each file as
# soon as it was transformed, so a failure on a later file (e.g. a corrupt
# anchor) left the earlier files already guarded and the tree mixed. The
# run still failed closed (exit 1, nothing ships), but the local tree needed
# a manual re-run to converge. Now guard_file() returns the new text and
# main() writes files only after EVERY file transformed cleanly AND every
# target was found -- a failed run modifies zero files.
#
# WHY A POST-GEN SCRIPT, NOT A STAGED EDIT OF THE GENERATED FILES:
#   The APK job unpacks a FRESH codegen tree (port-src.zip) over
#   autoports/<project>/port/ on every run (workflow, job 2 "Unpack port"),
#   so an edit to the generated files in the repo would be silently wiped
#   by the next recompile. This script is the durable vehicle; the staged
#   copies of childoflight_recomp.90.cpp / .46.cpp next to it are the
#   REFERENCE outputs the script must produce (verify with diff -u).
#
# SAFETY NOTES (all verified against the SDK-syntax generated tree):
#   - sub_827AE488 is already declared in childoflight_funcs.90.h:299 and
#     .46.h:343 and called 24x / 7x in those files. sub_8242EAC8 is NOT
#     declared there (only in childoflight_funcs.23.h:181), so the script
#     adds DECLARE_REX_FUNC(sub_8242EAC8); after the #include line of each
#     target file (same macro the funcs headers use).
#   - The recovery sequence is copied verbatim from sub_824C4FD8
#     (childoflight_recomp.23.cpp, li r4,66 / li r3,60 / bl 0x827ae488 /
#     cmplwi / bl 0x8242eac8 / stw r3,156(r31)); that function keeps ctx.r31
#     live across both calls, exactly as this guard does. sub_8242EAC8 ends
#     with __restgprlr_29(ctx, base); return; so ctx.r29-r31/lr survive it.
#   - sub_8242EAC8 is NOT a plain zero-fill: after zeroing offsets 0..56 it
#     conditionally registers the object (global at 0x82CEF754, calls
#     sub_8242DE20 / sub_82426CF8). That is why the guard calls the real ctor
#     instead of hand-rolling a memset.
#   - No logging is added: the generated PCH does not include <cstdio>, and
#     the observable outcome (game proceeds past JUGAR vs. stalls with no
#     crash) is itself the diagnostic. (Ronda 18, A2-R18-02: the stall, if
#     the heap never recovers, is the state-3 once-hook retrying every
#     frame, not "state 2" as this note used to say.) If it stalls, the
#     next step is guest-heap instrumentation, not a bigger guard.
#   - (Ronda 19, A2-R19-01.) sub_827AE488 is also declared in
#     childoflight_funcs.99.h:251; sub_8242EAC8 is declared in none of the
#     target files, so the script's DECLARE insertion covers .99.cpp too.
#     The 52F8 skip does NOT go to the epilogue: it lands before the two
#     sub_82410310 releases so the heap strings built by the pre-guard
#     bctrl are freed on the skip path; SetState(2) then runs (state stays
#     2, its entry value) with the once-flag +51 re-armed. LIMIT: under a
#     persistent heap exhaustion (H1) the pre-guard bctrl itself can fail
#     first -- its string ctor sub_82412398 allocates via sub_824C4CB0 ->
#     sub_827AE110 (same heap family) and stores to the result with NO null
#     check, so a failed small alloc faults at guest 0 (0x100000000) BEFORE
#     the guard point. This guard fixes the +156 path whenever those small
#     allocs succeed; it cannot cover a failure inside the bctrl.
#   - Idempotent: files already carrying the GUARD_R15_A2-R15-01 marker are
#     skipped. Any target function or anchor that does not match EXACTLY
#     fails the run (exit 1) instead of shipping unguarded code.
#   - (Ronda 17.) sub_827AE488 is also declared in the funcs headers of all
#     eight new target files (childoflight_funcs.32/.129/.86/.136/.184/.128/
#     .98/.50.h, one DECLARE each); sub_8242EAC8 is declared in none of them
#     and called in none of them yet, so the script's DECLARE insertion
#     covers all eight. The per-file tripwire counts in the workflow and in
#     the FULL script were extended accordingly (see below).
#
# Usage (CI, pwsh, after the localize step):
#   $gen = "$env:REXAUTO_WORK\${{ env.REX_PROJECT }}\port\generated\default"
#   python "$env:GITHUB_WORKSPACE\tools\guard_r15_col.py" "$gen\childoflight_recomp.*.cpp"
#   exit $LASTEXITCODE
# Local check: python3 tools/guard_r15_col.py --dry-run <glob>

import glob
import re
import sys

MARKER = "GUARD_R15_A2-R15-01"

# --- recovery snippet for sub_824C5150 (r4 = *(this+156), this = ctx.r31) ---
RECOVERY_5150 = """\t// %s: +156 es el sub-objeto creado por sub_824C4FD8 (Alloc(60, heap 66)
\t// + Ctor sub_8242EAC8); el ctor base pone +156 = 0 y solo sub_824C4FD8 lo
\t// llena. En el crash de R14 llega a 0 (init no corrio o el Alloc fallo)
\t// y sub_8247B6D0 lo pasa como `this` a sub_82459F10, que lee [r3+4] ->
\t// SIGSEGV en base+4. Si falta, se crea aqui como haria el init; si el
\t// Alloc vuelve a fallar se salta el bloque (sin crash). OJO (ronda 18,
\t// A2-R18-02): sub_824C5150 NO es la funcion por frame del estado 2 --
\t// es el once-hook del estado 3 (vtable offset 48; el per-frame del
\t// estado 2 es sub_824C4D70, offset 52). sub_824C6568 pone el flag once
\t// (+52) a 1 ANTES de llamar, asi que el salto rearma el flag (+52 = 0)
\t// y el proximo frame lo reintenta; sin el rearmado el init se perderia
\t// para siempre. Idioma propio del juego:
\t// sub_824C4C00 chequea +156 == 0 antes de llamar a sub_82459F10.
\tif (ctx.r4.u32 == 0) {
\t\tctx.r3.s64 = 60;
\t\tctx.r4.s64 = 66;
\t\tctx.lr = 0x824C516C;
\t\tsub_827AE488(ctx, base);
\t\tif (ctx.r3.u32 != 0) {
\t\t\tctx.lr = 0x824C516C;
\t\t\tsub_8242EAC8(ctx, base);
\t\t\tREX_STORE_U32(ctx.r31.u32 + 156, ctx.r3.u32);
\t\t\tctx.r4.u64 = ctx.r3.u64;
\t\t}
\t}
\tif (ctx.r4.u32 == 0) {
\t\t// A2-R18-02: rearmar el once-hook del estado 3 (byte +52 a 0) para
\t\t// que sub_824C6568 vuelva a llamar a sub_824C5150 el proximo frame.
\t\t// r4 ya es 0 en esta rama (es la condicion del salto) y r31 sigue
\t\t// siendo `this`; el epilogo no lee r4. Solo dos sitios escriben
\t\t// este flag: el ctor sub_824C6980 (= 0) y sub_824C6568 (= 1).
\t\tREX_STORE_U8(ctx.r31.u32 + 52, ctx.r4.u8);
\t\tgoto loc_824C5150_skip;
\t}
\t// %s (coord.): r3 es volatil y el Alloc/ctor lo clobberan (devuelven el
\t// puntero en r3); el codigo original llama a sub_8247B6D0 con r3 = el
\t// temporal de r1+80. Restaurarlo aqui (no-op si +156 ya venia creado).
\tctx.r3.s64 = ctx.r1.s64 + 80;
""" % (MARKER, MARKER)

# --- R17 text of the 5150 recovery, verbatim (ronda 18, A2-R18-04) ---
# The migration below replaces this text with RECOVERY_5150 above when it
# finds it in a file guarded by the R17 script. Do not edit either literal
# without updating the other side of the migration.
RECOVERY_5150_R17 = """\t// %s: +156 es el sub-objeto creado por sub_824C4FD8 (Alloc(60, heap 66)
\t// + Ctor sub_8242EAC8); el ctor base pone +156 = 0 y solo sub_824C4FD8 lo
\t// llena. En el crash de R14 llega a 0 (init no corrio o el Alloc fallo)
\t// y sub_8247B6D0 lo pasa como `this` a sub_82459F10, que lee [r3+4] ->
\t// SIGSEGV en base+4. Si falta, se crea aqui como haria el init; si el
\t// Alloc vuelve a fallar se salta el bloque (sin crash, estado queda en 2
\t// y se reintenta el proximo frame). Idioma propio del juego:
\t// sub_824C4C00 chequea +156 == 0 antes de llamar a sub_82459F10.
\tif (ctx.r4.u32 == 0) {
\t\tctx.r3.s64 = 60;
\t\tctx.r4.s64 = 66;
\t\tctx.lr = 0x824C516C;
\t\tsub_827AE488(ctx, base);
\t\tif (ctx.r3.u32 != 0) {
\t\t\tctx.lr = 0x824C516C;
\t\t\tsub_8242EAC8(ctx, base);
\t\t\tREX_STORE_U32(ctx.r31.u32 + 156, ctx.r3.u32);
\t\t\tctx.r4.u64 = ctx.r3.u64;
\t\t}
\t}
\tif (ctx.r4.u32 == 0) goto loc_824C5150_skip;
\t// %s (coord.): r3 es volatil y el Alloc/ctor lo clobberan (devuelven el
\t// puntero en r3); el codigo original llama a sub_8247B6D0 con r3 = el
\t// temporal de r1+80. Restaurarlo aqui (no-op si +156 ya venia creado).
\tctx.r3.s64 = ctx.r1.s64 + 80;
""" % (MARKER, MARKER)

# --- recovery snippet for sub_824C4B70 (r3 = *(this+156), this = ctx.r31) ---
RECOVERY_4B70 = """\t// %s: +156 es el sub-objeto creado por sub_824C4FD8 (Alloc(60, heap 66)
\t// + Ctor sub_8242EAC8); en el crash de R14 llega a 0 y esta rama lo pasa
\t// sin chequeo a sub_82459F10, que lee [r3+4] -> SIGSEGV en base+4. Si
\t// falta, se crea aqui como haria el init; si el Alloc vuelve a fallar
\t// se sigue por loc_824C4BE4 (la ruta de estado != 4, sin crash).
\tif (ctx.r3.u32 == 0) {
\t\tctx.r3.s64 = 60;
\t\tctx.r4.s64 = 66;
\t\tctx.lr = 0x824C4B98;
\t\tsub_827AE488(ctx, base);
\t\tif (ctx.r3.u32 != 0) {
\t\t\tctx.lr = 0x824C4B98;
\t\t\tsub_8242EAC8(ctx, base);
\t\t\tREX_STORE_U32(ctx.r31.u32 + 156, ctx.r3.u32);
\t\t}
\t}
\tif (ctx.r3.u32 == 0) goto loc_824C4BE4;
""" % MARKER

# --- recovery snippet for sub_824C52F8 (r4 = *(this+156), this = ctx.r31) ---
# Ronda 19 (A2-R19-01): the state-2 once-hook (vtable offset 44). Mirrors
# RECOVERY_5150, with two differences: (1) no r3 restore -- the original
# code sets r3 = r1+80 AFTER the +156 load, so the Alloc/Ctor clobber of r3
# is overwritten before the sub_82488668 call; (2) the skip label is NOT
# the epilogue: it sits BEFORE the two sub_82410310 releases, because the
# pre-guard bctrl already allocated two heap strings at r1+108/r1+116 and
# they must be freed even when the block is skipped (else one leak of two
# strings per failed retry-frame while the heap stays exhausted).
# SetState(2) still runs after the releases: the state stays 2 (its entry
# value) and the re-armed flag (+51 = 0) makes sub_824C6568 retry the hook
# next frame, exactly as 5150's skip leaves state 3 with +52 re-armed.
RECOVERY_52F8 = """\t// %s: +156 es el sub-objeto creado por sub_824C4FD8 (Alloc(60, heap 66)
\t// + Ctor sub_8242EAC8); el ctor base pone +156 = 0 y solo sub_824C4FD8 lo
\t// llena. En el crash de R14 llega a 0 (init no corrio o el Alloc fallo)
\t// y sub_82488668 lo pasa como `this` a sub_82459F10, que lee [r3+4] ->
\t// SIGSEGV en base+4 (el mismo crash que en sub_824C5150, por el otro
\t// once-hook). Si falta, se crea aqui como haria el init; si el Alloc
\t// vuelve a fallar se salta el bloque (sin crash). OJO (ronda 19,
\t// A2-R19-01): sub_824C52F8 es el once-hook del estado 2 (vtable offset
\t// 44; el per-frame del estado 2 es sub_824C4D70, offset 52).
\t// sub_824C6568 pone el flag once (+51) a 1 ANTES de llamar, asi que el
\t// salto rearma el flag (+51 = 0) y el proximo frame lo reintenta; sin
\t// el rearmado el init se perderia para siempre. El salto cae ANTES de
\t// las dos liberaciones sub_82410310 (r1+116 y r1+108): el bctrl previo
\t// (vtable offset 88 -> sub_82A61000 -> sub_82413FB8) ya construyo esas
\t// dos cadenas en el heap y hay que liberarlas aunque el bloque se
\t// salte; despues corre SetState(2) (el estado queda en 2, como a la
\t// entrada) y el epilogo. Idioma propio del juego: sub_824C4C00 chequea
\t// +156 == 0 antes de llamar a sub_82459F10.
\tif (ctx.r4.u32 == 0) {
\t\tctx.r3.s64 = 60;
\t\tctx.r4.s64 = 66;
\t\tctx.lr = 0x824C5330;
\t\tsub_827AE488(ctx, base);
\t\tif (ctx.r3.u32 != 0) {
\t\t\tctx.lr = 0x824C5330;
\t\t\tsub_8242EAC8(ctx, base);
\t\t\tREX_STORE_U32(ctx.r31.u32 + 156, ctx.r3.u32);
\t\t\tctx.r4.u64 = ctx.r3.u64;
\t\t}
\t}
\tif (ctx.r4.u32 == 0) {
\t\t// A2-R19-01: rearmar el once-hook del estado 2 (byte +51 a 0) para
\t\t// que sub_824C6568 vuelva a llamar a sub_824C52F8 el proximo frame.
\t\t// r4 ya es 0 en esta rama (es la condicion del salto) y r31 sigue
\t\t// siendo `this`; el salto cae antes de las liberaciones 810310, que
\t\t// leen solo r1+116/r1+108 (construidos por el bctrl previo), y de
\t\t// SetState(2). Solo dos sitios escriben este flag en esta clase:
\t\t// el ctor sub_824C6980 (= 0) y sub_824C6568 (= 1).
\t\tREX_STORE_U8(ctx.r31.u32 + 51, ctx.r4.u8);
\t\tgoto loc_824C52F8_skip;
\t}
""" % MARKER

# --- recovery snippets inserted BEFORE the +156 load (ronda 17) ---
# Templates use %(name)s placeholders (braces stay literal, like above).
# `lr` is the address of the guarded `bl 0x82459f10` (same convention as the
# R15 snippets: ctx.lr is only a cookie for the callee's save/restore).
# `skip` is an EXISTING label of the target function (verified by guard_file).
_RECOVERY_BEFORE_V1 = """\t// %(marker)s: +156 es el sub-objeto creado por sub_824C4FD8 (Alloc(60, heap 66)
\t// + Ctor sub_8242EAC8); el ctor base (sub_824C51C8) pone +156 = 0 y solo
\t// sub_824C4FD8 lo llena. Si llega a 0 (init no corrio o el Alloc fallo),
\t// sub_82459F10 lee [r3+4] -> SIGSEGV en base+4 (el crash de R14). Se
\t// crea aqui ANTES de la carga, como haria el init; si el Alloc vuelve
\t// a fallar se salta a %(skip)s (sin crash, se reintenta el proximo frame).
\t// %(base)s es no volatil: sobrevive al Alloc/ctor (que solo clobberan
\t// volatiles), asi que la carga de abajo lee el valor ya creado.
\tif (ctx.%(base)s.u32 != 0 && REX_LOAD_U32(ctx.%(base)s.u32 + 156) == 0) {
\t\tctx.r3.s64 = 60;
\t\tctx.r4.s64 = 66;
\t\tctx.lr = %(lr)s;
\t\tsub_827AE488(ctx, base);
\t\tif (ctx.r3.u32 != 0) {
\t\t\tctx.lr = %(lr)s;
\t\t\tsub_8242EAC8(ctx, base);
\t\t\tREX_STORE_U32(ctx.%(base)s.u32 + 156, ctx.r3.u32);
\t\t}
\t\tif (REX_LOAD_U32(ctx.%(base)s.u32 + 156) == 0) goto %(skip)s;
\t}
"""

_RECOVERY_BEFORE_V2 = """\t// %(marker)s: +156 es el sub-objeto creado por sub_824C4FD8 (Alloc(60, heap 66)
\t// + Ctor sub_8242EAC8); el ctor base (sub_824C51C8) pone +156 = 0 y solo
\t// sub_824C4FD8 lo llena. Si llega a 0 (init no corrio o el Alloc fallo),
\t// sub_82459F10 lee [r3+4] -> SIGSEGV en base+4 (el crash de R14). Se
\t// crea aqui ANTES de la carga, como haria el init; si el Alloc vuelve
\t// a fallar se salta a %(skip)s (sin crash, se reintenta el proximo frame).
\t// r6 es volatil: el Alloc/ctor lo clobberan, asi que el puntero del
\t// elemento se guarda en %(stash)s (no volatil, muerto aqui: la carga de
\t// abajo lo sobrescribe) y se restaura r6 despues, para la carga.
\tctx.%(stash)s.u64 = ctx.r6.u64;
\tif (ctx.%(stash)s.u32 != 0 && REX_LOAD_U32(ctx.%(stash)s.u32 + 156) == 0) {
\t\tctx.r3.s64 = 60;
\t\tctx.r4.s64 = 66;
\t\tctx.lr = %(lr)s;
\t\tsub_827AE488(ctx, base);
\t\tif (ctx.r3.u32 != 0) {
\t\t\tctx.lr = %(lr)s;
\t\t\tsub_8242EAC8(ctx, base);
\t\t\tREX_STORE_U32(ctx.%(stash)s.u32 + 156, ctx.r3.u32);
\t\t}
\t\tif (REX_LOAD_U32(ctx.%(stash)s.u32 + 156) == 0) goto %(skip)s;
\t}
\tctx.r6.u64 = ctx.%(stash)s.u64;
"""

_RECOVERY_BEFORE_V3 = """\t// %(marker)s: +156 es el sub-objeto creado por sub_824C4FD8 (Alloc(60, heap 66)
\t// + Ctor sub_8242EAC8); el ctor base (sub_824C51C8) pone +156 = 0 y solo
\t// sub_824C4FD8 lo llena. Si llega a 0 (init no corrio o el Alloc fallo),
\t// sub_82459F10 lee [r3+4] -> SIGSEGV en base+4 (el crash de R14). Se
\t// crea aqui ANTES de la carga, como haria el init; si el Alloc vuelve
\t// a fallar se salta a %(skip)s (sin crash, se reintenta el proximo frame).
\t// r6 es volatil: el Alloc/ctor lo clobberan, asi que el puntero del
\t// elemento se guarda en r1+%(slot)d (libre en este frame: sub_824C99D8 no
\t// usa ningun temporal en r1+0..95 salvo los saves de -8/-16) y se
\t// restaura r6 despues, para la carga.
\tREX_STORE_U32(ctx.r1.u32 + %(slot)d, ctx.r6.u32);
\tif (ctx.r6.u32 != 0 && REX_LOAD_U32(ctx.r6.u32 + 156) == 0) {
\t\tctx.r3.s64 = 60;
\t\tctx.r4.s64 = 66;
\t\tctx.lr = %(lr)s;
\t\tsub_827AE488(ctx, base);
\t\tif (ctx.r3.u32 != 0) {
\t\t\tctx.lr = %(lr)s;
\t\t\tsub_8242EAC8(ctx, base);
\t\t\tctx.r6.u64 = REX_LOAD_U32(ctx.r1.u32 + %(slot)d);
\t\t\tREX_STORE_U32(ctx.r6.u32 + 156, ctx.r3.u32);
\t\t}
\t\tctx.r6.u64 = REX_LOAD_U32(ctx.r1.u32 + %(slot)d);
\t\tif (REX_LOAD_U32(ctx.r6.u32 + 156) == 0) goto %(skip)s;
\t}
"""


def _before_v1(base, lr, skip):
    return _RECOVERY_BEFORE_V1 % {
        "marker": MARKER, "base": base, "lr": lr, "skip": skip}


def _before_v2(stash, lr, skip):
    return _RECOVERY_BEFORE_V2 % {
        "marker": MARKER, "stash": stash, "lr": lr, "skip": skip}


def _before_v3(slot, lr, skip):
    return _RECOVERY_BEFORE_V3 % {
        "marker": MARKER, "slot": slot, "lr": lr, "skip": skip}


# --- per-target spec: function, anchors, insertion, label ---
# mode "after": insert the recovery after anchor line
#   `insert_after_anchor_line` (R15 sites, unchanged).
# mode "before": insert the recovery before the anchor's first line (R17
#   sites); the anchor starts at the `// lwz ...` comment of the +156 load.
#   `skip_label` is an EXISTING label of the function that the recovery
#   jumps to when the Alloc fails again (guard_file verifies it exists).
# A target may carry several anchors (sub_824C4D70 has two identical loads,
#   disambiguated by the call that follows each one).
TARGETS = {
    "sub_824C5150": {
        "file_hint": "childoflight_recomp.90.cpp",
        "mode": "after",
        # Anchor: the load of +156 and the call that follows it.
        "anchors": [(
            "\t// lwz r4,156(r31)\n"
            "\tctx.r4.u64 = REX_LOAD_U32(ctx.r31.u32 + 156);\n"
            "\t// bl 0x8247b6d0\n"
        )],
        "insert_after_anchor_line": 2,  # after the REX_LOAD_U32 line
        "recovery": RECOVERY_5150,
        # Label anchor: the epilogue of this function only (824C6A68 called
        # once here); the skip label goes right before `// addi r1,r1,128`.
        "label_anchor": (
            "\tsub_824C6A68(ctx, base);\n"
            "\t// addi r1,r1,128\n"
        ),
        "label": "loc_824C5150_skip:\n",
        "skip_label": None,
    },
    "sub_824C4B70": {
        "file_hint": "childoflight_recomp.46.cpp",
        "mode": "after",
        "anchors": [(
            "\t// lwz r3,156(r3)\n"
            "\tctx.r3.u64 = REX_LOAD_U32(ctx.r3.u32 + 156);\n"
            "\t// bl 0x82459f10\n"
        )],
        "insert_after_anchor_line": 2,
        "recovery": RECOVERY_4B70,
        "label_anchor": None,  # reuses the existing loc_824C4BE4 label
        "label": None,
        "skip_label": None,
    },
    # --- ronda 19: A2-R19-01, state-2 once-hook (same class, wrapper path) ---
    # Found by tracing 59F10 calls through wrappers (r3 = r4 parameters):
    # sub_82488668 does `mr r3,r4; bl 59F10`, and its only caller is 52F8
    # with r4 = *(this+156). The R17 sweep missed it: it only traced DIRECT
    # +156 loads feeding 59F10 calls. The other r3=r4 wrappers (67C10,
    # 67938, 62B88, 67048, 65098, 66948, 67508, 62A88, 65AD8) take *(r30+136)
    # or *(r30+148) from OTHER classes -- same shape, no proof of
    # nullability, not guarded (see hunt-v146-round19/evidence-a2.md).
    "sub_824C52F8": {
        "file_hint": "childoflight_recomp.99.cpp",
        "mode": "after",
        # Anchor: the load of +156 only (2 lines). Unlike 5150, the
        # `// bl 0x82488668` comment does NOT follow the load directly:
        # the original code sets r3 = r1+80 between them, so a 3-line
        # anchor would never match. The recovery needs no r3 restore for
        # the same reason (see RECOVERY_52F8).
        "anchors": [(
            "\t// lwz r4,156(r31)\n"
            "\tctx.r4.u64 = REX_LOAD_U32(ctx.r31.u32 + 156);\n"
        )],
        "insert_after_anchor_line": 2,  # after the REX_LOAD_U32 line
        "recovery": RECOVERY_52F8,
        # Label anchor: the skip label goes BEFORE the first sub_82410310
        # release (not at the epilogue): the pre-guard bctrl already
        # allocated two heap strings at r1+108/r1+116 and they must be
        # freed even on the skip path; SetState(2) then runs (state stays
        # 2) and the epilogue follows. The label is inserted after the
        # `sub_8248BA00(ctx, base);` line, i.e. before `// addi r3,r1,116`.
        "label_anchor": (
            "\tsub_8248BA00(ctx, base);\n"
            "\t// addi r3,r1,116\n"
        ),
        "label": "loc_824C52F8_skip:\n",
        "skip_label": None,
    },
    # --- ronda 17: A2-R17-01, same `this` (r30 = entry r3), two sites ---
    "sub_824C4D70": {
        "file_hint": "childoflight_recomp.32.cpp",
        "mode": "before",
        "anchors": [
            (
                "\t// lwz r3,156(r30)\n"
                "\tctx.r3.u64 = REX_LOAD_U32(ctx.r30.u32 + 156);\n"
                "\t// bl 0x82459f10\n"
                "\tctx.lr = 0x824C4DC0;\n"
                "\tsub_82459F10(ctx, base);\n"
                "\t// bl 0x82413ad8\n"
            ),
            (
                "\t// lwz r3,156(r30)\n"
                "\tctx.r3.u64 = REX_LOAD_U32(ctx.r30.u32 + 156);\n"
                "\t// bl 0x82459f10\n"
                "\tctx.lr = 0x824C4DD8;\n"
                "\tsub_82459F10(ctx, base);\n"
                "\t// bl 0x8240dba0\n"
            ),
        ],
        # Site 1 skips to the SetState(1) path (r31 is 1 at both sites;
        # mirrors the existing 13AD8-returns-0 failure path at loc_824C4DF0).
        "recovery": None,  # per-anchor below (different lr per site)
        "recoveries": [
            _before_v1("r30", "0x824C4DC0", "loc_824C4DF0"),
            _before_v1("r30", "0x824C4DD8", "loc_824C4DF0"),
        ],
        "label_anchor": None,
        "label": None,
        "skip_label": "loc_824C4DF0",
    },
    # --- ronda 17: A2-R17-02, table-element sites (one anchor each) ---
    "sub_824C8940": {
        "file_hint": "childoflight_recomp.129.cpp",
        "mode": "before",
        "anchors": [(
            "\t// lwz r30,156(r30)\n"
            "\tctx.r30.u64 = REX_LOAD_U32(ctx.r30.u32 + 156);\n"
            "\t// mr r3,r30\n"
        )],
        "recovery": _before_v1("r30", "0x824C89D0", "loc_824C8A8C"),
        "label_anchor": None,
        "label": None,
        "skip_label": "loc_824C8A8C",  # epilogue (the 8A54 join needs r8/r10)
    },
    "sub_824C8018": {
        "file_hint": "childoflight_recomp.86.cpp",
        "mode": "before",
        "anchors": [(
            "\t// lwz r30,156(r30)\n"
            "\tctx.r30.u64 = REX_LOAD_U32(ctx.r30.u32 + 156);\n"
            "\t// mr r3,r30\n"
        )],
        "recovery": _before_v1("r30", "0x824C80A8", "loc_824C8204"),
        "label_anchor": None,
        "label": None,
        "skip_label": "loc_824C8204",  # epilogue
    },
    "sub_824C9A60": {
        "file_hint": "childoflight_recomp.136.cpp",
        "mode": "before",
        "anchors": [(
            "\t// lwz r29,156(r29)\n"
            "\tctx.r29.u64 = REX_LOAD_U32(ctx.r29.u32 + 156);\n"
            "\t// mr r3,r29\n"
        )],
        "recovery": _before_v1("r29", "0x824C9B04", "loc_824C9C18"),
        "label_anchor": None,
        "label": None,
        "skip_label": "loc_824C9C18",  # epilogue
    },
    "sub_82A60450": {
        "file_hint": "childoflight_recomp.184.cpp",
        "mode": "before",
        "anchors": [(
            "\t// lwz r30,156(r30)\n"
            "\tctx.r30.u64 = REX_LOAD_U32(ctx.r30.u32 + 156);\n"
            "\t// mr r3,r30\n"
        )],
        "recovery": _before_v1("r30", "0x82A604FC", "loc_82A605E8"),
        "label_anchor": None,
        "label": None,
        "skip_label": "loc_82A605E8",  # epilogue (the 605B0 join needs r9/r10/r11)
    },
    "sub_824C9DA8": {
        "file_hint": "childoflight_recomp.128.cpp",
        "mode": "before",
        "anchors": [(
            "\t// lwz r27,156(r6)\n"
            "\tctx.r27.u64 = REX_LOAD_U32(ctx.r6.u32 + 156);\n"
        )],
        "recovery": _before_v2("r27", "0x824C9F00", "loc_824C9FA0"),
        "label_anchor": None,
        "label": None,
        # State!=4 epilogue (returns r31, which is 0 at the guard point:
        # `li r31,0` at .128.cpp:11531). A2-R18-01: the old target
        # loc_824C9F8C did `mr r4,r28; mr r3,r29; bl sub_824C8600`, and r28
        # is STALE on the skip path -- its computation (`r28 = *(this+204)
        # + *(this+212)*60 - 60`, .128.cpp:11608) is jumped over -- while
        # sub_824C8600 dereferences r4 unconditionally (`lwz r11,0(r31)`).
        # loc_824C9FA0 reads no r28/r29, makes no calls, returns 0. The
        # 150 lines between the load and the call prepare a 9DA8-local temp
        # for the post-59F10 work; the epilogue does not read it, so
        # skipping the whole block on Alloc failure is safe (retried on
        # the next call of sub_824C9DA8; its host is vtable-reached, so
        # per-frame frequency is not statically proven).
        "skip_label": "loc_824C9FA0",
    },
    "sub_82A60C40": {
        "file_hint": "childoflight_recomp.98.cpp",
        "mode": "before",
        "anchors": [(
            "\t// lwz r28,156(r6)\n"
            "\tctx.r28.u64 = REX_LOAD_U32(ctx.r6.u32 + 156);\n"
        )],
        "recovery": _before_v2("r28", "0x82A60C84", "loc_82A60D64"),
        "label_anchor": None,
        "label": None,
        "skip_label": "loc_82A60D64",  # epilogue
    },
    "sub_824C99D8": {
        "file_hint": "childoflight_recomp.50.cpp",
        "mode": "before",
        "anchors": [(
            "\t// lwz r3,156(r6)\n"
            "\tctx.r3.u64 = REX_LOAD_U32(ctx.r6.u32 + 156);\n"
        )],
        "recovery": _before_v3(80, "0x824C9A10", "loc_824C9A48"),
        "label_anchor": None,
        "label": None,
        "skip_label": "loc_824C9A48",  # epilogue (shared with the 0FBB0-fail path)
    },
}

FUNC_RE = re.compile(r"^DEFINE_REX_FUNC\((sub_[0-9A-F]+)\) \{$")
INCLUDE_RE = re.compile(r'^#include "(childoflight_funcs\.\d+\.h)"$')


def brace_delta(line):
    return line.count("{") - line.count("}")


def find_function_span(lines, name):
    """Return (start, end) line indices of DEFINE_REX_FUNC(name) {...}."""
    start = None
    for i, line in enumerate(lines):
        m = FUNC_RE.match(line)
        if m and m.group(1) == name:
            start = i
            break
    if start is None:
        return None
    depth = 1
    for j in range(start + 1, len(lines)):
        depth += brace_delta(lines[j])
        if depth <= 0:
            return (start, j)
    return None


# --- migration from the R17 guard (ronda 18, parent catch, A2-R18-04) ---
# Two recoveries changed in R18: sub_824C9DA8's skip label (loc_824C9F8C ->
# loc_824C9FA0, A2-R18-01) and sub_824C5150's tail (the once-hook re-arm,
# A2-R18-02). A file guarded by the R17 script carries MARKER, so the plain
# "already applied" check would skip the whole file and the R18 fixes would
# never reach a tree guarded by the old script -- the local FULL build
# reuses its generated tree, and the tripwire only counts markers (22 either
# way), so nothing else would catch it. Same class as the R16 root cause
# (guard existed only in CI). The migration below replaces the old recovery
# text with the new one, verbatim, failing closed on any text it does not
# recognise.


def _find_block(lines, block_lines):
    """Start indices of every occurrence of block_lines as a contiguous run."""
    hits = []
    n = len(block_lines)
    for i in range(len(lines) - n + 1):
        if lines[i : i + n] == block_lines:
            hits.append(i)
    return hits


def _migrations():
    """(name, old recovery, new recovery) for the recoveries that changed."""
    return [
        ("sub_824C5150", RECOVERY_5150_R17, RECOVERY_5150),
        ("sub_824C9DA8",
         _before_v2("r27", "0x824C9F00", "loc_824C9F8C"),
         TARGETS["sub_824C9DA8"]["recovery"]),
    ]


def migrate_guard_file(path, text, eol, lines):
    """Upgrade a file guarded by the R17 script to the R18 recoveries.

    Returns the same tuple shape as guard_file. Only the two changed
    recoveries are touched; every other target is left exactly as it is.
    A target whose function is not defined in this file is skipped. A
    target whose recovery is neither the R17 nor the R18 text fails the
    whole run (exit 1) with zero files modified -- same atomicity rule as
    the fresh path."""
    migrated = set()
    for name, old_rec, new_rec in _migrations():
        if f"DEFINE_REX_FUNC({name})" not in text:
            continue
        old_lines = old_rec.rstrip("\n").split("\n")
        new_lines = new_rec.rstrip("\n").split("\n")
        old_hits = _find_block(lines, old_lines)
        new_hits = _find_block(lines, new_lines)
        if new_hits and not old_hits:
            continue  # already migrated
        if old_hits and not new_hits:
            if len(old_hits) != 1:
                return (set(), False,
                        f"{path}: {name}: R17 recovery found "
                        f"{len(old_hits)} times, refusing to guess",
                        None)
            i = old_hits[0]
            lines[i : i + len(old_lines)] = new_lines
            migrated.add(name)
            continue
        return (set(), False,
                f"{path}: {name}: recovery is neither the R17 nor the "
                f"R18 text (old={len(old_hits)}, new={len(new_hits)})",
                None)
    if not migrated:
        return (set(), True, None, None)
    return (migrated, False, None, eol.join(lines))


def guard_file(path, dry_run):
    """Apply the guards for any target function present in this file.

    Returns (transformed_names, already_applied, error, new_text), where
    transformed_names is the set of target functions transformed in this
    file (empty when the file holds none of them), and new_text is the full
    transformed file content (None when nothing changed).

    The generated tree is CRLF (the SDK codegen emits \\r\\n); the file is
    read and written with newline="" so the line ending is preserved
    byte-for-byte -- a naive text-mode rewrite would flip every line to LF
    and drown the diff in 36k unchanged lines.

    This function NEVER writes to disk (ronda 17, A2-R17-04): main() writes
    the collected new texts only after every file transformed cleanly and
    every target was found, so a failed run modifies zero files."""
    with open(path, encoding="utf-8", errors="surrogateescape",
              newline="") as f:
        text = f.read()
    eol = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(eol)
    if MARKER in text:
        # (Ronda 18, A2-R18-04.) A file guarded by the R17 script is
        # UPGRADED to the R18 recoveries, not skipped: see
        # migrate_guard_file above.
        return migrate_guard_file(path, text, eol, lines)
    transformed = set()
    changed = False
    for name, spec in TARGETS.items():
        span = find_function_span(lines, name)
        if span is None:
            continue  # target lives in another file of the glob
        start, end = span
        body = lines[start : end + 1]
        # A "before" target jumps to an existing label on Alloc failure:
        # it must exist inside this function, or the guard would emit a
        # goto to nowhere. Fail closed before inserting anything.
        if spec.get("skip_label") is not None:
            if not any(l.strip() == spec["skip_label"] + ":"
                       for l in body):
                return (set(), False,
                        f"{path}: {name}: skip label "
                        f"{spec['skip_label']} not found in function",
                        None)
        recoveries = spec.get("recoveries")
        if recoveries is None:
            recoveries = [spec["recovery"]] * len(spec["anchors"])
        for anchor_text, recovery in zip(spec["anchors"], recoveries):
            # Re-find the span (lines shift after each insert).
            span = find_function_span(lines, name)
            start, end = span
            body = lines[start : end + 1]
            anchor_lines = anchor_text.rstrip("\n").split("\n")
            # Locate the anchor inside the function body.
            idx = None
            for i in range(len(body) - len(anchor_lines) + 1):
                if body[i : i + len(anchor_lines)] == anchor_lines:
                    idx = i
                    break
            if idx is None:
                return (set(), False,
                        f"{path}: {name}: anchor not found verbatim -- "
                        "codegen output changed, refusing to guess",
                        None)
            if spec["mode"] == "before":
                insert_at = start + idx
            else:
                insert_at = start + idx + spec["insert_after_anchor_line"]
            lines[insert_at:insert_at] = recovery.rstrip("\n").split("\n")
            changed = True
            transformed.add(name)
        if spec.get("label") is not None:
            # Re-find the function span (lines shifted by the insert).
            span = find_function_span(lines, name)
            start, end = span
            body = lines[start : end + 1]
            label_lines = spec["label_anchor"].rstrip("\n").split("\n")
            lidx = None
            for i in range(len(body) - len(label_lines) + 1):
                if body[i : i + len(label_lines)] == label_lines:
                    lidx = i
                    break
            if lidx is None:
                return (set(), False,
                        f"{path}: {name}: label anchor not found verbatim",
                        None)
            label_at = start + lidx + 1  # before `// addi r1,r1,128`
            lines[label_at:label_at] = [spec["label"].rstrip("\n")]
    if not changed:
        return (set(), False, None, None)
    # sub_8242EAC8 is not declared in the target file's funcs header
    # (only in childoflight_funcs.23.h); declare it next to the include.
    for i, line in enumerate(lines):
        if INCLUDE_RE.match(line):
            decl = f"DECLARE_REX_FUNC(sub_8242EAC8);  // {MARKER}"
            if decl not in "\n".join(lines):
                lines.insert(i + 1, decl)
            break
    else:
        return (set(), False,
                f"{path}: no childoflight_funcs.N.h include found",
                None)
    new = eol.join(lines)
    return (transformed, False, None, new)


def main():
    if len(sys.argv) < 2:
        print("usage: guard_r15_col.py [--dry-run] <glob>", file=sys.stderr)
        return 2
    dry_run = "--dry-run" in sys.argv
    # Ronda 16 (A2-R16-02): UN SOLO glob posicional. Antes,
    # `guard_r15_col.py a.cpp b.cpp` procesaba SOLO a.cpp en silencio
    # (next() tomaba el primer posicional e ignoraba el resto; solo se
    # delataba si un target vivia en el fichero ignorado, por el chequeo
    # de missing al final). Y con solo `--dry-run` (sin posicional),
    # next() tiraba StopIteration sin mensaje. Un solo glob es la unica
    # forma soportada: guard_r15_col.py "childoflight_recomp.*.cpp".
    positionals = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(positionals) != 1:
        print(f"guard_r15_col: ERROR: se esperaba exactamente un glob "
              f"posicional, recibidos {len(positionals)}: {positionals!r}",
              file=sys.stderr)
        return 2
    pattern = positionals[0]
    paths = sorted(glob.glob(pattern))
    if not paths:
        print(f"guard_r15_col: no files matched {pattern!r}", file=sys.stderr)
        return 1
    applied = []
    skipped = []
    found = set()
    pending = []  # (path, new_text): written only after all files pass
    for path in paths:
        transformed, already, error, new_text = guard_file(path, dry_run)
        if error:
            print(f"guard_r15_col: ERROR: {error}", file=sys.stderr)
            return 1
        if transformed:
            pending.append((path, new_text))
            found |= transformed
        elif already:
            skipped.append(path)
            print(f"guard_r15_col: already applied, skipped {path}")
            # The marker is in the file: count the targets it defines.
            with open(path, encoding="utf-8", errors="surrogateescape") as f:
                t = f.read()
            for name in TARGETS:
                if f"DEFINE_REX_FUNC({name})" in t:
                    found.add(name)
    # Both targets must be present (guarded now or already applied).
    missing = sorted(set(TARGETS) - found)
    if missing:
        print(f"guard_r15_col: ERROR: target(s) not guarded: {', '.join(missing)} "
              "-- the generated tree does not contain them (glob or codegen "
              "changed)", file=sys.stderr)
        return 1
    # (Ronda 17, A2-R17-04.) Write only now: every file transformed
    # cleanly and every target was found, so a failed run above modified
    # zero files. In dry-run mode nothing is written, same as before.
    for path, new_text in pending:
        if not dry_run:
            with open(path, "w", encoding="utf-8",
                      errors="surrogateescape", newline="") as f:
                f.write(new_text)
        applied.append(path)
        print(f"guard_r15_col: guarded {path}")
    print(f"guard_r15_col: OK -- {len(applied)} file(s) guarded, "
          f"{len(skipped)} already applied, targets: {', '.join(sorted(found))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
