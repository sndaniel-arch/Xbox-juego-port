#!/usr/bin/env python3

# RONDA 21 (multi-target, familia sub_82461508 + P20-A2-01):
#   62 sitios en 58 funciones (A2-R20-01, diferido en R20): 25 RECOVER
#   (+136 ENTRY, forma A) + 37 SKIP-ONLY (+148, +156, otros offsets, MID).
#   Dos inserciones por sitio (Guard-A tras el stw / tras la carga, nunca
#   antes de la carga; Guard-B tras el `bl 61508`), mismo skip label.
#   Deteccion de aplicado POR TARGET (tag GUARD_R21_MT), no por fichero:
#   un fichero con la guardia vieja recibe sus targets MT nuevos en el
#   mismo pase. 147 marcadores MT en total (124 bloques + 23 DECLAREs
#   sub_82434368). P20-A2-01: 0 guardables en R21 (A4, INDETERMINADO).
#   Detalle y decisiones en hunt-v146-round21-fixes/RUNBOOK.md y
#   work-a2/DESIGN-multi-target.md (§9: Guard-A tras el stw; §10: r6).
# RONDA 22 (A2): crash (ii) de sub_82461508 fuera del censo R21 + hallazgo
#   hermano + laterales. 57 targets de insercion unica (marcador GUARD_R22):
#   10 SIBLING (getter lazy 3A728/3A7C0 devuelve 0 -> lwz r3,0(r31), fault
#   0x100000000, 5 funciones x 2 sitios, skip a etiqueta nueva antes del
#   `addi r3,r1,<temp>` previo a `bl 8BA00`); 47 crash-(ii) (61508 devuelve
#   0 si su Alloc(32) falla: 4 derefs directos +16/+12 y 43 mediados por
#   5E290/5E340/29648/296C8/29748/7B7E0, cada uno con skip auditado por
#   funcion: etiqueta existente o nueva antes del bloque de limpieza del
#   epilogo); 3 getter+8 (87838/84348/82F00, lwz rX,8(r3) tras 3A728);
#   7F780+148 y 818C8+148 (clase C148). Ademas: sub_824711B0+168 pasa de
#   SKIP-ONLY a RECOVER (receta Alloc(24,heap 4)+34368 de sub_82480EF8,
#   unica instancia idiomatica en el arbol; migracion R21->R22 en Fase 0b).
#   P20-A2-01 sigue INDETERMINADO (67/67): el dispatcher no se identifico
#   (ver evidence-a2.md); 0 targets para la familia en R22.
#   Detalle en hunt-v146-round22/evidence-a2.md.
# RONDA 23 (A2): los 26 sitios crash-(ii) diferidos de R22 (18 NEEDS-REVIEW
#   + 6 demotados por safecheck + 2 por tempcheck). 26 targets de insercion
#   unica (marcador GUARD_R23): 16 con skip a etiqueta existente del
#   epilogo, 10 con etiqueta nueva `loc_<func>_r23_skip` (9 distintas).
#   Cada sufijo auditado a mano y por simulacion (b_analyze26b.py) +
#   chequeo de flujo de registros (b_regcheck.py: 26/26 sin lecturas malas,
#   mr del epilogo nunca reescrito en el span saltado). P20-A2-01 sigue
#   INDETERMINADO (67/67, ver evidence-a2.md §A: 6 angulos nuevos, todos
#   negativos). 7B7E0 (b) REFUTADO: ningun metodo reescribe +8 a 0 (censo
#   de la vtable 0x8204DE18: 40 metodos, 0 stores a +8). D: familia nueva
#   crash-(iii): 59F10 devuelve 0 si su Alloc(56) falla y 107 sitios
#   dereferencian +48 del retorno sin chequeo (0 chequeados) -- retenida
#   para R24 con receta en evidence-a2.md §D.
# RONDA 24 (A2): 73 sitios crash-(iii) guardados (59F10 devuelve 0 si su
#   Alloc(56) falla; 47 derefs directos +48 y 26 pass-this con sufijo
#   auditado) + T1 B1/B2 dentro de sub_82459F10 (holder *(this+0)==0, crash
#   R23-1 al pulsar A en el titulo: 824C5150 -> 7B6D0 -> 59F10, pc +0x80 =
#   F40, no +0x44; la guardia R15 SI cubria la cadena, el agujero era el
#   holder nulo, segundo agujero en la misma cadena). Migracion R24 de las
#   recoveries 5150/52F8 (A2-R24-01): el segundo test leia r4 (basura tras
#   el Alloc) en vez de r3. 34 sitios crash-(iii) DIFERIDOS (sin camino
#   cero verificable o sufijo inseguro) + 6FFB0 (slot escrito solo en la
#   region saltada) + P20-A2-01 sigue INDETERMINADO. 7B6D0:10210 NO es
#   target crash-(iii) (pass-through sin chequeo; lo cubren B1/B2).
#   lazy+52 = this (back-pointer, ctor 596A8), NO el holder: el holder es
#   *(this+0) (correccion del analisis previo a R24).
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
import os
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

# --- R24 text of the 5150 recovery (A2-R24-01) ---
# Same as RECOVERY_5150 except the second test reads r3, not r4 (r4 is
# garbage after the Alloc call: 27AE488 clobbers it). The old text stays
# above for the migration (old-list).
RECOVERY_5150_R24 = """\t// %s: +156 es el sub-objeto creado por sub_824C4FD8 (Alloc(60, heap 66)
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
\tif (ctx.r3.u32 == 0) {
\t\t// A2-R24-01: r4 es basura tras el Alloc/ctor (27AE488 lo clobbera: mr r5,r4; li r4,16); el segundo test debe leer r3 (0 solo si el Alloc fallo; r1+80 si +156 ya existia; el objeto si se creo). El rearmado escribe r3.u8 (= 0 en esta rama).
\t\t// A2-R18-02: rearmar el once-hook del estado 3 (byte +52 a 0) para
\t\t// que sub_824C6568 vuelva a llamar a sub_824C5150 el proximo frame.
\t\t// r3 ya es 0 en esta rama (es la condicion del salto) y r31 sigue
\t\t// siendo `this`; el epilogo no lee r4. Solo dos sitios escriben
\t\t// este flag: el ctor sub_824C6980 (= 0) y sub_824C6568 (= 1).
\t\tREX_STORE_U8(ctx.r31.u32 + 52, ctx.r3.u8);
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

# --- R24 text of the 52F8 recovery (A2-R24-01) ---
# Same as RECOVERY_52F8 except the second test reads r3, not r4 (r4 is
# garbage after the Alloc call: 27AE488 clobbers it). The old text stays
# above for the migration (old-list).
RECOVERY_52F8_R24 = """\t// %s: +156 es el sub-objeto creado por sub_824C4FD8 (Alloc(60, heap 66)
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
\tif (ctx.r3.u32 == 0) {
\t\t// A2-R24-01: r4 es basura tras el Alloc/ctor (27AE488 lo clobbera: mr r5,r4; li r4,16); el segundo test debe leer r3 (0 solo si el Alloc fallo; r1+80 si +156 ya existia; el objeto si se creo). El rearmado escribe r3.u8 (= 0 en esta rama).
\t\t// A2-R19-01: rearmar el once-hook del estado 2 (byte +51 a 0) para
\t\t// que sub_824C6568 vuelva a llamar a sub_824C52F8 el proximo frame.
\t\t// r3 ya es 0 en esta rama (es la condicion del salto) y r31 sigue
\t\t// siendo `this`; el salto cae antes de las liberaciones 810310, que
\t\t// leen solo r1+116/r1+108 (construidos por el bctrl previo), y de
\t\t// SetState(2). Solo dos sitios escriben este flag en esta clase:
\t\t// el ctor sub_824C6980 (= 0) y sub_824C6568 (= 1).
\t\tREX_STORE_U8(ctx.r31.u32 + 51, ctx.r3.u8);
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
        "recovery": RECOVERY_5150_R24,
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
        "recovery": RECOVERY_52F8_R24,
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

# --- RONDA 21: modo MULTI-TARGET (familia sub_82461508 + P20-A2-01) ---
# 62 sitios en 58 funciones (A2-R20-01, diferido en R20 por no caber en
# una extension de guardia normal: 116 inserciones). Dos inserciones por
# sitio con el MISMO skip label (auditado por funcion en
# hunt-v146-round21-fixes/work-a2/a1-136-sites.md, a2-148-156-sites.md y
# a3-other-mid-sites.md):
#   Guard-A (crash (i), campo de entrada == 0): DESPUES del `stw
#   r10,NNN(r1)` (o despues de la carga si no hay stw), NUNCA antes de la
#   carga -- el epilogo lee el slot NNN via sub_82A365C0 y el slot debe
#   estar escrito antes de cualquier salto (DESIGN-multi-target.md §9).
#   RECOVER (+136 ENTRY, 25): crea el sub-objeto como el ctor hermano
#   (Alloc(24, heap 4) via sub_824C4CB0 + Ctor sub_82434368, r4=1); si el
#   Alloc vuelve a fallar, goto skip. r6 se fija a 0x40C00000 como en el
#   ctor: sub_824C4CB0 elige r5=66 con ese valor (si no, r5=1) (§10).
#   SKIP-ONLY (37): solo `if (r3==0) goto skip` (sin recovery probado).
#   Guard-B (crash (ii), 61508 devuelve 0): DESPUES del `bl 61508`, antes
#   del `lwz rX,28(r3)`: `if (r3==0) goto skip`.
# Deteccion de aplicado POR TARGET (no por fichero): cada bloque lleva el
# tag `GUARD_R21_MT <func>+<off>-<kind>`; un fichero ya guardado (p. ej.
# .90.cpp con 5150) recibe sus targets MT nuevos en el mismo pase.
# P20-A2-01 (67 sitios `*(param+0)` -> 59F10): 0 guardables en R21 (A4:
# todos INDETERMINADO, dispatcher sin identificar) -- no esta aqui.
# Marcadores MT: 2 por sitio (Guard-A + Guard-B) + 1 DECLARE sub_82434368
# por fichero RECOVER cuyo header no lo declare (23) = 147 en total.

MT_MARKER = "GUARD_R21_MT"

_MT_GUARD_A_RECOVER = """\t// %(marker)s %(tag)s: +%(off)s es el sub-objeto creado por los ctores hermanos
\t// (Alloc(24, heap 4) via sub_824C4CB0 + Ctor sub_82434368, r4=1); los
\t// ctores ponen +%(off)s = 0 si el Alloc falla, y sub_82461508 lee [r3+8]
\t// -> SIGSEGV en base+8 (crash (i)). Si falta, se crea aqui como haria
\t// el ctor; si el Alloc vuelve a fallar se salta a %(skip)s (sin crash).
\t// r6 se fija a 0x40C00000 como en el ctor: sub_824C4CB0 elige r5=66 con
\t// ese valor (si no, r5=1); r6 es volatil y muerto aqui. %(base)s es no
\t// volatil: sobrevive al Alloc/ctor. r3 ya trae el valor del campo.
\tif (ctx.r3.u32 == 0) {
\t\tctx.r6.s64 = 1086324736;
\t\tctx.r4.s64 = 4;
\t\tctx.r3.s64 = 24;
\t\tctx.lr = %(lr)s;
\t\tsub_824C4CB0(ctx, base);
\t\tif (ctx.r3.u32 != 0) {
\t\t\tctx.r4.s64 = 1;
\t\t\tctx.lr = %(lr)s;
\t\t\tsub_82434368(ctx, base);
\t\t\tREX_STORE_U32(ctx.%(base)s.u32 + %(off)s, ctx.r3.u32);
\t\t}
\t}
\tif (ctx.r3.u32 == 0) goto %(skip)s;
"""

_MT_GUARD_A_SKIP = """\t// %(marker)s %(tag)s: +%(off)s puede llegar a 0 (el ctor/writer almacena 0
\t// si su Alloc falla); sub_82461508 lee [r3+8] -> SIGSEGV en base+8
\t// (crash (i)). Sin recovery probado para este offset: se salta a
\t// %(skip)s (sin crash, se descarta el mensaje de este frame).
\tif (ctx.r3.u32 == 0) goto %(skip)s;
"""

_MT_GUARD_B = """\t// %(marker)s %(tag)s: sub_82461508 devuelve 0 si su Alloc(32) fallo
\t// (crash (ii)); el `lwz rX,28(r3)` de abajo leeria [0+28] -> SIGSEGV
\t// en base+28. Se salta a %(skip)s (sin crash).
\tif (ctx.r3.u32 == 0) goto %(skip)s;
"""


def _mt_tag(mt):
    return f"{mt[0]}+{mt[2]}-{mt[3]}"


def mt_guard_a(mt):
    tag = _mt_tag(mt)
    # skip SIN el ':' de la definicion: es destino de goto, no etiqueta.
    skip = mt[10] if mt[10] is not None else mt[11][0].rstrip("\n").rstrip(":")
    if mt[9] == "RECOVER":
        return _MT_GUARD_A_RECOVER % {
            "marker": MT_MARKER, "tag": tag, "off": mt[2],
            "base": mt[8], "lr": mt[6], "skip": skip}
    return _MT_GUARD_A_SKIP % {
        "marker": MT_MARKER, "tag": tag, "off": mt[2], "skip": skip}


def mt_guard_b(mt):
    tag = _mt_tag(mt)
    # skip SIN el ':' de la definicion (destino de goto).
    skip = mt[10] if mt[10] is not None else mt[11][0].rstrip("\n").rstrip(":")
    return _MT_GUARD_B % {
        "marker": MT_MARKER, "tag": tag, "skip": skip}


# func, file_no, off, kind, load_base, slot, lr, deref, base,
# verdict, skip (existente) o None, new_label o None.
# new_label: (label, (anchor_lines...), label_after).
TARGETS_MT = [
    ("sub_82463320", 70, 136, "ENTRY", "r3", None, "0x82463338", "r11", "r30", "RECOVER", None, ('loc_82463320_skip:\n', ('\tctx.lr = 0x824635C8;', '\tsub_82410310(ctx, base);', '\t// addi r1,r1,176'), 2)),
    ("sub_82463830", 65, 136, "ENTRY", "r3", 768, "0x82463858", "r9", "r26", "RECOVER", "loc_82463DA8", None),
    ("sub_82463FC8", 182, 136, "ENTRY", "r3", 688, "0x82463FEC", "r9", "r30", "RECOVER", "loc_824642C8", None),
    ("sub_82464590", 173, 136, "ENTRY", "r3", 400, "0x824645B4", "r9", "r29", "RECOVER", "loc_82464788", None),
    ("sub_8246A8D8", 184, 136, "ENTRY", "r3", 496, "0x8246A8FC", "r9", "r30", "RECOVER", "loc_8246ADBC", None),
    ("sub_8246ADD0", 58, 136, "ENTRY", "r3", 768, "0x8246ADF4", "r9", "r30", "RECOVER", "loc_8246B278", None),
    ("sub_8246B698", 11, 136, "ENTRY", "r3", 912, "0x8246B6BC", "r9", "r24", "RECOVER", "loc_8246C0D4", None),
    ("sub_8246C508", 3, 136, "ENTRY", "r3", 752, "0x8246C52C", "r9", "r30", "RECOVER", "loc_8246C988", None),
    ("sub_8246CE08", 80, 136, "ENTRY", "r3", 480, "0x8246CE2C", "r9", "r30", "RECOVER", "loc_8246D21C", None),
    ("sub_8246D230", 106, 136, "ENTRY", "r3", 496, "0x8246D254", "r9", "r30", "RECOVER", "loc_8246D5B0", None),
    ("sub_8246E088", 79, 136, "ENTRY", "r3", 784, "0x8246E0AC", "r9", "r30", "RECOVER", "loc_8246E47C", None),
    ("sub_8246E950", 136, 136, "ENTRY", "r3", 784, "0x8246E974", "r9", "r29", "RECOVER", "loc_8246EE3C", None),
    ("sub_82470490", 168, 136, "ENTRY", "r3", 784, "0x824704B4", "r9", "r30", "RECOVER", "loc_824708D0", None),
    ("sub_82471AF8", 18, 136, "ENTRY", "r3", 784, "0x82471B1C", "r9", "r30", "RECOVER", "loc_82471EC8", None),
    ("sub_82471F10", 15, 136, "ENTRY", "r3", 480, "0x82471F34", "r9", "r30", "RECOVER", "loc_8247233C", None),
    ("sub_82472858", 103, 136, "ENTRY", "r3", 496, "0x8247287C", "r9", "r30", "RECOVER", "loc_82472B10", None),
    ("sub_82472D60", 50, 136, "ENTRY", "r3", 448, "0x82472D84", "r9", "r30", "RECOVER", "loc_82473118", None),
    ("sub_82473128", 5, 136, "ENTRY", "r3", 496, "0x8247314C", "r9", "r30", "RECOVER", "loc_82473484", None),
    ("sub_82473498", 169, 136, "ENTRY", "r3", 448, "0x824734BC", "r9", "r30", "RECOVER", "loc_82473898", None),
    ("sub_824738A8", 115, 136, "ENTRY", "r3", 560, "0x824738CC", "r9", "r30", "RECOVER", "loc_82473C00", None),
    ("sub_82473E50", 116, 136, "ENTRY", "r3", 448, "0x82473E74", "r9", "r30", "RECOVER", "loc_82474250", None),
    ("sub_8247A160", 89, 136, "ENTRY", "r3", 960, "0x8247A184", "r9", "r30", "RECOVER", "loc_8247A57C", None),
    ("sub_8247D2D0", 183, 136, "ENTRY", "r3", 480, "0x8247D2F4", "r9", "r30", "RECOVER", "loc_8247D654", None),
    ("sub_82480580", 84, 136, "ENTRY", "r3", 704, "0x824805A4", "r9", "r30", "RECOVER", "loc_82480910", None),
    ("sub_82487838", 117, 136, "ENTRY", "r3", 416, "0x8248785C", "r9", "r30", "RECOVER", "loc_82487AFC", None),
    ("sub_8246A018", 117, 148, "ENTRY", "r3", 496, "0x8246A03C", "r9", None, "SKIP-ONLY", "loc_8246A2E4", None),
    ("sub_8246C998", 102, 148, "ENTRY", "r3", 512, "0x8246C9BC", "r9", None, "SKIP-ONLY", "loc_8246CDF8", None),
    ("sub_824708E0", 97, 148, "ENTRY", "r3", 512, "0x82470904", "r9", None, "SKIP-ONLY", "loc_82470BC8", None),
    ("sub_82470BD8", 156, 148, "ENTRY", "r3", 480, "0x82470BFC", "r9", None, "SKIP-ONLY", "loc_82470EBC", None),
    ("sub_82470ED0", 85, 148, "ENTRY", "r3", 496, "0x82470EF4", "r9", None, "SKIP-ONLY", "loc_824711A0", None),
    ("sub_824714A0", 59, 148, "ENTRY", "r3", 768, "0x824714C4", "r9", None, "SKIP-ONLY", "loc_82471808", None),
    ("sub_82471818", 76, 148, "ENTRY", "r3", 496, "0x8247183C", "r9", None, "SKIP-ONLY", "loc_82471AE8", None),
    ("sub_82469A68", 99, 156, "ENTRY", "r3", 496, "0x82469A8C", "r9", None, "SKIP-ONLY", "loc_82469D2C", None),
    ("sub_8247F4C8", 110, 52, "ENTRY", "r3", None, "0x8247F4E0", "r11", None, "SKIP-ONLY", "loc_8247F5EC", None),
    ("sub_82485D98", 34, 140, "ENTRY", "r3", 688, "0x82485DBC", "r9", None, "SKIP-ONLY", "loc_824860AC", None),
    ("sub_824849A8", 87, 144, "ENTRY", "r3", 720, "0x824849CC", "r9", None, "SKIP-ONLY", "loc_82484E64", None),
    ("sub_82464CB8", 90, 152, "ENTRY", "r3", None, "0x82464CD0", "r11", None, "SKIP-ONLY", "loc_82464E9C", None),
    ("sub_82464EA8", 162, 152, "ENTRY", "r3", None, "0x82464EC0", "r11", None, "SKIP-ONLY", "loc_8246508C", None),
    ("sub_8246E490", 101, 152, "ENTRY", "r3", 800, "0x8246E4B4", "r9", None, "SKIP-ONLY", "loc_8246E93C", None),
    ("sub_8246EE50", 190, 152, "ENTRY", "r3", 1040, "0x8246EE74", "r9", None, "SKIP-ONLY", "loc_8246F360", None),
    ("sub_824770C0", 121, 152, "ENTRY", "r3", 416, "0x824770E4", "r9", None, "SKIP-ONLY", "loc_82477374", None),
    ("sub_82477468", 104, 152, "ENTRY", "r3", 416, "0x8247748C", "r9", None, "SKIP-ONLY", "loc_8247772C", None),
    ("sub_82478050", 152, 152, "ENTRY", "r3", 496, "0x82478074", "r9", None, "SKIP-ONLY", "loc_8247837C", None),
    ("sub_8247DCC8", 113, 152, "ENTRY", "r3", 448, "0x8247DD00", "r9", None, "SKIP-ONLY", "loc_8247DF34", None),
    ("sub_824711B0", 128, 168, "ENTRY", "r3", 512, "0x824711D4", "r9", "r30", "RECOVER", "loc_82471490", None),
    ("sub_824635D0", 2, 172, "ENTRY", "r3", 400, "0x824635F4", "r9", None, "SKIP-ONLY", "loc_82463820", None),
    ("sub_82486E78", 48, 172, "ENTRY", "r3", 688, "0x82486E9C", "r9", None, "SKIP-ONLY", "loc_8248720C", None),
    ("sub_8246C0E8", 88, 184, "ENTRY", "r3", 592, "0x8246C10C", "r9", None, "SKIP-ONLY", "loc_8246C4F8", None),
    ("sub_82469688", 73, 216, "ENTRY", "r3", 752, "0x824696AC", "r9", None, "SKIP-ONLY", "loc_82469A58", None),
    ("sub_8246A2F8", 53, 216, "ENTRY", "r3", 480, "0x8246A31C", "r9", None, "SKIP-ONLY", "loc_8246A5D8", None),
    ("sub_8246A5E8", 139, 216, "ENTRY", "r3", 480, "0x8246A60C", "r9", None, "SKIP-ONLY", "loc_8246A8C8", None),
    ("sub_82469D40", 187, 224, "ENTRY", "r3", 496, "0x82469D64", "r9", None, "SKIP-ONLY", "loc_8246A008", None),
    ("sub_82463FC8", 182, 136, "MID", "r30", None, "0x82464134", "r11", None, "SKIP-ONLY", "loc_824642C8", None),
    ("sub_82485428", 93, 136, "MID", "r30", None, "0x82485548", "r11", None, "SKIP-ONLY", None, ('loc_82485428_skip:\n', ('\tsub_82410310(ctx, base);', '\t// addi r1,r1,224'), 1)),
    ("sub_8246B398", 29, 172, "MID", "r31", None, "0x8246B4D0", "r11", None, "SKIP-ONLY", "loc_8246B68C", None),
    ("sub_8246F370", 96, 152, "MID", "r30", None, "0x8246F7A0", "r11", None, "SKIP-ONLY", "loc_8246F9F4", None),
    ("sub_8246FA08", 98, 152, "MID", "r30", None, "0x8246FD88", "r11", None, "SKIP-ONLY", "loc_8246FFA0", None),
    ("sub_824770C0", 121, 152, "MID", "r31", None, "0x8247722C", "r11", None, "SKIP-ONLY", "loc_82477374", None),
    ("sub_82477468", 104, 152, "MID", "r31", None, "0x824775D4", "r11", None, "SKIP-ONLY", "loc_8247772C", None),
    ("sub_82477740", 146, 152, "MID", "r29", None, "0x8247795C", "r11", None, "SKIP-ONLY", "loc_8247803C", None),
    ("sub_8247F780", 172, 140, "MID", "r3", None, "0x8247F7B8", "r11", None, "SKIP-ONLY", "loc_8247F9A4", None),
    ("sub_824849A8", 87, 144, "MID", "r30", None, "0x82484B14", "r11", None, "SKIP-ONLY", "loc_82484E64", None),
]

MT_IDS = {f"{t[0]}+{t[2]}-{t[3]}" for t in TARGETS_MT}

R22_MARKER = "GUARD_R22"

# RONDA 22: targets de insercion unica.
# (func, file_no, tag, anchor_lines, insert_after, check_reg, skip, new_label)
# anchor_lines: lineas verbatim; la insercion va tras `insert_after` de
# ellas (0 = antes del ancla). check_reg: registro que se testea a 0
# (r3 = retorno de la llamada / valor cargado; r31 = parametro del getter;
# r11 = campo +148 cargado). skip: etiqueta existente (sin ':') o None
# cuando new_label la crea. new_label: (label, anchor_lines, label_after),
# como en TARGETS_MT. El snippet es siempre SKIP-ONLY: si el valor es 0
# se salta al epilogo auditado (la funcion descarta el mensaje de este
# frame); nunca se crea el objeto aqui.
TARGETS_R22 = [
    ('sub_82478588', 1, 'sub_82478588+SIB1', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// addi r28,r11,-11828', '\tctx.r28.s64 = r11.s64 + -11828;', '\t// stw r28,112(r1)', '\tREX_STORE_U32(ctx.r1.u32 + 112, ctx.r28.u32);', '\t// bl 0x82459f10', '\tctx.lr = 0x824785C0;'), 0, 'r31', None, ('loc_82478588_sib_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x8248ba00'), 0)),
    ('sub_82478588', 1, 'sub_82478588+SIB2', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// bl 0x82459f10', '\tctx.lr = 0x82478674;', '\tsub_82459F10(ctx, base);', '\t// lwz r11,48(r3)', '\tr11.u64 = REX_LOAD_U32(ctx.r3.u32 + 48);'), 0, 'r31', None, ('loc_82478588_sib_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x8248ba00'), 0)),
    ('sub_82479070', 13, 'sub_82479070+SIB1', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// addi r29,r11,-11828', '\tctx.r29.s64 = r11.s64 + -11828;', '\t// stw r29,112(r1)', '\tREX_STORE_U32(ctx.r1.u32 + 112, ctx.r29.u32);', '\t// bl 0x82459f10', '\tctx.lr = 0x824790A8;'), 0, 'r31', None, ('loc_82479070_sib_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x8248ba00'), 0)),
    ('sub_82479070', 13, 'sub_82479070+SIB2', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// bl 0x82459f10', '\tctx.lr = 0x8247915C;', '\tsub_82459F10(ctx, base);', '\t// lwz r11,48(r3)', '\tr11.u64 = REX_LOAD_U32(ctx.r3.u32 + 48);'), 0, 'r31', None, ('loc_82479070_sib_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x8248ba00'), 0)),
    ('sub_82487E98', 178, 'sub_82487E98+SIB1', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// addi r29,r11,-11828', '\tctx.r29.s64 = r11.s64 + -11828;', '\t// stw r29,112(r1)', '\tREX_STORE_U32(ctx.r1.u32 + 112, ctx.r29.u32);', '\t// bl 0x82459f10', '\tctx.lr = 0x82487ED8;'), 0, 'r31', None, ('loc_82487E98_sib_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x8248ba00'), 0)),
    ('sub_82487E98', 178, 'sub_82487E98+SIB2', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// bl 0x82459f10', '\tctx.lr = 0x82487F8C;', '\tsub_82459F10(ctx, base);', '\t// lwz r11,48(r3)', '\tr11.u64 = REX_LOAD_U32(ctx.r3.u32 + 48);'), 0, 'r31', None, ('loc_82487E98_sib_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x8248ba00'), 0)),
    ('sub_8247E3B0', 74, 'sub_8247E3B0+SIB1', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// addi r23,r11,-11828', '\tctx.r23.s64 = r11.s64 + -11828;', '\t// stw r23,104(r1)', '\tREX_STORE_U32(ctx.r1.u32 + 104, ctx.r23.u32);', '\t// bl 0x82459f10', '\tctx.lr = 0x8247E3FC;'), 0, 'r31', None, ('loc_8247E3B0_sib_skip:\n', ('\t// bl 0x8248c1d8', '\tctx.lr = 0x8247E4B0;', '\tsub_8248C1D8(ctx, base);', '\t// addi r3,r1,104', '\tctx.r3.s64 = ctx.r1.s64 + 104;'), 3)),
    ('sub_8247E3B0', 74, 'sub_8247E3B0+SIB2', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// bl 0x82459f10', '\tctx.lr = 0x8247E4CC;', '\tsub_82459F10(ctx, base);', '\t// lwz r11,48(r3)', '\tr11.u64 = REX_LOAD_U32(ctx.r3.u32 + 48);'), 0, 'r31', None, ('loc_8247E3B0_sib_skip:\n', ('\t// bl 0x8248c1d8', '\tctx.lr = 0x8247E4B0;', '\tsub_8248C1D8(ctx, base);', '\t// addi r3,r1,104', '\tctx.r3.s64 = ctx.r1.s64 + 104;'), 3)),
    ('sub_824796B0', 75, 'sub_824796B0+SIB1', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// addi r30,r11,-11828', '\tctx.r30.s64 = r11.s64 + -11828;', '\t// stw r30,112(r1)', '\tREX_STORE_U32(ctx.r1.u32 + 112, ctx.r30.u32);', '\t// bl 0x82459f10', '\tctx.lr = 0x824796EC;'), 0, 'r31', None, ('loc_824796B0_sib_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x8248ba00'), 0)),
    ('sub_824796B0', 75, 'sub_824796B0+SIB2', ('\t// lwz r3,0(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 0);', '\t// bl 0x82459f10', '\tctx.lr = 0x824797A0;', '\tsub_82459F10(ctx, base);', '\t// lwz r11,48(r3)', '\tr11.u64 = REX_LOAD_U32(ctx.r3.u32 + 48);'), 0, 'r31', None, ('loc_824796B0_sib_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x8248ba00'), 0)),
    ('sub_82481728', 32, 'sub_82481728+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8248174C;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_824818B8', None),
    ('sub_82462278', 35, 'sub_82462278+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824622A0;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_824623B0', None),
    ('sub_82461CA0', 21, 'sub_82461CA0+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82461CBC;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82461E0C', None),
    ('sub_82462530', 147, 'sub_82462530+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82462560;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_824627D4', None),
    ('sub_82465098', 129, 'sub_82465098+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824650C0;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82465258', None),
    ('sub_82465EB8', 27, 'sub_82465EB8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82465EE8;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82466170', None),
    ('sub_824623C8', 135, 'sub_824623C8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824623F4;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82462518', None),
    ('sub_824627E8', 174, 'sub_824627E8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82462810;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82462924', None),
    ('sub_82462938', 16, 'sub_82462938+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82462960;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82462A74', None),
    ('sub_82467508', 146, 'sub_82467508+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82467530;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82467650', None),
    ('sub_824C74F0', 83, 'sub_824C74F0+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824C7620;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_824C74F0_r22_skip:\n', ('\t// addi r1,r1,384', '\tctx.r1.s64 = ctx.r1.s64 + 384;', '\t// b 0x82a36534'), 0)),
    ('sub_824C4E18', 7, 'sub_824C4E18+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824C4E90;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_824C4F4C', None),
    ('sub_824C4E18', 7, 'sub_824C4E18+61508B#2', ('\t// bl 0x82461508', '\tctx.lr = 0x824C4EF0;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_824C4F4C', None),
    ('sub_824C4F58', 28, 'sub_824C4F58+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824C4F74;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_824C4F58_r22_skip:\n', ('\t// mr r3,r31', '\tctx.r3.u64 = ctx.r31.u64;', '\t// addi r1,r1,112'), 0)),
    ('sub_82486410', 99, 'sub_82486410+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82486430;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82486410_r22_skip:\n', ('\tctx.r1.s64 = ctx.r1.s64 + 128;', '\t// b 0x82a3654c', '\t__restgprlr_29(ctx, base);'), 0)),
    ('sub_82482F00', 57, 'sub_82482F00+GET8', ('\t// bl 0x8243a728', '\tctx.lr = 0x82482F24;', '\tsub_8243A728(ctx, base);'), 3, 'r3', None, ('loc_82482F00_r22_skip:\n', ('\t// mr r3,r28', '\tctx.r3.u64 = ctx.r28.u64;', '\t// ld r5,80(r1)'), 0)),
    ('sub_8247B7E0', 174, 'sub_8247B7E0+61508B-7B7E0', ('\t// lwz r3,8(r31)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r31.u32 + 8);'), 2, 'r3', None, ('loc_8247B7E0_r22_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x8248ba00'), 0)),
    ('sub_82461640', 66, 'sub_82461640+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82461680;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82461640_r22_skip:\n', ('\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 80);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 0)),
    ('sub_824616D8', 11, 'sub_824616D8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82461718;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_824616D8_r22_skip:\n', ('\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 80);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 0)),
    ('sub_82461770', 153, 'sub_82461770+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824617B0;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82461770_r22_skip:\n', ('\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 80);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 0)),
    ('sub_824618E8', 76, 'sub_824618E8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82461924;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_824618E8_r22_skip:\n', ('\tctx.r3.s64 = ctx.r1.s64 + 88;', '\t// bl 0x824127e8', '\tctx.lr = 0x824619A8;'), 0)),
    ('sub_82461A00', 109, 'sub_82461A00+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82461BC4;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82461A00_r22_skip:\n', ('\t// bl 0x82422a50', '\tctx.lr = 0x82461C54;', '\tsub_82422A50(ctx, base);', '\t// li r8,4', '\tctx.r8.s64 = 4;'), 5)),
    ('sub_82462A88', 17, 'sub_82462A88+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82462AC4;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82462A88_r22_skip:\n', ('\tctx.r3.s64 = ctx.r1.s64 + 88;', '\t// bl 0x824127e8', '\tctx.lr = 0x82462B50;'), 0)),
    ('sub_82462B88', 72, 'sub_82462B88+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82462C8C;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82462B88_r22_skip:\n', ('\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 116);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 0)),
    ('sub_82464798', 91, 'sub_82464798+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824647FC;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82464798_r22_skip:\n', ('\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 84);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 0)),
    ('sub_824665C8', 191, 'sub_824665C8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246667C;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_824665C8_r22_skip:\n', ('\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 88);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 0)),
    ('sub_824671B0', 190, 'sub_824671B0+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824671F0;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_824671B0_r22_skip:\n', ('\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 80);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 0)),
    ('sub_82467938', 62, 'sub_82467938+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824679CC;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82467938_r22_skip:\n', ('\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 100);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 0)),
    ('sub_82467C10', 40, 'sub_82467C10+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82467CA4;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82467C10_r22_skip:\n', ('\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 100);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 0)),
    ('sub_8246C508', 3, 'sub_8246C508+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246C7A0;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_8246C508_r22_skip:\n', ('\tctx.r3.s64 = ctx.r1.s64 + 120;', '\t// bl 0x8248b3d0', '\tctx.lr = 0x8246C980;'), 0)),
    ('sub_8246EE50', 190, 'sub_8246EE50+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246F200;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_8246EE50_r22_skip:\n', ('\tctx.r3.s64 = ctx.r1.s64 + 88;', '\t// bl 0x8248ba00', '\tctx.lr = 0x8246F31C;'), 0)),
    ('sub_82477740', 146, 'sub_82477740+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82477AE4;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82477740_r22_skip:\n', ('loc_82477FF0:', '\t// lwz r11,120(r1)', '\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 120);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 1)),
    ('sub_82477740', 146, 'sub_82477740+61508B#2', ('\t// bl 0x82461508', '\tctx.lr = 0x82477D7C;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82477740_r22_skip:\n', ('loc_82477FF0:', '\t// lwz r11,120(r1)', '\tr11.u64 = REX_LOAD_U32(ctx.r1.u32 + 120);', '\t// cmplwi cr6,r11,0', '\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);'), 1)),
    ('sub_82484348', 137, 'sub_82484348+GET8', ('\t// bl 0x8243a728', '\tctx.lr = 0x824844DC;', '\tsub_8243A728(ctx, base);'), 3, 'r3', None, ('loc_82484348_r22_skip:\n', ('\tctx.r3.u64 = REX_LOAD_U32(ctx.r1.u32 + 96);', '\t// cmplwi cr6,r3,0', '\tcr6.compare<uint32_t>(ctx.r3.u32, 0, ctx.xer);'), 0)),
    ('sub_824849A8', 87, 'sub_824849A8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82484CF0;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_824849A8_r22_skip:\n', ('\tctx.r3.s64 = ctx.r1.s64 + 128;', '\t// bl 0x824b4590', '\tctx.lr = 0x82484E5C;'), 0)),
    ('sub_82485628', 182, 'sub_82485628+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8248569C;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82485628_r22_skip:\n', ('\tctx.r3.u64 = REX_LOAD_U32(ctx.r1.u32 + 96);', '\t// cmplwi cr6,r3,0', '\tcr6.compare<uint32_t>(ctx.r3.u32, 0, ctx.xer);'), 0)),
    ('sub_82461E18', 12, 'sub_82461E18+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82461F58;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_8246226C', None),
    ('sub_824642D8', 134, 'sub_824642D8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246435C;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_8246457C', None),
    ('sub_82465270', 36, 'sub_82465270+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82465310;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82465578', None),
    ('sub_82465588', 49, 'sub_82465588+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824656B0;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82465AD0', None),
    ('sub_82465C00', 25, 'sub_82465C00+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82465CD8;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82465EA8', None),
    ('sub_82466188', 193, 'sub_82466188+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824662B0;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_824665C0', None),
    ('sub_82466C08', 60, 'sub_82466C08+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82466D30;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82467040', None),
    ('sub_8246FFB0', 37, 'sub_8246FFB0+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824701D0;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82470488', None),
    ('sub_82487838', 117, 'sub_82487838+GET8', ('\t// bl 0x8243a728', '\tctx.lr = 0x824879A4;', '\tsub_8243A728(ctx, base);'), 3, 'r3', 'loc_82487AFC', None),
    ('sub_8247F780', 172, 'sub_8247F780+148', ('\t// lwz r11,148(r3)', '\tr11.u64 = REX_LOAD_U32(ctx.r3.u32 + 148);'), 2, 'r11', 'loc_8247F9A4', None),
    ('sub_824818C8', 4, 'sub_824818C8+148', ('\t// lwz r11,148(r3)', '\tr11.u64 = REX_LOAD_U32(ctx.r3.u32 + 148);'), 2, 'r11', None, ('loc_824818C8_r22_skip:\n', ('\t// bl 0x82410310', '\tctx.lr = 0x824819A8;', '\tsub_82410310(ctx, base);', '\t// addi r1,r1,192', '\tctx.r1.s64 = ctx.r1.s64 + 192;'), 3)),
]

R22_IDS = {t[2] for t in TARGETS_R22}


def _r22_comment(tag):
    """Comentario de una linea para el bloque R22 (por familia)."""
    if "+SIB" in tag:
        return ("getter lazy devuelve 0 si su Alloc falla; la carga "
                "`lwz r3,0(r31)` leeria [0+0] -> SIGSEGV en base+0")
    if tag.endswith("+148"):
        return ("+148 puede llegar a 0 (el ctor pone 0 si su Alloc(68) "
                "falla); el deref leeria [0+40] -> SIGSEGV en base+40")
    if tag.endswith("+GET8"):
        return ("getter lazy devuelve 0 si su Alloc falla; el deref "
                "`lwz rX,8(r3)` leeria [0+8] -> SIGSEGV en base+8")
    return ("sub_82461508 devuelve 0 si su Alloc(32) fallo (crash (ii)); "
            "el deref o el callee mediado leeria [0+16] -> SIGSEGV")


def _r22_snippet(tag, reg, skip):
    return ("\t// %s %s: %s\n"
            "\tif (ctx.%s.u32 == 0) goto %s;\n"
            % (R22_MARKER, tag, _r22_comment(tag), reg, skip))


R23_MARKER = "GUARD_R23"

# RONDA 23: targets de insercion unica (26 sitios crash-(ii) diferidos de R22).
# (func, file_no, tag, anchor_lines, insert_after, check_reg, skip, new_label)
# Mismo formato y misma semantica que TARGETS_R22 (Fase 2b): ancla de 3
# lineas (`// bl 0x82461508`, `ctx.lr`, `sub_82461508`), insert_after=3,
# check_reg='r3' (retorno de 61508: 0 si su Alloc(32) fallo), skip a la
# etiqueta existente del epilogo o a etiqueta nueva `loc_<func>_r23_skip`
# antes del primer paso seguro de la cola (sufijo auditado: solo dtores
# null-safe sobre slots construidos/a cero/pre-call, INLINE-FREE de slots
# evidenciados, y el epilogo 82A365C0 con slot escrito antes de la llamada;
# 8C1D8 y 8BA00-sobre-temp-destruido NUNCA corren en el camino del skip).
# 16 skips a etiqueta existente, 10 a etiqueta nueva (9 distintas: los dos
# sitios de 6E950 comparten `loc_8246E950_r23_skip`). Tags `+61508B` /
# `+61508B#2` (segunda llamada en la funcion, precedente R22 C4E18/77740);
# 7E3B0 lleva `+61508B-cola` (la cola destruye objetos del cuerpo saltado).
TARGETS_R23 = [
    ('sub_82463830', 65, 'sub_82463830+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82463AA4;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82463830_r23_skip:\n', ('\t// addi r3,r1,80', '\tctx.r3.s64 = ctx.r1.s64 + 80;', '\t// bl 0x82410310', '\tctx.lr = 0x82463DA0;', '\tsub_82410310(ctx, base);'), 0)),
    ('sub_82464A08', 4, 'sub_82464A08+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82464A4C;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82464A08_r23_skip:\n', ('\tctx.lr = 0x82464C84;', '\tsub_82410310(ctx, base);', '\t// mr r3,r31', '\tctx.r3.u64 = ctx.r31.u64;', '\t// addi r1,r1,256', '\tctx.r1.s64 = ctx.r1.s64 + 256;', '\t// b 0x82a36540'), 2)),
    ('sub_82465AD8', 170, 'sub_82465AD8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82465B44;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82465AD8_r23_skip:\n', ('\tsub_8248B698(ctx, base);', '\t// mr r3,r31', '\tctx.r3.u64 = ctx.r31.u64;', '\t// addi r1,r1,160', '\tctx.r1.s64 = ctx.r1.s64 + 160;', '\t// b 0x82a36544'), 1)),
    ('sub_824667B0', 71, 'sub_824667B0+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824667F8;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82466910', None),
    ('sub_82466948', 132, 'sub_82466948+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824669CC;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82466948_r23_skip:\n', ('\t// lwz r3,400(r1)', '\tctx.r3.u64 = REX_LOAD_U32(ctx.r1.u32 + 400);', '\t// bl 0x82a365c0', '\tctx.lr = 0x82466BF8;', '\tsub_82A365C0(ctx, base);'), 0)),
    ('sub_82467668', 14, 'sub_82467668+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824676A4;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_8246779C', None),
    ('sub_82467DB0', 51, 'sub_82467DB0+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82467E94;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_824681AC', None),
    ('sub_82468EA8', 151, 'sub_82468EA8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82468EE0;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82469154', None),
    ('sub_8246B698', 11, 'sub_8246B698+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246B8D0;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_8246C0D4', None),
    ('sub_8246C0E8', 88, 'sub_8246C0E8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246C3A8;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_8246C0E8_r23_skip:\n', ('\t// addi r3,r1,160', '\tctx.r3.s64 = ctx.r1.s64 + 160;', '\t// bl 0x821edbf8', '\tctx.lr = 0x8246C4D0;', '\tsub_821EDBF8(ctx, base);'), 0)),
    ('sub_8246C998', 102, 'sub_8246C998+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246CBD4;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_8246CDF8', None),
    ('sub_8246CE08', 80, 'sub_8246CE08+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246D038;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_8246D214', None),
    ('sub_8246E490', 101, 'sub_8246E490+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246E70C;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_8246E928', None),
    ('sub_8246E950', 136, 'sub_8246E950+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8246EBE8;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_8246E950_r23_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x82410310', '\tctx.lr = 0x8246EE2C;', '\tsub_82410310(ctx, base);'), 0)),
    ('sub_8246E950', 136, 'sub_8246E950+61508B#2', ('\t// bl 0x82461508', '\tctx.lr = 0x8246EC58;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_8246E950_r23_skip:\n', ('\t// addi r3,r1,112', '\tctx.r3.s64 = ctx.r1.s64 + 112;', '\t// bl 0x82410310', '\tctx.lr = 0x8246EE2C;', '\tsub_82410310(ctx, base);'), 0)),
    ('sub_82470490', 168, 'sub_82470490+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82470738;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_824708D0', None),
    ('sub_82478050', 152, 'sub_82478050+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824781D8;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_82478050_r23_skip:\n', ('\t// addi r3,r1,96', '\tctx.r3.s64 = ctx.r1.s64 + 96;', '\t// bl 0x8248b3d0', '\tctx.lr = 0x82478374;', '\tsub_8248B3D0(ctx, base);'), 0)),
    ('sub_82485790', 52, 'sub_82485790+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824858A0;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82485B14', None),
    ('sub_824665C8', 191, 'sub_824665C8+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82466650;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82466798', None),
    ('sub_82466948', 132, 'sub_82466948+61508B#2', ('\t// bl 0x82461508', '\tctx.lr = 0x82466B18;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82466BE0', None),
    ('sub_82467048', 104, 'sub_82467048+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824670C8;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82467198', None),
    ('sub_82467248', 111, 'sub_82467248+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x824672BC;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_8246738C', None),
    ('sub_824673A0', 152, 'sub_824673A0+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82467418;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_824674F0', None),
    ('sub_82467AD0', 119, 'sub_82467AD0+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x82467B40;', '\tsub_82461508(ctx, base);'), 3, 'r3', 'loc_82467BFC', None),
    ('sub_8247E3B0', 74, 'sub_8247E3B0+61508B-cola', ('\t// bl 0x82461508', '\tctx.lr = 0x8247E818;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_8247E3B0_r23_cola_skip:\n', ('\tctx.lr = 0x8247E90C;', '\tsub_8248BA00(ctx, base);', '\t// mr r3,r29', '\tctx.r3.u64 = ctx.r29.u64;', '\t// addi r1,r1,416', '\tctx.r1.s64 = ctx.r1.s64 + 416;', '\t// b 0x82a36534'), 2)),
    ('sub_8247E918', 22, 'sub_8247E918+61508B', ('\t// bl 0x82461508', '\tctx.lr = 0x8247ECA8;', '\tsub_82461508(ctx, base);'), 3, 'r3', None, ('loc_8247E918_r23_skip:\n', ('\tctx.lr = 0x8247ED98;', '\tsub_8248BA00(ctx, base);', '\t// mr r3,r29', '\tctx.r3.u64 = ctx.r29.u64;', '\t// addi r1,r1,224', '\tctx.r1.s64 = ctx.r1.s64 + 224;', '\t// b 0x82a36544'), 2)),
]

R23_IDS = {t[2] for t in TARGETS_R23}


def _r23_comment(tag):
    """Comentario de una linea para el bloque R23 (familia crash (ii))."""
    if tag.endswith("-cola"):
        return ("sub_82461508 devuelve 0 si su Alloc(32) fallo (crash (ii)); "
                "la cola destruiria objetos no construidos (8C1D8 muta, "
                "8BA00 sobre temp destruido) -> SIGSEGV")
    return ("sub_82461508 devuelve 0 si su Alloc(32) fallo (crash (ii)); "
            "el deref o el callee mediado leeria [0+16] -> SIGSEGV")


def _r23_snippet(tag, reg, skip):
    return ("\t// %s %s: %s\n"
            "\tif (ctx.%s.u32 == 0) goto %s;\n"
            % (R23_MARKER, tag, _r23_comment(tag), reg, skip))


R24_MARKER = "GUARD_R24"

# RONDA 24 (A2): 73 sitios crash-(iii) + T1 B1/B2 (guardia dentro de
# sub_82459F10). (func, file_no, tag, anchor_lines, insert_after, check_reg,
# skip, new_label, custom). Mismo formato y misma semantica que TARGETS_R23
# (Fase 2d): ancla de 3 lineas (`// bl 0x82459f10`, `ctx.lr`, `sub_82459F10`),
# insert_after=3, check_reg='r3' (retorno de 59F10: 0 si su Alloc(56) fallo),
# skip a la etiqueta existente del camino "campo==0" (branch taken-on-zero)
# o a etiqueta nueva `loc_<func>_r24_skip` en el fall-through del chequeo
# del campo (branch taken-on-nonzero). Cada sufijo auditado por
# d_analyze24b.py (simulacion de sufijo con tracking de registros
# envenenados + evidencia de slots + reglas de dtores/free; filtro de
# alcanzabilidad desde el corte). 50 skips a etiqueta nueva, 23 a etiqueta
# existente, 1 custom (B2, multi-linea, no el formato estandar).
# Tags `+59F10` / `+59F10#2` (segunda llamada en la funcion).
# B1 `+59F10B-enter`: tras el beq flag==0 de 59F10, `if (r29==0) goto
# loc_82459F48` (r29 = holder = *(this+0); sin llamadas entre F30 y el beq).
# B2 `+59F10B-leave`: tras el beq flag==0 de 9F84, recarga el holder via el
# back-pointer del lazy (lazy+52 = this, ctor 596A8; holder = *(this+0)) y
# salta el Leave si es 0 (custom snippet, elemento 9 del target).
TARGETS_R24 = [
    ('sub_8246C998', 102, 'sub_8246C998+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246CB04;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246C998_r24_skip:\n', ('\t// bne cr6,0x8246cbb8', '\tif (!cr6.eq) goto loc_8246CBB8;'), 2), None),
    ('sub_82467048', 104, 'sub_82467048+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824670B8;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_82467198', None, None),
    ('sub_82461A00', 109, 'sub_82461A00+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82461A24;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82461A00_r24_skip:\n', ('\t// bne cr6,0x82461ad8', '\tif (!cr6.eq) goto loc_82461AD8;'), 2), None),
    ('sub_8246B698', 11, 'sub_8246B698+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246B7E8;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246B698_r24_skip:\n', ('\t// bne cr6,0x8246b898', '\tif (!cr6.eq) goto loc_8246B898;'), 2), None),
    ('sub_8246B698', 11, 'sub_8246B698+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246BC8C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246B698_r24_skip2:\n', ('\t// bne cr6,0x8246bd9c', '\tif (!cr6.eq) goto loc_8246BD9C;'), 2), None),
    ('sub_82473E50', 116, 'sub_82473E50+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x82473FC4;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82473E50_r24_skip:\n', ('\t// bne cr6,0x82474080', '\tif (!cr6.eq) goto loc_82474080;'), 2), None),
    ('sub_82473E50', 116, 'sub_82473E50+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x82474088;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82473E50_r24_skip2:\n', ('\t// bne cr6,0x82474130', '\tif (!cr6.eq) goto loc_82474130;'), 2), None),
    ('sub_8245BBF8', 118, 'sub_8245BBF8+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245BC14;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_8245BC34', None, None),
    ('sub_8245D6E0', 122, 'sub_8245D6E0+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245D754;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8245D6E0_r24_skip:\n', ('\t// bne cr6,0x8245d7f0', '\tif (!cr6.eq) goto loc_8245D7F0;'), 2), None),
    ('sub_8245D6E0', 122, 'sub_8245D6E0+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245D7F8;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8245D6E0_r24_skip2:\n', ('\t// bne cr6,0x8245d89c', '\tif (!cr6.eq) goto loc_8245D89C;'), 2), None),
    ('sub_82465098', 129, 'sub_82465098+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824651A8;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82465098_r24_skip:\n', ('\t// bne cr6,0x824651cc', '\tif (!cr6.eq) goto loc_824651CC;'), 2), None),
    ('sub_824C8940', 129, 'sub_824C8940+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824C89D0;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_824C8A54', None, None),
    ('sub_82466948', 132, 'sub_82466948+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82466990;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82466948_r24_skip:\n', ('\t// bne cr6,0x824669c4', '\tif (!cr6.eq) goto loc_824669C4;'), 2), None),
    ('sub_8246E950', 136, 'sub_8246E950+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246EABC;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246E950_r24_skip:\n', ('\t// bne cr6,0x8246ebc4', '\tif (!cr6.eq) goto loc_8246EBC4;'), 2), None),
    ('sub_824C9A60', 136, 'sub_824C9A60+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824C9B04;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_824C9C18', None, None),
    ('sub_824875C0', 148, 'sub_824875C0+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x82487638;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_824875C0_r24_skip:\n', ('\t// bne cr6,0x824876e0', '\tif (!cr6.eq) goto loc_824876E0;'), 2), None),
    ('sub_824875C0', 148, 'sub_824875C0+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x824876E8;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_824875C0_r24_skip2:\n', ('\t// bne cr6,0x82487794', '\tif (!cr6.eq) goto loc_82487794;'), 2), None),
    ('sub_82471F10', 15, 'sub_82471F10+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82472084;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82471F10_r24_skip:\n', ('\t// bne cr6,0x82472140', '\tif (!cr6.eq) goto loc_82472140;'), 2), None),
    ('sub_8245DA58', 161, 'sub_8245DA58+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245DA7C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8245DA58_r24_skip:\n', ('\t// bne cr6,0x8245db3c', '\tif (!cr6.eq) goto loc_8245DB3C;'), 2), None),
    ('sub_8247C4F0', 161, 'sub_8247C4F0+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247C614;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8247C4F0_r24_skip:\n', ('\t// bne cr6,0x8247c6b8', '\tif (!cr6.eq) goto loc_8247C6B8;'), 2), None),
    ('sub_82470490', 168, 'sub_82470490+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824705FC;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82470490_r24_skip:\n', ('\t// bne cr6,0x82470704', '\tif (!cr6.eq) goto loc_82470704;'), 2), None),
    ('sub_82473498', 169, 'sub_82473498+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247360C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82473498_r24_skip:\n', ('\t// bne cr6,0x824736c8', '\tif (!cr6.eq) goto loc_824736C8;'), 2), None),
    ('sub_82473498', 169, 'sub_82473498+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x824736D0;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82473498_r24_skip2:\n', ('\t// bne cr6,0x82473778', '\tif (!cr6.eq) goto loc_82473778;'), 2), None),
    ('sub_82462A88', 17, 'sub_82462A88+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82462B08;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82462A88_r24_skip:\n', ('\t// bne cr6,0x82462b1c', '\tif (!cr6.eq) goto loc_82462B1C;'), 2), None),
    ('sub_82465AD8', 170, 'sub_82465AD8+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82465B10;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82465AD8_r24_skip:\n', ('\t// bne cr6,0x82465b3c', '\tif (!cr6.eq) goto loc_82465B3C;'), 2), None),
    ('sub_82486878', 170, 'sub_82486878+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82486B10;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_82486BCC', None, None),
    ('sub_8247B7E0', 174, 'sub_8247B7E0+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247B814;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8247B7E0_r24_skip:\n', ('\t// bne cr6,0x8247b8b8', '\tif (!cr6.eq) goto loc_8247B8B8;'), 2), None),
    ('sub_82471AF8', 18, 'sub_82471AF8+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82471C6C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82471AF8_r24_skip:\n', ('\t// bne cr6,0x82471d7c', '\tif (!cr6.eq) goto loc_82471D7C;'), 2), None),
    ('sub_8245F1D0', 181, 'sub_8245F1D0+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245F1E8;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8245F1D0_r24_skip:\n', ('\t// bne cr6,0x8245f298', '\tif (!cr6.eq) goto loc_8245F298;'), 2), None),
    ('sub_8245F1D0', 181, 'sub_8245F1D0+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245F2A0;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_8245F40C', None, None),
    ('sub_8246A8D8', 184, 'sub_8246A8D8+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246AA44;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246A8D8_r24_skip:\n', ('\t// bne cr6,0x8246ab2c', '\tif (!cr6.eq) goto loc_8246AB2C;'), 2), None),
    ('sub_82A60450', 184, 'sub_82A60450+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82A604FC;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_82A605B0', None, None),
    ('sub_8245D328', 189, 'sub_8245D328+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245D39C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8245D328_r24_skip:\n', ('\t// bne cr6,0x8245d438', '\tif (!cr6.eq) goto loc_8245D438;'), 2), None),
    ('sub_8247B340', 191, 'sub_8247B340+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247B37C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8247B340_r24_skip:\n', ('\t// bne cr6,0x8247b43c', '\tif (!cr6.eq) goto loc_8247B43C;'), 2), None),
    ('sub_8245DD28', 21, 'sub_8245DD28+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245DD40;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_8245DD68', None, None),
    ('sub_8245E538', 22, 'sub_8245E538+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245E5F8;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_8245E61C', None, None),
    ('sub_8247E918', 22, 'sub_8247E918+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247E954;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8247E918_r24_skip:\n', ('\t// bne cr6,0x8247ea1c', '\tif (!cr6.eq) goto loc_8247EA1C;'), 2), None),
    ('sub_8247E918', 22, 'sub_8247E918+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247EA24;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8247E918_r24_skip2:\n', ('\t// bne cr6,0x8247eaf8', '\tif (!cr6.eq) goto loc_8247EAF8;'), 2), None),
    ('sub_8245BC80', 26, 'sub_8245BC80+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245BC98;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8245BC80_r24_skip:\n', ('\t// bne cr6,0x8245bd48', '\tif (!cr6.eq) goto loc_8245BD48;'), 2), None),
    ('sub_8245BC80', 26, 'sub_8245BC80+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245BD50;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8245BC80_r24_skip2:\n', ('\t// bne cr6,0x8245bdec', '\tif (!cr6.eq) goto loc_8245BDEC;'), 2), None),
    ('sub_82465EB8', 27, 'sub_82465EB8+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82465FCC;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82465EB8_r24_skip:\n', ('\t// bne cr6,0x82465ff0', '\tif (!cr6.eq) goto loc_82465FF0;'), 2), None),
    ('sub_8246C508', 3, 'sub_8246C508+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246C674;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246C508_r24_skip:\n', ('\t// bne cr6,0x8246c77c', '\tif (!cr6.eq) goto loc_8246C77C;'), 2), None),
    ('sub_824C4D70', 32, 'sub_824C4D70+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824C4DC0;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_824C4DF0', None, None),
    ('sub_82485D98', 34, 'sub_82485D98+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82485F04;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82485D98_r24_skip:\n', ('\t// bne cr6,0x8248600c', '\tif (!cr6.eq) goto loc_8248600C;'), 2), None),
    ('sub_8245BE78', 38, 'sub_8245BE78+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8245BE90;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8245BE78_r24_skip:\n', ('\t// bne cr6,0x8245bf3c', '\tif (!cr6.eq) goto loc_8245BF3C;'), 2), None),
    ('sub_8246D868', 43, 'sub_8246D868+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246D948;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246D868_r24_skip:\n', ('\t// bne cr6,0x8246da5c', '\tif (!cr6.eq) goto loc_8246DA5C;'), 2), None),
    ('sub_8247BA90', 45, 'sub_8247BA90+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247BBB4;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8247BA90_r24_skip:\n', ('\t// bne cr6,0x8247bc58', '\tif (!cr6.eq) goto loc_8247BC58;'), 2), None),
    ('sub_824C4B70', 46, 'sub_824C4B70+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824C4B98;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_824C4B70_r24_skip:\n', ('\tcr6.compare<uint32_t>(r11.u32, 0, ctx.xer);', '\t// bne cr6,0x824c4be4', '\tif (!cr6.eq) goto loc_824C4BE4;'), 3), None),
    ('sub_82486E78', 48, 'sub_82486E78+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8248701C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82486E78_r24_skip:\n', ('\t// bne cr6,0x8248710c', '\tif (!cr6.eq) goto loc_8248710C;'), 2), None),
    ('sub_82472D60', 50, 'sub_82472D60+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82472ED4;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82472D60_r24_skip:\n', ('\t// bne cr6,0x82472f80', '\tif (!cr6.eq) goto loc_82472F80;'), 2), None),
    ('sub_824C99D8', 50, 'sub_824C99D8+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824C9A10;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_824C9A48', None, None),
    ('sub_82467DB0', 51, 'sub_82467DB0+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82468010;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_82468074', None, None),
    ('sub_824681C0', 56, 'sub_824681C0+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824681F4;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_82468270', None, None),
    ('sub_82474328', 56, 'sub_82474328+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247435C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_824743D4', None, None),
    ('sub_82468290', 57, 'sub_82468290+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824682BC;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_82468374', None, None),
    ('sub_824C4C00', 57, 'sub_824C4C00+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x824C4C3C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_824C4C94', None, None),
    ('sub_824C4C00', 57, 'sub_824C4C00+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x824C4C54;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_824C4C8C', None, None),
    ('sub_824C4C00', 57, 'sub_824C4C00+59F10#3', ('\t// bl 0x82459f10', '\tctx.lr = 0x824C4C70;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_824C4C8C', None, None),
    ('sub_8246ADD0', 58, 'sub_8246ADD0+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246AF3C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246ADD0_r24_skip:\n', ('\t// bne cr6,0x8246b088', '\tif (!cr6.eq) goto loc_8246B088;'), 2), None),
    ('sub_824714A0', 59, 'sub_824714A0+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82471614;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_824714A0_r24_skip:\n', ('\t// bne cr6,0x82471724', '\tif (!cr6.eq) goto loc_82471724;'), 2), None),
    ('sub_8247BD40', 64, 'sub_8247BD40+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247BE64;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8247BD40_r24_skip:\n', ('\t// bne cr6,0x8247bf08', '\tif (!cr6.eq) goto loc_8247BF08;'), 2), None),
    ('sub_82463830', 65, 'sub_82463830+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246399C;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82463830_r24_skip:\n', ('\t// bne cr6,0x82463a80', '\tif (!cr6.eq) goto loc_82463A80;'), 2), None),
    ('sub_824667B0', 71, 'sub_824667B0+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824667E8;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_82466910', None, None),
    ('sub_82462B88', 72, 'sub_82462B88+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82462BC0;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82462B88_r24_skip:\n', ('\t// bne cr6,0x82462bfc', '\tif (!cr6.eq) goto loc_82462BFC;'), 2), None),
    ('sub_82469688', 73, 'sub_82469688+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824697F4;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82469688_r24_skip:\n', ('\t// bne cr6,0x824698f8', '\tif (!cr6.eq) goto loc_824698F8;'), 2), None),
    ('sub_8246CE08', 80, 'sub_8246CE08+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246CF74;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246CE08_r24_skip:\n', ('\t// bne cr6,0x8246d028', '\tif (!cr6.eq) goto loc_8246D028;'), 2), None),
    ('sub_82480580', 84, 'sub_82480580+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824806EC;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_82480580_r24_skip:\n', ('\t// bne cr6,0x824807f0', '\tif (!cr6.eq) goto loc_824807F0;'), 2), None),
    ('sub_824C8018', 86, 'sub_824C8018+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x824C80A8;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_824C81CC', None, None),
    ('sub_824849A8', 87, 'sub_824849A8+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82484C54;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_824849A8_r24_skip:\n', ('\t// bne cr6,0x82484cd4', '\tif (!cr6.eq) goto loc_82484CD4;'), 2), None),
    ('sub_8246C0E8', 88, 'sub_8246C0E8+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x8246C254;', '\tsub_82459F10(ctx, base);'), 3, 'r3', None, ('loc_8246C0E8_r24_skip:\n', ('\t// bne cr6,0x8246c308', '\tif (!cr6.eq) goto loc_8246C308;'), 2), None),
    ('sub_8247A160', 89, 'sub_8247A160+59F10#1', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247A2D4;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_8247A3F0', None, None),
    ('sub_8247A160', 89, 'sub_8247A160+59F10#2', ('\t// bl 0x82459f10', '\tctx.lr = 0x8247A2EC;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_8247A3E8', None, None),
    ('sub_82A60C40', 98, 'sub_82A60C40+59F10', ('\t// bl 0x82459f10', '\tctx.lr = 0x82A60C84;', '\tsub_82459F10(ctx, base);'), 3, 'r3', 'loc_82A60D64', None, None),
    ('sub_82459F10', 63, 'sub_82459F10+59F10B-enter', ('\tctx.r10.u64 = REX_LOAD_U8(ctx.r30.u32 + -25098);', '\t// cmplwi cr6,r10,0', '\tcr6.compare<uint32_t>(ctx.r10.u32, 0, ctx.xer);', '\t// beq cr6,0x82459f48', '\tif (cr6.eq) goto loc_82459F48;'), 5, 'r29', 'loc_82459F48', None, None),
    ('sub_82459F10', 63, 'sub_82459F10+59F10B-leave', ('\tctx.r10.u64 = REX_LOAD_U8(ctx.r30.u32 + -25098);', '\t// cmplwi cr6,r10,0', '\tcr6.compare<uint32_t>(ctx.r10.u32, 0, ctx.xer);', '\t// beq cr6,0x82459f98', '\tif (cr6.eq) goto loc_82459F98;'), 5, None, 'loc_82459F98', None, '\\t// GUARD_R24 sub_82459F10+59F10B-leave: holder nulo en sub_82459F10 (crash R23-1): *(this+0)==0 cuando el ctor sub_8242EAC8 no lo lleno (global 0x82CD7744==0, 26CF8==0 o Alloc(20) fallo); el Enter se salto en B1 pero el Leave leeria [r29+0] -> SIGSEGV en base+0. Se recarga el holder via el back-pointer del lazy (lazy+52 = this, ctor sub_824596A8, cola incondicional; holder = *(this+0)); si es 0 se salta el Leave (el Enter no corrio o corrio con critsec 0, y *(holder+0) solo lo escribe sub_8241AD10). r10 es scratch muerto tras 9F84 en ambos caminos.\\n\\tif (ctx.r3.u32 != 0) {\\n\\t\\tctx.r10.u64 = REX_LOAD_U32(ctx.r3.u32 + 52);\\n\\t\\tif (ctx.r10.u32 == 0) goto loc_82459F98;\\n\\t\\tctx.r10.u64 = REX_LOAD_U32(ctx.r10.u32 + 0);\\n\\t\\tif (ctx.r10.u32 == 0) goto loc_82459F98;\\n\\t}\\n'),
]

R24_IDS = {t[2] for t in TARGETS_R24}


def _r24_comment(tag):
    """Comentario de una linea para el bloque R24 (familia crash (iii))."""
    if tag.endswith("59F10B-enter"):
        return ("sub_82459F10: holder *(this+0)==0 (ctor 2EAC8 no lo lleno); "
                "el Enter leeria [r29+0] -> SIGSEGV en base+0 (crash R23-1)")
    if tag.endswith("59F10B-leave"):
        return ("sub_82459F10: holder recargado via lazy+52==0 -> el Leave "
                "leeria [r29+0] -> SIGSEGV en base+0 (crash R23-1)")
    return ("sub_82459F10 devuelve 0 si su Alloc(56) fallo (crash (iii)); "
            "el deref +48 o el callee mediado leeria [0+48] -> SIGSEGV")


def _r24_snippet(tag, reg, skip):
    return ("\t// %s %s: %s\n"
            "\tif (ctx.%s.u32 == 0) goto %s;\n"
            % (R24_MARKER, tag, _r24_comment(tag), reg, skip))


def _migrate_711b0(path, lines):
    """Migracion R21 -> R22 de sub_824711B0+168 (SKIP-ONLY -> RECOVER).

    Solo actua si el fichero lleva la guardia MT y define la funcion.
    Deriva los bloques viejo (SKIP) y nuevo (RECOVER) de las plantillas,
    sin texto hardcodeado: si esta el viejo y falta el nuevo, lo reemplaza;
    si esta el nuevo y falta el viejo, no hace nada; cualquier otro estado
    es corrupto y devuelve error (fail-closed, cero ficheros modificados).
    Devuelve (changed, error)."""
    if "DEFINE_REX_FUNC(sub_824711B0)" not in "\n".join(lines):
        return (False, None)
    mt = [t for t in TARGETS_MT if t[0] == "sub_824711B0"][0]
    tag = _mt_tag(mt)
    old = _MT_GUARD_A_SKIP % {"marker": MT_MARKER, "tag": tag, "off": mt[2],
                              "skip": mt[10]}
    new = mt_guard_a(mt)
    old_lines = old.rstrip("\n").split("\n")
    new_lines = new.rstrip("\n").split("\n")
    old_hits = _find_block(lines, old_lines)
    new_hits = _find_block(lines, new_lines)
    if new_hits and not old_hits:
        return (False, None)  # ya migrado
    if old_hits and not new_hits:
        if len(old_hits) != 1:
            return (False,
                    f"{path}: sub_824711B0: bloque SKIP viejo encontrado "
                    f"{len(old_hits)} veces, refusing to guess")
        i = old_hits[0]
        lines[i:i + len(old_lines)] = new_lines
        return (True, None)
    return (False,
            f"{path}: sub_824711B0: Guard-A ni SKIP ni RECOVER "
            f"(old={len(old_hits)}, new={len(new_hits)})")


# Anclas propias (no siguen el patron estandar): func -> lineas Anchor-A
# (sin el comentario `// bl` ni la linea `ctx.lr`, que se anaden despues).
_MT_CUSTOM_ANCHOR_A = {

    "sub_82463830": [
        '\t// lwz r3,136(r3)',
        '\tctx.r3.u64 = REX_LOAD_U32(ctx.r3.u32 + 136);',
        '\t// li r31,0',
        '\tctx.r31.s64 = 0;',
        '\t// lwz r10,-26272(r11)',
        '\tctx.r10.u64 = REX_LOAD_U32(r11.u32 + -26272);',
        '\t// stw r10,768(r1)',
        '\tREX_STORE_U32(ctx.r1.u32 + 768, ctx.r10.u32);',
    ],
    "sub_8247DCC8": [
        '\t// lwz r3,152(r3)',
        '\tctx.r3.u64 = REX_LOAD_U32(ctx.r3.u32 + 152);',
        '\t// li r29,1',
        '\tctx.r29.s64 = 1;',
        '\t// li r31,0',
        '\tctx.r31.s64 = 0;',
        '\t// lwz r10,-26272(r11)',
        '\tctx.r10.u64 = REX_LOAD_U32(r11.u32 + -26272);',
        '\t// mr r28,r31',
        '\tctx.r28.u64 = ctx.r31.u64;',
        '\t// stb r29,276(r30)',
        '\tREX_STORE_U8(ctx.r30.u32 + 276, ctx.r29.u8);',
        '\t// stw r31,96(r1)',
        '\tREX_STORE_U32(ctx.r1.u32 + 96, ctx.r31.u32);',
        '\t// stw r10,448(r1)',
        '\tREX_STORE_U32(ctx.r1.u32 + 448, ctx.r10.u32);',
    ],
}


def mt_anchor_a(mt):
    """(lineas Anchor-A, indice tras el que se inserta Guard-A).

    Anchor-A: del comentario `// lwz` a la linea `ctx.lr`. Guard-A va
    DESPUES del `stw` (sitios con slot) o DESPUES de la carga (sin stw),
    nunca antes de la carga (DESIGN §9: el epilogo lee el slot)."""
    func, _fno, off, _kind, load_base, slot, lr, _d, _b, _v, _s, _n = mt
    if func in _MT_CUSTOM_ANCHOR_A:
        lines = list(_MT_CUSTOM_ANCHOR_A[func])
        insert_after = len(lines) - 1  # tras el stw
    elif slot is not None:
        lines = [
            f"\t// lwz r3,{off}({load_base})",
            f"\tctx.r3.u64 = REX_LOAD_U32(ctx.{load_base}.u32 + {off});",
            "\t// lwz r10,-26272(r11)",
            "\tctx.r10.u64 = REX_LOAD_U32(r11.u32 + -26272);",
            f"\t// stw r10,{slot}(r1)",
            f"\tREX_STORE_U32(ctx.r1.u32 + {slot}, ctx.r10.u32);",
        ]
        insert_after = len(lines) - 1  # tras el stw
    else:
        lines = [
            f"\t// lwz r3,{off}({load_base})",
            f"\tctx.r3.u64 = REX_LOAD_U32(ctx.{load_base}.u32 + {off});",
        ]
        insert_after = len(lines) - 1  # tras la carga
    lines += ["\t// bl 0x82461508", f"\tctx.lr = {lr};"]
    return lines, insert_after


def mt_anchor_b(mt):
    """Lineas Anchor-B (// bl + lr + call); Guard-B va tras la llamada."""
    return ["\t// bl 0x82461508", f"\tctx.lr = {mt[6]};",
            "\tsub_82461508(ctx, base);"]

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
    """(name, [old recoveries], new recovery) for the recoveries that changed.

    R24: the 5150 recovery changed twice (R17 -> R18 -> R24) and the 52F8
    recovery once (R19 -> R24), so each entry carries a LIST of old texts;
    exactly one of them (once) plus no new text means "migrate", the new
    text alone means "already migrated", anything else is corrupt.
    """
    return [
        ("sub_824C5150", [RECOVERY_5150_R17, RECOVERY_5150],
         RECOVERY_5150_R24),
        ("sub_824C52F8", [RECOVERY_52F8], RECOVERY_52F8_R24),
        ("sub_824C9DA8",
         [_before_v2("r27", "0x824C9F00", "loc_824C9F8C")],
         TARGETS["sub_824C9DA8"]["recovery"]),
    ]


def migrate_guard_file(path, text, eol, lines):
    """Upgrade a file guarded by an older script to the current recoveries.

    Returns the same tuple shape as guard_file. Only the changed recoveries
    are touched; every other target is left exactly as it is. A target
    whose function is not defined in this file is skipped. A target whose
    recovery is neither an old text nor the new text fails the whole run
    (exit 1) with zero files modified -- same atomicity rule as the fresh
    path."""
    migrated = set()
    for name, old_recs, new_rec in _migrations():
        if f"DEFINE_REX_FUNC({name})" not in text:
            continue
        new_lines = new_rec.rstrip("\n").split("\n")
        new_hits = _find_block(lines, new_lines)
        old_hits = []
        old_len = None
        for old_rec in old_recs:
            ol = old_rec.rstrip("\n").split("\n")
            h = _find_block(lines, ol)
            if h:
                old_hits += h
                old_len = len(ol)
        if new_hits and not old_hits:
            continue  # already migrated
        if old_hits and not new_hits:
            if len(old_hits) != 1:
                return (set(), False,
                        f"{path}: {name}: old recovery found "
                        f"{len(old_hits)} times, refusing to guess",
                        None)
            i = old_hits[0]
            lines[i : i + old_len] = new_lines
            migrated.add(name)
            continue
        return (set(), False,
                f"{path}: {name}: recovery is neither an old text nor "
                f"the new text (old={len(old_hits)}, new={len(new_hits)})",
                None)
    if not migrated:
        return (set(), True, None, None)
    return (migrated, False, None, eol.join(lines))


# --- RONDA 21: nuevo guard_file + main (reemplazan a los de R15-R19) ---
# Cambios: (1) la deteccion de "ya aplicado" es POR TARGET, no por
# fichero (un fichero con la guardia vieja recibe sus targets MT nuevos
# en el mismo pase); (2) los targets MT se aplican por sitio con
# verificacion de ancla exactamente-una-vez y de skip label; (3) el
# DECLARE de sub_82434368 se inserta solo si falta en el fichero Y en su
# header hermano; (4) main() exige los 11 targets viejos Y los 62 MT.


def _recovery_present(body, spec):
    """True si el recovery del target viejo esta integro en el cuerpo."""
    recs = spec.get("recoveries")
    if recs is None:
        recs = [spec["recovery"]]
    for rec in recs:
        if not _find_block(body, rec.rstrip("\n").split("\n")):
            return False
    return True


def _insert_declare(lines, decl):
    """Inserta decl tras el #include de childoflight_funcs.N.h.

    Devuelve True si inserto, False si ya estaba. Falla cerrado (ValueError)
    si no hay include."""
    if decl in "\n".join(lines):
        return False
    for i, line in enumerate(lines):
        if INCLUDE_RE.match(line):
            lines.insert(i + 1, decl)
            return True
    raise ValueError("no childoflight_funcs.N.h include found")


def guard_file(path, dry_run):
    """Aplica las guardias viejas, MT, R22, R23 y R24 para los targets
    presentes en el fichero. Devuelve (found_old, found_mt, found_r22,
    found_r23, found_r24, error, new_text).

    found_old: nombres de TARGETS viejos encontrados (aplicados ahora o ya
    aplicados). found_mt: tags de TARGETS_MT encontrados. new_text es None
    cuando el fichero no cambio. La funcion NUNCA escribe a disco (ronda
    17, A2-R17-04): main() escribe solo despues de que TODOS los ficheros
    pasen y todos los targets se encuentren."""
    with open(path, encoding="utf-8", errors="surrogateescape",
              newline="") as f:
        text = f.read()
    eol = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(eol)
    found_old = set()
    found_mt = set()
    found_r22 = set()
    found_r23 = set()
    found_r24 = set()
    changed = False
    # --- Fase 0: migracion R17 -> R18 (solo si MARKER presente) ---
    if MARKER in text:
        migrated, _already, error, new_text = migrate_guard_file(
            path, text, eol, lines)
        if error:
            return (set(), set(), set(), set(), set(), error, None)
        if new_text is not None:
            lines = new_text.split(eol)
            text = new_text
            changed = True
            found_old |= migrated
    # --- Fase 0b: migracion R21 -> R22 de sub_824711B0+168 ---
    if MT_MARKER in text:
        migrated, error = _migrate_711b0(path, lines)
        if error:
            return (set(), set(), set(), set(), set(), error, None)
        if migrated:
            changed = True
    # --- Fase 1: targets viejos (por target, no por fichero) ---
    for name, spec in TARGETS.items():
        span = find_function_span(lines, name)
        if span is None:
            continue  # el target vive en otro fichero del glob
        start, end = span
        body = lines[start:end + 1]
        body_text = "\n".join(body)
        if MARKER in body_text and not _recovery_present(body, spec):
            return (set(), set(), set(), set(), set(),
                    f"{path}: {name}: marcador viejo presente pero el "
                    "recovery no esta integro (estado corrupto, no se "
                    "adivina)",
                    None)
        if _recovery_present(body, spec):
            if spec.get("label") is not None:
                label = spec["label"].rstrip("\n")
                if not any(l.strip() == label for l in body):
                    return (set(), set(), set(), set(), set(),
                            f"{path}: {name}: recovery presente pero falta "
                            f"la etiqueta {label} (estado corrupto)",
                            None)
            found_old.add(name)
            continue
        # Aplicacion fresca (logica R15-R19, sin cambios).
        recoveries = spec.get("recoveries")
        if recoveries is None:
            recoveries = [spec["recovery"]] * len(spec["anchors"])
        for anchor_text, recovery in zip(spec["anchors"], recoveries):
            span = find_function_span(lines, name)
            start, end = span
            body = lines[start:end + 1]
            anchor_lines = anchor_text.rstrip("\n").split("\n")
            idx = None
            for i in range(len(body) - len(anchor_lines) + 1):
                if body[i:i + len(anchor_lines)] == anchor_lines:
                    idx = i
                    break
            if idx is None:
                return (set(), set(), set(), set(), set(),
                        f"{path}: {name}: anchor not found verbatim -- "
                        "codegen output changed, refusing to guess",
                        None)
            if spec["mode"] == "before":
                insert_at = start + idx
            else:
                insert_at = start + idx + spec["insert_after_anchor_line"]
            lines[insert_at:insert_at] = recovery.rstrip("\n").split("\n")
            changed = True
            found_old.add(name)
        if spec.get("label") is not None:
            span = find_function_span(lines, name)
            start, end = span
            body = lines[start:end + 1]
            label_lines = spec["label_anchor"].rstrip("\n").split("\n")
            lidx = None
            for i in range(len(body) - len(label_lines) + 1):
                if body[i:i + len(label_lines)] == label_lines:
                    lidx = i
                    break
            if lidx is None:
                return (set(), set(), set(), set(), set(),
                        f"{path}: {name}: label anchor not found verbatim",
                        None)
            label_at = start + lidx + 1  # before `// addi r1,r1,128`
            lines[label_at:label_at] = [spec["label"].rstrip("\n")]
    # --- Fase 2: targets MT (por sitio, no por fichero) ---
    for mt in TARGETS_MT:
        func = mt[0]
        tag = _mt_tag(mt)
        span = find_function_span(lines, func)
        if span is None:
            continue  # el target vive en otro fichero del glob
        start, end = span
        body = lines[start:end + 1]
        if MT_MARKER + " " + tag in "\n".join(body):
            # Ya aplicado: verificar la etiqueta nueva si la hay.
            if mt[11] is not None:
                label = mt[11][0].rstrip("\n")
                if not any(l.strip() == label for l in body):
                    return (set(), set(), set(), set(), set(),
                            f"{path}: {func} ({mt[3]}): tag MT presente "
                            f"pero falta la etiqueta {label}",
                            None)
            found_mt.add(tag)
            continue
        # Anclas: exactamente una vez cada una en la funcion.
        a_lines, a_insert = mt_anchor_a(mt)
        b_lines = mt_anchor_b(mt)
        if len(_find_block(body, a_lines)) != 1:
            return (set(), set(), set(), set(), set(),
                    f"{path}: {func} ({mt[3]}): ancla-A MT no casa "
                    "exactamente una vez -- codegen output changed, "
                    "refusing to guess",
                    None)
        if len(_find_block(body, b_lines)) != 1:
            return (set(), set(), set(), set(), set(),
                    f"{path}: {func} ({mt[3]}): ancla-B MT no casa "
                    "exactamente una vez -- codegen output changed, "
                    "refusing to guess",
                    None)
        # Skip label: existente (debe estar en la funcion) o nueva
        # (su label_anchor exactamente una vez, la etiqueta aun no existe).
        if mt[11] is not None:
            label, anchor_lines, label_after = mt[11]
            if any(l.strip() == label.rstrip("\n") for l in body):
                return (set(), set(), set(), set(), set(),
                        f"{path}: {func} ({mt[3]}): etiqueta nueva "
                        f"{label.strip()} ya existe sin tag MT (estado "
                        "corrupto)",
                        None)
            if len(_find_block(body, list(anchor_lines))) != 1:
                return (set(), set(), set(), set(), set(),
                        f"{path}: {func} ({mt[3]}): label_anchor no casa "
                        "exactamente una vez",
                        None)
        else:
            skip = mt[10]
            if not any(l.strip() == skip + ":" for l in body):
                return (set(), set(), set(), set(), set(),
                        f"{path}: {func} ({mt[3]}): skip label {skip} "
                        "not found in function",
                        None)
        # Guard-A (tras el stw o tras la carga; nunca antes de la carga).
        span = find_function_span(lines, func)
        start, end = span
        body = lines[start:end + 1]
        idx = _find_block(body, a_lines)[0]
        ga = mt_guard_a(mt).rstrip("\n").split("\n")
        lines[start + idx + a_insert + 1:start + idx + a_insert + 1] = ga
        changed = True
        # Guard-B (tras la llamada a 61508). Si la linea siguiente a la
        # llamada ya lleva un bloque MT sin este tag, es estado corrupto.
        span = find_function_span(lines, func)
        start, end = span
        body = lines[start:end + 1]
        idx = _find_block(body, b_lines)[0]
        after_call = start + idx + len(b_lines)
        if after_call < len(lines) and MT_MARKER in lines[after_call]:
            return (set(), set(), set(), set(), set(),
                    f"{path}: {func} ({mt[3]}): hay un bloque MT tras la "
                    "llamada sin este tag (estado corrupto)",
                    None)
        gb = mt_guard_b(mt).rstrip("\n").split("\n")
        lines[after_call:after_call] = gb
        changed = True
        # Etiqueta nueva si la hay (tras label_after lineas del ancla).
        if mt[11] is not None:
            label, anchor_lines, label_after = mt[11]
            span = find_function_span(lines, func)
            start, end = span
            body = lines[start:end + 1]
            lidx = _find_block(body, list(anchor_lines))[0]
            lines[start + lidx + label_after:start + lidx + label_after] = [
                label.rstrip("\n")]
            changed = True
        found_mt.add(tag)
    # --- Fase 2b: targets R22 (insercion unica por sitio) ---
    for r22 in TARGETS_R22:
        func, _fno, tag, anchor_lines, insert_after, reg, skip, new_label = r22
        span = find_function_span(lines, func)
        if span is None:
            continue  # el target vive en otro fichero del glob
        start, end = span
        body = lines[start:end + 1]
        if R22_MARKER + " " + tag in "\n".join(body):
            # Ya aplicado: verificar la etiqueta nueva si la hay.
            if new_label is not None:
                label = new_label[0].rstrip("\n")
                if not any(l.strip() == label for l in body):
                    return (set(), set(), set(), set(), set(),
                            f"{path}: {func} ({tag}): tag R22 presente "
                            f"pero falta la etiqueta {label}",
                            None)
            found_r22.add(tag)
            continue
        # Ancla: exactamente una vez en la funcion.
        if len(_find_block(body, list(anchor_lines))) != 1:
            return (set(), set(), set(), set(), set(),
                    f"{path}: {func} ({tag}): ancla R22 no casa "
                    "exactamente una vez -- codegen output changed, "
                    "refusing to guess",
                    None)
        # Skip label: existente (debe estar en la funcion) o nueva
        # (su label_anchor exactamente una vez, la etiqueta aun no existe).
        label_exists = False
        if new_label is not None:
            label, la_lines, label_after = new_label
            label_stripped = label.rstrip("\n")
            if any(l.strip() == label_stripped for l in body):
                # La etiqueta puede venir de un target hermano R22 de la
                # misma funcion que comparte skip (p. ej. SIB1/SIB2, o las
                # dos llamadas de 77740): solo es legitima si el tag de
                # ese hermano ya esta en el cuerpo.
                sib_tags = [t[2] for t in TARGETS_R22
                            if t[0] == func and t[7] is not None
                            and t[7][0].rstrip("\n") == label_stripped
                            and t[2] != tag]
                if not any(R22_MARKER + " " + st in "\n".join(body)
                           for st in sib_tags):
                    return (set(), set(), set(), set(), set(),
                            f"{path}: {func} ({tag}): etiqueta nueva "
                            f"{label.strip()} ya existe sin tag R22 (estado "
                            "corrupto)",
                            None)
                label_exists = True
            elif len(_find_block(body, list(la_lines))) != 1:
                return (set(), set(), set(), set(), set(),
                        f"{path}: {func} ({tag}): label_anchor R22 no casa "
                        "exactamente una vez",
                        None)
            skip = label_stripped.rstrip(":")
        else:
            if not any(l.strip() == skip + ":" for l in body):
                return (set(), set(), set(), set(), set(),
                        f"{path}: {func} ({tag}): skip label {skip} "
                        "not found in function",
                        None)
        # Insercion (tras `insert_after` lineas del ancla). Si la linea
        # siguiente ya lleva un bloque R22, es estado corrupto.
        span = find_function_span(lines, func)
        start, end = span
        body = lines[start:end + 1]
        idx = _find_block(body, list(anchor_lines))[0]
        insert_at = start + idx + insert_after
        if insert_at < len(lines) and R22_MARKER in lines[insert_at]:
            return (set(), set(), set(), set(), set(),
                    f"{path}: {func} ({tag}): hay un bloque R22 en el "
                    "punto de insercion sin este tag (estado corrupto)",
                    None)
        snippet = _r22_snippet(tag, reg, skip).rstrip("\n").split("\n")
        lines[insert_at:insert_at] = snippet
        changed = True
        # Etiqueta nueva si la hay y no la puso ya un hermano (tras
        # label_after lineas del ancla).
        if new_label is not None and not label_exists:
            label, la_lines, label_after = new_label
            span = find_function_span(lines, func)
            start, end = span
            body = lines[start:end + 1]
            lidx = _find_block(body, list(la_lines))[0]
            lines[start + lidx + label_after:start + lidx + label_after] = [
                label.rstrip("\n")]
            changed = True
        found_r22.add(tag)
    # --- Fase 2c: targets R23 (insercion unica por sitio) ---
    for r23 in TARGETS_R23:
        func, _fno, tag, anchor_lines, insert_after, reg, skip, new_label = r23
        span = find_function_span(lines, func)
        if span is None:
            continue  # el target vive en otro fichero del glob
        start, end = span
        body = lines[start:end + 1]
        if R23_MARKER + " " + tag in "\n".join(body):
            # Ya aplicado: verificar la etiqueta nueva si la hay.
            if new_label is not None:
                label = new_label[0].rstrip("\n")
                if not any(l.strip() == label for l in body):
                    return (set(), set(), set(), set(), set(),
                            f"{path}: {func} ({tag}): tag R23 presente "
                            f"pero falta la etiqueta {label}",
                            None)
            found_r23.add(tag)
            continue
        # Ancla: exactamente una vez en la funcion.
        if len(_find_block(body, list(anchor_lines))) != 1:
            return (set(), set(), set(), set(), set(),
                    f"{path}: {func} ({tag}): ancla R23 no casa "
                    "exactamente una vez -- codegen output changed, "
                    "refusing to guess",
                    None)
        # Skip label: existente (debe estar en la funcion) o nueva
        # (su label_anchor exactamente una vez, la etiqueta aun no existe).
        label_exists = False
        if new_label is not None:
            label, la_lines, label_after = new_label
            label_stripped = label.rstrip("\n")
            if any(l.strip() == label_stripped for l in body):
                # La etiqueta puede venir de un target hermano R23 de la
                # misma funcion que comparte skip (p. ej. SIB1/SIB2, o las
                # dos llamadas de 77740): solo es legitima si el tag de
                # ese hermano ya esta en el cuerpo.
                sib_tags = [t[2] for t in TARGETS_R23
                            if t[0] == func and t[7] is not None
                            and t[7][0].rstrip("\n") == label_stripped
                            and t[2] != tag]
                if not any(R23_MARKER + " " + st in "\n".join(body)
                           for st in sib_tags):
                    return (set(), set(), set(), set(), set(),
                            f"{path}: {func} ({tag}): etiqueta nueva "
                            f"{label.strip()} ya existe sin tag R23 (estado "
                            "corrupto)",
                            None)
                label_exists = True
            elif len(_find_block(body, list(la_lines))) != 1:
                return (set(), set(), set(), set(), set(),
                        f"{path}: {func} ({tag}): label_anchor R23 no casa "
                        "exactamente una vez",
                        None)
            skip = label_stripped.rstrip(":")
        else:
            if not any(l.strip() == skip + ":" for l in body):
                return (set(), set(), set(), set(), set(),
                        f"{path}: {func} ({tag}): skip label {skip} "
                        "not found in function",
                        None)
        # Insercion (tras `insert_after` lineas del ancla). Si la linea
        # siguiente ya lleva un bloque R23, es estado corrupto.
        span = find_function_span(lines, func)
        start, end = span
        body = lines[start:end + 1]
        idx = _find_block(body, list(anchor_lines))[0]
        insert_at = start + idx + insert_after
        if insert_at < len(lines) and R23_MARKER in lines[insert_at]:
            return (set(), set(), set(), set(), set(),
                    f"{path}: {func} ({tag}): hay un bloque R23 en el "
                    "punto de insercion sin este tag (estado corrupto)",
                    None)
        snippet = _r23_snippet(tag, reg, skip).rstrip("\n").split("\n")
        lines[insert_at:insert_at] = snippet
        changed = True
        # Etiqueta nueva si la hay y no la puso ya un hermano (tras
        # label_after lineas del ancla).
        if new_label is not None and not label_exists:
            label, la_lines, label_after = new_label
            span = find_function_span(lines, func)
            start, end = span
            body = lines[start:end + 1]
            lidx = _find_block(body, list(la_lines))[0]
            lines[start + lidx + label_after:start + lidx + label_after] = [
                label.rstrip("\n")]
            changed = True
        found_r23.add(tag)
    # --- Fase 2d: targets R24 (insercion unica por sitio) ---
    for r24 in TARGETS_R24:
        func, _fno, tag, anchor_lines, insert_after, reg, skip, new_label, custom = r24
        span = find_function_span(lines, func)
        if span is None:
            continue  # el target vive en otro fichero del glob
        start, end = span
        body = lines[start:end + 1]
        if R24_MARKER + " " + tag in "\n".join(body):
            # Ya aplicado: verificar la etiqueta nueva si la hay.
            if new_label is not None:
                label = new_label[0].rstrip("\n")
                if not any(l.strip() == label for l in body):
                    return (set(), set(), set(), set(), set(),
                            f"{path}: {func} ({tag}): tag R24 presente "
                            f"pero falta la etiqueta {label}",
                            None)
            found_r24.add(tag)
            continue
        # Ancla: exactamente una vez en la funcion.
        if len(_find_block(body, list(anchor_lines))) != 1:
            return (set(), set(), set(), set(), set(),
                    f"{path}: {func} ({tag}): ancla R24 no casa "
                    "exactamente una vez -- codegen output changed, "
                    "refusing to guess",
                    None)
        # Skip label: existente (debe estar en la funcion) o nueva
        # (su label_anchor exactamente una vez, la etiqueta aun no existe).
        label_exists = False
        if new_label is not None:
            label, la_lines, label_after = new_label
            label_stripped = label.rstrip("\n")
            if any(l.strip() == label_stripped for l in body):
                # La etiqueta puede venir de un target hermano R24 de la
                # misma funcion que comparte skip (p. ej. SIB1/SIB2, o las
                # dos llamadas de 77740): solo es legitima si el tag de
                # ese hermano ya esta en el cuerpo.
                sib_tags = [t[2] for t in TARGETS_R24
                            if t[0] == func and t[7] is not None
                            and t[7][0].rstrip("\n") == label_stripped
                            and t[2] != tag]
                if not any(R24_MARKER + " " + st in "\n".join(body)
                           for st in sib_tags):
                    return (set(), set(), set(), set(), set(),
                            f"{path}: {func} ({tag}): etiqueta nueva "
                            f"{label.strip()} ya existe sin tag R24 (estado "
                            "corrupto)",
                            None)
                label_exists = True
            elif len(_find_block(body, list(la_lines))) != 1:
                return (set(), set(), set(), set(), set(),
                        f"{path}: {func} ({tag}): label_anchor R24 no casa "
                        "exactamente una vez",
                        None)
            skip = label_stripped.rstrip(":")
        else:
            if not any(l.strip() == skip + ":" for l in body):
                return (set(), set(), set(), set(), set(),
                        f"{path}: {func} ({tag}): skip label {skip} "
                        "not found in function",
                        None)
        # Insercion (tras `insert_after` lineas del ancla). Si la linea
        # siguiente ya lleva un bloque R24, es estado corrupto.
        span = find_function_span(lines, func)
        start, end = span
        body = lines[start:end + 1]
        idx = _find_block(body, list(anchor_lines))[0]
        insert_at = start + idx + insert_after
        if insert_at < len(lines) and R24_MARKER in lines[insert_at]:
            return (set(), set(), set(), set(), set(),
                    f"{path}: {func} ({tag}): hay un bloque R24 en el "
                    "punto de insercion sin este tag (estado corrupto)",
                    None)
        snippet = (custom if custom is not None else _r24_snippet(tag, reg, skip)).rstrip("\n").split("\n")
        lines[insert_at:insert_at] = snippet
        changed = True
        # Etiqueta nueva si la hay y no la puso ya un hermano (tras
        # label_after lineas del ancla).
        if new_label is not None and not label_exists:
            label, la_lines, label_after = new_label
            span = find_function_span(lines, func)
            start, end = span
            body = lines[start:end + 1]
            lidx = _find_block(body, list(la_lines))[0]
            lines[start + lidx + label_after:start + lidx + label_after] = [
                label.rstrip("\n")]
            changed = True
        found_r24.add(tag)
    # --- Fase 3: DECLAREs ---
    if found_old:
        # sub_8242EAC8 no esta declarado en los headers de los ficheros
        # viejos (solo en childoflight_funcs.23.h).
        try:
            if _insert_declare(
                    lines, f"DECLARE_REX_FUNC(sub_8242EAC8);  // {MARKER}"):
                changed = True
        except ValueError as e:
            return (set(), set(), set(), set(), set(), f"{path}: {e}", None)
    mt_recover_here = [mt for mt in TARGETS_MT
                       if _mt_tag(mt) in found_mt and mt[9] == "RECOVER"]
    if mt_recover_here:
        # sub_82434368: declararla solo si falta en el fichero Y en su
        # header hermano (.106/.89 ya la tienen; las demas no).
        m = re.match(r"childoflight_recomp\.(\d+)\.cpp$",
                     path.replace("\\", "/").split("/")[-1])
        if m is None:
            return (set(), set(), set(), set(), set(),
                    f"{path}: no se pudo derivar el numero de fichero para "
                    "el header hermano",
                    None)
        import os
        hdr = os.path.join(os.path.dirname(path),
                           f"childoflight_funcs.{m.group(1)}.h")
        try:
            with open(hdr, encoding="utf-8",
                      errors="surrogateescape") as f:
                htext = f.read()
        except OSError:
            return (set(), set(), set(), set(), set(),
                    f"{path}: no se pudo leer el header hermano {hdr}",
                    None)
        decl_mt = f"DECLARE_REX_FUNC(sub_82434368);  // {MT_MARKER}"
        if ("DECLARE_REX_FUNC(sub_82434368)" not in htext
                and decl_mt not in "\n".join(lines)):
            try:
                if _insert_declare(lines, decl_mt):
                    changed = True
            except ValueError as e:
                return (set(), set(), set(), set(), set(), f"{path}: {e}", None)
    new_text = eol.join(lines) if changed else None
    return (found_old, found_mt, found_r22, found_r23, found_r24, None, new_text)


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
    found_old = set()
    found_mt = set()
    found_r22 = set()
    found_r23 = set()
    found_r24 = set()
    pending = []  # (path, new_text): written only after all files pass
    for path in paths:
        fo, fm, fr, fr23, fr24, error, new_text = guard_file(path, dry_run)
        if error:
            print(f"guard_r15_col: ERROR: {error}", file=sys.stderr)
            return 1
        found_old |= fo
        found_mt |= fm
        found_r22 |= fr
        found_r23 |= fr23
        found_r24 |= fr24
        if new_text is not None:
            pending.append((path, new_text))
        elif fo or fm or fr:
            skipped.append(path)
            print(f"guard_r15_col: already applied, skipped {path}")
    # Todos los targets deben estar presentes (guardados ahora o ya
    # aplicados): los 11 viejos, los 62 MT, los 57 R22, los 26 R23 y los
    # 75 R24.
    missing_old = sorted(set(TARGETS) - found_old)
    if missing_old:
        print(f"guard_r15_col: ERROR: old target(s) not guarded: "
              f"{', '.join(missing_old)} -- the generated tree does not "
              "contain them (glob or codegen changed)", file=sys.stderr)
        return 1
    missing_mt = sorted(MT_IDS - found_mt)
    if missing_mt:
        print(f"guard_r15_col: ERROR: MT target(s) not guarded: "
              f"{', '.join(missing_mt)} -- the generated tree does not "
              "contain them (glob or codegen changed)", file=sys.stderr)
        return 1
    missing_r22 = sorted(R22_IDS - found_r22)
    if missing_r22:
        print(f"guard_r15_col: ERROR: R22 target(s) not guarded: "
              f"{', '.join(missing_r22)} -- the generated tree does not "
              "contain them (glob or codegen changed)", file=sys.stderr)
        return 1
    missing_r23 = sorted(R23_IDS - found_r23)
    if missing_r23:
        print(f"guard_r15_col: ERROR: R23 target(s) not guarded: "
              f"{', '.join(missing_r23)} -- the generated tree does not "
              "contain them (glob or codegen changed)", file=sys.stderr)
        return 1
    missing_r24 = sorted(R24_IDS - found_r24)
    if missing_r24:
        print(f"guard_r15_col: ERROR: R24 target(s) not guarded: "
              f"{', '.join(missing_r24)} -- the generated tree does not "
              "contain them (glob or codegen changed)", file=sys.stderr)
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
          f"{len(skipped)} already applied, old targets: "
          f"{len(found_old)}/{len(TARGETS)}, MT targets: "
          f"{len(found_mt)}/{len(MT_IDS)}, R22 targets: "
          f"{len(found_r22)}/{len(R22_IDS)}, R23 targets: "
          f"{len(found_r23)}/{len(R23_IDS)}, R24 targets: "
          f"{len(found_r24)}/{len(R24_IDS)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
