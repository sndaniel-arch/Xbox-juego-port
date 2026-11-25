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
# THE FIX (this script, two sites in the SDK-syntax generated tree):
#   1. sub_824C5150 (childoflight_recomp.90.cpp): after loading r4 = *(this+156),
#      if it is 0, create the sub-object exactly as sub_824C4FD8 would
#      (Alloc(60, 66) via sub_827AE488, then Ctor sub_8242EAC8, store to +156).
#      If the Alloc fails again, skip the block (goto loc_824C5150_skip, just
#      before the epilogue): no crash, state stays 2, the state machine
#      retries next frame (sub_824C6568 calls this slot every frame while
#      state == 2). The temp at r1+80 is never touched, so its destructor is
#      skipped too -- it was never constructed on this path.
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
#   A guard on sub_82459F10 ALONE is NOT enough: sub_82413AD8 does
#   r3 = *(r3+48) and sub_82474328 does r3 = *(r31+52) with r31 = the result
#   of sub_82459F10, so a NULL return from there would only move the crash.
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
#     the observable outcome (game proceeds past JUGAR vs. stalls in state 2
#     with no crash) is itself the diagnostic. If it stalls, the next step
#     is guest-heap instrumentation, not a bigger guard.
#   - Idempotent: files already carrying the GUARD_R15_A2-R15-01 marker are
#     skipped. Any target function or anchor that does not match EXACTLY
#     fails the run (exit 1) instead of shipping unguarded code.
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

# --- per-target spec: function, anchor lines, insertion, label anchor ---
TARGETS = {
    "sub_824C5150": {
        "file_hint": "childoflight_recomp.90.cpp",
        # Anchor: the load of +156 and the call that follows it.
        "anchor": (
            "\t// lwz r4,156(r31)\n"
            "\tctx.r4.u64 = REX_LOAD_U32(ctx.r31.u32 + 156);\n"
            "\t// bl 0x8247b6d0\n"
        ),
        "insert_after_anchor_line": 2,  # after the REX_LOAD_U32 line
        "recovery": RECOVERY_5150,
        # Label anchor: the epilogue of this function only (824C6A68 called
        # once here); the skip label goes right before `// addi r1,r1,128`.
        "label_anchor": (
            "\tsub_824C6A68(ctx, base);\n"
            "\t// addi r1,r1,128\n"
        ),
        "label": "loc_824C5150_skip:\n",
    },
    "sub_824C4B70": {
        "file_hint": "childoflight_recomp.46.cpp",
        "anchor": (
            "\t// lwz r3,156(r3)\n"
            "\tctx.r3.u64 = REX_LOAD_U32(ctx.r3.u32 + 156);\n"
            "\t// bl 0x82459f10\n"
        ),
        "insert_after_anchor_line": 2,
        "recovery": RECOVERY_4B70,
        "label_anchor": None,  # reuses the existing loc_824C4BE4 label
        "label": None,
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


def guard_file(path, dry_run):
    """Apply the guards for any target function present in this file.

    Returns (transformed_names, already_applied, error), where
    transformed_names is the set of target functions transformed in this
    file (empty when the file holds none of them).

    The generated tree is CRLF (the SDK codegen emits \\r\\n); the file is
    read and written with newline="" so the line ending is preserved
    byte-for-byte -- a naive text-mode rewrite would flip every line to LF
    and drown the diff in 36k unchanged lines."""
    with open(path, encoding="utf-8", errors="surrogateescape",
              newline="") as f:
        text = f.read()
    if MARKER in text:
        return (set(), True, None)
    eol = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(eol)
    transformed = set()
    changed = False
    for name, spec in TARGETS.items():
        span = find_function_span(lines, name)
        if span is None:
            continue  # target lives in another file of the glob
        start, end = span
        body = lines[start : end + 1]
        anchor_lines = spec["anchor"].rstrip("\n").split("\n")
        # Locate the anchor inside the function body.
        idx = None
        for i in range(len(body) - len(anchor_lines) + 1):
            if body[i : i + len(anchor_lines)] == anchor_lines:
                idx = i
                break
        if idx is None:
            return (set(), False,
                    f"{path}: {name}: anchor not found verbatim -- "
                    "codegen output changed, refusing to guess")
        insert_at = start + idx + spec["insert_after_anchor_line"]
        lines[insert_at:insert_at] = spec["recovery"].rstrip("\n").split("\n")
        changed = True
        transformed.add(name)
        if spec["label"] is not None:
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
                        f"{path}: {name}: label anchor not found verbatim")
            label_at = start + lidx + 1  # before `// addi r1,r1,128`
            lines[label_at:label_at] = [spec["label"].rstrip("\n")]
    if not changed:
        return (set(), False, None)
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
                f"{path}: no childoflight_funcs.N.h include found")
    new = eol.join(lines)
    if not dry_run:
        with open(path, "w", encoding="utf-8", errors="surrogateescape",
                  newline="") as f:
            f.write(new)
    return (transformed, False, None)


def main():
    if len(sys.argv) < 2:
        print("usage: guard_r15_col.py [--dry-run] <glob>", file=sys.stderr)
        return 2
    dry_run = "--dry-run" in sys.argv
    pattern = next(a for a in sys.argv[1:] if not a.startswith("--"))
    paths = sorted(glob.glob(pattern))
    if not paths:
        print(f"guard_r15_col: no files matched {pattern!r}", file=sys.stderr)
        return 1
    applied = []
    skipped = []
    found = set()
    for path in paths:
        transformed, already, error = guard_file(path, dry_run)
        if error:
            print(f"guard_r15_col: ERROR: {error}", file=sys.stderr)
            return 1
        if transformed:
            applied.append(path)
            found |= transformed
            print(f"guard_r15_col: guarded {path}")
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
    print(f"guard_r15_col: OK -- {len(applied)} file(s) guarded, "
          f"{len(skipped)} already applied, targets: {', '.join(sorted(found))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
