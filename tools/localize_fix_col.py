#!/usr/bin/env python3
# Post-codegen pass for the *_as_local codegen options, adapted for Child of Light.
#
# Origin: tools/localize_fix.py from santiquiroz/gears-of-war-2-pc-port
# (BSD-3-Clause, see NOTICE in that repo), which this file derives from.
# A register codegen made a C++ local is private to each function, but guest
# code shares registers across calls: CRT funclets take the parent's frame in
# r12, code split into several functions reads its parent's registers, and
# some functions read a non-volatile on a path that never set it, getting
# whatever an ancestor left. This pass runs a liveness analysis over the
# generated C++ (control flow from labels, gotos, returns, switch and if
# blocks; a call reads what its callee needs; a register a function never
# names passes through it to its callees), puts the registers a function
# reads from its caller back in ctx there, and makes every direct caller
# copy its locals to ctx around such a call. non_volatile_as_local also
# drops the __save*/__rest* helper calls; where a register still lives in
# ctx, or the codegen copied a local to ctx before a funclet call, the
# function now saves it on entry and restores it on every return, as the
# helpers did.
#
# CoL adaptations vs Gears (audit ronda 2, P1-1; verified against the SDK
# codegen source in tools/rexauto/android/sdk/rexglue-sdk/src/codegen/):
#   (a) function regex: the SDK emits DEFINE_REX_FUNC(<name>), not
#       PPC_FUNC_IMPL(__imp__sub_XXXXXXXX) (function_graph.cpp:370,482).
#       The DEFINE name IS the call name: DEFINE_REX_FUNC(name) emits the
#       body as __imp__name with `name` a weak alias (pch_h.inja:79-88), and
#       calls use `name(ctx, base)` (context.cpp:231-265). No stripping.
#   (b) call names are already normalised in the SDK (defensive; kept).
#   (c) save_helpers() reads PPCFuncMappings[] from <project>_init.cpp
#       (childoflight_init.cpp; init_cpp.inja:33-36, codegen_writer.cpp:228-
#       231), NOT ppc_func_mapping.cpp -- that file does not exist in SDK
#       output (writer emits <project>_init.cpp, <project>_funcs.N.h,
#       <project>_recomp.N.cpp, <project>_pch.h, <project>_register.cpp).
#       Entries are `{ 0xADDR, __savegprlr_N }` (address 0x{:X}, unpadded,
#       uppercase; codegen_writer.cpp:74). The `// bl 0x...` comments that
#       link a function to its helper come from GNU binutils op_str
#       (thirdparty/disasm/ppc-dis.c:5768: "0x%llx", lowercase, unpadded),
#       so both sides are compared as integers. If the table cannot be
#       loaded at all, FuncRewrite falls back to treating every demoted
#       non-volatile as saved (extra lf_in_ slots, never a silent clobber).
#   (d) indirect calls are REX_CALL_INDIRECT_FUNC, not PPC_CALL_INDIRECT_FUNC
#       (control_flow.cpp:104,180,189,196). Args carry `.u32`
#       (ctr.u32 / ctx.ctr.u32 / uint32_t(old_lr)); the script keys on the
#       macro name only, so all three forms match.
#   (e) split_prologue() looks for REX_FUNC_PROLOGUE();, not PPC_FUNC_PROLOGUE();
#       (function_graph.cpp:371,483). It is always the first body line.
#   (f) STORE regex also matches REX_MM_STORE_U8/16/32/64 (MMIO stores;
#       context.cpp:533-553, memory.cpp). PPC_STORE_U* is kept defensively
#       (never emitted by the SDK). REX_STORE_U* is what the SDK emits.
#   (g) xer IS tracked here (removed from IGNORED, added to LOCALIZABLE).
#       Gears ignores xer ("compares read xer.so, never set by compiled
#       code") but the SDK sets xer.ca (adde: arithmetic.cpp:36
#       `xer.ca = temp.u8;`) and reads it in callees (adde:
#       arithmetic.cpp:28-35 `... + xer.ca ...`). Ignoring it would silently
#       zero the carry across calls. xer writes are deliberately NOT treated
#       as defs (PARTIAL_AS_FULL has no xer arm): a write to .ca does not
#       define .so/.ov, so it stays a conservative use.
#   (h) the SDK has a SINGLE PPCContext definition (rex/ppc/context.h:213,
#       223; reached via the generated <project>_pch.h). There is no second
#       generated ppc_context.h to drift against it, so the dual-definition
#       sync problem of the XenonRecomp tree does not exist here. (The old
#       (h) about patch 0021 / 208-field comparison is XenonRecomp-only and
#       does not apply.)
#   (i) SEH funclets: the SDK ALREADY flushes r14-r31 around a direct call
#       to a sharesRegisters funclet (context.cpp:215-228: `ctx.rN = rN;` /
#       `rN = ctx.rN;`, GPRs only -- NOT f/v/cr/ctr/xer). The script must
#       NOT duplicate that flush: codegen_flushed_above() detects the
#       plain `ctx.rN = rN;` run immediately above a call line and the
#       rewrite subtracts those regs from its own flush (f/v regs the SDK
#       does NOT flush are still flushed by the script). The SDK emits NO
#       other `ctx.R = R;` line anywhere (only context.cpp:218), so the
#       pattern is unambiguous. Calls the SDK emits WITHOUT a flush --
#       SEH __finally/restore-helper calls in function_graph.cpp:620-635 --
#       get the generic live-in flush, as before.
#   (j) function close is by BRACE DEPTH, not by a column-0 `}`. The SDK
#       closes non-SEH functions with `}` at column 0 but SEH functions
#       with an indented `}` (function_graph.cpp:600-637: the SEH_TRY block
#       opens in `out`, the body closes it, and the final `}` is indented
#       by the SEH re-indent pass) -- and inner blocks also close with an
#       indented `}` (e.g. build_bnectr, control_flow.cpp:196-199). A
#       column-0-only close test silently DISCARDS every SEH function body
#       at the next DEFINE (or at EOF). parse() and rewrite_file() track
#       depth from the DEFINE `{` (brace_delta() strips strings and `//`
#       comments first) and end the function when depth returns to 0.
#   (k) empty input fails loud: a glob matching no files, or a tree with
#       zero functions, exits 2 with an error on stderr instead of the old
#       silent exit 0. (The workflow tripwire stays as the second guard.)
#   (l) labels/gotos are UNPADDED hex: the SDK emits `loc_{:X}:` and
#       `goto loc_{:X};` (function_graph.cpp:513, control_flow.cpp:37) but
#       `goto loc_{:08X};` for conditional branches (context.cpp:289).
#       LABEL/GOTO accept 1-8 hex digits; 0x82... addresses are 8 digits
#       in practice, but a <0x10000000 target would otherwise break the CFG.
#   (m) --indirect-union (OPT-IN, default OFF): restrict the indirect-call
#       flush to kept locals that are live-in of SOME function in this
#       tree (the union of all live-in sets, computed by a dry-run
#       analysis pre-pass over the original files, before any rewrite).
#       Direct calls already flush exactly the callee's genuine live-ins;
#       indirect calls cannot know their target, so the default flushes
#       ALL kept locals (Hunt 3 P1-1). The union is the sound restriction:
#       any possible indirect target is a function in this tree (or an
#       import, which only reads argument regs from ctx, never localized
#       non-volatiles), and its live-ins are in the union; a kept reg no
#       function ever reads as a live-in can never be needed by a callee.
#       LIMITS, read before enabling: (1) the union covers only the ONE
#       module globbed (generated/default). A cross-module indirect target
#       (DLL module, REX_CALL_INDIRECT_FUNC falls back to
#       ResolveIndirectFunction across modules) whose live-ins are outside
#       this module's union would read STALE registers -- do NOT enable if
#       the port has DLL modules (check has_dll_modules in the generated
#       *_init.cpp / manifest first). (2) The union is computed on the
#       ORIGINAL tree; rewrite passes can only add live-ins that were
#       already in it (a flush line reads a reg the callee genuinely
#       needs, hence in the union; demotion only rewrites regs already
#       live-in). (3) The pre-pass costs one extra full analysis in CI
#       wall-time; the payoff is per-frame game CPU, not CI time. Measure
#       first: copy generated/default aside, run with and without the
#       flag, compare `grep -c LOCALIZE_FIX`. The 19% saving sometimes
#       quoted for this restriction could NOT be verified against any
#       source in this audit (no file states it); treat it as unproven
#       until the CI comparison measures the real tree.
# usage: localize_fix_col.py "<generated/default>/*.cpp" [--dry-run] [--verbose] [--list=N] [--why=FUNC] [--indirect-union]
#   The glob in CI is "<generated/default>/childoflight_recomp.*.cpp"
#   (codegen_writer.cpp:301 emits {project}_recomp.{N}.cpp with
#   REX_PROJECT=childoflight; workflow .github/workflows/
#   recompile-android-rexauto.yml:355,:381. The old ppc_recomp.*.cpp glob
#   matched NOTHING -- XenonRecomp naming, recompiler.cpp:3174 -- and was
#   fixed in the workflow (caza extra X-L-1). See REPORT-A.)
import collections
import glob
import pathlib
import re
import sys

FUNC = re.compile(r"^DEFINE_REX_FUNC\((\w+)\) \{$")


def norm_name(name):
    # SDK: the DEFINE name IS the call name (weak alias `name` -> body
    # `__imp__name`; pch_h.inja:79-88). No stripping; identity kept as a
    # function so call sites stay uniform. Import calls (__imp__Foo) never
    # match a defined function and correctly resolve to no live-ins.
    return name
DECL = re.compile(r"^\s*PPC\w*Register (\w+)\{\};$")
LABEL = re.compile(r"^(loc_[0-9A-F]{1,8}):$")
GOTO = re.compile(r"goto (loc_[0-9A-F]{1,8});")
CALL = re.compile(r"\b(\w+)\(ctx, base\);")
FULL_DEF = re.compile(r"^(\w+)\.(u64|s64|f64)\s*=\s*(.*);$")
METHOD_DEF = re.compile(r"^(\w+)\.(compare(?:<[^>]*>)?|setFromMask)\((.*)\);$")
IGNORED = {"temp", "vTemp"}  # temps: codegen scratch (xer IS tracked here, see header (g))
MARK = "// LOCALIZE_FIX"
VERBOSE = "--verbose" in sys.argv


class Func:
    def __init__(self, name, path, start):
        self.name, self.path, self.start = name, path, start
        self.lines = []
        self.locals = []
        self.ctx_regs = set()


# Registers some codegen *_as_local option can make a local. A function that still reads one of
# them from ctx (an SEH funclet keeps the non-volatiles of the parent frame there). A function this pass
# already demoted needs it from its caller like any live-in local.
LOCALIZABLE = r"(?:r(?:0|2|11|12|1[4-9]|2\d|3[01])|f(?:0|1[4-9]|2\d|3[01])|v(?:1[4-9]|[2-9]\d|1[01]\d|12[0-7])|cr[0-7]|ctr|xer|reserved)"
CTX_REF = re.compile(r"\bctx\.(" + LOCALIZABLE + r")\b")


def ctx_regs_of(func):
    regs = set()
    for line in func.lines:
        regs |= set(CTX_REF.findall(code_of(line)))
    return regs - set(func.locals)


# Brace delta of one generated line, ignoring braces inside string
# literals and `//` comments. Generated strings/comments never contain an
# unbalanced quote (REXLOG/REXFATAL messages, `// <mnemonic> <op>` disasm
# comments); a stray quote in a comment simply leaves the comment text to
# be stripped by the `//` pass.
_BRACES_IN_STRING = re.compile(r'"[^"]*"')
_BRACES_COMMENT = re.compile(r"//.*$")


def brace_delta(line):
    s = _BRACES_IN_STRING.sub('""', line)
    s = _BRACES_COMMENT.sub("", s)
    return s.count("{") - s.count("}")


def parse(paths):
    funcs = {}
    for path in paths:
        cur = None
        depth = 0
        for i, line in enumerate(open(path, encoding="utf-8", errors="surrogateescape").read().split("\n")):
            m = FUNC.match(line)
            if m:
                cur = Func(norm_name(m.group(1)), path, i)
                funcs[cur.name] = cur
                depth = 1  # the `{` on the DEFINE line
                continue
            if line.startswith("DEFINE_REX_FUNC("):
                # A DEFINE line that does not match FUNC (e.g. the prologue
                # glued onto the same line) is silently skipped by the
                # parser: the function keeps its locals and gets NO flush
                # wrappers. Warn loudly instead of failing the whole run:
                # one malformed function must not hide as "0 functions".
                print(f"localize_fix: WARNING: {path}:{i + 1}: DEFINE line "
                      f"does not match ^DEFINE_REX_FUNC(name) {{$: skipped, "
                      f"function will NOT be localized: {line.strip()[:100]}",
                      file=sys.stderr)
            if cur is None:
                continue
            depth += brace_delta(line)
            if depth <= 0:
                # Function close: `}` at column 0 (plain) or indented
                # (SEH functions, header (j)). The close line is not body.
                cur = None
                depth = 0
                continue
            cur.lines.append(line)
            d = DECL.match(line)
            if d and d.group(1) not in IGNORED:
                cur.locals.append(d.group(1))
    for func in funcs.values():
        func.ctx_regs = ctx_regs_of(func)
    return funcs


CODEGEN_FLUSH = re.compile(r"^ctx\.(\w+) = (?:ctx\.)?\1;$")


# Saves and restores this pass wrote only carry a register through unchanged: not a use.
def code_of(line):
    s = line.strip()
    if s.startswith("//") or DECL.match(s):
        return ""
    if MARK in s:
        w = WRAPPED_RETURN.match(line)
        if w:
            return f"if ({w.group(2)}) return;"
        if "lf_in_" in s or "lf_call_" in s:
            return ""
    # Codegen copies every register local to ctx before a call into a funclet, defined or not:
    # the call line already reads what the funclet needs.
    elif CODEGEN_FLUSH.match(s):
        return ""
    return s


def matching_close(lines, i):
    depth = 0
    for j in range(i, len(lines)):
        s = code_of(lines[j])
        depth += s.count("{") - s.count("}")
        if depth <= 0 and j > i:
            return j
    return len(lines) - 1


def build_cfg(lines):
    labels = {}
    for i, line in enumerate(lines):
        m = LABEL.match(line.strip())
        if m:
            labels[m.group(1)] = i
    succ = [[] for _ in lines]
    n = len(lines)
    for i, line in enumerate(lines):
        s = code_of(line)
        targets = [labels[t] for t in GOTO.findall(s) if t in labels]
        ends = s in ("return;",) or re.fullmatch(r"goto loc_[0-9A-F]{1,8};", s) is not None
        if not ends and i + 1 < n:
            succ[i].append(i + 1)
        succ[i].extend(targets)
        if s.endswith("{") and s.count("{") > s.count("}"):
            close = matching_close(lines, i)
            if close + 1 < n:
                succ[i].append(close + 1)
            if s.startswith("switch"):
                for j in range(i + 1, close):
                    cs = code_of(lines[j])
                    if cs.startswith("case ") or cs.startswith("default:"):
                        succ[i].append(j)
    return succ


LOCAL_REF = re.compile(r"(?<![\w.])([A-Za-z_]\w*)")
STORE = re.compile(r"^(PPC_STORE_U(?:8|16|32|64)|REX_STORE_U(?:8|16|32|64)|REX_MM_STORE_U(?:8|16|32|64)|simde_mm_store_si128|simde_mm_store_ps)\((.*)\);$")
VEC_DEST = re.compile(r"^(?:\(simde__m128i\*\))?(\w+)\.(?:u8|s8|u16|s16|u32|s32|f32|u64|s64)$")
# Writes treated as whole-register: lwarx fills reserved.u32, stwcx. and mtcrf write cr fields one
# by one and the code after them reads only what they wrote, and `v57 = vTemp;` copies a whole register.
PARTIAL_AS_FULL = re.compile(r"^(reserved|cr\d|v\d+|f\d+|r\d+)(?:\.(?:u32|lt|gt|eq|so))?\s*=\s*(.*);$")
PROLOGUE_SLOT = re.compile(r"^ctx\.r1\.u32 \+ -\d+$")
NON_VOLATILE = re.compile(r"^(r(1[4-9]|2\d|3[01])|f(1[4-9]|2\d|3[01])|v(1[4-9]|2\d|3[01]|6[4-9]|[7-9]\d|1[01]\d|12[0-7]))$")


def split_top(args):
    depth = 0
    for i, c in enumerate(args):
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            return args[:i], args[i + 1:]
    return args, ""


def use_def(stmt, bit_of, livein_of):
    dfn = 0
    reads = stmt
    spilled = ""
    if stmt.count(";") <= 1:
        m = FULL_DEF.match(stmt) or METHOD_DEF.match(stmt)
        if m and m.group(1) in bit_of:
            dfn = bit_of[m.group(1)]
            reads = m.group(3)
        st = STORE.match(stmt)
        if st:
            addr, value = split_top(st.group(2))
            reg = VEC_DEST.match(addr.strip())
            if reg and reg.group(1) in bit_of:
                dfn = bit_of[reg.group(1)]
                reads = value
            elif PROLOGUE_SLOT.match(addr.strip()):
                # A non-volatile stored below the stack pointer is the prologue saving it
                reads, spilled = addr, value
        pd = PARTIAL_AS_FULL.match(stmt)
        if pd and pd.group(1) in bit_of and not re.search(rf"(?<![\w.]){pd.group(1)}\b", pd.group(2)):
            dfn = bit_of[pd.group(1)]
            reads = pd.group(2)
    use = 0
    for w in set(LOCAL_REF.findall(reads)):
        use |= bit_of.get(w, 0)
    for w in set(LOCAL_REF.findall(spilled)):
        if not NON_VOLATILE.match(w):
            use |= bit_of.get(w, 0)
    for callee in CALL.findall(stmt):
        for reg in livein_of.get(norm_name(callee), ()):
            use |= bit_of.get(reg, 0)
    return use, dfn


def normalized(func):
    if not func.ctx_regs:
        return [code_of(l) for l in func.lines]
    ref = re.compile(r"\bctx\.(" + "|".join(sorted(func.ctx_regs, key=len, reverse=True)) + r")\b")
    return [ref.sub(r"\1", code_of(l)) for l in func.lines]


def prepare(func):
    tracked = list(func.locals) + sorted(func.ctx_regs)
    func.bit_of = {r: 1 << k for k, r in enumerate(tracked)}
    func.succ = build_cfg(func.lines)
    func.norm = normalized(func)
    func.base_ud = [use_def(s, func.bit_of, {}) for s in func.norm]
    func.calls = [[norm_name(c) for c in CALL.findall(s)] for s in func.norm]


def passed_through(func, livein_of):
    regs = set()
    for callees in func.calls:
        for callee in callees:
            regs |= set(livein_of.get(callee, ()))
    return {r for r in regs if r not in func.bit_of}


# A register this function never names reaches its callees unchanged: their live-ins are its own.
def livein(func, livein_of):
    return tracked_livein(func, livein_of) | passed_through(func, livein_of)


def tracked_livein(func, livein_of):
    if not func.bit_of:
        return set()
    bit_of = func.bit_of
    lines = func.lines
    succ = func.succ
    ud = []
    for (use, dfn), callees in zip(func.base_ud, func.calls):
        for callee in callees:
            for reg in livein_of.get(callee, ()):
                use |= bit_of.get(reg, 0)
        ud.append((use, dfn))
    live_in = [0] * len(lines)
    changed = True
    while changed:
        changed = False
        for i in range(len(lines) - 1, -1, -1):
            out = 0
            for j in succ[i]:
                out |= live_in[j]
            use, dfn = ud[i]
            new = use | (out & ~dfn)
            if new != live_in[i]:
                live_in[i] = new
                changed = True
    entry = live_in[0] if lines else 0
    return {r for r, b in bit_of.items() if entry & b}


def analyse(funcs):
    callers = collections.defaultdict(set)
    for f in funcs.values():
        prepare(f)
        for callees in f.calls:
            for c in callees:
                callers[c].add(f.name)
    livein_of = {}
    work = list(funcs)
    if "--roots" in sys.argv:
        for name in sorted(work):
            odd = sorted(r for r in livein(funcs[name], {}) if r != "r12")
            if odd:
                print(f"  root {name}: {' '.join(odd)}")
    rnd = 0
    while work:
        nxt = set()
        for name in work:
            li = livein(funcs[name], livein_of)
            if li != livein_of.get(name, set()):
                if li:
                    livein_of[name] = li
                else:
                    livein_of.pop(name, None)
                nxt |= callers[name]
        if VERBOSE:
            print(f"round {rnd}: {len(livein_of)} function(s) read a caller's register")
        work = sorted(nxt)
        rnd += 1
    return livein_of


LIST = int(next((a.split("=")[1] for a in sys.argv if a.startswith("--list=")), "0"))
WHY = [a.split("=", 1)[1] for a in sys.argv if a.startswith("--why=")]


def witness(func, reg, livein_of):
    bit = func.bit_of[reg]
    prev = {0: None}
    queue = collections.deque([0])
    while queue:
        i = queue.popleft()
        use, dfn = use_def(func.norm[i], func.bit_of, livein_of)
        if use & bit:
            path = []
            while i is not None:
                path.append(i)
                i = prev[i]
            return path[::-1]
        if dfn & bit:
            continue
        for j in func.succ[i]:
            if j not in prev:
                prev[j] = i
                queue.append(j)
    return []


def explain(funcs, livein_of):
    for name in WHY:
        func = funcs[name]
        for reg in sorted(livein_of.get(name, ())):
            path = witness(func, reg, livein_of)
            print(f"{name} {reg}: {len(path)} lines on the path")
            for i in [k for k in path if LABEL.match(func.lines[k].strip()) or "goto" in func.lines[k] or "(ctx, base)" in func.lines[k]][-8:] + path[-1:]:
                print(f"    {i:5d} {func.lines[i].strip()[:150]}")


def report(livein_of):
    if not (VERBOSE or LIST):
        return
    by_reg = collections.Counter(r for v in livein_of.values() for r in v)
    print("by register:", dict(sorted(by_reg.items(), key=lambda kv: -kv[1])))
    shown = [kv for kv in sorted(livein_of.items()) if not kv[0].startswith("__")]
    for name, regs in shown[:LIST]:
        print(f"  {name}: {' '.join(sorted(regs))}")


def one_pass(paths, dry):
    funcs = parse(paths)
    print(f"{len(funcs)} functions, {sum(1 for f in funcs.values() if f.locals)} with register locals")
    if not funcs:
        # Header (k): a tree with zero functions means the script no longer
        # understands the codegen (or the glob was wrong). Fail loud.
        print("localize_fix: no functions found -- the codegen syntax changed "
              "again or the glob matched no generated files", file=sys.stderr)
        return -1
    livein_of = analyse(funcs)
    report(livein_of)
    explain(funcs, livein_of)
    if dry:
        return 0
    demoting = sum(1 for f in funcs.values() if demoted_locals(f, livein_of))
    flushes = rewrite(paths, funcs, livein_of)
    print(f"demoted registers in {demoting} function(s), {flushes} call site(s) copy registers through ctx")
    return demoting + flushes


MAX_PASSES = 8


INDIRECT_UNION = None  # header (m): set by main() iff --indirect-union


def main():
    global INDIRECT_UNION
    if len(sys.argv) < 2:
        # (Caza extra X-L-1, ronda 2.) Sin argumentos moría con IndexError y
        # traceback en vez de uso/exit 2 (el glob vacío sí tiene exit 2).
        print("usage: localize_fix_col.py \"<generated/default>/*.cpp\" [--dry-run] [--verbose] [--list=N] [--why=FUNC] [--indirect-union]",
              file=sys.stderr)
        return 2
    paths = sorted(glob.glob(sys.argv[1]))
    if not paths:
        # Header (k): an empty glob used to exit 0 with "0 functions" and
        # let the job die later at the tripwire with a misleading message.
        print(f"localize_fix: no files matched {sys.argv[1]!r}", file=sys.stderr)
        return 2
    if "--indirect-union" in sys.argv:
        # Header (m): dry-run analysis pre-pass over the ORIGINAL tree
        # (before any rewrite) -- the union of all live-in sets bounds
        # what any indirect callee in this module can read.
        pre_funcs = parse(paths)
        pre_livein = analyse(pre_funcs)
        INDIRECT_UNION = {r for regs in pre_livein.values() for r in regs}
        print(f"indirect union: {len(INDIRECT_UNION)} register(s) ever read "
              f"as live-in: {' '.join(sorted(INDIRECT_UNION))}")
    dry = "--dry-run" in sys.argv
    # Flushes added by one pass read registers the next pass may find a caller must supply.
    for _ in range(MAX_PASSES):
        r = one_pass(paths, dry)
        if r == 0:
            return 0
        if r < 0:
            return 2
    print(f"localize_fix: still changing after {MAX_PASSES} passes", file=sys.stderr)
    return 1


def demote_line(line, regs):
    if not regs or line.strip().startswith("//"):
        return line
    return re.sub(r"(?<![\w.])(" + "|".join(sorted(regs, key=len, reverse=True)) + r")\b",
                  r"ctx.\1", line)


# Hunt 3, P1-1: an indirect call's callee is unknown at analysis time
# (dispatch on ctr in runtime), so it may read ANY kept localizable
# register as a live-in -- observed live-ins include r27 (4,136 functions)
# and volatile vectors (v57 in 790, v55 in 697, v127 in 573). Flushing
# only r12 left every other live-in stale in ctx. Every indirect call
# therefore flushes ALL kept locals and copies them back afterwards,
# exactly like a direct call. That also covers the switch-trap default:
# case (the trap target goes on with every register of this function).
# One leftover: a wrapper from the old r12-only pass flushed r12 with
# copy_back=False, and line() only wraps the delta (kept - flushed_above),
# so r12 kept no copy-back after indirect calls (27,713 of 28,179 sites).
# complete_indirect_copybacks() adds the missing copy-back lines at the end
# of body(), so indirects sync back exactly like directs. A dataflow check
# proved the gap benign in this tree (0 stale r12 reads: r12 is always
# redefined before any use after a call), but the invariant now holds by
# construction instead of by luck.
INDIRECT = "REX_CALL_INDIRECT_FUNC("
NON_VOLATILE_CR = re.compile(r"^cr[234]$")
# SDK init table: `{ 0x82A93144, __savegprlr_14 },` (init_cpp.inja:33-36;
# address 0x{:X}: uppercase, unpadded -- codegen_writer.cpp:74).
SAVE_HELPER = re.compile(r"\{ 0x([0-9A-Fa-f]{1,8}), __save(gprlr|fpr|vmx)_(\d+) \}")
# Disasm comment for the bl that called the helper, from GNU binutils op_str
# (thirdparty/disasm/ppc-dis.c:5768: "0x%llx", lowercase, unpadded):
# `\t// bl 0x82a93144`. Tolerant on case/padding; compared as integers.
BL_COMMENT = re.compile(r"^\s*// bl 0x([0-9a-fA-F]{1,8})\b.*$")
HELPER_CALL = re.compile(r"\b__(?:save|rest)(?:gprlr|fpr|vmx)_\d+\(ctx, base\);")
FLUSH = re.compile(r"^\s*ctx\.(\w+) = \1;  " + re.escape(MARK) + "$")
COPYBACK = re.compile(r"^\s*(\w+) = ctx\.\1;  " + re.escape(MARK) + "$")
SELF_COPY = re.compile(r"^\s*ctx\.(\w+) = ctx\.\1;  " + re.escape(MARK) + "$")
RESTORE_IN = re.compile(r"ctx\.(\w+) = lf_in_\1;")
CALL_SLOT = re.compile(r"\blf_call_(\w+)\b(?!\))")
SLOT_DECL = re.compile(r"^\s*decltype\(ctx\.\w+\) (lf_(?:in|call)_\w+);")
COND_RETURN = re.compile(r"^(\s*)if \((.*)\) return;$")
WRAPPED_RETURN = re.compile(r"^(\s*)if \((.*)\) \{ (.*)return; \}  " + re.escape(MARK) + "$")


def non_volatile(reg):
    return bool(NON_VOLATILE.match(reg) or NON_VOLATILE_CR.match(reg))


def helper_regs(kind, n):
    prefix = {"gprlr": "r", "fpr": "f", "vmx": "v"}[kind]
    top = 128 if kind == "vmx" and n >= 64 else 32
    return {f"{prefix}{k}" for k in range(n, top)}


def save_helpers(gen_dir):
    # SDK: the table is PPCFuncMappings[] in <project>_init.cpp
    # (codegen_writer.cpp:228-231 renders codegen/init_cpp). There is no
    # ppc_func_mapping.cpp in SDK output. Find the init file by glob and
    # prefer the one that actually contains the table.
    candidates = sorted(gen_dir.glob("*_init.cpp"))
    path = None
    for cand in candidates:
        try:
            if "PPCFuncMappings" in cand.read_text(errors="replace"):
                path = cand
                break
        except OSError:
            continue
    if path is None and candidates:
        path = candidates[0]
    if path is None:
        print("localize_fix: WARNING: no *_init.cpp in "
              f"{gen_dir} -- save/restore helper info unavailable, "
              "falling back to conservative entry save/restore",
              file=sys.stderr)
        return {}
    text = path.read_text(errors="replace")
    # Keys are integers: the table prints 0x{:X} (uppercase, unpadded) while
    # the `// bl` comment prints 0x%llx (lowercase, unpadded).
    return {int(a, 16): helper_regs(kind, int(n)) for a, kind, n in SAVE_HELPER.findall(text)}


# non_volatile_as_local drops the calls to __savegprlr_N and __restgprlr_N (and the fpr and vmx
# ones): a register such a function hands back to ctx would no longer be restored on return.
def helper_saved(func, helpers):
    if any(HELPER_CALL.search(line) for line in func.lines):
        return set()
    regs = set()
    for line in func.lines:
        m = BL_COMMENT.match(line)
        if m and int(m.group(1), 16) in helpers:
            regs |= helpers[int(m.group(1), 16)]
    return regs


def codegen_flushed_above(out):
    # Plain `ctx.rN = rN;` lines the SDK itself emitted immediately above
    # the call (the SEH-funclet flush, context.cpp:215-228) -- header (i).
    # Scan upward over our own MARK lines too: a previous pass already
    # wrapped this same call, so its MARK flush/slot lines now sit between
    # the SDK flush and the call. Without skipping them, pass 2 misses the
    # SDK flush and adds a duplicate `ctx.rN = rN; // LOCALIZE_FIX` -- and
    # worse, its `ctx.rN = lf_call_rN;` restore then runs BEFORE the SDK's
    # own `rN = ctx.rN;` copy-back, so the copy-back loads the pre-call
    # value and the funclet's write to the caller's frame is lost.
    # Anything else stops the scan: an SDK copy-back (`rN = ctx.rN;`,
    # plain, no MARK) always intervenes between two call sites, so the
    # scan can never pick up another call's flush.
    names = set()
    for line in reversed(out):
        if MARK in line:
            continue
        m = CODEGEN_FLUSH.match(line.strip())
        if not m:
            break
        names.add(m.group(1))
    return names


def flushed_above(out):
    names = set()
    for line in reversed(out):
        if MARK not in line:
            break
        m = FLUSH.match(line)
        if m:
            names.add(m.group(1))
    return names


def last_code(out):
    return next((l.strip() for l in reversed(out) if MARK not in l), "")


def mark(indent, stmt):
    return f"{indent}{stmt}  {MARK}"


# Around a call the callee must see these registers in ctx; this function's own caller keeps
# its view of the non-volatile ones, and copy_back returns what the callee left to the locals.
def around_call(indent, line, regs, copy_back, slots):
    nv = sorted(r for r in regs if non_volatile(r))
    slots |= {f"lf_call_{r}" for r in nv}
    before = [mark(indent, f"lf_call_{r} = ctx.{r};") for r in nv]
    before += [mark(indent, f"ctx.{r} = {r};") for r in sorted(regs)]
    after = [mark(indent, f"{r} = ctx.{r};") for r in sorted(regs)] if copy_back else []
    after += [mark(indent, f"ctx.{r} = lf_call_{r};") for r in nv]
    return before + [line] + after


def restored_above(out):
    names = set()
    for line in reversed(out):
        if MARK not in line:
            break
        names |= set(RESTORE_IN.findall(line))
    return names


def with_restores(line, out, entry):
    if not entry:
        return [line]
    m = WRAPPED_RETURN.match(line)
    if m:
        missing = sorted(entry - set(RESTORE_IN.findall(m.group(3))))
        stmts = m.group(3) + "".join(f"ctx.{r} = lf_in_{r}; " for r in missing)
        return [f"{m.group(1)}if ({m.group(2)}) {{ {stmts}return; }}  {MARK}"]
    m = COND_RETURN.match(line)
    if m:
        stmts = "".join(f"ctx.{r} = lf_in_{r}; " for r in sorted(entry))
        return [f"{m.group(1)}if ({m.group(2)}) {{ {stmts}return; }}  {MARK}"]
    if line.strip() == "return;":
        indent = re.match(r"\s*", line).group(0)
        missing = sorted(entry - restored_above(out))
        return [mark(indent, f"ctx.{r} = lf_in_{r};") for r in missing] + [line]
    return [line]


LOCAL_TO_CTX = re.compile(r"^\s*ctx\.(\w+) = \1;$")


def codegen_flushed(func):
    return {m.group(1) for m in map(LOCAL_TO_CTX.match, func.lines) if m}


class FuncRewrite:
    def __init__(self, func, demoted, livein_of, helpers):
        self.demoted = demoted
        self.livein_of = livein_of
        self.kept = set(func.locals) - demoted
        # The codegen drops __save*/__rest* calls even where registers stay in ctx (funclets).
        if helpers:
            saved = {r for r in (demoted | func.ctx_regs) & helper_saved(func, helpers) if non_volatile(r)}
        else:
            # No helper table (no *_init.cpp, or no __save entries in it):
            # fail safe -- preserve every demoted/ctx non-volatile on
            # entry/return instead of silently clobbering the caller's
            # value. Extra lf_in_ slots only; never wrong. Header (c).
            saved = {r for r in (demoted | func.ctx_regs) if non_volatile(r)}
        # Its own copies into ctx before a funclet call overwrite the caller's value for good.
        flushed = {r for r in codegen_flushed(func) & self.kept if non_volatile(r)}
        self.new_entry = saved | flushed
        self.slots = set()
        self.flushes = 0

    def complete_indirect_copybacks(self, out):
        # A wrapper written by the old r12-only pass flushed r12 before the
        # call but copied nothing back (copy_back=False); line() above only
        # wraps the delta (kept - flushed_above), so r12 still has no
        # copy-back. Add the missing copy-back lines so an indirect call
        # syncs its locals back exactly like a direct call. The dataflow
        # check (0 stale r12 reads in the tree) shows the gap is benign in
        # practice -- r12 is always redefined before any use after a call --
        # but the invariant should hold by construction, not by luck.
        added = 0
        i = 0
        while i < len(out):
            line = out[i]
            if INDIRECT in line and not line.strip().startswith("//"):
                indent = re.match(r"\s*", line).group(0)
                flushed = set()
                j = i - 1
                while j >= 0 and MARK in out[j]:
                    m = FLUSH.match(out[j])
                    if m:
                        flushed.add(m.group(1))
                    j -= 1
                copied = set()
                k = i + 1
                last_copyback = i
                while k < len(out) and MARK in out[k]:
                    m = COPYBACK.match(out[k])
                    if m:
                        copied.add(m.group(1))
                        last_copyback = k
                    k += 1
                missing = sorted(flushed - copied)
                if missing:
                    ins = [mark(indent, f"{r} = ctx.{r};") for r in missing]
                    out[last_copyback + 1:last_copyback + 1] = ins
                    added += len(ins)
            i += 1
        return added

    def body(self, lines):
        existing = {m.group(1) for m in map(SLOT_DECL.match, lines) if m}
        self.slots = set(existing)
        saved = {s[len("lf_in_"):] for s in existing if s.startswith("lf_in_")}
        self.new_entry -= saved
        entry = saved | self.new_entry
        self.slots |= {f"lf_in_{r}" for r in self.new_entry}
        out = []
        for line in lines:
            out.extend(self.line(line, out, entry))
        if entry and last_code(out) not in ("return;",) and not last_code(out).startswith("goto "):
            out.extend(mark("\t", f"ctx.{r} = lf_in_{r};") for r in sorted(entry - restored_above(out)))
        self.flushes += self.complete_indirect_copybacks(out)
        return self.prologue(lines, existing) + out

    def prologue(self, lines, existing):
        decls = [mark("\t", f"decltype(ctx.{s.split('_', 2)[2]}) {s};") for s in sorted(self.slots - existing)]
        saves = [mark("\t", f"lf_in_{r} = ctx.{r};") for r in sorted(self.new_entry)]
        return decls + saves

    # Once this function reads R from ctx itself, a callee's change to ctx.R is its change too.
    def stale_call_slot(self, line):
        m = CALL_SLOT.search(line)
        return bool(m and MARK in line and m.group(1) in self.demoted)

    def line(self, line, out, entry):
        d = DECL.match(line)
        if d and d.group(1) in self.demoted:
            return []
        line = demote_line(line, self.demoted)
        if SELF_COPY.match(line) or self.stale_call_slot(line):
            return []
        code = "" if line.strip().startswith("//") else line
        indent = re.match(r"\s*", line).group(0)
        regs = set()
        for callee in CALL.findall(code):
            regs |= set(self.livein_of.get(callee, ())) & self.kept
        # Header (i): the SDK already flushed some of these itself before
        # a funclet call (plain `ctx.rN = rN;` lines above); do not flush
        # them a second time. f/v regs the SDK never flushes stay in regs.
        regs -= flushed_above(out) | codegen_flushed_above(out)
        if regs:
            self.flushes += 1
            return around_call(indent, line, regs, True, self.slots)
        if code.strip().startswith(INDIRECT):
            if INDIRECT_UNION is not None:
                # Header (m): flush only kept locals some function in this
                # module actually reads as a live-in.
                regs = (self.kept & INDIRECT_UNION) - flushed_above(out) - codegen_flushed_above(out)
            else:
                regs = self.kept - flushed_above(out) - codegen_flushed_above(out)
            self.flushes += bool(regs)
            return around_call(indent, line, regs, True, self.slots) if regs else [line]
        return with_restores(line, out, entry)


def demoted_locals(func, livein_of):
    return set(livein_of.get(func.name, ())) & set(func.locals)


def split_prologue(lines):
    if lines and lines[0].strip() == "REX_FUNC_PROLOGUE();":
        return lines[:1], lines[1:]
    return [], lines


def rewrite_file(path, funcs, livein_of, helpers):
    text = open(path, encoding="utf-8", errors="surrogateescape").read()
    out = []
    flushes = 0
    cur = None
    body = []
    depth = 0
    for line in text.split("\n"):
        m = FUNC.match(line)
        if m:
            if cur is not None:
                # Malformed input: previous function never closed (braces
                # unbalanced). Flush its body instead of silently dropping
                # it; the missing `}` stays missing and visible.
                fr = FuncRewrite(cur, demoted_locals(cur, livein_of), livein_of, helpers)
                head, rest = split_prologue(body)
                out.extend(head + fr.body(rest))
                flushes += fr.flushes
            cur, body = funcs.get(norm_name(m.group(1))), []
            depth = 1  # the `{` on the DEFINE line
            out.append(line)
        elif cur is not None:
            depth += brace_delta(line)
            if depth <= 0:
                # Function close (header (j)): `}` at column 0, or indented
                # for SEH functions. The close line itself is not body.
                fr = FuncRewrite(cur, demoted_locals(cur, livein_of), livein_of, helpers)
                head, rest = split_prologue(body)
                out.extend(head + fr.body(rest))
                out.append(line)
                flushes += fr.flushes
                cur = None
                depth = 0
            else:
                body.append(line)
        else:
            out.append(line)
    new = "\n".join(out)
    if new != text:
        open(path, "w", encoding="utf-8", errors="surrogateescape").write(new)
    return flushes


def rewrite(paths, funcs, livein_of):
    helpers = save_helpers(pathlib.Path(paths[0]).parent) if paths else {}
    return sum(rewrite_file(p, funcs, livein_of, helpers) for p in paths)


if __name__ == "__main__":
    sys.exit(main())
