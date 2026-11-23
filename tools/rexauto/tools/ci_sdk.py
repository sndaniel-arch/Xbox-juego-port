#!/usr/bin/env python3
"""CI helper for the one-click workflow: install / verify the pinned ReXGlue SDK.

    python tools/ci_sdk.py url       -> prints the SDK zip URL for this release
    python tools/ci_sdk.py install   -> downloads + lays it out via gui/setup.py
    python tools/ci_sdk.py verify    -> detect_env() + SDK pin check, exits 1 on failure
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "gui"))


def _emit(ev):
    print("[setup:%s] %s" % (ev.get("level"), ev.get("text")), flush=True)


def cmd_url():
    import setup
    sys.stdout.write(setup.REXGLUE_URL)


def cmd_install():
    import setup
    ok = setup.install_rexglue(_emit)
    sys.exit(0 if ok else 1)


def cmd_verify():
    import rexauto
    import setup
    e = rexauto.detect_env()
    for k in ("rexglue", "sdk", "clang", "clangxx", "vcvars", "python", "jt_repo", "idat"):
        print("%-8s %s" % (k, e.get(k)))
    # (A5-R8-01, ronda 8.) REGRESSION of A5-R7-03: the fatal check used to
    # call sdk_pin_mismatch() unconditionally, but that function never reads
    # REXAUTO_SDK_PIN -- only verify_sdk_pin() and setup.pin_enforced()
    # honour REXAUTO_SDK_PIN=0. With the job env REXAUTO_SDK_PIN=0 (the
    # 0.10.1 repack is not the pinned xdzleo binary) every run died here
    # (run #26). Mirror setup.py:78,244: skip the mismatch call entirely
    # when the pin is disabled.
    bad = rexauto.sdk_pin_mismatch(e) if setup.pin_enforced() else None
    if bad:
        # (A5-R7-03, ronda 7.) BEHAVIOUR CHANGE: a pin mismatch used to
        # be only a ::warning:: that silently disabled the pin for the
        # run (REXAUTO_SDK_PIN=0), so the step called "Verify SDK pin"
        # verified nothing that could fail on pin. A stale SDK_PIN is now
        # a LOUD failure when the pin IS enforced: fix SDK_PIN (or the
        # asset) instead of building against an SDK that is not the
        # pinned one. When the pin is intentionally disabled
        # (REXAUTO_SDK_PIN=0, e.g. the 0.10.1 repack bundle) the check is
        # skipped above and this step only verifies tool presence.
        print("::error::SDK hash differs from SDK_PIN on %s: got %s want %s -- refusing to build against an unpinned SDK; update SDK_PIN (or the asset) instead of disabling the pin"
              % (bad[0], bad[2][:16], bad[1][:16]))
        sys.exit(1)
    missing = [k for k in ("rexglue", "sdk", "clang", "clangxx", "vcvars") if not e.get(k)]
    if missing:
        print("::error::missing tools: %s" % ", ".join(missing))
        sys.exit(1)
    print("toolchain OK")


if __name__ == "__main__":
    {"url": cmd_url, "install": cmd_install, "verify": cmd_verify}[sys.argv[1]]()
