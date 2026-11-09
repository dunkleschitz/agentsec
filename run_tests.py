#!/usr/bin/env python3
"""Run every tool's unittest suite and fail if any suite fails or runs zero tests.

Usage: python3 run_tests.py [tool ...]
Each suite runs in its own subprocess (with the tool folder as working directory)
so module names and sys.path tweaks never leak between tools.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(ROOT, "tools")


def discover_args(tool_dir):
    tests = os.path.join(tool_dir, "tests")
    start = "tests" if os.path.isdir(tests) else "."
    return ["-m", "unittest", "discover", "-s", start, "-t", start, "-p", "test_*.py", "-v"]


def run_suite(name):
    tool_dir = os.path.join(TOOLS_DIR, name)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable] + discover_args(tool_dir), cwd=tool_dir,
                          capture_output=True, text=True, env=env)
    out = proc.stdout + proc.stderr
    m = re.search(r"^Ran (\d+) tests? in", out, re.M)
    count = int(m.group(1)) if m else 0
    ok = proc.returncode == 0 and count > 0
    return ok, count, out


def run_pkg_suite():
    """Run tests/ at the repo root (unified CLI, packaging)."""
    tests = os.path.join(ROOT, "tests")
    if not os.path.isdir(tests):
        return True, 0, "no tests/ directory\n"
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    # Repo root must be on PYTHONPATH so `import agentsec` works without install.
    env["PYTHONPATH"] = ROOT + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover",
         "-s", tests, "-t", tests, "-p", "test_*.py", "-v"],
        cwd=ROOT, capture_output=True, text=True, env=env,
    )
    out = proc.stdout + proc.stderr
    m = re.search(r"^Ran (\d+) tests? in", out, re.M)
    count = int(m.group(1)) if m else 0
    ok = proc.returncode == 0 and count > 0
    return ok, count, out


def main(argv):
    names = argv or sorted(d for d in os.listdir(TOOLS_DIR)
                           if os.path.isdir(os.path.join(TOOLS_DIR, d)))
    total, failed = 0, []
    print("%-12s %6s  %s" % ("suite", "tests", "result"))
    for name in names:
        ok, count, out = run_suite(name)
        total += count
        status = "PASS" if ok else ("FAIL (zero tests ran)" if count == 0 else "FAIL")
        print("%-12s %6d  %s" % (name, count, status))
        if not ok:
            failed.append(name)
            sys.stderr.write("\n----- %s output -----\n%s\n" % (name, out))
    # Package / CLI tests run when the full suite is requested.
    if not argv:
        ok, count, out = run_pkg_suite()
        total += count
        status = "PASS" if ok else ("FAIL (zero tests ran)" if count == 0 else "FAIL")
        print("%-12s %6d  %s" % ("agentsec", count, status))
        if not ok:
            failed.append("agentsec")
            sys.stderr.write("\n----- agentsec (tests/) output -----\n%s\n" % out)
    print("-" * 32)
    print("%-12s %6d  %s" % ("TOTAL", total,
                             "PASS" if not failed else "FAIL: " + ", ".join(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
