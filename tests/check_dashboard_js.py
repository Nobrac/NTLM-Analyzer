"""Syntax check for the JavaScript embedded in the collector's pages.

The dashboard and the login page are strings inside ntlm-collector.py, so no
editor or linter ever looks at their scripts. One stray bracket there leaves
the dashboard blank. This pulls every <script> block out and lets Node parse
it. Needs Node.js (preinstalled on GitHub's runners):

    python tests/check_dashboard_js.py
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = os.path.join(HERE, os.pardir, "ntlm-collector.py")


def main():
    with open(COLLECTOR, encoding="utf-8") as f:
        src = f.read()
    pages = re.findall(r'^(\w+_HTML) = r?"""(.*?)"""', src, re.S | re.M)
    if not pages:
        sys.exit("no pages found in ntlm-collector.py")
    failed = 0
    checked = 0
    for name, html in pages:
        for i, script in enumerate(re.findall(r"<script[^>]*>(.*?)</script>", html, re.S)):
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as t:
                t.write(script)
                path = t.name
            try:
                r = subprocess.run(["node", "--check", path], capture_output=True, text=True)
            finally:
                os.unlink(path)
            checked += 1
            if r.returncode:
                failed += 1
                print("FAIL %s script %d:\n%s" % (name, i + 1, r.stderr))
            else:
                print("ok   %s script %d (%d lines)" % (name, i + 1, script.count("\n") + 1))
    if not checked:
        sys.exit("no <script> blocks found")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
