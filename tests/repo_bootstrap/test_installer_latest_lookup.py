"""The one-shot installers must resolve "latest" without depending on the REST API.

Both installers asked ``api.github.com/repos/<repo>/releases/latest`` anonymously
and gave up when it failed. An IP that has spent GitHub's anonymous API rate limit
gets HTTP 403 there -- shared CI runners and NATed networks reach that limit -- and
the macOS installer smoke test of ci.yml run 43840419572 failed exactly so
(``curl: (56) ... 403`` then ``could not detect latest version``). The
``github.com/<repo>/releases/latest`` redirect names the same tag and is not API
rate limited, so it is the fallback; action.yml already resolves "latest" this way.

These tests run the real scripts against stub ``curl``/``uname`` (install.sh) and
stub ``Invoke-RestMethod``/``Invoke-WebRequest`` functions (install.ps1). Every
stubbed download fails on purpose: the asset URL in the failure proves which tag
the installer resolved, and nothing is installed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "install.sh"
INSTALL_PS1 = REPO_ROOT / "install.ps1"

API_URL = "https://api.github.com/repos/n24q02m/skret/releases/latest"
LATEST_URL = "https://github.com/n24q02m/skret/releases/latest"
DOWNLOAD_BASE = "https://github.com/n24q02m/skret/releases/download"

# One stub curl, three behaviours, chosen by files in the stub directory:
# api-tag (the API answers with that tag), redirect-tag (the redirect lands on
# that tag's page). A missing file means that endpoint refuses. Any other URL is
# a download, which always fails and names itself on stderr.
STUB_CURL = f"""#!/bin/sh
stub_dir=$(dirname "$0")
for arg in "$@"; do
  case "$arg" in
    {API_URL})
      [ -f "$stub_dir/api-tag" ] || {{
        echo "curl: (56) The requested URL returned error: 403" >&2; exit 56; }}
      printf '{{\\n  "tag_name": "%s",\\n  "name": "x"\\n}}\\n' "$(cat "$stub_dir/api-tag")"
      exit 0 ;;
    {LATEST_URL})
      [ -f "$stub_dir/redirect-tag" ] || {{
        echo "curl: (6) Could not resolve host: github.com" >&2; exit 6; }}
      printf '%s' "https://github.com/n24q02m/skret/releases/tag/$(cat "$stub_dir/redirect-tag")"
      exit 0 ;;
    https://*)
      echo "STUB-DOWNLOAD $arg" >&2; exit 22 ;;
  esac
done
echo "stub curl: no URL in $*" >&2
exit 2
"""

STUB_UNAME = """#!/bin/sh
case "${1:-}" in
  -m) echo x86_64 ;;
  *) echo Linux ;;
esac
"""


@unittest.skipUnless(shutil.which("sh"), "sh is required to run install.sh")
class InstallShLatestLookupTests(unittest.TestCase):
    def run_installer(self, *, api_tag: str | None, redirect_tag: str | None) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            stub_dir = Path(tmp) / "bin"
            stub_dir.mkdir()
            for name, body in (("curl", STUB_CURL), ("uname", STUB_UNAME)):
                stub = stub_dir / name
                stub.write_text(body, encoding="utf-8", newline="\n")
                stub.chmod(0o755)
            if api_tag is not None:
                (stub_dir / "api-tag").write_text(api_tag, encoding="utf-8")
            if redirect_tag is not None:
                (stub_dir / "redirect-tag").write_text(redirect_tag, encoding="utf-8")
            home = Path(tmp) / "home"
            home.mkdir()
            env = dict(os.environ)
            env["PATH"] = str(stub_dir) + os.pathsep + env.get("PATH", "")
            env["HOME"] = str(home)
            result = subprocess.run(
                [shutil.which("sh"), str(INSTALL_SH), "--user", "--no-completion"],
                capture_output=True,
                encoding="utf-8",
                env=env,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0, "a stubbed download cannot install anything")
        return result.stderr

    def test_api_refusal_falls_back_to_the_latest_redirect(self) -> None:
        stderr = self.run_installer(api_tag=None, redirect_tag="v9.9.9")
        self.assertNotIn("could not detect latest version", stderr)
        self.assertIn(
            f"STUB-DOWNLOAD {DOWNLOAD_BASE}/v9.9.9/skret_9.9.9_linux_amd64.tar.gz", stderr
        )

    def test_api_tag_is_used_when_the_api_answers(self) -> None:
        stderr = self.run_installer(api_tag="v1.2.3", redirect_tag="v9.9.9")
        self.assertIn(
            f"STUB-DOWNLOAD {DOWNLOAD_BASE}/v1.2.3/skret_1.2.3_linux_amd64.tar.gz", stderr
        )

    def test_both_lookups_failing_still_stops_before_any_download(self) -> None:
        stderr = self.run_installer(api_tag=None, redirect_tag=None)
        self.assertIn("could not detect latest version", stderr)
        self.assertNotIn("STUB-DOWNLOAD", stderr)


# Functions win over cmdlets in PowerShell command lookup, so these replace the two
# web cmdlets for the installer run. The redirect stub returns the PowerShell 7
# response shape: BaseResponse is an HttpResponseMessage whose RequestMessage
# carries the final URI after redirects (Windows PowerShell 5.1 exposes it as
# BaseResponse.ResponseUri instead).
PS_STUBS = """
function global:Invoke-RestMethod {
    param([Parameter(Position = 0)][string]$Uri)
    if ($env:STUB_API_TAG) { return [pscustomobject]@{ tag_name = $env:STUB_API_TAG } }
    throw "Response status code does not indicate success: 403 (rate limit exceeded)."
}
function global:Invoke-WebRequest {
    param([Parameter(Position = 0)][string]$Uri, [string]$Method, [string]$OutFile,
          [switch]$UseBasicParsing)
    if ($Uri -eq '%(latest)s') {
        if (-not $env:STUB_REDIRECT_TAG) { throw "No such host is known. (github.com:443)" }
        $final = [uri]('https://github.com/n24q02m/skret/releases/tag/' + $env:STUB_REDIRECT_TAG)
        return [pscustomobject]@{
            BaseResponse = [pscustomobject]@{
                RequestMessage = [pscustomobject]@{ RequestUri = $final }
            }
        }
    }
    throw "STUB-DOWNLOAD $Uri"
}
""" % {"latest": LATEST_URL}


@unittest.skipUnless(
    os.name == "nt" and shutil.which("pwsh"), "install.ps1 runs on Windows under pwsh"
)
class InstallPs1LatestLookupTests(unittest.TestCase):
    def run_installer(self, *, api_tag: str | None, redirect_tag: str | None) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env.pop("STUB_API_TAG", None)
            env.pop("STUB_REDIRECT_TAG", None)
            if api_tag is not None:
                env["STUB_API_TAG"] = api_tag
            if redirect_tag is not None:
                env["STUB_REDIRECT_TAG"] = redirect_tag
            script = PS_STUBS + f"& '{INSTALL_PS1}' -Prefix '{Path(tmp) / 'prefix'}'"
            result = subprocess.run(
                [shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                encoding="utf-8",
                env=env,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0, "a stubbed download cannot install anything")
        return result.stdout + result.stderr

    def test_api_refusal_falls_back_to_the_latest_redirect(self) -> None:
        output = self.run_installer(api_tag=None, redirect_tag="v9.9.9")
        self.assertNotIn("could not detect latest version", output)
        self.assertIn(
            f"STUB-DOWNLOAD {DOWNLOAD_BASE}/v9.9.9/skret_9.9.9_windows_amd64.zip", output
        )

    def test_api_tag_is_used_when_the_api_answers(self) -> None:
        output = self.run_installer(api_tag="v1.2.3", redirect_tag="v9.9.9")
        self.assertIn(f"STUB-DOWNLOAD {DOWNLOAD_BASE}/v1.2.3/skret_1.2.3_windows_amd64.zip", output)

    def test_both_lookups_failing_still_stops_before_any_download(self) -> None:
        output = self.run_installer(api_tag=None, redirect_tag=None)
        self.assertIn("could not detect latest version", output)
        self.assertNotIn("STUB-DOWNLOAD", output)


if __name__ == "__main__":
    unittest.main()
