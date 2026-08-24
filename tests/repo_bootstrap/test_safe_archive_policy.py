import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "install.sh"
INSTALL_PS1 = REPO_ROOT / "install.ps1"
VERSION = "v1.0.0"


class SafeArchiveFixtureBuilder:
    @staticmethod
    def create_tar_archive(
        entries: list[tuple[str, bytes, int | None]],
        symlinks: list[tuple[str, str]] | None = None,
        hardlinks: list[tuple[str, str]] | None = None,
        raw_headers: list[tarfile.TarInfo] | None = None,
    ) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as archive:
            for name, content, mode in entries or []:
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                info.mtime = 1700000000
                info.type = tarfile.REGTYPE
                info.mode = mode if mode is not None else 0o644
                archive.addfile(info, io.BytesIO(content))
            for name, target in symlinks or []:
                info = tarfile.TarInfo(name=name)
                info.type = tarfile.SYMTYPE
                info.linkname = target
                info.mtime = 1700000000
                archive.addfile(info)
            for name, target in hardlinks or []:
                info = tarfile.TarInfo(name=name)
                info.type = tarfile.LNKTYPE
                info.linkname = target
                info.mtime = 1700000000
                archive.addfile(info)
            for info in raw_headers or []:
                archive.addfile(info)
        return buf.getvalue()

    @staticmethod
    def create_tar_zero_entry(name: str, size: int) -> bytes:
        class ZeroReader(io.RawIOBase):
            def __init__(self, remaining: int) -> None:
                self.remaining = remaining

            def read(self, requested: int = -1) -> bytes:
                if self.remaining <= 0:
                    return b""
                if requested < 0 or requested > self.remaining:
                    requested = self.remaining
                self.remaining -= requested
                return b"\0" * requested

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as archive:
            info = tarfile.TarInfo(name=name)
            info.size = size
            info.mode = 0o755
            info.mtime = 1700000000
            archive.addfile(info, ZeroReader(size))
        return buf.getvalue()

    @staticmethod
    def create_tar_zero_entries(entries: list[tuple[str, int]]) -> bytes:
        class ZeroReader(io.RawIOBase):
            def __init__(self, remaining: int) -> None:
                self.remaining = remaining

            def read(self, requested: int = -1) -> bytes:
                if self.remaining <= 0:
                    return b""
                if requested < 0 or requested > self.remaining:
                    requested = self.remaining
                self.remaining -= requested
                return b"\0" * requested

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as archive:
            for name, size in entries:
                info = tarfile.TarInfo(name=name)
                info.size = size
                info.mode = 0o644
                info.mtime = 1700000000
                archive.addfile(info, ZeroReader(size))
        return buf.getvalue()

    @staticmethod
    def create_zip_archive(
        entries: list[tuple[str, bytes, int | None]],
        symlinks: list[tuple[str, str]] | None = None,
        raw_entries: list[tuple[zipfile.ZipInfo, bytes]] | None = None,
    ) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content, mode in entries or []:
                zinfo = zipfile.ZipInfo(filename=name)
                zinfo.date_time = (2026, 8, 24, 0, 0, 0)
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                file_mode = mode if mode is not None else 0o644
                zinfo.external_attr = (stat.S_IFREG | file_mode) << 16
                archive.writestr(zinfo, content)
            for name, target in symlinks or []:
                zinfo = zipfile.ZipInfo(filename=name)
                zinfo.date_time = (2026, 8, 24, 0, 0, 0)
                zinfo.create_system = 3
                zinfo.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(zinfo, target.encode("utf-8"))
            for zinfo, payload in raw_entries or []:
                archive.writestr(zinfo, payload)
        return buf.getvalue()

    @staticmethod
    def create_zip_zero_entry(name: str, size: int) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            zinfo = zipfile.ZipInfo(filename=name)
            zinfo.date_time = (2026, 8, 24, 0, 0, 0)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.external_attr = (stat.S_IFREG | 0o755) << 16
            with archive.open(zinfo, mode="w") as stream:
                remaining = size
                chunk = b"\0" * (1024 * 1024)
                while remaining:
                    payload = chunk if remaining >= len(chunk) else chunk[:remaining]
                    stream.write(payload)
                    remaining -= len(payload)
        return buf.getvalue()

    @staticmethod
    def create_zip_zero_entries(entries: list[tuple[str, int]]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, size in entries:
                zinfo = zipfile.ZipInfo(filename=name)
                zinfo.date_time = (2026, 8, 24, 0, 0, 0)
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                zinfo.external_attr = (stat.S_IFREG | 0o644) << 16
                with archive.open(zinfo, mode="w") as stream:
                    remaining = size
                    chunk = b"\0" * (1024 * 1024)
                    while remaining:
                        payload = chunk if remaining >= len(chunk) else chunk[:remaining]
                        stream.write(payload)
                        remaining -= len(payload)
        return buf.getvalue()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_snapshot(path: Path) -> tuple:
    if path.is_symlink():
        return ("symlink", os.readlink(path))
    if path.is_file():
        return ("file", path.read_bytes())
    if not path.exists():
        return ("absent",)
    if path.is_dir():
        return (
            "directory",
            tuple((child.name, tree_snapshot(child)) for child in sorted(path.iterdir(), key=lambda item: item.name)),
        )
    return ("other", path.stat().st_mode)


def make_unix_binary(fails: bool = False) -> bytes:
    if fails:
        return b"#!/bin/sh\nexit 23\n"
    return b"#!/bin/sh\nprintf '%s\\n' 'skret 1.0.0'\n"


def make_windows_entry(content: bytes | None = None) -> bytes:
    return Path(sys.executable).read_bytes() if content is None else content


def make_windows_failing_entry() -> bytes:
    return b"not-a-valid-windows-executable"


class SafeArchiveScriptContractTests(unittest.TestCase):
    def test_installer_scripts_keep_safe_archive_contract_markers(self) -> None:
        self.assertTrue(INSTALL_SH.is_file())
        self.assertTrue(INSTALL_PS1.is_file())
        sh_text = INSTALL_SH.read_text(encoding="utf-8")
        ps1_text = INSTALL_PS1.read_text(encoding="utf-8")
        for marker in ("SAFE-ARCHIVE-V1", "MAX_ENTRIES=16", "MAX_TOTAL_BYTES=104857600", "MAX_ENTRY_BYTES=104857600", "MAX_RATIO=20"):
            self.assertIn(marker, sh_text)
        for marker in ("SAFE-ARCHIVE-V1", "$MaxEntries    = 16", "$MaxTotalBytes = 104857600", "$MaxEntryBytes = 104857600", "$MaxRatio      = 20"):
            self.assertIn(marker, ps1_text)
        self.assertIn("Protect-OwnerOnlyDirectory", ps1_text)
        self.assertIn("Assert-NoReparsePointInAncestorPath", ps1_text)
        self.assertIn("SKRET_INSECURE_SKIP_VERIFY", sh_text)
        self.assertIn("SKRET_INSECURE_SKIP_VERIFY", ps1_text)


class UnixInstallerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sh_bin = shutil.which("sh") or shutil.which("bash")

    def require_shell(self) -> str:
        if not self.sh_bin:
            self.skipTest("sh/bash runtime not available")
        return self.sh_bin

    def run_installer(
        self,
        archive: bytes,
        *,
        checksum_rows: str | None = None,
        skip_verify: bool = False,
        cosign_present: bool = True,
        cosign_status: int = 0,
        bundle_present: bool = True,
        prior: bytes | None = None,
        prefix_symlink: bool = False,
        fail_copy: bool = False,
        fail_move: bool = False,
        outside_payload: bytes = b"outside sentinel",
    ) -> dict:
        shell = self.require_shell()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            release = root / "release"
            release.mkdir()
            prefix = root / "prefix"
            outside = root / "outside"
            outside.mkdir()
            (outside / "sentinel").write_bytes(outside_payload)
            if prefix_symlink:
                prefix.symlink_to(outside, target_is_directory=True)
            elif prior is not None:
                prefix.mkdir()
                (prefix / "skret").write_bytes(prior)
                (prefix / "skret").chmod(0o755)

            asset = "skret_1.0.0_linux_amd64.tar.gz"
            (release / asset).write_bytes(archive)
            checksum = sha256_bytes(archive)
            if checksum_rows is None:
                checksum_rows = f"{checksum}  {asset}\n"
            (release / "checksums.txt").write_text(checksum_rows, encoding="utf-8")
            if bundle_present:
                (release / "checksums.txt.bundle").write_bytes(b"local bundle")

            stubs = root / "stubs"
            stubs.mkdir()
            (stubs / "curl").write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "url=''\nout=''\n"
                "while [ $# -gt 0 ]; do\n"
                "  case \"$1\" in\n"
                "    -o) out=$2; shift 2 ;;\n"
                "    http://*|https://*) url=$1; shift ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "case \"$url\" in\n"
                "  *checksums.txt.bundle) src='release/checksums.txt.bundle' ;;\n"
                "  *checksums.txt) src='release/checksums.txt' ;;\n"
                "  *) src='release/skret_1.0.0_linux_amd64.tar.gz' ;;\n"
                "esac\n"
                "cat \"$src\" > \"$out\"\n",
                encoding="utf-8",
            )
            (stubs / "uname").write_text(
                "#!/bin/sh\ncase \"${1:-}\" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 1 ;; esac\n",
                encoding="utf-8",
            )
            if cosign_present:
                (stubs / "cosign").write_text(
                    "#!/bin/sh\nexit \"${STUB_COSIGN_STATUS:-0}\"\n",
                    encoding="utf-8",
                )
            if fail_copy:
                (stubs / "cp").write_text(
                    "#!/bin/sh\n"
                    "if [ \"${STUB_FAIL_CP:-0}\" = 1 ]; then exit 37; fi\n"
                    "exec /usr/bin/cp \"$@\"\n",
                    encoding="utf-8",
                )
            if fail_move:
                (stubs / "mv").write_text(
                    "#!/bin/sh\n"
                    "if [ \"${STUB_FAIL_MV:-0}\" = 1 ]; then exit 38; fi\n"
                    "exec /usr/bin/mv \"$@\"\n",
                    encoding="utf-8",
                )
            for stub in stubs.iterdir():
                stub.chmod(0o755)

            env = os.environ.copy()
            env["STUB_COSIGN_STATUS"] = str(cosign_status)
            if skip_verify:
                env["SKRET_INSECURE_SKIP_VERIFY"] = "1"
            else:
                env.pop("SKRET_INSECURE_SKIP_VERIFY", None)
            if fail_copy:
                env["STUB_FAIL_CP"] = "1"
            if fail_move:
                env["STUB_FAIL_MV"] = "1"

            shutil.copy2(INSTALL_SH, root / "install.sh")
            command = [
                shell,
                "-c",
                (
                    'PATH="$PWD/stubs:/usr/bin:/bin"; export PATH; '
                    'exec sh install.sh --version=v1.0.0 --prefix=prefix '
                    "--no-completion --quiet"
                ),
            ]
            result = subprocess.run(
                command,
                cwd=root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            destination = prefix / "skret"
            residues = tuple(sorted(item.name for item in prefix.glob(".skret.*"))) if prefix.exists() else ()
            return {
                "result": result,
                "prefix": tree_snapshot(prefix),
                "outside": tree_snapshot(outside),
                "destination": tree_snapshot(destination),
                "residues": residues,
                "prefix_exists": prefix.exists() or prefix.is_symlink(),
            }

    def benign_archive(self, *, fails: bool = False) -> bytes:
        return SafeArchiveFixtureBuilder.create_tar_archive(
            [
                ("skret", make_unix_binary(fails), 0o755),
                ("README.md", b"# skret\n", 0o644),
                ("LICENSE", b"Apache-2.0\n", 0o644),
            ]
        )

    def assert_rejected_without_target_change(self, archive: bytes, **kwargs: object) -> None:
        before_outside = ("directory", (("sentinel", ("file", b"outside sentinel")),))
        outcome = self.run_installer(archive, skip_verify=True, **kwargs)
        self.assertNotEqual(outcome["result"].returncode, 0, outcome["result"].stdout + outcome["result"].stderr)
        self.assertEqual(outcome["outside"], before_outside)
        self.assertEqual(outcome["destination"], ("absent",))
        self.assertEqual(outcome["residues"], ())

    def test_benign_archive_executes_full_unix_installer(self) -> None:
        outcome = self.run_installer(self.benign_archive(), skip_verify=True)
        self.assertEqual(outcome["result"].returncode, 0, outcome["result"].stdout + outcome["result"].stderr)
        self.assertEqual(outcome["destination"], ("file", make_unix_binary(False)))
        self.assertEqual(outcome["residues"], ())

    def test_successful_upgrade_replaces_regular_prior_binary(self) -> None:
        prior = b"PRIOR-UNIX-BINARY"
        outcome = self.run_installer(
            self.benign_archive(),
            skip_verify=True,
            prior=prior,
        )
        self.assertEqual(
            outcome["result"].returncode,
            0,
            outcome["result"].stdout + outcome["result"].stderr,
        )
        self.assertEqual(outcome["destination"], ("file", make_unix_binary(False)))
        self.assertEqual(outcome["residues"], ())


    def test_signature_tool_and_bundle_are_required_before_extraction(self) -> None:
        missing_cosign = self.run_installer(self.benign_archive(), cosign_present=False)
        self.assertNotEqual(missing_cosign["result"].returncode, 0)
        self.assertEqual(missing_cosign["destination"], ("absent",))
        self.assertEqual(missing_cosign["residues"], ())

        missing_bundle = self.run_installer(
            self.benign_archive(),
            cosign_present=True,
            bundle_present=False,
        )
        self.assertNotEqual(missing_bundle["result"].returncode, 0)
        self.assertEqual(missing_bundle["destination"], ("absent",))
        self.assertEqual(missing_bundle["residues"], ())

    def test_checksum_duplicates_and_malformed_rows_fail_closed(self) -> None:
        archive = self.benign_archive()
        digest = sha256_bytes(archive)
        duplicate_rows = f"{digest}  skret_1.0.0_linux_amd64.tar.gz\n{digest}  skret_1.0.0_linux_amd64.tar.gz\n"
        malformed_rows = f"{digest}  skret_1.0.0_linux_amd64.tar.gz\nnot-a-checksum row\n"
        for rows in (duplicate_rows, malformed_rows):
            outcome = self.run_installer(archive, checksum_rows=rows, skip_verify=True)
            self.assertNotEqual(outcome["result"].returncode, 0)
            self.assertEqual(outcome["destination"], ("absent",))
            self.assertEqual(outcome["residues"], ())

    def test_traversal_absolute_backslash_ads_unexpected_and_missing_binary_fail(self) -> None:
        cases = [
            SafeArchiveFixtureBuilder.create_tar_archive(
                [("../outside/payload", b"evil", 0o644), ("skret", make_unix_binary(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_tar_archive(
                [("/tmp/payload", b"evil", 0o644), ("skret", make_unix_binary(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_tar_archive(
                [("..\\outside\\payload", b"evil", 0o644), ("skret", make_unix_binary(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_tar_archive(
                [("skret:payload", b"evil", 0o644), ("skret", make_unix_binary(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_tar_archive(
                [("unexpected.bin", b"evil", 0o644), ("skret", make_unix_binary(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_tar_archive(
                [("README.md", b"docs", 0o644), ("LICENSE", b"license", 0o644)]
            ),
        ]
        for archive in cases:
            with self.subTest(case=len(archive)):
                self.assert_rejected_without_target_change(archive)

    def test_duplicate_case_collision_symlink_hardlink_and_nonregular_fail(self) -> None:
        duplicate = SafeArchiveFixtureBuilder.create_tar_archive(
            [("skret", make_unix_binary(), 0o755), ("skret", b"second", 0o755)]
        )
        symlink = SafeArchiveFixtureBuilder.create_tar_archive(
            [("skret", make_unix_binary(), 0o755)], symlinks=[("README.md", "../outside/payload")]
        )
        hardlink = SafeArchiveFixtureBuilder.create_tar_archive(
            [("skret", make_unix_binary(), 0o755)], hardlinks=[("README.md", "skret")]
        )
        directory = tarfile.TarInfo(name="README.md")
        directory.type = tarfile.DIRTYPE
        directory.mtime = 1700000000
        nonregular = SafeArchiveFixtureBuilder.create_tar_archive(
            [("skret", make_unix_binary(), 0o755)], raw_headers=[directory]
        )
        for archive in (duplicate, symlink, hardlink, nonregular):
            with self.subTest(case=len(archive)):
                self.assert_rejected_without_target_change(archive)

    def test_entry_count_entry_size_total_size_and_ratio_bombs_fail(self) -> None:
        count_bomb = SafeArchiveFixtureBuilder.create_tar_archive(
            [("skret", make_unix_binary(), 0o755)] * 17
        )
        entry_bomb = SafeArchiveFixtureBuilder.create_tar_zero_entry("skret", 104857601)
        total_bomb = SafeArchiveFixtureBuilder.create_tar_zero_entries(
            [("skret", 52428801), ("README.md", 52428801)]
        )
        ratio_bomb = SafeArchiveFixtureBuilder.create_tar_zero_entry("skret", 1024 * 1024)
        for archive in (count_bomb, entry_bomb, total_bomb, ratio_bomb):
            with self.subTest(case=len(archive)):
                self.assert_rejected_without_target_change(archive)

    def test_upgrade_smoke_failure_restores_byte_identical_prior_binary(self) -> None:
        prior = b"PRIOR-BINARY-BYTE-FOR-BYTE"
        outcome = self.run_installer(self.benign_archive(fails=True), skip_verify=True, prior=prior)
        self.assertNotEqual(outcome["result"].returncode, 0)
        self.assertEqual(outcome["destination"], ("file", prior))
        self.assertEqual(outcome["residues"], ())

    def test_copy_and_swap_failures_restore_prior_without_residue(self) -> None:
        prior = b"PRIOR-COPY-SWAP-BINARY"
        for failure in ("copy", "move"):
            with self.subTest(failure=failure):
                outcome = self.run_installer(
                    self.benign_archive(),
                    skip_verify=True,
                    prior=prior,
                    fail_copy=failure == "copy",
                    fail_move=failure == "move",
                )
                self.assertNotEqual(outcome["result"].returncode, 0)
                self.assertEqual(outcome["destination"], ("file", prior))
                self.assertEqual(outcome["residues"], ())

    def test_first_install_smoke_failure_leaves_target_absent(self) -> None:
        outcome = self.run_installer(self.benign_archive(fails=True), skip_verify=True)
        self.assertNotEqual(outcome["result"].returncode, 0)
        self.assertEqual(outcome["destination"], ("absent",))
        self.assertEqual(outcome["residues"], ())

    def test_unix_destination_symlink_ancestor_is_rejected_without_outside_write(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlink support unavailable")
        outcome = self.run_installer(self.benign_archive(), skip_verify=True, prefix_symlink=True)
        self.assertNotEqual(outcome["result"].returncode, 0)
        self.assertEqual(outcome["outside"], ("directory", (("sentinel", ("file", b"outside sentinel")),)))
        self.assertEqual(outcome["destination"], ("absent",))


class WindowsInstallerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.powershell = shutil.which("pwsh") or shutil.which("powershell")

    def require_powershell(self) -> str:
        if os.name != "nt" or not self.powershell:
            self.skipTest("Windows PowerShell runtime not available")
        return self.powershell

    def run_installer(
        self,
        archive: bytes,
        *,
        checksum_rows: str | None = None,
        skip_verify: bool = False,
        cosign_present: bool = True,
        cosign_status: int = 0,
        bundle_present: bool = True,
        prior: bytes | None = None,
        prefix_symlink: bool = False,
    ) -> dict:
        powershell = self.require_powershell()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            release = root / "release"
            release.mkdir()
            prefix = root / "prefix"
            outside = root / "outside"
            outside.mkdir()
            (outside / "sentinel").write_bytes(b"outside sentinel")
            if prefix_symlink:
                try:
                    prefix.symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"directory symlink unavailable: {exc}")
            elif prior is not None:
                prefix.mkdir()
                (prefix / "skret.exe").write_bytes(prior)

            asset = "skret_1.0.0_windows_amd64.zip"
            (release / asset).write_bytes(archive)
            digest = sha256_bytes(archive)
            if checksum_rows is None:
                checksum_rows = f"{digest}  {asset}\n"
            (release / "checksums.txt").write_text(checksum_rows, encoding="utf-8")
            if bundle_present:
                (release / "checksums.txt.bundle").write_bytes(b"local bundle")

            def ps_literal(value: Path | str) -> str:
                return "'" + str(value).replace("'", "''") + "'"

            wrapper = root / "run-installer.ps1"
            cosign_function = "" if not cosign_present else (
                "function cosign { $global:LASTEXITCODE = [int]$env:STUB_COSIGN_STATUS }\n"
            )
            wrapper.write_text(
                "$ErrorActionPreference = 'Stop'\n"
                "$root = (Get-Location).Path\n"
                f"$release = {ps_literal(release)}\n"
                "$oldPath = [Environment]::GetEnvironmentVariable('Path', 'User')\n"
                "function Invoke-WebRequest {\n"
                "  param([string]$Uri, [string]$OutFile)\n"
                "  if ($Uri -like '*checksums.txt.bundle') { $source = Join-Path $release 'checksums.txt.bundle' }\n"
                "  elseif ($Uri -like '*checksums.txt') { $source = Join-Path $release 'checksums.txt' }\n"
                f"  else {{ $source = Join-Path $release {ps_literal(asset)} }}\n"
                "  Copy-Item -LiteralPath $source -Destination $OutFile -Force\n"
                "}\n"
                + cosign_function
                + "try {\n"
                f"  & {ps_literal(INSTALL_PS1)} -Version 'v1.0.0' -Prefix {ps_literal(prefix)} -Quiet\n"
                "} finally {\n"
                "  [Environment]::SetEnvironmentVariable('Path', $oldPath, 'User')\n"
                "}\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["STUB_COSIGN_STATUS"] = str(cosign_status)
            if skip_verify:
                env["SKRET_INSECURE_SKIP_VERIFY"] = "1"
            else:
                env.pop("SKRET_INSECURE_SKIP_VERIFY", None)
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(wrapper)],
                cwd=root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            destination = prefix / "skret.exe"
            residues = tuple(sorted(item.name for item in prefix.glob(".skret.*"))) if prefix.exists() else ()
            return {
                "result": result,
                "prefix": tree_snapshot(prefix),
                "outside": tree_snapshot(outside),
                "destination": tree_snapshot(destination),
                "residues": residues,
            }

    def benign_archive(self, *, binary: bytes | None = None) -> bytes:
        return SafeArchiveFixtureBuilder.create_zip_archive(
            [
                ("skret.exe", make_windows_entry(binary), 0o755),
                ("README.md", b"# skret\r\n", 0o644),
                ("LICENSE", b"Apache-2.0\r\n", 0o644),
            ]
        )

    def assert_rejected_without_target_change(self, archive: bytes, **kwargs: object) -> None:
        outcome = self.run_installer(archive, skip_verify=True, **kwargs)
        self.assertNotEqual(outcome["result"].returncode, 0, outcome["result"].stdout + outcome["result"].stderr)
        self.assertEqual(outcome["outside"], ("directory", (("sentinel", ("file", b"outside sentinel")),)))
        self.assertEqual(outcome["destination"], ("absent",))
        self.assertEqual(outcome["residues"], ())

    def test_benign_archive_executes_full_powershell_installer(self) -> None:
        outcome = self.run_installer(self.benign_archive(), skip_verify=True)
        self.assertEqual(outcome["result"].returncode, 0, outcome["result"].stdout + outcome["result"].stderr)
        self.assertEqual(outcome["destination"], ("file", make_windows_entry()))
        self.assertEqual(outcome["residues"], ())

    def test_signature_tool_and_checksum_material_fail_closed(self) -> None:
        missing_cosign = self.run_installer(self.benign_archive(), cosign_present=False)
        self.assertNotEqual(missing_cosign["result"].returncode, 0)
        self.assertEqual(missing_cosign["destination"], ("absent",))
        missing_bundle = self.run_installer(self.benign_archive(), bundle_present=False)
        self.assertNotEqual(missing_bundle["result"].returncode, 0)
        self.assertEqual(missing_bundle["destination"], ("absent",))

    def test_successful_upgrade_replaces_regular_prior_binary(self) -> None:
        prior = b"PRIOR-WINDOWS-BINARY"
        outcome = self.run_installer(
            self.benign_archive(),
            skip_verify=True,
            prior=prior,
        )
        self.assertEqual(
            outcome["result"].returncode,
            0,
            outcome["result"].stdout + outcome["result"].stderr,
        )
        self.assertEqual(outcome["destination"], ("file", make_windows_entry()))
        self.assertEqual(outcome["residues"], ())


    def test_checksum_duplicates_and_malformed_rows_fail_closed(self) -> None:
        archive = self.benign_archive()
        digest = sha256_bytes(archive)
        asset = "skret_1.0.0_windows_amd64.zip"
        rows = (f"{digest}  {asset}\n{digest}  {asset}\n", f"{digest}  {asset}\nnot-a-checksum row\n")
        for checksum_rows in rows:
            outcome = self.run_installer(archive, checksum_rows=checksum_rows, skip_verify=True)
            self.assertNotEqual(outcome["result"].returncode, 0)
            self.assertEqual(outcome["destination"], ("absent",))

    def test_traversal_absolute_backslash_ads_unexpected_and_missing_binary_fail(self) -> None:
        cases = [
            SafeArchiveFixtureBuilder.create_zip_archive(
                [("..\\outside\\payload", b"evil", 0o644), ("skret.exe", make_windows_entry(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_zip_archive(
                [("C:/Windows/System32/payload.dll", b"evil", 0o644), ("skret.exe", make_windows_entry(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_zip_archive(
                [("\\\\server\\share\\payload.dll", b"evil", 0o644), ("skret.exe", make_windows_entry(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_zip_archive(
                [("skret.exe:Zone.Identifier", b"evil", 0o644), ("skret.exe", make_windows_entry(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_zip_archive(
                [("unexpected.dll", b"evil", 0o644), ("skret.exe", make_windows_entry(), 0o755)]
            ),
            SafeArchiveFixtureBuilder.create_zip_archive(
                [("README.md", b"docs", 0o644), ("LICENSE", b"license", 0o644)]
            ),
        ]
        for archive in cases:
            with self.subTest(case=len(archive)):
                self.assert_rejected_without_target_change(archive)

    def test_duplicate_case_collision_symlink_and_nonregular_fail(self) -> None:
        zi1 = zipfile.ZipInfo(filename="SKRET.EXE")
        zi1.compress_type = zipfile.ZIP_DEFLATED
        zi1.external_attr = (stat.S_IFREG | 0o755) << 16
        zi2 = zipfile.ZipInfo(filename="skret.exe")
        zi2.compress_type = zipfile.ZIP_DEFLATED
        zi2.external_attr = (stat.S_IFREG | 0o755) << 16
        duplicate = SafeArchiveFixtureBuilder.create_zip_archive([], raw_entries=[(zi1, b"one"), (zi2, b"two")])
        symlink = SafeArchiveFixtureBuilder.create_zip_archive(
            [("skret.exe", make_windows_entry(), 0o755)], symlinks=[("README.md", "target.dll")]
        )
        directory = zipfile.ZipInfo(filename="README.md")
        directory.external_attr = (stat.S_IFDIR | 0o755) << 16
        nonregular = SafeArchiveFixtureBuilder.create_zip_archive(
            [("skret.exe", make_windows_entry(), 0o755)], raw_entries=[(directory, b"")]
        )
        for archive in (duplicate, symlink, nonregular):
            with self.subTest(case=len(archive)):
                self.assert_rejected_without_target_change(archive)

    def test_entry_count_entry_size_total_size_and_ratio_bombs_fail(self) -> None:
        duplicate_entries = []
        for _ in range(17):
            zinfo = zipfile.ZipInfo(filename="skret.exe")
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.external_attr = (stat.S_IFREG | 0o755) << 16
            duplicate_entries.append((zinfo, b"duplicate"))
        count_bomb = SafeArchiveFixtureBuilder.create_zip_archive([], raw_entries=duplicate_entries)
        entry_bomb = SafeArchiveFixtureBuilder.create_zip_zero_entry("skret.exe", 104857601)
        total_bomb = SafeArchiveFixtureBuilder.create_zip_zero_entries(
            [("skret.exe", 52428801), ("README.md", 52428801)]
        )
        ratio_bomb = SafeArchiveFixtureBuilder.create_zip_zero_entry("skret.exe", 1024 * 1024)
        for archive in (count_bomb, entry_bomb, total_bomb, ratio_bomb):
            with self.subTest(case=len(archive)):
                self.assert_rejected_without_target_change(archive)

    def test_upgrade_smoke_failure_restores_byte_identical_prior_binary(self) -> None:
        failing = make_windows_failing_entry()
        if failing is None:
            self.skipTest("cmd.exe unavailable for a failing executable fixture")
        prior = b"PRIOR-WINDOWS-BINARY-BYTE-FOR-BYTE"
        outcome = self.run_installer(self.benign_archive(binary=failing), skip_verify=True, prior=prior)
        self.assertNotEqual(outcome["result"].returncode, 0)
        self.assertEqual(outcome["destination"], ("file", prior))
        self.assertEqual(outcome["residues"], ())

    def test_first_install_smoke_failure_leaves_target_absent(self) -> None:
        failing = make_windows_failing_entry()
        if failing is None:
            self.skipTest("cmd.exe unavailable for a failing executable fixture")
        outcome = self.run_installer(self.benign_archive(binary=failing), skip_verify=True)
        self.assertNotEqual(outcome["result"].returncode, 0)
        self.assertEqual(outcome["destination"], ("absent",))
        self.assertEqual(outcome["residues"], ())

    def test_destination_reparse_ancestor_is_rejected_without_outside_write(self) -> None:
        outcome = self.run_installer(self.benign_archive(), skip_verify=True, prefix_symlink=True)
        self.assertNotEqual(outcome["result"].returncode, 0)
        self.assertEqual(outcome["outside"], ("directory", (("sentinel", ("file", b"outside sentinel")),)))
        self.assertEqual(outcome["destination"], ("absent",))


if __name__ == "__main__":
    unittest.main()
