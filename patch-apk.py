#!/usr/bin/python3
"""patch-apk - Pull and patch Android apps for use with objection/frida."""

from __future__ import annotations

# ─────────────────────────────────────────────
# Section 1: STDLIB IMPORTS
# ─────────────────────────────────────────────
import argparse
import datetime
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree
from dataclasses import dataclass
from pathlib import Path

# ─────────────────────────────────────────────
# Section 2: LOGGING INFRASTRUCTURE
# ─────────────────────────────────────────────

_STANDARD_LOG_RECORD_ATTRS: frozenset[str] = frozenset({
    "args", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "message", "module", "msecs", "msg",
    "name", "pathname", "process", "processName", "relativeCreated",
    "stack_info", "taskName", "thread", "threadName",
})


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per line with timestamp, level, message, and extras."""

    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, object] = {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created, tz=datetime.timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        extra = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _STANDARD_LOG_RECORD_ATTRS and not k.startswith("_")
        }
        if extra:
            out["extra"] = extra
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out)


class TextFormatter(logging.Formatter):
    """Human-readable colored single-line format."""

    _LEVEL_COLORS: dict[str, str] = {
        "DEBUG":   "\033[36m",
        "INFO":    "\033[32m",
        "WARNING": "\033[33m",
        "ERROR":   "\033[31m",
        "RESET":   "\033[0m",
    }

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.datetime.fromtimestamp(
            record.created, tz=datetime.timezone.utc
        ).strftime("%H:%M:%S")
        color = self._LEVEL_COLORS.get(record.levelname, "")
        reset = self._LEVEL_COLORS["RESET"]
        return f"{ts} {color}{record.levelname:<7s}{reset} {record.getMessage()}"


def _configure_logging(cfg: Config) -> None:
    handler = logging.StreamHandler()
    if cfg.log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(TextFormatter())
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(getattr(logging, cfg.log_level))


logger = logging.getLogger(__name__)


def _subprocess_stdout() -> int | None:
    """Return subprocess stdout target based on current log level."""
    return None if logger.isEnabledFor(logging.DEBUG) else subprocess.DEVNULL


# ─────────────────────────────────────────────
# Section 3: EXCEPTIONS
# ─────────────────────────────────────────────

class PatchApkError(Exception):
    """Base exception for all patch-apk failures."""


class DependencyError(PatchApkError):
    """A required external tool is missing or the keystore is absent."""


class DeviceError(PatchApkError):
    """ADB device communication failure or no device connected."""


class PackageError(PatchApkError):
    """Package not found on device or ambiguous package name."""


class ApkError(PatchApkError):
    """APK manipulation failure (pull, decompile, recompile, sign, align, patch)."""


# ─────────────────────────────────────────────
# Section 4: CONFIG / ARG PARSING
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class Config:
    pkgname: str
    no_enable_user_certs: bool
    save_apk: Path | None
    disable_styles_hack: bool
    log_level: str
    log_format: str
    keystore_path: Path


def parse_args() -> Config:
    """Parse CLI arguments and return an immutable Config."""
    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="patch-apk - Pull and patch Android apps for use with objection/frida."
    )
    parser.add_argument(
        "--no-enable-user-certs",
        help="Prevent patch-apk from enabling user-installed certificate support via network security config in the patched APK.",
        action="store_true",
    )
    parser.add_argument(
        "--save-apk",
        help="Save a copy of the APK (or single APK) prior to patching for use with other tools.",
        type=Path,
    )
    parser.add_argument(
        "--disable-styles-hack",
        help="Disable the styles hack that removes duplicate entries from res/values/styles.xml.",
        action="store_true",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging verbosity (default: INFO).",
    )
    parser.add_argument(
        "--log-format",
        choices=["json", "text"],
        default="json",
        help="Log output format (default: json).",
    )
    # Kept for backward compatibility; hidden from --help
    parser.add_argument(
        "--debug-output",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "pkgname",
        help="The name, or partial name, of the package to patch (e.g. com.foo.bar).",
    )

    ns = parser.parse_args()

    log_level = ns.log_level
    if ns.debug_output:
        log_level = "DEBUG"

    return Config(
        pkgname=ns.pkgname,
        no_enable_user_certs=ns.no_enable_user_certs,
        save_apk=ns.save_apk,
        disable_styles_hack=ns.disable_styles_hack,
        log_level=log_level,
        log_format=ns.log_format,
        keystore_path=script_dir / "data" / "patch-apk.keystore",
    )


# ─────────────────────────────────────────────
# Section 5: UTILITIES
# ─────────────────────────────────────────────

def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string like '2.4.2' or '2.9.0-dirty' into a comparable integer tuple."""
    clean = version_str.strip().split("-")[0]
    return tuple(int(part) for part in clean.split("."))


def run_command(
    cmd: list[str],
    *,
    capture_output: bool = False,
    error_msg: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run an external command, logging it at DEBUG level.

    Raises:
        DependencyError: If the executable is not found.
        ApkError: If the process exits with a non-zero return code.
    """
    logger.debug("Running command: %s", " ".join(cmd))

    stdout_target: int | None
    stderr_target: int | None
    if capture_output:
        stdout_target = subprocess.PIPE
        stderr_target = subprocess.PIPE
    else:
        stdout_target = _subprocess_stdout()
        stderr_target = None

    try:
        result = subprocess.run(
            cmd,
            stdout=stdout_target,
            stderr=stderr_target,
        )
    except FileNotFoundError:
        raise DependencyError(f"Command not found: {cmd[0]!r}")

    if result.returncode != 0:
        base = error_msg or f"Command failed: {' '.join(cmd)}"
        stderr_detail = ""
        if capture_output and result.stderr:
            stderr_detail = "\n" + result.stderr.decode("utf-8", errors="replace").strip()
        raise ApkError(f"{base}{stderr_detail}")

    return result


def _apktool_uses_bat() -> bool:
    """Return True if apktool is installed as apktool.bat on Windows."""
    return os.name == "nt" and shutil.which("apktool.bat") is not None


def run_apktool(params: list[str]) -> None:
    """Run apktool cross-platform, handling the Windows .bat pause hack.

    On Windows, apktool.bat executes 'pause' at the end, requiring stdin input
    to unblock it. Only applies when apktool.bat is actually on PATH; modern
    Windows installs may ship a plain 'apktool' wrapper instead.
    """
    if _apktool_uses_bat():
        cmd = ["apktool.bat"] + params
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=_subprocess_stdout(),
        )
        proc.communicate(b"\r\n")
        if proc.returncode != 0:
            raise ApkError(f"apktool failed: {' '.join(cmd)}")
    else:
        run_command(
            ["apktool"] + params,
            error_msg=f"apktool failed: apktool {' '.join(params)}",
        )


def get_objection_version() -> str:
    """Return the installed objection version string."""
    result = run_command(["objection", "version"], capture_output=True)
    return result.stdout.decode("utf-8").strip().split(": ")[-1].strip()


def get_apktool_version() -> str:
    """Return the installed apktool version string."""
    if _apktool_uses_bat():
        cmd = ["apktool.bat", "-version"]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, _ = proc.communicate(b"\r\n")
        return out.decode("utf-8").strip().split("-")[0].strip()
    else:
        result = run_command(["apktool", "-version"], capture_output=True)
        return result.stdout.decode("utf-8").strip().split("-")[0].strip()


# ─────────────────────────────────────────────
# Section 6: DEPENDENCY / DEVICE CHECKS
# ─────────────────────────────────────────────

def check_dependencies(cfg: Config) -> None:
    """Verify required tools are on PATH, a device is connected, and the keystore exists."""
    deps = ["adb", "apktool", "jarsigner", "objection", "zipalign"]
    missing = [dep for dep in deps if shutil.which(dep) is None]
    if missing:
        raise DependencyError(
            "Missing dependencies, ensure the following commands are available on the PATH: "
            + ", ".join(missing)
        )

    proc = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE)
    if proc.returncode != 0:
        raise DeviceError("Failed to run 'adb devices'.")
    device_out = proc.stdout.decode("utf-8")
    if len(device_out.strip().splitlines()) == 1:
        raise DeviceError(
            "No Android device connected ('adb devices'). Connect a device first."
        )

    if not cfg.keystore_path.exists():
        raise DependencyError(
            f"Keystore not found at {cfg.keystore_path}. "
            "Please clone the repository or place the keystore file at this location."
        )


# ─────────────────────────────────────────────
# Section 7: PACKAGE / APK OPERATIONS
# ─────────────────────────────────────────────

def verify_package_name(pkgname: str) -> str:
    """Verify the package is installed on the device; return the exact package name.

    If multiple packages match the search term, prompt the user to select one.
    """
    result = run_command(
        ["adb", "shell", "pm", "list", "packages"],
        capture_output=True,
        error_msg="Failed to list installed packages",
    )
    out = result.stdout.decode("utf-8")

    packages: list[str] = []
    for line in out.splitlines():
        if line.startswith("package:"):
            pkg = line[8:].strip()
            if pkgname.lower() in pkg.lower():
                packages.append(pkg)

    if not packages:
        raise PackageError(
            f"No packages found on the device matching '{pkgname}'. "
            "Run 'adb shell pm list packages' to verify installed package names."
        )

    if len(packages) == 1:
        return packages[0]

    logger.info("Multiple matching packages installed, select the package to patch.")
    choice = -1
    while choice == -1:
        for i, pkg in enumerate(packages):
            print(f"[{i + 1}] {pkg}")
        raw = input("Choice: ")
        if raw.isnumeric() and 1 <= int(raw) <= len(packages):
            choice = int(raw)
        else:
            print("Invalid choice.\n")
    print("")
    return packages[choice - 1]


def get_apk_paths_for_package(pkgname: str) -> list[str]:
    """Return the APK path(s) on the device for the given package name."""
    logger.info("Getting APK path(s) for package: %s", pkgname)
    result = run_command(
        ["adb", "shell", "pm", "path", pkgname],
        capture_output=True,
        error_msg=f"Failed to get APK path for package '{pkgname}'",
    )
    out = result.stdout.decode("utf-8")

    paths: list[str] = []
    for line in out.splitlines():
        if line.startswith("package:"):
            path = line[8:].strip()
            logger.info("APK path: %s", path)
            paths.append(path)
    print("")
    return paths


def get_target_apk(
    pkgname: str,
    apk_paths: list[str],
    tmp_path: Path,
    cfg: Config,
) -> Path:
    """Pull the APK file(s) from the device and return the local path to work with.

    If the package is a split APK / app bundle, combines them into a single APK.
    """
    logger.info("Pulling APK file(s) from device.")
    local_apks: list[Path] = []
    for remote_path in apk_paths:
        base_name = remote_path.split("/")[-1]
        local_path = tmp_path / f"{pkgname}-{base_name}"
        local_apks.append(local_path)
        logger.info("Pulling: %s", f"{pkgname}-{base_name}")
        run_command(
            ["adb", "pull", remote_path, str(local_path)],
            error_msg=f"Failed to pull APK from device: {remote_path}",
        )
    print("")

    if len(local_apks) == 1:
        return local_apks[0]
    return combine_split_apks(pkgname, local_apks, tmp_path, cfg)


def combine_split_apks(
    pkgname: str,
    local_apks: list[Path],
    tmp_path: Path,
    cfg: Config,
) -> Path:
    """Combine app bundle / split APKs into a single APK for patching."""
    logger.info("App bundle/split APK detected, rebuilding as a single APK.")
    print("")

    logger.info("Extracting individual APKs with apktool.")
    base_apk_dir = tmp_path / f"{pkgname}-base"
    base_apk_filename = f"{pkgname}-base.apk"
    split_apk_dirs: list[Path] = []

    for apk_path in local_apks:
        logger.info("Extracting: %s", apk_path)
        apk_dir = apk_path.with_suffix("")
        run_apktool(["d", str(apk_path), "-o", str(apk_dir)])

        if not apk_path.name.endswith("base.apk"):
            split_apk_dirs.append(apk_dir)

        if detect_proguard(apk_dir):
            logger.warning("Detected ProGuard/AndResGuard, decompile/recompile may not succeed.")
    print("")

    copy_split_apk_files(base_apk_dir, split_apk_dirs)
    fix_public_resource_ids(base_apk_dir, split_apk_dirs)

    if not cfg.disable_styles_hack:
        hack_remove_duplicate_style_entries(base_apk_dir)

    disable_apk_splitting(base_apk_dir)

    logger.info("Rebuilding as a single APK.")
    if (base_apk_dir / "res" / "navigation").exists():
        logger.info("Found res/navigation directory, rebuilding with 'apktool --use-aapt2'.")
        run_apktool(["--use-aapt2", "b", str(base_apk_dir)])
    elif _parse_version(get_apktool_version()) > _parse_version("2.4.2"):
        logger.info("Found apktool version > 2.4.2, rebuilding with 'apktool --use-aapt2'.")
        run_apktool(["--use-aapt2", "b", str(base_apk_dir)])
    else:
        logger.info("Building APK with apktool.")
        run_apktool(["b", str(base_apk_dir)])

    logger.info("Signing new APK.")
    run_command(
        [
            "jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1",
            "-keystore", str(cfg.keystore_path),
            "-storepass", "patch-apk",
            str(base_apk_dir / "dist" / base_apk_filename),
            "patch-apk-key",
        ],
        error_msg="jarsigner failed to sign the combined APK",
    )

    logger.info("Zip aligning new APK.")
    aligned_path = base_apk_dir / "dist" / base_apk_filename.replace(".apk", "-aligned.apk")
    run_command(
        [
            "zipalign", "-f", "4",
            str(base_apk_dir / "dist" / base_apk_filename),
            str(aligned_path),
        ],
        error_msg="zipalign failed on the combined APK",
    )
    aligned_path.replace(base_apk_dir / "dist" / base_apk_filename)
    print("")

    return base_apk_dir / "dist" / base_apk_filename


# ─────────────────────────────────────────────
# Section 8: APK MANIPULATION HELPERS
# ─────────────────────────────────────────────

def detect_proguard(extracted_path: Path) -> bool:
    """Attempt to detect ProGuard/AndResGuard in an extracted APK directory."""
    if (extracted_path / "original" / "META-INF" / "proguard").exists():
        return True
    manifest = extracted_path / "original" / "META-INF" / "MANIFEST.MF"
    if manifest.exists():
        if "proguard" in manifest.read_text(errors="replace").lower():
            return True
    return False


def copy_split_apk_files(base_apk_dir: Path, split_apk_dirs: list[Path]) -> None:
    """Copy files and directories from split APKs into the base APK directory."""
    logger.info("Copying files and directories from split APKs into base APK.")
    for apk_dir in split_apk_dirs:
        for root, dirs, files in os.walk(apk_dir):
            root_path = Path(root)
            if root_path.is_relative_to(apk_dir / "original"):
                continue

            for d in dirs:
                dest = base_apk_dir / (root_path / d).relative_to(apk_dir)
                if not dest.exists():
                    logger.debug("Creating directory in base APK: %s", dest.relative_to(base_apk_dir))
                    dest.mkdir(parents=True, exist_ok=True)

            for f in files:
                if root_path == apk_dir and f in ("AndroidManifest.xml", "apktool.yml"):
                    continue

                src = root_path / f
                dest = base_apk_dir / src.relative_to(apk_dir)

                if f.lower().endswith(".xml") and dest.is_relative_to(base_apk_dir / "res"):
                    continue

                logger.debug("Moving file to base APK: %s", dest.relative_to(base_apk_dir))
                shutil.move(str(src), dest)
    print("")


def fix_public_resource_ids(base_apk_dir: Path, split_apk_dirs: list[Path]) -> None:
    """Fix public resource identifiers shared across split APKs.

    Maps all APKTOOL_DUMMY_ resource IDs in the base APK to real resource names
    from the split APKs, then updates references in other resource files.
    """
    public_xml = base_apk_dir / "res" / "values" / "public.xml"
    if not public_xml.exists():
        return

    logger.info("Found public.xml in the base APK, fixing resource identifiers across split APKs.")

    id_to_dummy_name: dict[str, str] = {}
    dummy_name_to_real_name: dict[str, str | None] = {}

    base_xml_tree = xml.etree.ElementTree.parse(public_xml)
    for el in base_xml_tree.getroot():
        if "name" in el.attrib and "id" in el.attrib:
            if el.attrib["name"].startswith("APKTOOL_DUMMY_") and el.attrib["name"] not in id_to_dummy_name:
                id_to_dummy_name[el.attrib["id"]] = el.attrib["name"]
                dummy_name_to_real_name[el.attrib["name"]] = None
    logger.info("Resolving %d resource identifiers.", len(id_to_dummy_name))

    found = 0
    for split_dir in split_apk_dirs:
        split_public_xml = split_dir / "res" / "values" / "public.xml"
        if split_public_xml.exists():
            tree = xml.etree.ElementTree.parse(split_public_xml)
            for el in tree.getroot():
                if "name" in el.attrib and "id" in el.attrib:
                    if el.attrib["id"] in id_to_dummy_name:
                        dummy_name_to_real_name[id_to_dummy_name[el.attrib["id"]]] = el.attrib["name"]
                        found += 1
    logger.info("Located %d true resource names.", found)

    updated = 0
    for el in base_xml_tree.getroot():
        if "name" in el.attrib and "id" in el.attrib:
            if el.attrib["name"] in dummy_name_to_real_name and dummy_name_to_real_name[el.attrib["name"]] is not None:
                el.attrib["name"] = dummy_name_to_real_name[el.attrib["name"]]  # type: ignore[assignment]
                updated += 1
    base_xml_tree.write(str(public_xml), encoding="utf-8", xml_declaration=True)
    logger.info("Updated %d dummy resource names with true names in the base APK.", updated)

    updated = 0
    manifest_path = base_apk_dir / "AndroidManifest.xml"
    namespaces = dict(
        node
        for _, node in xml.etree.ElementTree.iterparse(str(manifest_path), events=["start-ns"])
    )
    for ns_prefix, ns_uri in namespaces.items():
        xml.etree.ElementTree.register_namespace(ns_prefix, ns_uri)
    android_ns = "{" + namespaces["android"] + "}"

    for root, _, files in os.walk(base_apk_dir / "res"):
        for f in files:
            if not f.lower().endswith(".xml"):
                continue
            file_path = Path(root) / f
            try:
                logger.debug("Parsing %s", file_path)
                tree = xml.etree.ElementTree.parse(str(file_path))
                changed = False

                for el in tree.iter():
                    for attr in list(el.attrib):
                        val = el.attrib[attr]
                        if (
                            val.startswith("@") and "/" in val
                            and val.split("/")[1].startswith("APKTOOL_DUMMY_")
                            and dummy_name_to_real_name.get(val.split("/")[1]) is not None
                        ):
                            el.attrib[attr] = val.split("/")[0] + "/" + dummy_name_to_real_name[val.split("/")[1]]  # type: ignore[operator]
                            updated += 1
                            changed = True
                        elif (
                            val.startswith("APKTOOL_DUMMY_")
                            and dummy_name_to_real_name.get(val) is not None
                        ):
                            el.attrib[attr] = dummy_name_to_real_name[val]  # type: ignore[assignment]
                            updated += 1
                            changed = True

                    val = el.text
                    if (
                        val is not None
                        and val.startswith("@") and "/" in val
                        and val.split("/")[1].startswith("APKTOOL_DUMMY_")
                        and dummy_name_to_real_name.get(val.split("/")[1]) is not None
                    ):
                        el.text = val.split("/")[0] + "/" + dummy_name_to_real_name[val.split("/")[1]]  # type: ignore[operator]
                        updated += 1
                        changed = True

                if changed:
                    tree.write(str(file_path), encoding="utf-8", xml_declaration=True)
            except xml.etree.ElementTree.ParseError:
                logger.warning("XML parse error in %s, skipping.", file_path)

    logger.info("Updated %d references to dummy resource names in the base APK.", updated)
    print("")


def hack_remove_duplicate_style_entries(base_apk_dir: Path) -> None:
    """Remove duplicate <item> entries from res/values/styles.xml before rebuilding.

    Workaround for an apktool bug affecting some apps (e.g. com.ubercab).
    See: https://github.com/iBotPeaches/Apktool/issues/2240
    """
    styles_xml = base_apk_dir / "res" / "values" / "styles.xml"
    if not styles_xml.exists():
        return

    logger.info(
        "Found styles.xml in the base APK, checking for duplicate <style> -> <item> elements."
    )
    logger.warning(
        "Styles hack active — may impact app visuals. Disable with --disable-styles-hack."
    )

    dupes: list[tuple[xml.etree.ElementTree.Element, xml.etree.ElementTree.Element]] = []
    tree = xml.etree.ElementTree.parse(str(styles_xml))

    for style_el in tree.getroot().findall("style"):
        seen_names: list[str] = []
        for item_el in style_el:
            name = item_el.attrib.get("name", "")
            if name in seen_names:
                dupes.append((style_el, item_el))
            else:
                seen_names.append(name)

    for parent_el, dupe_el in dupes:
        parent_el.remove(dupe_el)

    if dupes:
        tree.write(str(styles_xml), encoding="utf-8", xml_declaration=True)
        logger.info("Removed %d duplicate entries from styles.xml.", len(dupes))
    print("")


def disable_apk_splitting(base_apk_dir: Path) -> None:
    """Update AndroidManifest.xml to disable APK splitting.

    - Removes the 'isSplitRequired' attribute from the 'application' element.
    - Sets 'extractNativeLibs' to 'true' on the 'application' element.
    - Removes meta-data elements for 'com.android.vending.splits' and
      'com.android.vending.splits.required'.
    """
    logger.info("Disabling APK splitting in AndroidManifest.xml of base APK.")
    manifest_path = base_apk_dir / "AndroidManifest.xml"

    namespaces = dict(
        node
        for _, node in xml.etree.ElementTree.iterparse(str(manifest_path), events=["start-ns"])
    )
    for ns_prefix, ns_uri in namespaces.items():
        xml.etree.ElementTree.register_namespace(ns_prefix, ns_uri)
    android_ns = "{" + namespaces["android"] + "}"

    tree = xml.etree.ElementTree.parse(str(manifest_path))
    app_el: xml.etree.ElementTree.Element | None = None
    els_to_remove: list[xml.etree.ElementTree.Element] = []

    for el in tree.iter():
        if el.tag == "application":
            app_el = el
            el.attrib.pop(android_ns + "isSplitRequired", None)
            if android_ns + "extractNativeLibs" in el.attrib:
                el.attrib[android_ns + "extractNativeLibs"] = "true"
        elif app_el is not None and el.tag == "meta-data":
            name_attr = el.attrib.get(android_ns + "name", "")
            if name_attr in (
                "com.android.vending.splits.required",
                "com.android.vending.splits",
            ):
                els_to_remove.append(el)

    for el in els_to_remove:
        app_el.remove(el)  # type: ignore[union-attr]

    tree.write(str(manifest_path), encoding="utf-8", xml_declaration=True)
    print("")


def enable_user_certs(apk_file: Path, cfg: Config) -> None:
    """Patch an APK to enable support for user-installed CA certificates (e.g. Burp Suite)."""
    logger.info("Patching APK to enable support for user-installed CA certificates.")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        apk_dir = tmp_path / apk_file.stem
        apk_name = apk_dir.name + ".apk"

        run_apktool(["d", str(apk_file), "-o", str(apk_dir)])

        manifest_path = apk_dir / "AndroidManifest.xml"
        namespaces = dict(
            node
            for _, node in xml.etree.ElementTree.iterparse(str(manifest_path), events=["start-ns"])
        )
        for ns_prefix, ns_uri in namespaces.items():
            xml.etree.ElementTree.register_namespace(ns_prefix, ns_uri)
        android_ns = "{" + namespaces["android"] + "}"

        tree = xml.etree.ElementTree.parse(str(manifest_path))
        for el in tree.findall("application"):
            el.attrib[android_ns + "networkSecurityConfig"] = "@xml/network_security_config"
        tree.write(str(manifest_path), encoding="utf-8", xml_declaration=True)

        nsc_dir = apk_dir / "res" / "xml"
        nsc_dir.mkdir(parents=True, exist_ok=True)
        nsc_content = (
            '<?xml version="1.0" encoding="utf-8" ?>'
            "<network-security-config>"
            "<base-config>"
            "<trust-anchors>"
            '<certificates src="system" />'
            '<certificates src="user" />'
            "</trust-anchors>"
            "</base-config>"
            "</network-security-config>"
        )
        (nsc_dir / "network_security_config.xml").write_bytes(nsc_content.encode("utf-8"))

        run_apktool(["b", str(apk_dir)])
        run_command(
            [
                "jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1",
                "-keystore", str(cfg.keystore_path),
                "-storepass", "patch-apk",
                str(apk_dir / "dist" / apk_name),
                "patch-apk-key",
            ],
            error_msg="jarsigner failed to sign the user-cert-patched APK",
        )

        apk_file.unlink()
        run_command(
            ["zipalign", "4", str(apk_dir / "dist" / apk_name), str(apk_file)],
            error_msg="zipalign failed on the user-cert-patched APK",
        )
    print("")


# ─────────────────────────────────────────────
# Section 9: MAIN
# ─────────────────────────────────────────────

def patch_with_objection(apk_file: Path, cfg: Config) -> None:
    """Inject the Frida gadget into the APK using objection patchapk."""
    logger.info("Patching %s with objection.", apk_file.name)
    base_cmd = ["objection", "patchapk", "--skip-resources"]
    if _parse_version(get_objection_version()) >= _parse_version("1.9.3"):
        base_cmd.append("--ignore-nativelibs")
    base_cmd += ["-s", str(apk_file)]

    run_command(
        base_cmd,
        error_msg=f"objection patchapk failed on {apk_file.name}",
    )

    objection_apk = apk_file.with_name(apk_file.stem + ".objection.apk")
    apk_file.unlink()
    objection_apk.rename(apk_file)
    print("")


def uninstall_and_reinstall(pkgname: str, apk_file: Path, cfg: Config) -> None:
    """Uninstall the original package and install the patched APK."""
    logger.info("Uninstalling the original package from the device.")
    run_command(
        ["adb", "uninstall", pkgname],
        error_msg=f"Failed to uninstall '{pkgname}' from the device",
    )
    print("")

    logger.info("Installing the patched APK to the device.")
    run_command(
        ["adb", "install", str(apk_file)],
        error_msg=f"Failed to install patched APK '{apk_file.name}'",
    )
    print("")


def main() -> None:
    cfg = parse_args()
    _configure_logging(cfg)

    try:
        check_dependencies(cfg)
        pkgname = verify_package_name(cfg.pkgname)
        apk_paths = get_apk_paths_for_package(pkgname)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            apk_file = get_target_apk(pkgname, apk_paths, tmp_path, cfg)

            if cfg.save_apk is not None:
                logger.info("Saving a copy of the APK to %s", cfg.save_apk)
                shutil.copy(apk_file, cfg.save_apk)
                print("")

            patch_with_objection(apk_file, cfg)

            if not cfg.no_enable_user_certs:
                enable_user_certs(apk_file, cfg)

            uninstall_and_reinstall(pkgname, apk_file, cfg)

        logger.info("Done, cleaning up temporary files.")

    except PatchApkError as exc:
        logger.error("%s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
