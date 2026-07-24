# /// script
# dependencies = [
#     "mcp[cli]>=0.1.0",
#     "pyarrow>=14.0.0",
# ]
# ///

import os
import re
import sys
import glob
import shutil
import logging
import tempfile
import subprocess
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

# 1. Force Python logging to stderr to keep stdout clean for MCP JSON-RPC traffic
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger("hdfs-mcp-server")

# 2. Silence log4j / Hadoop stdout output
os.environ["HADOOP_ROOT_LOGGER"] = "WARN,console"


# 2b. TLS truststore for the libhdfs JVM.
# The AWS SDK v2 HTTP client (used by the S3A connector) validates endpoint
# certificates against the JVM's truststore. In a CDP RAZ environment the correct
# truststore is Hadoop's ssl-client.xml `ssl.client.truststore.location` (the CM
# AutoTLS global truststore), which trusts both the internal RAZ endpoint and the
# public CAs used by S3. Without it, s3a:// access fails with
# "SSLHandshakeException: No trusted certificate found".
def _hadoop_ssl_truststore() -> Tuple[str, str]:
    """Return (location, password) from ssl-client.xml, or ('', '') if not found."""
    conf_dirs = []
    if os.environ.get("HADOOP_CONF_DIR"):
        conf_dirs.append(os.environ["HADOOP_CONF_DIR"])
    conf_dirs.append("/etc/hadoop/conf")
    seen = set()
    for d in conf_dirs:
        if not d or d in seen:
            continue
        seen.add(d)
        path = os.path.join(d, "ssl-client.xml")
        if not os.path.isfile(path):
            continue
        try:
            root = ET.parse(path).getroot()
            props = {}
            for prop in root.findall("property"):
                name = (prop.findtext("name") or "").strip()
                value = (prop.findtext("value") or "").strip()
                if name:
                    props[name] = value
            loc = props.get("ssl.client.truststore.location", "")
            pw = props.get("ssl.client.truststore.password", "")
            if loc and os.path.isfile(loc):
                return loc, pw
        except Exception as e:
            logger.warning(f"Failed to parse {path}: {e}")
    return "", ""


_DEFAULT_STOREPASS = "changeit"


def _default_truststore_cache() -> str:
    """A writable path for the built truststore.

    The Agent Studio bubblewrap sandbox does NOT make /tmp writable — its writable
    temp is TMPDIR (e.g. /workspace/tmp), which is also where the package itself is
    unpacked. Honor tempfile.gettempdir() (which respects TMPDIR/TEMP/TMP) instead
    of hardcoding /tmp, falling back through a few candidates.
    """
    candidates = [
        os.environ.get("HDFS_MCP_TRUSTSTORE_CACHE", ""),
        os.path.join(tempfile.gettempdir(), "hdfs-mcp-truststore.jks"),
        os.path.join(os.environ.get("TMPDIR", "").rstrip("/"), "hdfs-mcp-truststore.jks")
        if os.environ.get("TMPDIR") else "",
        "/tmp/hdfs-mcp-truststore.jks",
    ]
    for c in candidates:
        if not c:
            continue
        d = os.path.dirname(c) or "."
        if os.path.isdir(d) and os.access(d, os.W_OK):
            return c
    # Last resort: let tempfile pick a guaranteed-writable dir.
    return os.path.join(tempfile.mkdtemp(prefix="hdfs-mcp-"), "hdfs-mcp-truststore.jks")


_TRUSTSTORE_CACHE = _default_truststore_cache()
# Populated by configure_jvm_options(); surfaced via diagnose_environment().
_ACTIVE_TRUSTSTORE = ""


def _candidate_java_homes() -> List[str]:
    """Java homes to search for cacerts/keytool.

    Under Agent Studio's bubblewrap sandbox, JAVA_HOME (/usr/lib/jvm/...) and
    /etc/ssl may not be mounted, but the hadoop-cli runtime addon (which ships its
    own JVM) is. So we also look for a JVM under the runtime addon.
    """
    homes: List[str] = []
    if os.environ.get("JAVA_HOME"):
        homes.append(os.environ["JAVA_HOME"])

    search_globs = []
    libhdfs_dir = os.environ.get("ARROW_LIBHDFS_DIR", "")
    if libhdfs_dir:
        search_globs.append(os.path.join(libhdfs_dir, "jvm", "*"))
    search_globs.append("/runtime-addons/*/usr/lib/jvm/*")
    for pat in search_globs:
        for d in sorted(glob.glob(pat)):
            if os.path.isdir(d):
                homes.append(d)

    seen, out = set(), []
    for h in homes:
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _default_cacerts() -> str:
    """Path to a usable JVM cacerts *keystore* (JKS/PKCS12), sandbox-aware.

    Preferred because copying one file preserves the full public (+ any internal)
    trust set cheaply. Note: os.path.isfile() follows symlinks, so a dangling
    symlink (e.g. Debian's /etc/ssl/certs/java/cacerts -> unmounted target) is
    correctly treated as absent.
    """
    for home in _candidate_java_homes():
        for p in (
            os.path.join(home, "jre", "lib", "security", "cacerts"),
            os.path.join(home, "lib", "security", "cacerts"),
        ):
            if os.path.isfile(p):
                return p
    for p in (
        "/etc/ssl/certs/java/cacerts",               # Debian/Ubuntu (ca-certificates-java)
        "/etc/pki/ca-trust/extracted/java/cacerts",  # RHEL/CentOS/Rocky
        "/etc/pki/java/cacerts",                      # older RHEL
    ):
        if os.path.isfile(p):
            return p
    return ""


def _keytool() -> str:
    for home in _candidate_java_homes():
        candidate = os.path.join(home, "bin", "keytool")
        if os.path.isfile(candidate):
            return candidate
    return "keytool"


def _ca_pem_files() -> List[str]:
    """PEM CA files to add to the truststore.

    The reduced ``ca-certificates-java`` keystore in some CDP runtimes omits public
    roots (e.g. Amazon/Starfield) that AWS S3 endpoints chain to, even though the
    individual PEM files exist under /etc/ssl/certs. Import those. Additional CAs
    (e.g. an internal RAZ CA) can be supplied via HDFS_MCP_EXTRA_CA_PEM.
    """
    files: List[str] = []

    # Public root CAs bundled with the package — always available even inside a
    # sandbox that doesn't mount /etc/ssl (e.g. Agent Studio's bubblewrap).
    bundled_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cacerts")
    if os.path.isdir(bundled_dir):
        files.extend(sorted(glob.glob(os.path.join(bundled_dir, "*.pem"))))

    globs_env = os.getenv("HDFS_MCP_CA_PEM_GLOBS", "").strip()
    if globs_env:
        patterns = [g.strip() for g in globs_env.split(":") if g.strip()]
    else:
        patterns = [
            "/etc/ssl/certs/Amazon_Root_CA_*.pem",
            "/etc/ssl/certs/Starfield_*.pem",
        ]
    for pat in patterns:
        files.extend(sorted(glob.glob(pat)))

    extra = os.getenv("HDFS_MCP_EXTRA_CA_PEM", "").strip()
    for item in (x.strip() for x in extra.split(":") if x.strip()):
        if os.path.isdir(item):
            files.extend(sorted(glob.glob(os.path.join(item, "*.pem"))))
            files.extend(sorted(glob.glob(os.path.join(item, "*.crt"))))
        elif os.path.isfile(item):
            files.append(item)

    seen, out = set(), []
    for f in files:
        if f not in seen and os.path.isfile(f):
            seen.add(f)
            out.append(f)
    return out


def _ca_bundle_files() -> List[str]:
    """Concatenated PEM CA *bundle* files (many certs in one file).

    These hold the full public root set. keytool can't import a multi-cert PEM in
    one shot, so we split them (see _split_pem_bundle) and import each cert. Used
    as the base when no JVM cacerts keystore is available, so we don't lose trust
    for non-AWS public endpoints (Azure/abfs, etc.). Override/disable with
    HDFS_MCP_CA_BUNDLE (colon-separated; set to 'none' to disable).
    """
    env = os.getenv("HDFS_MCP_CA_BUNDLE", "").strip()
    if env.lower() == "none":
        return []
    if env:
        cands = [x.strip() for x in env.split(":") if x.strip()]
    else:
        cands = [
            "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",    # RHEL/CentOS
            "/etc/ssl/ca-bundle.pem",              # SUSE
        ]
    return [c for c in cands if os.path.isfile(c)]


def _split_pem_bundle(path: str) -> List[str]:
    """Split a concatenated PEM bundle into individual cert files in a temp dir."""
    try:
        with open(path, "r", errors="ignore") as f:
            data = f.read()
    except Exception as e:
        logger.warning(f"Could not read CA bundle {path}: {e}")
        return []
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.DOTALL
    )
    if not blocks:
        return []
    out: List[str] = []
    d = tempfile.mkdtemp(prefix="hdfs-mcp-cabundle-")
    for i, block in enumerate(blocks):
        p = os.path.join(d, f"cert_{i}.pem")
        try:
            with open(p, "w") as fh:
                fh.write(block.strip() + "\n")
            out.append(p)
        except Exception:
            continue
    return out


def _build_truststore(base_cacerts: str, merge_jks: str = "", merge_jks_pw: str = "") -> str:
    """Create a truststore = base cacerts + public CA PEMs (+ optional internal JKS).

    Returns the path to the built truststore (password _DEFAULT_STOREPASS), or "".
    """
    pem_files = _ca_pem_files()
    keytool = _keytool()
    have_base = bool(base_cacerts and os.path.isfile(base_cacerts))
    have_merge = bool(merge_jks and os.path.isfile(merge_jks))

    # When there's no JVM cacerts keystore to seed from, fall back to the system
    # PEM CA bundle (full public root set) so we don't narrow trust to just the
    # bundled AWS roots. Skipped when have_base, since the base already carries
    # the full public set (avoids ~130 extra keytool calls).
    bundle_pems: List[str] = []
    if not have_base:
        for bundle in _ca_bundle_files():
            certs = _split_pem_bundle(bundle)
            if certs:
                logger.info(
                    f"No JVM cacerts base; importing {len(certs)} CA certs from "
                    f"system bundle {bundle} to preserve full public trust."
                )
                bundle_pems.extend(certs)

    import_pems = pem_files + bundle_pems

    # Nothing to work with at all.
    if not import_pems and not have_base and not have_merge:
        logger.warning("Truststore build skipped: no base cacerts, no CA PEMs, no internal truststore.")
        return ""

    try:
        # Seed the destination store: prefer the JVM's cacerts (keeps existing
        # public + RAZ trust). If it isn't reachable (e.g. restricted sandbox),
        # build from scratch — keytool -importcert creates the store on demand.
        if have_base:
            shutil.copyfile(base_cacerts, _TRUSTSTORE_CACHE)
            try:
                os.chmod(_TRUSTSTORE_CACHE, 0o644)
            except OSError:
                pass
        elif os.path.exists(_TRUSTSTORE_CACHE):
            os.remove(_TRUSTSTORE_CACHE)

        if have_merge:
            r = subprocess.run(
                [keytool, "-importkeystore", "-noprompt",
                 "-srckeystore", merge_jks, "-srcstorepass", merge_jks_pw or _DEFAULT_STOREPASS,
                 "-destkeystore", _TRUSTSTORE_CACHE, "-deststorepass", _DEFAULT_STOREPASS],
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode != 0:
                logger.warning(f"Could not merge internal truststore '{merge_jks}': {r.stderr.strip()}")

        imported = 0
        last_err = ""
        for i, pem in enumerate(import_pems):
            alias = f"hdfsmcp_{i}"
            r = subprocess.run(
                [keytool, "-importcert", "-noprompt", "-trustcacerts",
                 "-alias", alias, "-file", pem,
                 "-keystore", _TRUSTSTORE_CACHE, "-storepass", _DEFAULT_STOREPASS],
                capture_output=True, text=True, timeout=60,
            )
            out = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
            # Success is only real if the certificate was added AND the store was
            # persisted to disk. Some JDKs (Java 8) return non-zero even on a
            # genuine add, so we confirm by checking the file exists afterwards.
            if os.path.isfile(_TRUSTSTORE_CACHE) and (
                "added to keystore" in out.lower() or r.returncode == 0
            ):
                imported += 1
            else:
                last_err = out
                logger.warning(f"keytool could not import {pem} (exit={r.returncode}): {out}")

        # Verify the built store actually contains entries.
        entries = _truststore_entry_count(_TRUSTSTORE_CACHE, keytool)
        usable = os.path.isfile(_TRUSTSTORE_CACHE) and (
            entries > 0 or imported > 0 or have_base or have_merge
        )
        if not usable:
            logger.warning(
                f"Truststore build produced no usable store at {_TRUSTSTORE_CACHE} "
                f"(imported={imported}/{len(import_pems)}, verified_entries={entries}, "
                f"file_exists={os.path.isfile(_TRUSTSTORE_CACHE)}). "
                f"Last keytool output: {last_err}"
            )
            return ""

        logger.info(
            f"Built TLS truststore {_TRUSTSTORE_CACHE} "
            f"(base={base_cacerts if have_base else 'NONE(from-scratch)'}, "
            f"+{imported}/{len(import_pems)} PEM CAs "
            f"[{len(pem_files)} individual + {len(bundle_pems)} from system bundle]"
            f"{', merged ' + merge_jks if have_merge else ''}, "
            f"total_entries={entries}) via keytool={keytool}."
        )
        return _TRUSTSTORE_CACHE
    except Exception as e:
        logger.warning(f"Failed to build merged truststore: {e}")
        return ""


def _truststore_entry_count(store: str, keytool: str) -> int:
    """Count entries in a keystore via `keytool -list`, or -1 if it can't be read."""
    if not os.path.isfile(store):
        return 0
    try:
        r = subprocess.run(
            [keytool, "-list", "-keystore", store, "-storepass", _DEFAULT_STOREPASS],
            capture_output=True, text=True, timeout=60,
        )
        out = (r.stdout or "") + (r.stderr or "")
        for line in out.splitlines():
            low = line.lower()
            if "your keystore contains" in low:
                for tok in low.split():
                    if tok.isdigit():
                        return int(tok)
        # Fallback: count "trustedCertEntry" lines.
        n = sum(1 for ln in out.splitlines() if "trustedcertentry" in ln.lower())
        return n if n > 0 else (-1 if r.returncode != 0 else 0)
    except Exception as e:
        logger.warning(f"Could not list truststore {store}: {e}")
        return -1


def _resolve_truststore() -> Tuple[str, str]:
    """Return (path, password) for the JVM truststore, building one if needed."""
    explicit = os.getenv("HDFS_MCP_TRUSTSTORE", "").strip()
    if explicit:
        return explicit, os.getenv("HDFS_MCP_TRUSTSTORE_PASSWORD", "").strip()

    # Any internal/CM truststore to fold in (for RAZ endpoint trust).
    internal_loc, internal_pw = _hadoop_ssl_truststore()
    if not internal_loc:
        for cand in (
            "/var/lib/cloudera-scm-agent/agent-cert/cm-auto-global_truststore.jks",
            "/etc/cdp/security/truststore/cdp-truststore.jks",
        ):
            if os.path.isfile(cand):
                internal_loc = cand
                break

    base = _default_cacerts()
    logger.info(
        "TLS truststore resolve [v4-system-ca]: "
        f"cache_path={_TRUSTSTORE_CACHE!r} (TMPDIR={os.environ.get('TMPDIR')!r}, "
        f"gettempdir={tempfile.gettempdir()!r}), "
        f"JAVA_HOME={os.environ.get('JAVA_HOME')!r}, base_cacerts={base or 'NONE'!r}, "
        f"keytool={_keytool()!r}, candidate_java_homes={_candidate_java_homes()}, "
        f"individual_pems={_ca_pem_files()}, system_ca_bundles={_ca_bundle_files()}, "
        f"internal_truststore={internal_loc or 'NONE'!r}"
    )
    built = _build_truststore(base, merge_jks=internal_loc, merge_jks_pw=internal_pw)
    if built:
        return built, _DEFAULT_STOREPASS

    # Fall back to whatever internal truststore we found, else nothing.
    if internal_loc:
        return internal_loc, internal_pw
    return "", ""


def configure_jvm_options():
    """Build LIBHDFS_OPTS without clobbering any value already set by the operator."""
    global _ACTIVE_TRUSTSTORE
    parts: List[str] = []
    existing = os.environ.get("LIBHDFS_OPTS", "").strip()
    if existing:
        parts.append(existing)
    parts.append("-Dlog4j.configuration=file:///dev/null")

    loc, pw = _resolve_truststore()
    if loc and "javax.net.ssl.trustStore" not in existing:
        _ACTIVE_TRUSTSTORE = loc
        parts.append(f"-Djavax.net.ssl.trustStore={loc}")
        if pw:
            parts.append(f"-Djavax.net.ssl.trustStorePassword={pw}")
        logger.info(f"Configured JVM TLS truststore: {loc}")
    elif not loc:
        logger.warning(
            "No TLS truststore could be resolved or built. If s3a:// fails with "
            "'No trusted certificate found', set HDFS_MCP_TRUSTSTORE (and "
            "HDFS_MCP_TRUSTSTORE_PASSWORD), or HDFS_MCP_EXTRA_CA_PEM to add CA PEM files."
        )

    os.environ["LIBHDFS_OPTS"] = " ".join(parts)


configure_jvm_options()

# 3. Dynamically discover full Hadoop Classpath (includes HDFS, S3A, ADLS, Ozone, RAZ)

# The exact class whose absence breaks s3a:// filesystem instantiation on CDP.
# We locate whichever jar actually *contains* it rather than guessing by filename,
# because CDP may ship the AWS SDK v2 either as a shaded ``bundle-*.jar`` or as
# separate module jars (e.g. ``s3-transfer-manager-*.jar``).
_AWS_SDK_MARKER_CLASS = "software/amazon/awssdk/transfer/s3/progress/TransferListener.class"
_MAX_JARS_TO_SCAN = 5000


def _classpath_search_roots() -> List[str]:
    """Directories to scan for AWS SDK jars, in preference order (existing only)."""
    libhdfs_dir = os.environ.get("ARROW_LIBHDFS_DIR", "")
    roots: List[str] = []
    if os.environ.get("HADOOP_HOME"):
        roots.append(os.environ["HADOOP_HOME"])
    if libhdfs_dir:
        roots.append(libhdfs_dir)                   # e.g. /runtime-addons/.../usr/lib
        roots.append(os.path.dirname(libhdfs_dir))  # e.g. /runtime-addons/.../usr
    roots.append("/runtime-addons")
    roots.append("/opt/cloudera/parcels")
    # Allow the operator to add roots without editing this file.
    extra = os.getenv("HDFS_MCP_CLASSPATH_SEARCH_ROOTS", "").strip()
    if extra:
        roots.extend(p.strip() for p in extra.split(":"))

    out: List[str] = []
    seen = set()
    for r in roots:
        if r and r not in seen and os.path.isdir(r):
            seen.add(r)
            out.append(r)
    return out


def _list_jars(root: str, timeout: int = 30) -> List[str]:
    try:
        result = subprocess.run(
            ["find", "-L", root, "-maxdepth", "10", "-type", "f", "-name", "*.jar"],
            capture_output=True, text=True, timeout=timeout,
        )
        return [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    except Exception as e:
        logger.warning(f"jar search failed under '{root}': {e}")
        return []


def _jar_contains_class(jar_path: str, class_path: str) -> bool:
    """True if the jar's central directory lists the given class entry (cheap)."""
    try:
        with zipfile.ZipFile(jar_path) as zf:
            return class_path in zf.namelist()
    except Exception:
        return False


def _find_aws_sdk_classpath_dirs() -> List[str]:
    """Return classpath dirs for the AWS SDK v2, located by actual class content.

    CDP's S3A connector uses AWS SDK v2 (``software.amazon.awssdk``). The jar that
    provides ``TransferListener`` is required to instantiate an s3a:// filesystem;
    without it you get ``ClassNotFoundException`` / ``NoClassDefFoundError`` for
    that class. ``hadoop classpath`` does not include the SDK by default.

    An explicit ``HDFS_MCP_AWS_SDK_DIR`` short-circuits discovery.
    """
    override = os.getenv("HDFS_MCP_AWS_SDK_DIR", "").strip()
    if override:
        logger.info(f"Using HDFS_MCP_AWS_SDK_DIR override for AWS SDK classpath: {override}")
        return [override]

    roots = _classpath_search_roots()

    # Gather candidate jars, prioritizing AWS-SDK-looking names so we usually
    # only need to open a handful before finding the marker class.
    all_jars: List[str] = []
    seen = set()
    for root in roots:
        for jar in _list_jars(root):
            if jar not in seen:
                seen.add(jar)
                all_jars.append(jar)

    def looks_like_aws_sdk(path: str) -> bool:
        base = os.path.basename(path).lower()
        return (
            base.startswith("bundle-")
            or "awssdk" in base
            or "aws-sdk" in base
            or "aws-java-sdk" in base
            or base.startswith("s3-transfer-manager")
            or base.startswith("s3-")
        )

    prioritized = [j for j in all_jars if looks_like_aws_sdk(j)]
    remainder = [j for j in all_jars if not looks_like_aws_sdk(j)]
    scan_order = (prioritized + remainder)[:_MAX_JARS_TO_SCAN]

    for jar in scan_order:
        if _jar_contains_class(jar, _AWS_SDK_MARKER_CLASS):
            logger.info(
                f"Located AWS SDK v2 class '{_AWS_SDK_MARKER_CLASS}' in jar: {jar}"
            )
            return [os.path.dirname(jar)]

    logger.warning(
        "Could not find any jar containing '%s' under %s (scanned %d jars). "
        "s3a:// access will fail with ClassNotFoundException for the AWS SDK v2. "
        "Set HDFS_MCP_AWS_SDK_DIR to a directory containing the AWS SDK v2 jar(s), "
        "or HDFS_MCP_EXTRA_CLASSPATH / HDFS_MCP_CLASSPATH_SEARCH_ROOTS as needed.",
        _AWS_SDK_MARKER_CLASS, ", ".join(roots) or "<no roots>", len(scan_order),
    )
    return []


def configure_hadoop_classpath():
    parts: List[str] = ["/etc/hadoop/conf"]  # site XMLs take priority

    # 'hadoop classpath --glob' is only a fallback for plain edge nodes where the
    # hadoop CLI is on PATH but CLASSPATH isn't pre-set. In Agent Studio the
    # hadoop binary isn't on PATH and CLASSPATH is provided via env, so skip the
    # call quietly instead of emitting an alarming warning.
    hadoop_bin = shutil.which("hadoop")
    if hadoop_bin:
        try:
            result = subprocess.run(
                [hadoop_bin, "classpath", "--glob"], capture_output=True, text=True, check=True
            )
            parts.append(result.stdout.strip())
            logger.info("Configured Hadoop CLASSPATH via 'hadoop classpath --glob'")
        except Exception as e:
            logger.warning(f"'hadoop classpath --glob' failed: {e}. Relying on environment CLASSPATH.")
    else:
        logger.info("hadoop CLI not on PATH; using environment CLASSPATH (expected in Agent Studio).")

    # Ensure the AWS SDK v2 bundle is present (required by the S3A connector).
    for d in _find_aws_sdk_classpath_dirs():
        parts.append(os.path.join(d, "*"))

    existing_cp = os.environ.get("CLASSPATH", "")
    if existing_cp:
        parts.append(existing_cp)

    # Allow arbitrary extra classpath entries without editing this file.
    extra_cp = os.getenv("HDFS_MCP_EXTRA_CLASSPATH", "").strip()
    if extra_cp:
        parts.append(extra_cp)

    os.environ["CLASSPATH"] = ":".join(p for p in parts if p)

configure_hadoop_classpath()

# Import PyArrow AFTER CLASSPATH and environment variables are set
import pyarrow.fs as pafs
from mcp.server.fastmcp import FastMCP

# Initialize MCP Server
mcp = FastMCP(
    "Cloudera Enterprise Storage MCP",
    dependencies=["pyarrow", "mcp"]
)


SUPPORTED_SCHEMES = ("hdfs", "s3a", "abfs", "abfss", "ofs")

# Cache of instantiated HadoopFileSystem objects keyed by (host, user). Each
# HadoopFileSystem instantiation spins up a JVM FileSystem via libhdfs (JNI),
# so we reuse connections across tool calls for the same bucket/user.
_FS_CACHE: Dict[Tuple[str, str], "pafs.HadoopFileSystem"] = {}


def get_user_context() -> str:
    """Extract active CDP user identity from environment.

    RAZ authorizes every storage request against the workload user, so this
    identity determines which Ranger policies apply. In Cloudera Agent Studio /
    CML the workload user is exposed via CDP_WORKLOAD_USER.
    """
    candidate = (os.getenv("CDP_WORKLOAD_USER") or "").strip()
    # Guard against an unexpanded shell placeholder (e.g. a config that literally
    # passes "$CML_USER" without substitution) — such a value would be treated as
    # the identity by RAZ and never match a Ranger policy. Fall back through the
    # env vars CML/Agent Studio actually set for the workload user.
    if not candidate or candidate.startswith("$"):
        if candidate.startswith("$"):
            logger.warning(
                f"CDP_WORKLOAD_USER is unexpanded ('{candidate}'); MCP config env values "
                "are literal (no shell substitution). Falling back to CML_USER / "
                "HADOOP_USER_NAME / USER."
            )
        for var in ("CML_USER", "HADOOP_USER_NAME", "USER"):
            value = (os.getenv(var) or "").strip()
            if value and not value.startswith("$"):
                candidate = value
                break
        else:
            candidate = "default_user"
    logger.info(f"Executing storage request under user context: {candidate}")
    return candidate


def build_raz_conf() -> Dict[str, str]:
    """Return extra Hadoop configuration required for RAZ-authorized access.

    These settings supplement (but do not replace) the RAZ delegation-token
    binding that Cloudera deploys into core-site.xml. Disabling the S3A
    signature cache is explicitly required by Cloudera for RAZ-enabled S3
    access; leaving it enabled can produce spurious authorization failures.
    Any value may be overridden via the HDFS_MCP_EXTRA_CONF environment
    variable (comma-separated key=value pairs).
    """
    conf: Dict[str, str] = {
        # Required by Cloudera for RAZ-enabled S3 access.
        "fs.s3a.signature.cache.max.size": "0",
    }

    extra = os.getenv("HDFS_MCP_EXTRA_CONF", "").strip()
    if extra:
        for pair in extra.split(","):
            pair = pair.strip()
            if not pair or "=" not in pair:
                continue
            key, _, value = pair.partition("=")
            conf[key.strip()] = value.strip()

    return conf


def get_default_fs() -> str:
    """Return the configured default filesystem authority, if any.

    Set HDFS_MCP_DEFAULT_FS (e.g. 's3a://go01-demo') to allow callers to pass
    scheme-less / relative paths (e.g. '/data/logs') that resolve against this
    filesystem. Fully-qualified URIs always take precedence over this default.
    """
    default_fs = os.getenv("HDFS_MCP_DEFAULT_FS", "").strip().rstrip("/")
    if not default_fs:
        return ""

    parsed = urlparse(default_fs)
    if parsed.scheme.lower() not in SUPPORTED_SCHEMES or not parsed.netloc:
        raise ValueError(
            f"Invalid HDFS_MCP_DEFAULT_FS '{default_fs}'. Expected a fully "
            "qualified authority such as 's3a://bucket' or 'hdfs://nameservice1'."
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc}"


def resolve_filesystem(path_uri: str) -> Tuple[pafs.FileSystem, str]:
    """
    Parse a fully-qualified storage URI and return a PyArrow HadoopFileSystem
    configured for CDP RAZ, alongside the path relative to that filesystem.

    Access is routed through libhdfs (the JNI bridge to the Java Hadoop
    client) rather than PyArrow's native S3FileSystem. This is deliberate:
    RAZ authorization is enforced in the Java S3A connector, so the native
    S3 client would bypass RAZ entirely.

    Note on connecting to non-HDFS schemes (s3a/abfs/ofs)
    -----------------------------------------------------
    PyArrow's HadoopFileSystem hardcodes the ``hdfs://`` scheme onto any
    explicit ``host`` value. Passing ``host="s3a://bucket"`` therefore
    produces a namenode of ``hdfs://s3a://bucket`` and fails with
    ``UnknownHostException: s3a``. The only host that escapes this behavior
    is the literal ``"default"``, which makes libhdfs use ``fs.defaultFS``.
    So we always connect with ``host="default"`` and, for a URI that carries
    an authority (bucket / container / volume / nameservice), override
    ``fs.defaultFS`` via ``extra_conf`` so libhdfs instantiates the correct
    Java FileSystem (S3A, ABFS, Ozone, or HDFS). Paths are then resolved
    relative to that default filesystem.

    Scheme-less / relative paths (e.g. ``/data/logs``) are supported only when
    HDFS_MCP_DEFAULT_FS is configured; they resolve against that filesystem.
    """
    parsed = urlparse(path_uri)
    scheme = parsed.scheme.lower()

    if scheme:
        if scheme not in SUPPORTED_SCHEMES:
            raise ValueError(
                f"Unsupported filesystem scheme: '{scheme}'. "
                "Supported schemes: hdfs://, s3a://, abfs://, abfss://, ofs://"
            )
        # The authority (e.g. the S3 bucket in s3a://go01-demo/...) becomes the
        # default filesystem. If a scheme is given without an authority
        # (e.g. hdfs:///path) we honor that scheme's core-site.xml fs.defaultFS
        # rather than the HDFS_MCP_DEFAULT_FS override (which is reserved for
        # scheme-less paths) to avoid silently redirecting to another store.
        default_fs = f"{scheme}://{parsed.netloc}" if parsed.netloc else None
        relative_path = parsed.path if parsed.path else "/"
    else:
        # No scheme: resolve the bare path against the configured default FS.
        default_fs = get_default_fs()
        if not default_fs:
            raise ValueError(
                f"Path '{path_uri}' has no filesystem scheme. Provide a fully "
                "qualified URI (e.g. 's3a://bucket/path') or set HDFS_MCP_DEFAULT_FS."
            )
        rel = parsed.path or path_uri
        relative_path = rel if rel.startswith("/") else f"/{rel}"

    user = get_user_context()
    cache_key = (default_fs or "default", user)

    fs = _FS_CACHE.get(cache_key)
    if fs is None:
        extra_conf = build_raz_conf()
        if default_fs:
            extra_conf["fs.defaultFS"] = default_fs
        try:
            fs = pafs.HadoopFileSystem(
                host="default",
                port=0,
                user=user,
                extra_conf=extra_conf,
            )
            _FS_CACHE[cache_key] = fs
            logger.info(
                f"Initialized RAZ-authorized filesystem "
                f"(fs.defaultFS='{default_fs or '<core-site>'}') as user '{user}'"
            )
        except Exception as e:
            logger.error(f"Failed to initialize filesystem for {path_uri}: {str(e)}")
            raise RuntimeError(f"Storage connection failed via RAZ: {str(e)}")

    return fs, relative_path


@mcp.tool()
def list_directory(path: str, recursive: bool = False) -> List[Dict[str, Any]]:
    """
    List files and subdirectories in a directory across HDFS, S3a, ADLS, or Ozone.
    
    :param path: Fully qualified URI (e.g., 's3a://go01-demo/data/', 'hdfs:///data/logs', 'ofs://ozone1/vol/bucket/dir')
    :param recursive: If True, lists subdirectories recursively.
    :return: List of object metadata dictionaries (path, type, size, mtime).
    """
    fs, clean_path = resolve_filesystem(path)
    
    selector = pafs.FileSelector(clean_path, recursive=recursive)
    try:
        file_infos = fs.get_file_info(selector)
        results = []
        
        for info in file_infos:
            file_type = "directory" if info.type == pafs.FileType.Directory else "file"
            results.append({
                "path": info.path,
                "name": info.base_name,
                "type": file_type,
                "size_bytes": info.size,
                "mtime": info.mtime.isoformat() if info.mtime else None
            })
        return results
    except Exception as e:
        return [{"error": f"Failed to list directory '{path}': {str(e)}"}]


@mcp.tool()
def open_file(
    path: str, 
    max_bytes: int = 1048576, 
    offset: int = 0, 
    encoding: str = "utf-8"
) -> Dict[str, Any]:
    """
    Open and read content from a file in HDFS, S3a, ADLS, or Ozone via RAZ authentication.
    
    :param path: Fully qualified URI (e.g., 's3a://go01-demo/warehouse/table/part1.csv')
    :param max_bytes: Maximum bytes to read to protect context window (default 1MB).
    :param offset: Byte offset to start reading from.
    :param encoding: String encoding (default 'utf-8'). Use 'bytes' for raw hex output.
    :return: File content metadata and body payload.
    """
    fs, clean_path = resolve_filesystem(path)
    
    try:
        info = fs.get_file_info(clean_path)
        if info.type == pafs.FileType.Directory:
            return {"error": f"Path '{path}' is a directory, not a file."}
        
        total_size = info.size
        
        with fs.open_input_stream(clean_path) as stream:
            if offset > 0:
                stream.seek(offset)
            
            data = stream.read(max_bytes)
            truncated = (offset + len(data)) < total_size
            
            if encoding == "bytes":
                content = data.hex()
            else:
                content = data.decode(encoding, errors="replace")

            return {
                "path": path,
                "total_file_size": total_size,
                "bytes_read": len(data),
                "offset": offset,
                "truncated": truncated,
                "content": content
            }
            
    except Exception as e:
        return {"error": f"Failed to read file '{path}': {str(e)}"}


@mcp.tool()
def diagnose_environment() -> Dict[str, Any]:
    """
    Report storage/classpath diagnostics for troubleshooting RAZ + S3A access.

    Returns key environment variables, the effective CLASSPATH, the resolved
    workload user, and — crucially — whether the AWS SDK v2 class required by
    the S3A connector can be located on disk (and in which jar). Use this when
    s3a:// access fails with ClassNotFoundException.
    """
    env_keys = [
        "JAVA_HOME", "HADOOP_HOME", "HADOOP_CONF_DIR", "ARROW_LIBHDFS_DIR",
        "LD_LIBRARY_PATH", "LIBHDFS_OPTS", "CDP_WORKLOAD_USER", "USER", "CML_USER",
        "HDFS_MCP_DEFAULT_FS", "HDFS_MCP_AWS_SDK_DIR",
        "HDFS_MCP_EXTRA_CLASSPATH", "HDFS_MCP_CLASSPATH_SEARCH_ROOTS",
        "HDFS_MCP_TRUSTSTORE",
    ]
    classpath = os.environ.get("CLASSPATH", "")
    truststore_loc = _ACTIVE_TRUSTSTORE

    # Locate the marker class across all discoverable jars (authoritative check).
    marker_jars: List[str] = []
    scanned = 0
    for root in _classpath_search_roots():
        for jar in _list_jars(root):
            scanned += 1
            if scanned > _MAX_JARS_TO_SCAN:
                break
            if _jar_contains_class(jar, _AWS_SDK_MARKER_CLASS):
                if jar not in marker_jars:
                    marker_jars.append(jar)

    return {
        "resolved_user": get_user_context(),
        "env": {k: os.environ.get(k) for k in env_keys},
        "classpath_entry_count": len([p for p in classpath.split(":") if p]),
        "classpath": classpath,
        "aws_sdk_marker_class": _AWS_SDK_MARKER_CLASS,
        "aws_sdk_marker_jars": marker_jars,
        "aws_sdk_marker_found": bool(marker_jars),
        "classpath_search_roots": _classpath_search_roots(),
        "jars_scanned": scanned,
        "tls_truststore": truststore_loc or None,
        "tls_truststore_found": bool(truststore_loc),
        "tls_ca_pem_files": _ca_pem_files(),
        "tls_system_ca_bundles": _ca_bundle_files(),
        "tls_base_cacerts": _default_cacerts() or None,
        "tls_keytool": _keytool(),
        "tls_candidate_java_homes": _candidate_java_homes(),
        "supported_schemes": list(SUPPORTED_SCHEMES),
    }


def main():
    mcp.run()


if __name__ == "__main__":
    main()
