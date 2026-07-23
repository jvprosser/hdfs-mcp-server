# /// script
# dependencies = [
#     "mcp[cli]>=0.1.0",
#     "pyarrow>=14.0.0",
# ]
# ///

import os
import sys
import logging
import subprocess
import zipfile
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

# 1. Force Python logging to stderr to keep stdout clean for MCP JSON-RPC traffic
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger("hdfs-mcp-server")

# 2. Silence log4j / Hadoop stdout output
os.environ["HADOOP_ROOT_LOGGER"] = "WARN,console"
os.environ["LIBHDFS_OPTS"] = "-Dlog4j.configuration=file:///dev/null"

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

    try:
        result = subprocess.run(
            ["hadoop", "classpath", "--glob"], capture_output=True, text=True, check=True
        )
        parts.append(result.stdout.strip())
        logger.info("Configured Hadoop CLASSPATH via 'hadoop classpath --glob'")
    except Exception as e:
        logger.warning(f"Could not execute 'hadoop classpath --glob': {e}. Relying on environment CLASSPATH.")

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
    # the identity by RAZ and never match a Ranger policy.
    if not candidate or candidate.startswith("$"):
        if candidate.startswith("$"):
            logger.warning(
                f"CDP_WORKLOAD_USER is unexpanded ('{candidate}'); falling back to $USER. "
                "Ensure the platform substitutes the value (e.g. set CDP_WORKLOAD_USER "
                "to the real workload user)."
            )
        candidate = (os.getenv("USER") or "").strip() or "default_user"
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
        "LD_LIBRARY_PATH", "CDP_WORKLOAD_USER", "USER",
        "HDFS_MCP_DEFAULT_FS", "HDFS_MCP_AWS_SDK_DIR",
        "HDFS_MCP_EXTRA_CLASSPATH", "HDFS_MCP_CLASSPATH_SEARCH_ROOTS",
    ]
    classpath = os.environ.get("CLASSPATH", "")

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
        "supported_schemes": list(SUPPORTED_SCHEMES),
    }


def main():
    mcp.run()


if __name__ == "__main__":
    main()
