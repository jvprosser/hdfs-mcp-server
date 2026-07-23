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
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

# 1. Force Python logging to stderr to keep stdout clean for MCP JSON-RPC traffic
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger("hdfs-mcp-server")

# 2. Silence log4j / Hadoop stdout output
os.environ["HADOOP_ROOT_LOGGER"] = "WARN,console"
os.environ["LIBHDFS_OPTS"] = "-Dlog4j.configuration=file:///dev/null"

# 3. Dynamically discover full Hadoop Classpath (includes HDFS, S3A, ADLS, Ozone, RAZ)
def configure_hadoop_classpath():
    try:
        cmd = ["hadoop", "classpath", "--glob"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        discovered_cp = result.stdout.strip()
        
        existing_cp = os.environ.get("CLASSPATH", "")
        # Prepend /etc/hadoop/conf so site XMLs take priority
        os.environ["CLASSPATH"] = f"/etc/hadoop/conf:{discovered_cp}:{existing_cp}"
        logger.info("Successfully configured Hadoop CLASSPATH via 'hadoop classpath --glob'")
    except Exception as e:
        logger.warning(f"Could not execute 'hadoop classpath --glob': {e}. Relying on environment CLASSPATH.")

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
    user = os.getenv("CDP_WORKLOAD_USER") or os.getenv("USER") or "default_user"
    logger.info(f"Executing storage request under user context: {user}")
    return user


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
    """
    parsed = urlparse(path_uri)
    scheme = parsed.scheme.lower()

    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(
            f"Unsupported filesystem scheme: '{scheme}'. "
            "Supported schemes: hdfs://, s3a://, abfs://, abfss://, ofs://"
        )

    # The authority (e.g. the S3 bucket in s3a://go01-demo/...) becomes the
    # default filesystem. If absent (e.g. hdfs:///path) we fall back to the
    # fs.defaultFS already configured in core-site.xml.
    default_fs = f"{scheme}://{parsed.netloc}" if parsed.netloc else None

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

    relative_path = parsed.path if parsed.path else "/"
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


def main():
    mcp.run()


if __name__ == "__main__":
    main()
