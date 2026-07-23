# /// script
# dependencies = [
#     "mcp[cli]>=0.1.0",
#     "pyarrow>=14.0.0",
# ]
# ///

import os
import sys
import logging
from typing import List, Dict, Any
from urllib.parse import urlparse
from mcp.server.fastmcp import FastMCP
import pyarrow.fs as pafs

# Ensure python logging streams to stderr to protect the MCP stdout JSON channel
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger("hdfs-mcp-server")

# Prevent log4j / Hadoop stdout noise
os.environ["HADOOP_ROOT_LOGGER"] = "WARN,console"
os.environ["LIBHDFS_OPTS"] = "-Dlog4j.configuration=file:///dev/null"

# Initialize FastMCP Server
mcp = FastMCP(
    "Cloudera Enterprise Storage MCP",
    dependencies=["pyarrow", "mcp"]
)


def get_user_context() -> str:
    """Extract active CDP user identity from environment."""
    user = os.getenv("CDP_WORKLOAD_USER") or os.getenv("USER") or "default_user"
    logger.info(f"Executing storage request under user context: {user}")
    return user


def get_hadoop_filesystem() -> pafs.FileSystem:
    """
    Instantiates PyArrow HadoopFileSystem with host='default'.
    Setting host='default' forces libhdfs to use core-site.xml and 
    delegate scheme routing (hdfs://, s3a://, abfs://, ofs://) to Java Hadoop.
    """
    try:
        return pafs.HadoopFileSystem(
            host="default",
            port=0,
            user=get_user_context()
        )
    except Exception as e:
        logger.error(f"Failed to initialize HadoopFileSystem: {str(e)}")
        raise RuntimeError(f"Storage connection failed via RAZ: {str(e)}")


def validate_scheme(path_uri: str) -> str:
    """Validates that the URI scheme is supported."""
    parsed = urlparse(path_uri)
    scheme = parsed.scheme.lower()
    
    if scheme not in ["hdfs", "s3a", "abfs", "abfss", "ofs"]:
        raise ValueError(
            f"Unsupported filesystem scheme: '{scheme}'. "
            "Supported schemes: hdfs://, s3a://, abfs://, ofs://"
        )
    return path_uri


@mcp.tool()
def list_directory(path: str, recursive: bool = False) -> List[Dict[str, Any]]:
    """
    List files and subdirectories in a directory across HDFS, S3a, ADLS, or Ozone.
    
    :param path: Fully qualified URI (e.g., 's3a://go01-demo/data/', 'hdfs:///data/logs', 'ofs://ozone1/vol/bucket/dir')
    :param recursive: If True, lists subdirectories recursively.
    :return: List of object metadata dictionaries (path, type, size, mtime).
    """
    try:
        clean_path = validate_scheme(path)
        fs = get_hadoop_filesystem()
        
        selector = pafs.FileSelector(clean_path, recursive=recursive)
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
    try:
        clean_path = validate_scheme(path)
        fs = get_hadoop_filesystem()
        
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
