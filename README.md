# hdfs-mcp-server
Handy Cloudera HDFS tools
# HDFS & Enterprise Storage MCP Server

An Model Context Protocol (MCP) Server for **Cloudera Agent Studio**. Provides seamless access to files stored in **HDFS**, **S3a**, **ADLS (ABFS)**, and **Apache Ozone (OFS)** using CDP's **Ranger Authorization Service (RAZ)** and user workload session context.

---

## How RAZ authorization works (S3A)

Access is routed through **`libhdfs`** (the JNI bridge to the Java Hadoop client) via
PyArrow's `HadoopFileSystem` — **not** PyArrow's native `S3FileSystem`. This is
intentional:

* RAZ authorization is enforced inside the **Java S3A connector**. Every `s3a://`
  request is intercepted and authorized against **Ranger policies** for the active
  workload user before it reaches S3.
* PyArrow's native `S3FileSystem` talks directly to AWS via the C++ SDK and would
  **bypass RAZ entirely**, so it is not used here.

For this to work:

1. The container must have the Hadoop **classpath** (including `hadoop-aws` and
   `ranger-raz` jars) and `/etc/hadoop/conf` on the `CLASSPATH` so `core-site.xml`
   (which carries the RAZ delegation-token binding) is loaded. The server auto-runs
   `hadoop classpath --glob` at startup and prepends `/etc/hadoop/conf`.
2. The workload user identity is taken from `CDP_WORKLOAD_USER` (mapped from
   `$CML_USER`). RAZ authorizes the `s3a://bucket/path` request against the Ranger
   policies for **that** user.
3. The server sets `fs.s3a.signature.cache.max.size=0`, which Cloudera requires for
   RAZ-enabled S3 access. Additional Hadoop settings can be supplied via the
   `HDFS_MCP_EXTRA_CONF` environment variable as comma-separated `key=value` pairs,
   e.g. `HDFS_MCP_EXTRA_CONF="fs.s3a.connection.maximum=100,fs.s3a.threads.max=64"`.

### Default filesystem (optional)

By default every tool call must pass a **fully-qualified URI** (e.g.
`s3a://go01-demo/data/logs`). For single-bucket deployments you can set
`HDFS_MCP_DEFAULT_FS` (e.g. `s3a://go01-demo`) so that **scheme-less / relative
paths** like `/data/logs` resolve against that bucket. Fully-qualified URIs always
take precedence over this default.

```json
"env": {
  "HDFS_MCP_DEFAULT_FS": "s3a://go01-demo"
}
```

### Why the bucket is passed as `fs.defaultFS`

PyArrow's `HadoopFileSystem` forces the `hdfs://` scheme onto any explicit `host`
value, so connecting with `host="s3a://bucket"` produces a namenode of
`hdfs://s3a://bucket` and fails with `UnknownHostException: s3a`. The only host
string that bypasses this is the literal `"default"`, which tells libhdfs to use
`fs.defaultFS`. The server therefore connects with `host="default"` and overrides
`fs.defaultFS` (via `extra_conf`) to the target authority — e.g.
`s3a://go01-demo` — so libhdfs instantiates the correct Java `S3AFileSystem`
(where RAZ is enforced). Requested paths are then resolved relative to that bucket.

---

## Included Tools

* **`list_directory(path: str, recursive: bool = False)`**: Lists entries inside target URI.
* **`open_file(path: str, max_bytes: int = 1048576, offset: int = 0, encoding: str = "utf-8")`**: Reads contents of target file safely with context guardrails.

---

## Configuration for Cloudera Agent Studio

Add the following to your MCP settings inside CML / Agent Studio:

```json
{
  "mcpServers": {
    "hdfs-mcp-server": {
      "command": "uvx",
      "args": [
        "--quiet",
        "--from",
        "git+https://github.com/jvprosser/hdfs-mcp-server.git",
        "hdfs-mcp-server"
      ],
      "env": {
        "HADOOP_CONF_DIR": "/etc/hadoop/conf",
        "JAVA_HOME": "/usr/lib/jvm/java-8-openjdk-amd64",
        "ARROW_LIBHDFS_DIR": "/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib",
        "LD_LIBRARY_PATH": "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/server:/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/native",
        "CLASSPATH": "/etc/hadoop/conf:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-hdfs/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-hdfs/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-aws/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-aws/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-azure/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-azure/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/ranger-raz/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/ranger-raz/lib/*:/usr/lib/hadoop-aws/*:/usr/lib/hadoop-aws/lib/*:/usr/lib/ranger-raz/*:/usr/lib/ranger-raz/lib/*",
        "CDP_WORKLOAD_USER": "$CML_USER"
      }
    }
  }
}
