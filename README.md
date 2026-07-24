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

1. The container must have the Hadoop **classpath** (including `hadoop-aws`, the
   **AWS SDK v2 bundle** (`bundle-*.jar`), and `ranger-raz` jars) and
   `/etc/hadoop/conf` on the `CLASSPATH` so `core-site.xml` (which carries the RAZ
   delegation-token binding) is loaded. The server auto-runs `hadoop classpath
   --glob` at startup, prepends `/etc/hadoop/conf`, and **auto-discovers the AWS
   SDK v2 bundle jar** (see below).
2. The workload user identity is taken from `CDP_WORKLOAD_USER` (mapped from
   `$CML_USER`). RAZ authorizes the `s3a://bucket/path` request against the Ranger
   policies for **that** user.
3. The server sets `fs.s3a.signature.cache.max.size=0`, which Cloudera requires for
   RAZ-enabled S3 access. Additional Hadoop settings can be supplied via the
   `HDFS_MCP_EXTRA_CONF` environment variable as comma-separated `key=value` pairs,
   e.g. `HDFS_MCP_EXTRA_CONF="fs.s3a.connection.maximum=100,fs.s3a.threads.max=64"`.

### Default filesystem (optional)

By default every tool call must pass a **fully-qualified URI** (e.g.
`s3a://YOURBUCKET/data/logs`). For single-bucket deployments you can set
`HDFS_MCP_DEFAULT_FS` (e.g. `s3a://YOURBUCKET`) so that **scheme-less / relative
paths** like `/data/logs` resolve against that bucket. Fully-qualified URIs always
take precedence over this default.

```json
"env": {
  "HDFS_MCP_DEFAULT_FS": "s3a://YOURBUCKET"
}
```

### AWS SDK v2 bundle on the classpath

CDP's S3A connector uses the **AWS SDK v2** (`software.amazon.awssdk`), shipped as a
shaded `bundle-<version>.jar`. That jar lives in the Hadoop *tools* area, which
`hadoop classpath` does **not** include by default, so instantiating an `s3a://`
filesystem otherwise fails with:

```
ClassNotFoundException: software.amazon.awssdk.transfer.s3.progress.TransferListener
```

On startup the server scans `HADOOP_HOME`, `ARROW_LIBHDFS_DIR` (and its parent),
`/runtime-addons`, and `/opt/cloudera/parcels` and locates the **jar that actually
contains** `software/amazon/awssdk/transfer/s3/progress/TransferListener.class`
(matching by class content, not filename, since CDP may ship the SDK either as a
shaded `bundle-*.jar` or as separate module jars like `s3-transfer-manager-*.jar`).
The directory holding that jar is added to the classpath. If your layout differs:

* Set `HDFS_MCP_AWS_SDK_DIR` to the directory that contains the AWS SDK jar(s), **or**
* Set `HDFS_MCP_CLASSPATH_SEARCH_ROOTS` (colon-separated) to add search roots, **or**
* Set `HDFS_MCP_EXTRA_CLASSPATH` to any extra classpath entries to append.

Use the **`diagnose_environment`** tool to see the effective `CLASSPATH`, resolved
workload user, and whether the required AWS SDK class was located (and in which jar).

To locate it manually in your environment:

```bash
for j in $(find / -name '*.jar' 2>/dev/null); do \
  unzip -l "$j" 2>/dev/null | grep -q 'transfer/s3/progress/TransferListener' && echo "FOUND: $j"; \
done
```

> Do not put both the AWS SDK **v1** (`aws-java-sdk-bundle-*.jar`) and **v2**
> (`bundle-*.jar`) on the classpath at the same time unless required — mixing SDK
> versions can cause linkage errors. Prefer the v2 `bundle-*.jar` that matches the
> Hadoop version.

### TLS truststore (certificate validation)

The AWS SDK v2 HTTP client validates the S3/RAZ endpoint certificate against the
**JVM truststore**. In a CDP RAZ environment the correct truststore is Hadoop's
`ssl-client.xml` → `ssl.client.truststore.location` (the CM AutoTLS global
truststore), which trusts both the internal RAZ endpoint and the public CAs used by
S3. Without it you get:

```
SSLHandshakeException: No trusted certificate found
```

Some CDP runtimes ship a **reduced `ca-certificates-java` keystore that omits public
roots** (e.g. Amazon/Starfield) that AWS S3 endpoints chain to — so the default
`cacerts` fails even for public S3, even though the individual PEM files exist under
`/etc/ssl/certs`.

**Agent Studio sandbox note:** MCP servers run inside a bubblewrap sandbox with an
isolated filesystem. `/runtime-addons` (and its JVM) is mounted, but `/etc/ssl` and
`/usr/lib/jvm` typically are **not**. To stay self-sufficient the server therefore:

* **bundles the public AWS root CAs** (Amazon Root CA 1–4 + Starfield Services Root
  CA G2) inside the package (`hdfs_mcp_server/cacerts/*.pem`), so they're always
  importable regardless of what the sandbox mounts; and
* discovers `cacerts`/`keytool` from the **runtime-addon JVM** (under
  `/runtime-addons/.../usr/lib/jvm/`) in addition to `JAVA_HOME`.

On startup the server resolves a truststore as follows:

1. If `HDFS_MCP_TRUSTSTORE` (+ `HDFS_MCP_TRUSTSTORE_PASSWORD`) is set, use it as-is.
2. Otherwise it **builds** a truststore (cached at `HDFS_MCP_TRUSTSTORE_CACHE`,
   default `/tmp/hdfs-mcp-truststore.jks`) = a copy of a discovered JVM `cacerts`,
   **plus** public CA PEMs (the bundled Amazon/Starfield roots, and — when present —
   `Amazon_Root_CA_*.pem` + `Starfield_*.pem` under `/etc/ssl/certs`), **plus** any
   internal/CM truststore (`ssl-client.xml` `ssl.client.truststore.location` or a
   known CDP AutoTLS path) so the RAZ endpoint stays trusted.

It injects `-Djavax.net.ssl.trustStore[Password]` into `LIBHDFS_OPTS` (without
clobbering any value you already set). `diagnose_environment` reports the resolved
truststore under `tls_truststore` and the imported PEMs under `tls_ca_pem_files`.

Related overrides:

* `HDFS_MCP_CA_PEM_GLOBS` — colon-separated globs of CA PEM files to import
  (defaults to Amazon/Starfield). Widen this for other clouds (ADLS/GCS).
* `HDFS_MCP_EXTRA_CA_PEM` — colon-separated extra CA PEM files or directories
  (e.g. an internal RAZ CA).

### Why the bucket is passed as `fs.defaultFS`

PyArrow's `HadoopFileSystem` forces the `hdfs://` scheme onto any explicit `host`
value, so connecting with `host="s3a://bucket"` produces a namenode of
`hdfs://s3a://bucket` and fails with `UnknownHostException: s3a`. The only host
string that bypasses this is the literal `"default"`, which tells libhdfs to use
`fs.defaultFS`. The server therefore connects with `host="default"` and overrides
`fs.defaultFS` (via `extra_conf`) to the target authority — e.g.
`s3a://YOURBUCKET` — so libhdfs instantiates the correct Java `S3AFileSystem`
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
        "--refresh",
        "--reinstall",
        "--from",
        "git+https://github.com/jvprosser/hdfs-mcp-server.git",
        "hdfs-mcp-server"
      ],
      "env": {
        "HADOOP_CONF_DIR": "/etc/hadoop/conf",
        "JAVA_HOME": "/usr/lib/jvm/java-8-openjdk-amd64",
        "ARROW_LIBHDFS_DIR": "/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib",
        "LD_LIBRARY_PATH": "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/server:/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/native",
        "CLASSPATH": "/etc/hadoop/conf:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-hdfs/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-hdfs/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-mapreduce/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-mapreduce/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-aws/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-aws/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-azure/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/hadoop-azure/lib/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/ranger-raz/*:/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib/ranger-raz/lib/*:/usr/lib/hadoop-aws/*:/usr/lib/hadoop-aws/lib/*:/usr/lib/ranger-raz/*:/usr/lib/ranger-raz/lib/*",
        "CDP_WORKLOAD_USER": "$CML_USER"
      }
    }
  }
}
