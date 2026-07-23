# hdfs-mcp-server
Handy Cloudera HDFS tools
# HDFS & Enterprise Storage MCP Server

An Model Context Protocol (MCP) Server for **Cloudera Agent Studio**. Provides seamless access to files stored in **HDFS**, **S3a**, **ADLS (ABFS)**, and **Apache Ozone (OFS)** using CDP's **Ranger Authorization Service (RAZ)** and user workload session context.

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
