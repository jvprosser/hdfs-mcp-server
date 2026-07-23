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
		  "--from",
		  "git+https://github.com/jvprosser/hdfs-mcp-server.git",
		  "hdfs-mcp-server"
	    ],
	    "env": {
		  "HADOOP_CONF_DIR": "/etc/hadoop/conf",
		  "ARROW_LIBHDFS_DIR": "/runtime-addons/hadoop-cli-7.3.1.101-c2jhs/usr/lib",
		  "JAVA_HOME": "/usr/lib/jvm/java-8-openjdk-amd64",
		  "CLASSPATH": "/etc/hadoop/conf:/usr/lib/hadoop/*:/usr/lib/hadoop/lib/*:/usr/lib/hadoop-hdfs/*:/usr/lib/hadoop-hdfs/lib/*",
		  "CDP_WORKLOAD_USER": "$CML_USER"
	    }
	  }
    }
}
