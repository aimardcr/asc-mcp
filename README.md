# asc-mcp

`asc-mcp` is a read-only Model Context Protocol server for agent-driven static
analysis of Android artifacts. It gives MCP clients structured access to APK
metadata, DEX declarations and instructions, targeted decompilation,
cross-references, resources, signing data, and artifact comparison. There is no
manual decompilation CLI; running `asc-mcp` starts the server.

This project is an MCP-focused continuation of
[Droid ASC](https://github.com/MG1937/ASC), created by
[MG1937](https://github.com/MG1937). The original author designed and
implemented ASC's direct DEX querying, cross-reference engine, minimal-DEX
reconstruction, and on-demand decompilation architecture. The MCP server and its
structured analysis interface are built on that work.

The original ASC project was presented at
[Black Hat Europe Arsenal](https://blackhat.com/europe/arsenal/schedule/index.html#droid-asc-r8-compiler-optimization-as-a-decompiler-primitive-54834)
as "R8 Compiler Optimization as a DeCompiler Primitive." Its published 352 MB
benchmark reported global cross-reference search in 1.79 seconds and class
decompilation in 177 milliseconds using 141 MB of RAM. Those figures describe
the original benchmark, not a guarantee for every artifact or MCP client.

![Benchmark](./docs/benchmark_all_en.png)

## Features

- Structured manifest, package, SDK, permission, and component analysis
- Class listing, outlines, on-demand Java source, and Dalvik disassembly
- Descriptor-aware string, type, method, and field cross-reference search
- Reference evidence with opcode, method-relative offset, access type, and exact target
- Method and field discovery, DEX string search, and method-body search
- Class hierarchy and bounded caller/callee graphs
- Resource inventory, binary XML decoding, and native-library discovery
- APK signing schemes, certificate fingerprints, and embedded-secret scanning
- Class-inventory comparison between artifact versions
- MCP resources for decoded manifests and decompiled class source
- Isolated analysis workers that protect the MCP process from decompiler globals
- Bounded worker caches for repeated class, DEX, and identical reference queries

All analysis tools are read-only. The server does not install, modify, rebuild,
or sign APK files.

## Supported inputs

| Format | Support |
| --- | --- |
| `.apk` | Full manifest, DEX, resources, native libraries, and signing analysis |
| `.dex` | Full DEX class, search, reference, disassembly, and decompilation analysis |
| `.jar` | Full DEX analysis when DEX is embedded, plus JVM `.class` inventory |
| `.aar` | Archive and JVM class inventory, including classes inside embedded JARs |
| `.aab`, `.apks`, `.xapk`, `.zip` | Archive inventory and analysis of directly embedded DEX files |

`load_artifact` reports a capability list for each file. Operations that require
an unavailable structure, such as requesting signing data from a DEX file, fail
with a clear MCP tool error. JVM bytecode decompilation is not currently included;
ordinary JAR files expose their class and archive inventories.

## Install

Python 3.10 or newer is required.

```bash
python -m pip install .
```

The Python distribution and installed executable are both named `asc-mcp`:

```bash
asc-mcp
```

`asc-mcp` starts an MCP server over stdio. It does not provide manual
decompilation subcommands.

## MCP client configuration

Configure an MCP host to launch the installed command:

```json
{
  "mcpServers": {
    "asc-mcp": {
      "command": "asc-mcp",
      "env": {
        "ASC_MCP_ALLOWED_ROOTS": "/home/user/apks:/work/mobile"
      }
    }
  }
}
```

On Windows, separate multiple allowed roots with `;` instead of `:`. If
`ASC_MCP_ALLOWED_ROOTS` is omitted, only the server's working directory is
accessible.

Typical agent workflow:

1. Call `load_artifact` with an allowed artifact path.
2. Reuse the returned `analysis_id` with the analysis tools.
3. Use descriptors returned by `apk_get_class_outline` unchanged when selecting
   overloaded methods or fields.
4. Call `close_artifact` when the analysis is no longer needed.

## MCP tools

| Area | Tools |
| --- | --- |
| Lifecycle | `load_artifact`, `close_artifact`, `server_status` |
| Artifact overview | `apk_get_summary`, `apk_get_manifest`, `apk_get_signing_info` |
| Classes | `apk_list_classes`, `apk_get_class_outline`, `apk_get_class_source`, `apk_get_class_hierarchy` |
| Code | `apk_disassemble_method`, `apk_get_call_graph`, `apk_get_string_constants`, `apk_search_method_bodies` |
| References | `apk_find_method_references`, `apk_find_field_references`, `apk_find_type_instructions`, `apk_find_string_references` |
| Search | `apk_search_members`, `apk_search_strings`, `apk_scan_secrets` |
| Contents | `apk_list_entries`, `apk_get_resource_content`, `apk_list_native_libraries` |
| Comparison | `apk_diff` |

List and search results are paginated and capped. Tool results use MCP structured
output schemas rather than human-formatted CLI text.

The server publishes routing instructions, tool descriptions, and descriptions
for every input parameter so MCP clients can choose calls without relying on this
README. The most important search distinctions are:

| Intent | Tool | Example input |
| --- | --- | --- |
| Find a declared method or field | `apk_search_members` | `kind="method", query="<init>"` |
| Find direct method call sites | `apk_find_method_references` | `class_name="com.example.Controller", method_name="<init>", descriptor="(Landroid/content/Context;)V"` |
| Find field reads and writes | `apk_find_field_references` | `class_name="com.example.Config", field_name="apiKey", field_type="Ljava/lang/String;"` |
| Find explicit type instructions | `apk_find_type_instructions` | `type_name="com.example.Config"` |
| Search literal values in the DEX string pool | `apk_search_strings` | `query="https://"` |
| Find where matching strings are loaded | `apk_find_string_references` | `value="https://"` |
| Search rendered opcode or operand text | `apk_search_method_bodies` | `query="invoke-virtual"` |

`apk_find_type_instructions` covers type operands such as `new-instance`,
`check-cast`, and `const-class`; it does not include method calls, field accesses,
signatures, or declarations. Empty reference results include a hint explaining
their scope and the next appropriate tool. Every reference hit includes evidence
for each matching instruction: its byte offset within the caller, opcode,
read/write/invoke/load classification, and structured target metadata.

Repeated work on the same unchanged artifact reuses bounded per-worker caches.
The cache covers inflated DEX buffers, parsed lightweight and Androguard DEX
objects, class inventories, call-graph indexes, and identical reference queries.
Cache keys include file size and modification time, so replacing an artifact
does not reuse stale analysis data.

## Resources and prompts

The server exposes these resource templates:

- `artifact://{analysis_id}/manifest.xml`
- `artifact://{analysis_id}/class/{class_name}`

It also includes `artifact_triage`, `trace_behavior`, and `compare_artifacts` prompts.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `ASC_MCP_ALLOWED_ROOTS` | Current directory | Filesystem roots from which artifacts may be opened |
| `ASC_MCP_WORKERS` | Up to 4 CPUs | Spawned analysis worker count |
| `ASC_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |
| `ASC_MCP_HOST` | `127.0.0.1` | HTTP bind address |
| `ASC_MCP_PORT` | `8000` | HTTP port |
| `ASC_MCP_HTTP_PATH` | `/mcp` | Streamable HTTP endpoint |

Do not expose Streamable HTTP to untrusted networks without an authenticated
deployment boundary. The stdio transport is recommended for local analysis.

## Development

```bash
python -m pip install -r requirements.txt
python tests/run_tests.py --require-decompiler --suite unit
python tests/run_tests.py --require-decompiler --suite integration
python tests/benchmark_startup.py --samples 9
python tests/benchmark_reference.py --samples 9
```

The integration suite starts an in-process MCP client and exercises a spawned
analysis worker. The release test also validates the deterministic source
archive outside the checkout.

## Original ASC sponsors

These sponsors are credited by the original Droid ASC project:

| Sponsor | Amount |
| --- | ---: |
| [HTTChina](https://github.com/HTTChina) | 5000￥ |
| [c01ns](https://github.com/c01ns) | 11.9￥ |
| [gguowang](https://github.com/gguowang) and [cococount](https://github.com/cococount) | 2￥ |
| [Ylarod](https://github.com/Ylarod) | 50.11￥ |

## Acknowledgements

Primary credit goes to [MG1937](https://github.com/MG1937) for creating
[Droid ASC](https://github.com/MG1937/ASC) and its core analysis engine. Thanks
also to [Androguard](https://github.com/androguard/androguard) for the Android
reverse-engineering and DEX analysis foundation, and to the
[Model Context Protocol Python SDK](https://github.com/modelcontextprotocol/python-sdk)
for the server runtime.

Licensed under Apache-2.0.
