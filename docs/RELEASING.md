# Releases

ASC MCP supports APK, DEX, JAR, AAB, AAR, APKS, XAPK, and ZIP inputs and requires
Python 3.10 or newer. A source archive contains the standard
Python project metadata and can be installed after extraction:

```sh
python -m pip install .
asc-mcp
```

The server uses stdio unless `ASC_MCP_TRANSPORT=streamable-http` is set. Configure
`ASC_MCP_ALLOWED_ROOTS` before opening artifact files.

## Maintainers

Merge the release candidate into the development branch, then tag the intended
commit with `vMAJOR.MINOR.PATCH` or a supported prerelease suffix and push the
tag. The release workflow compares performance against the tag's first parent,
runs the unit and integration suites, builds the deterministic source archive,
and publishes only after every gate passes.

PR CI tests Python 3.10 through 3.12, validates in-process and stdio MCP calls,
runs the core reference workload, and opens the release archive outside the
checkout.

Build locally with:

```sh
python scripts/build_release.py v0.2.0 --output dist
```

The output is `ASC-MCP-v0.2.0-source.zip` plus `SHA256SUMS`.
