# Test commands

Install `requirements.txt` in a virtual environment, then run:

```sh
python tests/run_tests.py --require-decompiler --suite unit
python tests/run_tests.py --require-decompiler --suite integration
python tests/benchmark_startup.py --samples 9
python tests/benchmark_reference.py --samples 9
```

The unit suite covers DEX rebuilding, reference search, class enumeration,
MUTF-8, path policy, MCP schemas, and deterministic packaging. The integration
suite starts in-process and stdio MCP clients, launches isolated analysis workers,
and tests APK, DEX, JAR, and AAR loading alongside summaries, class inspection,
cross references, decompilation, disassembly, searches, and resource reads.

The startup benchmark measures a fresh MCP server, artifact load, and one class
decompilation. The reference benchmark retains the original core correctness and
decompilation budget. `benchmark_compare.py` compares core and transport-neutral
service performance against a baseline checkout.

Benchmark reports and raw logs are written under `artifacts/` and uploaded by CI.
