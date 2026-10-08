import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from mcp.client import Client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asc_mcp.server import create_server


async def run(apk: Path) -> dict:
    server = create_server([apk.parent], worker_count=1)
    async with Client(server) as client:
        started = time.perf_counter()
        opened = await client.call_tool("load_artifact", {"path": str(apk)})
        open_ms = (time.perf_counter() - started) * 1000
        if opened.is_error:
            raise RuntimeError(opened.content[0].text)
        analysis_id = opened.structured_content["analysis_id"]
        source_started = time.perf_counter()
        source = await client.call_tool(
            "apk_get_class_source",
            {"analysis_id": analysis_id, "class_name": "example.Test"},
        )
        source_ms = (time.perf_counter() - source_started) * 1000
        if source.is_error:
            raise RuntimeError(source.content[0].text)
        text = source.structured_content["source"]
        return {
            "open_ms": open_ms,
            "source_ms": source_ms,
            "total_ms": open_ms + source_ms,
            "source_ok": all(value in text for value in ("class Test", "void first()", "void second()")),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run(args.apk))))


if __name__ == "__main__":
    main()
