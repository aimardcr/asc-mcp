import os

from asc_mcp.server import create_server


def main() -> None:
    transport = os.environ.get("ASC_MCP_TRANSPORT", "stdio")
    if transport not in ("stdio", "streamable-http"):
        raise SystemExit("ASC_MCP_TRANSPORT must be stdio or streamable-http")
    server = create_server()
    if transport == "stdio":
        server.run()
        return
    server.run(
        transport="streamable-http",
        host=os.environ.get("ASC_MCP_HOST", "127.0.0.1"),
        port=int(os.environ.get("ASC_MCP_PORT", "8000")),
        streamable_http_path=os.environ.get("ASC_MCP_HTTP_PATH", "/mcp"),
    )


if __name__ == "__main__":
    main()
