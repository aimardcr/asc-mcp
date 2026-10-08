import asyncio
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor

from asc_mcp.worker import execute, initialize_worker


class AnalysisRuntime:
    def __init__(self, worker_count: int | None = None):
        configured = worker_count or int(os.environ.get("ASC_MCP_WORKERS", "0"))
        self.worker_count = configured if configured > 0 else min(4, os.cpu_count() or 1)
        self._executor: ProcessPoolExecutor | None = None

    def start(self) -> None:
        if self._executor is not None:
            return
        self._executor = ProcessPoolExecutor(
            max_workers=self.worker_count,
            mp_context=multiprocessing.get_context("spawn"),
            initializer=initialize_worker,
        )

    async def run(self, operation: str, payload: dict) -> dict:
        if self._executor is None:
            raise RuntimeError("Analysis runtime is not running")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, execute, operation, payload)

    def close(self) -> None:
        executor = self._executor
        self._executor = None
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
