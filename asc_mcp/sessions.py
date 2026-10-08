import hashlib
import os
import secrets
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path


ARCHIVE_TYPES = {
    ".aab": "aab",
    ".aar": "aar",
    ".apk": "apk",
    ".apks": "apks",
    ".jar": "jar",
    ".xapk": "xapk",
    ".zip": "zip",
}


@dataclass(frozen=True)
class AnalysisSession:
    analysis_id: str
    path: Path
    size_bytes: int
    modified_ns: int
    sha256: str
    entry_count: int
    dex_files: tuple[str, ...]
    artifact_type: str
    capabilities: tuple[str, ...]


class SessionRegistry:
    def __init__(
        self,
        allowed_roots: list[str | Path] | None = None,
        max_artifact_bytes: int = 2 * 1024 * 1024 * 1024,
        max_entries: int = 100_000,
        max_uncompressed_bytes: int = 4 * 1024 * 1024 * 1024,
        max_dex_bytes: int = 1024 * 1024 * 1024,
    ):
        roots = allowed_roots if allowed_roots is not None else self._roots_from_environment()
        self.allowed_roots = tuple(Path(root).resolve() for root in roots)
        self.max_artifact_bytes = max_artifact_bytes
        self.max_entries = max_entries
        self.max_uncompressed_bytes = max_uncompressed_bytes
        self.max_dex_bytes = max_dex_bytes
        self._sessions: dict[str, AnalysisSession] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _roots_from_environment() -> list[Path]:
        configured = os.environ.get("ASC_MCP_ALLOWED_ROOTS")
        if configured:
            return [Path(value) for value in configured.split(os.pathsep) if value]
        return [Path.cwd()]

    def _resolve_artifact(self, value: str) -> Path:
        candidate = Path(value).expanduser()
        try:
            path = candidate.resolve(strict=True)
        except PermissionError:
            path = candidate.absolute()
        if not path.is_file():
            raise ValueError("Artifact path is not a file")
        if path.suffix.lower() not in {*ARCHIVE_TYPES, ".dex"}:
            raise ValueError("Supported file types are APK, DEX, JAR, AAB, AAR, APKS, XAPK, and ZIP")
        if not any(path == root or root in path.parents for root in self.allowed_roots):
            raise PermissionError("Artifact path is outside the configured allowed roots")
        return path

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def open(self, value: str) -> AnalysisSession:
        path = self._resolve_artifact(value)
        stat = path.stat()
        if stat.st_size > self.max_artifact_bytes:
            raise ValueError("Artifact exceeds the configured size limit")

        suffix = path.suffix.lower()
        artifact_type = "dex" if suffix == ".dex" else ARCHIVE_TYPES[suffix]
        capabilities = []
        if artifact_type == "dex":
            if stat.st_size > self.max_dex_bytes:
                raise ValueError("DEX exceeds the configured size limit")
            with path.open("rb") as stream:
                magic = stream.read(4)
            if magic != b"dex\n":
                raise ValueError("File is not a valid DEX")
            infos = ()
            dex_files = (path.name,)
            capabilities.append("dex")
            entry_count = 1
        else:
            if not zipfile.is_zipfile(path):
                raise ValueError("File is not a valid ZIP-based artifact")
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                if len(infos) > self.max_entries:
                    raise ValueError("Artifact exceeds the configured entry limit")
                if sum(info.file_size for info in infos) > self.max_uncompressed_bytes:
                    raise ValueError("Artifact exceeds the uncompressed-size limit")
                seen_names = set()
                for info in infos:
                    parts = Path(info.filename.replace("\\", "/")).parts
                    if info.filename.startswith(("/", "\\")) or ".." in parts or "\x00" in info.filename:
                        raise ValueError("Artifact contains an unsafe entry path")
                    if info.filename in seen_names:
                        raise ValueError("Artifact contains duplicate entry names")
                    seen_names.add(info.filename)
                    if info.filename.lower().endswith(".dex") and info.file_size > self.max_dex_bytes:
                        raise ValueError("Artifact contains a DEX file above the size limit")
                names = {info.filename for info in infos}
                dex_files = tuple(
                    info.filename for info in infos if info.filename.lower().endswith(".dex")
                )
                if dex_files:
                    capabilities.append("dex")
                if any(name.lower().endswith((".class", ".jar")) for name in names):
                    capabilities.append("jvm-class-inventory")
                if "AndroidManifest.xml" in names:
                    capabilities.append("manifest")
                if artifact_type == "apk":
                    capabilities.append("signing")
                capabilities.append("archive")
                entry_count = len(infos)

        session = AnalysisSession(
            analysis_id=secrets.token_urlsafe(18),
            path=path,
            size_bytes=stat.st_size,
            modified_ns=stat.st_mtime_ns,
            sha256=self._hash_file(path),
            entry_count=entry_count,
            dex_files=dex_files,
            artifact_type=artifact_type,
            capabilities=tuple(capabilities),
        )
        with self._lock:
            self._sessions[session.analysis_id] = session
        return session

    def get(self, analysis_id: str) -> AnalysisSession:
        with self._lock:
            session = self._sessions.get(analysis_id)
        if session is None:
            raise KeyError("Unknown or closed analysis ID")
        try:
            stat = session.path.stat()
        except FileNotFoundError as error:
            raise FileNotFoundError("Artifact no longer exists") from error
        if stat.st_size != session.size_bytes or stat.st_mtime_ns != session.modified_ns:
            raise ValueError("Artifact changed after it was opened")
        return session

    def close(self, analysis_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(analysis_id, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
