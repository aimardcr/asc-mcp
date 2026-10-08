import base64
import functools
import io
import json
import mimetypes
import re
import struct
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from asc_mcp.analysis.artifact_handler import ArtifactHandler, _inflate_dex, _parse_cd_dex_entries
from asc_mcp.analysis.asc_handler import AscHandler
from asc_mcp.analysis.dex_container import iter_logical_dex_buffers
from asc_mcp.analysis.manifest_handler import get_manifest_xml
from asc_mcp.core.utils.tinydex import DEX


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_KINDS = ("activity", "activity-alias", "service", "receiver", "provider")
SECRET_PATTERNS = (
    ("aws_access_key", "high", re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("google_api_key", "high", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("jwt", "medium", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("private_key", "high", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("credential_assignment", "medium", re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}")),
)


def normalize_class_name(name: str) -> str:
    if not name:
        raise ValueError("Class name cannot be empty")
    if name.startswith("L") and name.endswith(";") and "/" in name:
        return name
    normalized = name.replace(".", "/")
    if not normalized.startswith("L"):
        normalized = f"L{normalized}"
    if not normalized.endswith(";"):
        normalized = f"{normalized};"
    return normalized


def normalize_method_descriptor(descriptor: str) -> str:
    return "".join(descriptor.split())


def build_reference_query(
    kind: str,
    value: str | None,
    class_name: str | None,
    fuzzy_class: bool,
    exact_member: bool,
    target_descriptor: str | None,
) -> dict:
    if kind in ("string", "type"):
        if not value:
            raise ValueError(f"{kind} query cannot be empty")
        return {kind: value}
    if kind not in ("method", "field"):
        raise ValueError("Reference kind must be string, type, method, or field")
    if not value and not class_name:
        raise ValueError(f"{kind} query needs a value or class name")
    normalized_class = None
    if class_name:
        normalized_class = class_name.replace(".", "/") if fuzzy_class else normalize_class_name(class_name)
    member = [value, True] if value and exact_member else value
    descriptor = normalize_method_descriptor(target_descriptor) if kind == "method" and target_descriptor else target_descriptor
    return {
        kind: {
            "class": [normalized_class, not fuzzy_class] if normalized_class else None,
            kind: member,
            "descriptor": descriptor,
        }
    }


def paginate(items: list, cursor: str | None, limit: int) -> tuple[list, str | None]:
    if limit < 1 or limit > 1000:
        raise ValueError("Limit must be between 1 and 1000")
    try:
        start = int(cursor) if cursor else 0
    except ValueError as error:
        raise ValueError("Cursor is invalid") from error
    if start < 0 or start > len(items):
        raise ValueError("Cursor is outside the result set")
    end = min(start + limit, len(items))
    return items[start:end], str(end) if end < len(items) else None


def _artifact_cache_key(artifact_path: str) -> tuple[str, int, int]:
    path = Path(artifact_path).resolve()
    stat = path.stat()
    return str(path), stat.st_size, stat.st_mtime_ns


@functools.lru_cache(maxsize=1)
def _cached_dex_buffers(artifact_path: str, _size: int, _modified_ns: int) -> tuple[tuple[str, bytes], ...]:
    buffers = []
    with open(artifact_path, "rb") as stream:
        import mmap

        mapped = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            entries = _parse_cd_dex_entries(mapped, Path(artifact_path).name)
            entries.sort(key=lambda entry: entry[2])
            for entry in entries:
                data = _inflate_dex(mapped, entry)
                buffers.extend(iter_logical_dex_buffers(entry[0], data))
        finally:
            mapped.close()
    return tuple(buffers)


@functools.lru_cache(maxsize=1)
def _cached_tiny_dexes(artifact_path: str, size: int, modified_ns: int):
    return tuple(
        (dex_name, dex_buffer, DEX.parse(memoryview(dex_buffer), dex_name))
        for dex_name, dex_buffer in _cached_dex_buffers(artifact_path, size, modified_ns)
    )


def _iter_tiny_dexes(artifact_path: str):
    yield from _cached_tiny_dexes(*_artifact_cache_key(artifact_path))


@functools.lru_cache(maxsize=1)
def _cached_androguard_dexes(artifact_path: str, size: int, modified_ns: int):
    from androguard.core.dex import DEX as AndroguardDEX

    return tuple(
        (dex_name, AndroguardDEX(dex_buffer))
        for dex_name, dex_buffer in _cached_dex_buffers(artifact_path, size, modified_ns)
    )


def _iter_androguard_dexes(artifact_path: str):
    yield from _cached_androguard_dexes(*_artifact_cache_key(artifact_path))


@functools.lru_cache(maxsize=1)
def _cached_call_graph_index(artifact_path: str, size: int, modified_ns: int):
    methods = set()
    forward = {}
    reverse = {}
    for _dex_name, dex in _cached_androguard_dexes(artifact_path, size, modified_ns):
        dex_methods = []
        for clazz in dex.get_classes():
            for method in clazz.get_methods():
                key = (
                    method.get_class_name(),
                    method.get_name(),
                    normalize_method_descriptor(method.get_descriptor()),
                )
                methods.add(key)
                dex_methods.append((key, method))
        for caller, method in dex_methods:
            for instruction in method.get_instructions():
                if not instruction.get_name().startswith("invoke-"):
                    continue
                target = dex.get_cm_method(instruction.get_ref_kind())
                callee = (
                    target.get_class_name(),
                    target.get_name(),
                    normalize_method_descriptor(target.get_descriptor()),
                )
                forward.setdefault(caller, set()).add(callee)
                reverse.setdefault(callee, set()).add(caller)
    return (
        frozenset(methods),
        {key: frozenset(values) for key, values in forward.items()},
        {key: frozenset(values) for key, values in reverse.items()},
    )


def _find_tiny_class(artifact_path: str, class_name: str):
    for dex_name, dex_buffer, dex in _iter_tiny_dexes(artifact_path):
        clazz = dex.get_class(class_name)
        if clazz is not None:
            return dex_name, dex_buffer, dex, clazz
    return None


def _find_androguard_class(artifact_path: str, class_name: str):
    for dex_name, dex in _iter_androguard_dexes(artifact_path):
        clazz = dex.get_class(class_name)
        if clazz is not None:
            return dex_name, dex, clazz
    return None


def _list_jvm_classes(artifact_path: str) -> list[str]:
    if not zipfile.is_zipfile(artifact_path):
        return []
    with zipfile.ZipFile(artifact_path) as archive:
        classes = [
            f"L{info.filename[:-6]};"
            for info in archive.infolist()
            if not info.is_dir() and info.filename.lower().endswith(".class")
        ]
        for info in archive.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".jar") or info.file_size > 64 * 1024 * 1024:
                continue
            try:
                with zipfile.ZipFile(io.BytesIO(archive.read(info))) as nested:
                    classes.extend(
                        f"L{item.filename[:-6]};"
                        for item in nested.infolist()
                        if not item.is_dir() and item.filename.lower().endswith(".class")
                    )
            except zipfile.BadZipFile:
                continue
    return list(dict.fromkeys(classes))


@functools.lru_cache(maxsize=2)
def _cached_classes(artifact_path: str, _size: int, _modified_ns: int, max_workers: int) -> tuple[str, ...]:
    classes = ArtifactHandler(artifact_path, max_workers=max_workers).list_classes()
    return tuple(dict.fromkeys([*classes, *_list_jvm_classes(artifact_path)]))


def _all_classes(artifact_path: str, max_workers: int) -> list[str]:
    return list(_cached_classes(*_artifact_cache_key(artifact_path), max_workers))


@functools.lru_cache(maxsize=8)
def _cached_reference_rows(
    artifact_path: str,
    size: int,
    modified_ns: int,
    max_workers: int,
    kind: str,
    query_json: str,
) -> tuple[dict, ...]:
    query = json.loads(query_json)
    handler = ArtifactHandler(artifact_path, max_workers=max_workers)
    rows = []
    for _dex_name, batch in handler.for_each_findrefs_structured(kind, query):
        rows.extend(batch)
    rows.sort(key=lambda row: (row["method_class"], row["method_name"], row["method_descriptor"], row["dex_name"]))
    return tuple(rows)


def _method_descriptor(dex: DEX, method) -> str:
    prototype = method.prototype
    parameters = "".join(str(item) for item in prototype.parameters_type)
    return_type = dex.types[prototype.return_type_idx].descriptor
    return f"({parameters}){return_type}"


def _entry_kind(path: str) -> str:
    if path.endswith(".dex") and "/" not in path:
        return "dex"
    if path.startswith("res/") or path == "resources.arsc":
        return "resource"
    if path.startswith("assets/"):
        return "asset"
    if path.startswith("lib/") and path.endswith(".so"):
        return "native"
    if path.startswith("META-INF/") or path == "AndroidManifest.xml":
        return "metadata"
    return "other"


def _manifest_value(element, name: str) -> str | None:
    return element.get(f"{ANDROID_NS}{name}")


def _bool_value(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.lower() == "true"


class AndroidAnalysisService:
    def __init__(
        self,
        artifact_path: str,
        artifact_type: str,
        capabilities: tuple[str, ...] | list[str],
        max_workers: int = 4,
    ):
        self.artifact_path = artifact_path
        self.artifact_type = artifact_type
        self.capabilities = tuple(capabilities)
        self.max_workers = max(1, max_workers)

    def _require_dex(self) -> None:
        if "dex" not in self.capabilities:
            raise ValueError("This operation requires DEX bytecode; JVM class analysis is inventory-only")

    def _manifest(self, include_xml: bool) -> dict:
        if "manifest" not in self.capabilities:
            raise ValueError("This artifact does not contain a root AndroidManifest.xml")
        xml = get_manifest_xml(self.artifact_path, pretty=True)
        root = ElementTree.fromstring(xml)
        uses_sdk = root.find("uses-sdk")
        application = root.find("application")
        components = []
        if application is not None:
            for kind in COMPONENT_KINDS:
                for element in application.findall(kind):
                    name = _manifest_value(element, "name")
                    if not name:
                        continue
                    actions = []
                    for action in element.findall("intent-filter/action"):
                        action_name = _manifest_value(action, "name")
                        if action_name:
                            actions.append(action_name)
                    components.append(
                        {
                            "kind": kind,
                            "name": name,
                            "exported": _bool_value(_manifest_value(element, "exported")),
                            "enabled": _bool_value(_manifest_value(element, "enabled")),
                            "permission": _manifest_value(element, "permission"),
                            "intent_actions": actions,
                        }
                    )
        permissions = sorted(
            value
            for element in root.findall("uses-permission")
            if (value := _manifest_value(element, "name"))
        )
        return {
            "package_name": root.get("package"),
            "version_name": _manifest_value(root, "versionName"),
            "version_code": _manifest_value(root, "versionCode"),
            "min_sdk": _manifest_value(uses_sdk, "minSdkVersion") if uses_sdk is not None else None,
            "target_sdk": _manifest_value(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None,
            "application_name": _manifest_value(application, "name") if application is not None else None,
            "debuggable": _bool_value(_manifest_value(application, "debuggable")) if application is not None else None,
            "permissions": permissions,
            "components": components,
            "xml": xml if include_xml else None,
        }

    def summary(self, analysis_id: str, sha256: str) -> dict:
        if "archive" in self.capabilities:
            with zipfile.ZipFile(self.artifact_path) as archive:
                infos = archive.infolist()
            dex_files = [info.filename for info in infos if info.filename.lower().endswith(".dex")]
            native_abis = sorted(
                {info.filename.split("/", 2)[1] for info in infos if _entry_kind(info.filename) == "native"}
            )
            entry_count = len(infos)
        else:
            dex_files = [Path(self.artifact_path).name]
            native_abis = []
            entry_count = 1
        manifest = self._manifest(False) if "manifest" in self.capabilities else {}
        return {
            "analysis_id": analysis_id,
            "name": Path(self.artifact_path).name,
            "artifact_type": self.artifact_type,
            "capabilities": list(self.capabilities),
            "size_bytes": Path(self.artifact_path).stat().st_size,
            "sha256": sha256,
            "entry_count": entry_count,
            "dex_files": dex_files,
            "native_abis": native_abis,
            "package_name": manifest.get("package_name"),
            "version_name": manifest.get("version_name"),
            "version_code": manifest.get("version_code"),
            "min_sdk": manifest.get("min_sdk"),
            "target_sdk": manifest.get("target_sdk"),
        }

    def manifest(self, include_xml: bool) -> dict:
        return self._manifest(include_xml)

    def list_classes(self, prefix: str | None, query: str | None, cursor: str | None, limit: int) -> dict:
        classes = _all_classes(self.artifact_path, self.max_workers)
        if prefix:
            normalized_prefix = prefix if prefix.startswith("L") else f"L{prefix.replace('.', '/')}"
            classes = [name for name in classes if name.startswith(normalized_prefix)]
        if query:
            needle = query.lower()
            classes = [name for name in classes if needle in name.lower()]
        page, next_cursor = paginate(classes, cursor, limit)
        return {"classes": page, "total": len(classes), "next_cursor": next_cursor}

    def class_source(self, class_name: str) -> dict:
        self._require_dex()
        normalized = normalize_class_name(class_name)
        hit = _find_tiny_class(self.artifact_path, normalized)
        if hit is None:
            raise ValueError(f"Class {normalized} was not found")
        dex_name, dex_buffer, _dex, _clazz = hit
        source, references = AscHandler().getclass_with_metadata(dex_buffer, normalized)
        return {
            "class_name": normalized,
            "dex_name": dex_name,
            "source": source,
            "member_references": [
                {
                    "start": item[0],
                    "end": item[1],
                    "kind": item[2],
                    "declaring_class": item[3],
                    "name": item[4],
                    "descriptor": item[5],
                    "declaration": item[6],
                }
                for item in references
            ],
        }

    def class_outline(self, class_name: str) -> dict:
        self._require_dex()
        normalized = normalize_class_name(class_name)
        hit = _find_tiny_class(self.artifact_path, normalized)
        if hit is None:
            raise ValueError(f"Class {normalized} was not found")
        dex_name, _dex_buffer, dex, clazz = hit
        access_flags = struct.unpack_from("<I", dex.buf, clazz._class_def_off + 4)[0]
        superclass_idx = struct.unpack_from("<I", dex.buf, clazz._class_def_off + 8)[0]
        interfaces_off = struct.unpack_from("<I", dex.buf, clazz._class_def_off + 12)[0]
        interfaces = []
        if interfaces_off:
            count = struct.unpack_from("<I", dex.buf, interfaces_off)[0]
            interfaces = [
                dex.types[struct.unpack_from("<H", dex.buf, interfaces_off + 4 + index * 2)[0]].descriptor
                for index in range(count)
            ]
        fields = [
            {
                "name": field.name,
                "type": field.type.descriptor,
                "access_flags": field.access_flags,
                "static": field.is_static,
            }
            for field in clazz.fields
        ]
        methods = [
            {
                "name": method.name,
                "descriptor": _method_descriptor(dex, method),
                "access_flags": method.access_flags,
                "kind": "direct" if method.is_direct else "virtual",
                "has_code": method.code_offset != 0,
            }
            for method in clazz.methods
        ]
        return {
            "class_name": normalized,
            "dex_name": dex_name,
            "access_flags": access_flags,
            "superclass": None if superclass_idx == 0xFFFFFFFF else dex.types[superclass_idx].descriptor,
            "interfaces": interfaces,
            "fields": fields,
            "methods": methods,
        }

    def find_references(
        self,
        kind: str,
        value: str | None,
        class_name: str | None,
        fuzzy_class: bool,
        exact_member: bool,
        target_descriptor: str | None,
        cursor: str | None,
        limit: int,
    ) -> dict:
        self._require_dex()
        query = build_reference_query(
            kind,
            value,
            class_name,
            fuzzy_class,
            exact_member,
            target_descriptor,
        )
        cache_key = _artifact_cache_key(self.artifact_path)
        rows = list(
            _cached_reference_rows(
                *cache_key,
                self.max_workers,
                kind,
                json.dumps(query, sort_keys=True, separators=(",", ":")),
            )
        )
        page, next_cursor = paginate(rows, cursor, limit)
        return {"hits": page, "total": len(rows), "next_cursor": next_cursor}

    def search_members(self, kind: str, query: str, cursor: str | None, limit: int) -> dict:
        self._require_dex()
        if kind not in ("method", "field"):
            raise ValueError("Member kind must be method or field")
        if not query:
            raise ValueError("Member query cannot be empty")
        needle = query.lower()
        rows = []
        for dex_name, _dex_buffer, dex in _iter_tiny_dexes(self.artifact_path):
            for class_index in range(len(dex.classes)):
                clazz = dex.classes[class_index]
                members = clazz.methods if kind == "method" else clazz.fields
                for member in members:
                    if needle not in member.name.lower():
                        continue
                    descriptor = _method_descriptor(dex, member) if kind == "method" else member.type.descriptor
                    rows.append(
                        {
                            "dex_name": dex_name,
                            "class_name": clazz.fullname,
                            "name": member.name,
                            "descriptor": descriptor,
                            "access_flags": member.access_flags,
                        }
                    )
        rows.sort(key=lambda row: (row["class_name"], row["name"], row["descriptor"]))
        page, next_cursor = paginate(rows, cursor, limit)
        return {"kind": kind, "members": page, "total": len(rows), "next_cursor": next_cursor}

    def search_strings(self, query: str, cursor: str | None, limit: int) -> dict:
        self._require_dex()
        if not query:
            raise ValueError("String query cannot be empty")
        needle = query.lower()
        rows = []
        for dex_name, _dex_buffer, dex in _iter_tiny_dexes(self.artifact_path):
            for index in range(len(dex.strings)):
                value = str(dex.strings[index])
                if needle in value.lower():
                    rows.append({"dex_name": dex_name, "index": index, "value": value})
        page, next_cursor = paginate(rows, cursor, limit)
        return {"strings": page, "total": len(rows), "next_cursor": next_cursor}

    def string_constants(self, class_name: str) -> dict:
        self._require_dex()
        normalized = normalize_class_name(class_name)
        hit = _find_androguard_class(self.artifact_path, normalized)
        if hit is None:
            raise ValueError(f"Class {normalized} was not found")
        dex_name, dex, clazz = hit
        constants = []
        for method in clazz.get_methods():
            offset = 0
            for instruction in method.get_instructions():
                if instruction.get_name() in ("const-string", "const-string/jumbo"):
                    constants.append(
                        {
                            "method_name": method.get_name(),
                            "method_descriptor": normalize_method_descriptor(method.get_descriptor()),
                            "offset": offset,
                            "value": dex.get_cm_string(instruction.get_ref_kind()),
                        }
                    )
                offset += instruction.get_length()
        return {"class_name": normalized, "dex_name": dex_name, "constants": constants}

    def search_method_bodies(self, query: str, cursor: str | None, limit: int) -> dict:
        self._require_dex()
        if not query:
            raise ValueError("Method-body query cannot be empty")
        needle = query.lower()
        rows = []
        for dex_name, dex in _iter_androguard_dexes(self.artifact_path):
            for clazz in dex.get_classes():
                for method in clazz.get_methods():
                    for instruction in method.get_instructions():
                        rendered = f"{instruction.get_name()} {instruction.get_output()}".strip()
                        if needle not in rendered.lower():
                            continue
                        rows.append(
                            {
                                "dex_name": dex_name,
                                "class_name": method.get_class_name(),
                                "method_name": method.get_name(),
                                "method_descriptor": normalize_method_descriptor(method.get_descriptor()),
                                "instruction": rendered,
                            }
                        )
        rows.sort(
            key=lambda row: (
                row["class_name"],
                row["method_name"],
                row["method_descriptor"],
                row["instruction"],
            )
        )
        page, next_cursor = paginate(rows, cursor, limit)
        return {"hits": page, "total": len(rows), "next_cursor": next_cursor}

    def call_graph(
        self,
        class_name: str,
        method_name: str,
        descriptor: str | None,
        depth: int,
    ) -> dict:
        self._require_dex()
        if depth < 1 or depth > 3:
            raise ValueError("Call-graph depth must be between 1 and 3")
        normalized = normalize_class_name(class_name)
        normalized_descriptor = normalize_method_descriptor(descriptor) if descriptor is not None else None
        methods, forward, reverse = _cached_call_graph_index(*_artifact_cache_key(self.artifact_path))

        candidates = [
            key
            for key in methods
            if key[0] == normalized
            and key[1] == method_name
            and (normalized_descriptor is None or key[2] == normalized_descriptor)
        ]
        if not candidates:
            raise ValueError("Method was not found")
        if len(candidates) > 1:
            raise ValueError("Method name is overloaded; provide its descriptor")
        root = candidates[0]
        visited = {root}
        frontier = {root}
        edge_keys = set()
        for _ in range(depth):
            next_frontier = set()
            for method in frontier:
                for callee in forward.get(method, ()):
                    edge_keys.add((method, callee))
                    next_frontier.add(callee)
                for caller in reverse.get(method, ()):
                    edge_keys.add((caller, method))
                    next_frontier.add(caller)
            frontier = next_frontier - visited
            visited.update(next_frontier)
            if not frontier:
                break

        def node(key):
            return {"class_name": key[0], "method_name": key[1], "descriptor": key[2]}

        return {
            "root": node(root),
            "callers": [node(key) for key in sorted(reverse.get(root, ()))],
            "callees": [node(key) for key in sorted(forward.get(root, ()))],
            "edges": [
                {"caller": node(caller), "callee": node(callee)}
                for caller, callee in sorted(edge_keys)
            ],
        }

    def list_entries(self, kind: str | None, cursor: str | None, limit: int) -> dict:
        valid_kinds = {"resource", "asset", "native", "dex", "metadata", "other"}
        if kind is not None and kind not in valid_kinds:
            raise ValueError("Entry kind is invalid")
        if "archive" in self.capabilities:
            with zipfile.ZipFile(self.artifact_path) as archive:
                rows = [
                    {
                        "path": info.filename,
                        "kind": _entry_kind(info.filename),
                        "size_bytes": info.file_size,
                        "compressed_size": info.compress_size,
                    }
                    for info in archive.infolist()
                    if not info.is_dir() and (kind is None or _entry_kind(info.filename) == kind)
                ]
        else:
            size = Path(self.artifact_path).stat().st_size
            rows = [] if kind not in (None, "dex") else [{
                "path": Path(self.artifact_path).name,
                "kind": "dex",
                "size_bytes": size,
                "compressed_size": size,
            }]
        rows.sort(key=lambda row: row["path"])
        page, next_cursor = paginate(rows, cursor, limit)
        return {"entries": page, "total": len(rows), "next_cursor": next_cursor}

    def resource_content(self, path: str, max_bytes: int) -> dict:
        if max_bytes < 1 or max_bytes > 1024 * 1024:
            raise ValueError("max_bytes must be between 1 and 1048576")
        normalized = path.replace("\\", "/")
        if normalized.startswith("/") or ".." in Path(normalized).parts or "\x00" in normalized:
            raise ValueError("Resource path is unsafe")
        if "archive" in self.capabilities:
            with zipfile.ZipFile(self.artifact_path) as archive:
                try:
                    info = archive.getinfo(normalized)
                except KeyError as error:
                    raise ValueError("Resource was not found") from error
                if info.file_size > 64 * 1024 * 1024:
                    raise ValueError("Resource exceeds the read limit")
                data = archive.read(info)
        else:
            if normalized != Path(self.artifact_path).name:
                raise ValueError("Resource was not found")
            with Path(self.artifact_path).open("rb") as stream:
                data = stream.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        mime_type = mimetypes.guess_type(normalized)[0] or "application/octet-stream"
        if normalized.endswith(".xml"):
            try:
                from androguard.core.axml import AXMLPrinter

                printer = AXMLPrinter(data)
                if printer.is_valid():
                    content = printer.get_xml(pretty=True).decode("utf-8", errors="replace")
                    return {
                        "path": normalized,
                        "mime_type": "application/xml",
                        "encoding": "utf-8",
                        "content": content,
                        "truncated": truncated,
                    }
            except (ValueError, TypeError):
                pass
        try:
            content = data.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            content = base64.b64encode(data).decode("ascii")
            encoding = "base64"
        return {
            "path": normalized,
            "mime_type": mime_type,
            "encoding": encoding,
            "content": content,
            "truncated": truncated,
        }

    def native_libraries(self) -> dict:
        if "archive" not in self.capabilities:
            return {"libraries": [], "abis": []}
        with zipfile.ZipFile(self.artifact_path) as archive:
            libraries = [
                {
                    "path": info.filename,
                    "abi": info.filename.split("/", 2)[1],
                    "name": info.filename.rsplit("/", 1)[-1],
                    "size_bytes": info.file_size,
                    "compressed_size": info.compress_size,
                }
                for info in archive.infolist()
                if _entry_kind(info.filename) == "native"
            ]
        libraries.sort(key=lambda item: (item["abi"], item["name"]))
        return {"libraries": libraries, "abis": sorted({item["abi"] for item in libraries})}

    def signing(self) -> dict:
        from androguard.core.apk import APK

        if "signing" not in self.capabilities:
            raise ValueError("Signing analysis is available only for APK artifacts")
        apk = APK(self.artifact_path, skip_analysis=True)
        certificates = []
        for certificate in apk.get_certificates():
            validity = certificate["tbs_certificate"]["validity"]
            certificates.append(
                {
                    "subject": certificate.subject.human_friendly,
                    "issuer": certificate.issuer.human_friendly,
                    "serial_number": str(certificate.serial_number),
                    "sha256": certificate.sha256.hex(),
                    "not_before": validity["not_before"].native.isoformat(),
                    "not_after": validity["not_after"].native.isoformat(),
                }
            )
        return {
            "signed": apk.is_signed(),
            "v1": apk.is_signed_v1(),
            "v2": apk.is_signed_v2(),
            "v3": apk.is_signed_v3(),
            "v31": apk.is_signed_v31(),
            "certificates": certificates,
        }

    def scan_secrets(self, include_values: bool, limit: int) -> dict:
        self._require_dex()
        if limit < 1 or limit > 1000:
            raise ValueError("Limit must be between 1 and 1000")
        findings = []
        total = 0
        for dex_name, _dex_buffer, dex in _iter_tiny_dexes(self.artifact_path):
            for index in range(len(dex.strings)):
                value = str(dex.strings[index])
                for kind, severity, pattern in SECRET_PATTERNS:
                    match = pattern.search(value)
                    if match is None:
                        continue
                    total += 1
                    if len(findings) < limit:
                        matched = match.group(0)
                        shown = matched if include_values else f"{matched[:4]}...{matched[-4:]}"
                        findings.append(
                            {
                                "kind": kind,
                                "severity": severity,
                                "dex_name": dex_name,
                                "string_index": index,
                                "value": shown,
                            }
                        )
        return {"findings": findings, "total": total, "truncated": total > len(findings)}

    def class_hierarchy(self, class_name: str) -> dict:
        self._require_dex()
        normalized = normalize_class_name(class_name)
        graph = {}
        for _dex_name, _dex_buffer, dex in _iter_tiny_dexes(self.artifact_path):
            for index in range(len(dex.classes)):
                clazz = dex.classes[index]
                superclass_idx = struct.unpack_from("<I", dex.buf, clazz._class_def_off + 8)[0]
                interfaces_off = struct.unpack_from("<I", dex.buf, clazz._class_def_off + 12)[0]
                interfaces = []
                if interfaces_off:
                    count = struct.unpack_from("<I", dex.buf, interfaces_off)[0]
                    interfaces = [
                        dex.types[struct.unpack_from("<H", dex.buf, interfaces_off + 4 + item * 2)[0]].descriptor
                        for item in range(count)
                    ]
                graph[clazz.fullname] = (
                    None if superclass_idx == 0xFFFFFFFF else dex.types[superclass_idx].descriptor,
                    interfaces,
                )
        if normalized not in graph:
            raise ValueError(f"Class {normalized} was not found")
        chain = []
        current = graph[normalized][0]
        seen = set()
        while current and current not in seen:
            chain.append(current)
            seen.add(current)
            current = graph.get(current, (None, []))[0]
        interfaces = graph[normalized][1]
        subclasses = sorted(name for name, (parent, _items) in graph.items() if parent == normalized)
        implementors = sorted(name for name, (_parent, items) in graph.items() if normalized in items)
        return {
            "class_name": normalized,
            "superclass_chain": chain,
            "interfaces": interfaces,
            "subclasses": subclasses,
            "implementors": implementors,
        }

    def disassemble_method(self, class_name: str, method_name: str, descriptor: str | None) -> dict:
        self._require_dex()
        normalized = normalize_class_name(class_name)
        hit = _find_androguard_class(self.artifact_path, normalized)
        if hit is None:
            raise ValueError(f"Class {normalized} was not found")
        dex_name, _dex, clazz = hit
        candidates = [method for method in clazz.get_methods() if method.get_name() == method_name]
        if descriptor is not None:
            normalized_descriptor = normalize_method_descriptor(descriptor)
            candidates = [
                method
                for method in candidates
                if normalize_method_descriptor(method.get_descriptor()) == normalized_descriptor
            ]
        if not candidates:
            raise ValueError("Method was not found")
        if len(candidates) > 1:
            raise ValueError("Method name is overloaded; provide its descriptor")
        method = candidates[0]
        instructions = []
        offset = 0
        for instruction in method.get_instructions():
            instructions.append(
                {
                    "offset": offset,
                    "opcode": instruction.get_name(),
                    "operands": instruction.get_output(),
                }
            )
            offset += instruction.get_length()
        return {
            "class_name": normalized,
            "method_name": method_name,
            "descriptor": normalize_method_descriptor(method.get_descriptor()),
            "dex_name": dex_name,
            "instructions": instructions,
        }


def diff_artifacts(
    left_id: str,
    left_path: str,
    left_sha256: str,
    right_id: str,
    right_path: str,
    right_sha256: str,
    max_workers: int,
) -> dict:
    left = set(_all_classes(left_path, max_workers))
    right = set(_all_classes(right_path, max_workers))
    return {
        "left_analysis_id": left_id,
        "right_analysis_id": right_id,
        "added_classes": sorted(right - left),
        "removed_classes": sorted(left - right),
        "common_class_count": len(left & right),
        "left_sha256": left_sha256,
        "right_sha256": right_sha256,
    }
