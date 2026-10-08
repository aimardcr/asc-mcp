import asyncio
import re
import zipfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from asc_mcp.models import (
    ArtifactDiff,
    ArtifactHandle,
    ArtifactSummary,
    CallGraph,
    ClassHierarchy,
    ClassOutline,
    ClassPage,
    ClassSource,
    CloseResult,
    EntryPage,
    ManifestResult,
    MemberPage,
    MethodDisassembly,
    MethodTextPage,
    NativeLibraryResult,
    ReferencePage,
    ResourceContent,
    SecretScanResult,
    ServerStatus,
    SigningResult,
    StringConstantResult,
    StringPage,
)
from asc_mcp.runtime import AnalysisRuntime
from asc_mcp.sessions import AnalysisSession, SessionRegistry


READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
LIFECYCLE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=False,
)

AnalysisId = Annotated[
    str,
    Field(
        min_length=1,
        description="Opaque analysis handle returned by load_artifact.",
        examples=["analysis-id-from-load_artifact"],
    ),
]
ArtifactPath = Annotated[
    str,
    Field(
        min_length=1,
        description=(
            "Path to an .apk, .dex, .jar, .aab, .aar, .apks, .xapk, or .zip file under an allowed root. "
            "Relative paths resolve from the server workspace."
        ),
        examples=["app.apk", "build/classes.dex", "libs/example.jar"],
    ),
]
ClassName = Annotated[
    str,
    Field(
        min_length=1,
        description="Class in Java dotted form (com.example.Foo) or Dalvik form (Lcom/example/Foo;).",
        examples=["com.example.Foo", "Lcom/example/Foo;"],
    ),
]
MethodName = Annotated[
    str,
    Field(
        min_length=1,
        description="Declared method name, including <init> for a constructor or <clinit> for a class initializer.",
        examples=["onCreate", "<init>"],
    ),
]
MethodDescriptor = Annotated[
    str | None,
    Field(
        min_length=1,
        description=(
            "Exact Dalvik method descriptor, such as (Ljava/lang/String;)V; "
            "copy it directly from apk_get_class_outline, or omit it only when the name is unambiguous."
        ),
        examples=["(Ljava/lang/String;)V", "(Landroid/content/Context;IZ)V"],
    ),
]
FieldDescriptor = Annotated[
    str | None,
    Field(
        min_length=1,
        description="Exact Dalvik field type; copy the type directly from apk_get_class_outline.",
        examples=["Ljava/lang/String;", "I", "[B"],
    ),
]
PageCursor = Annotated[
    str | None,
    Field(
        description="Opaque next_cursor from the preceding call; omit for the first page.",
        examples=["200"],
    ),
]
PageLimit = Annotated[
    int,
    Field(
        ge=1,
        le=1000,
        description="Maximum results to return in this page, from 1 to 1000.",
        examples=[200],
    ),
]

SERVER_INSTRUCTIONS = (
    "Start by calling load_artifact(path), then reuse its analysis_id. Check the returned capabilities before "
    "choosing a tool: DEX tools require 'dex', while manifest, signing, and archive tools require their matching "
    "capabilities. Choose one purpose-specific search: apk_search_members finds declarations; "
    "apk_find_method_references finds method call sites; apk_find_field_references finds field accesses; "
    "apk_find_string_references finds const-string use sites; apk_find_type_instructions finds only instructions "
    "whose operand is a type, such as new-instance, check-cast, or const-class. A zero reference count does not "
    "mean the declaration is absent. Use method_name='<init>' for constructor call sites. "
    "Copy method descriptors and field types from apk_get_class_outline to select exact overloads. Reference-hit "
    "evidence reports each opcode, caller-relative byte offset, access kind, and exact target; use it before "
    "requesting a full disassembly. "
    "apk_search_method_bodies only substring-matches rendered Dalvik opcode and operand text. Use apk_list_classes "
    "to resolve class names before outline, source, disassembly, hierarchy, or call-graph calls. Class parameters "
    "accept Java dotted names or Dalvik descriptors. Follow next_cursor until null and call close_artifact when "
    "finished."
)


@dataclass
class ServerState:
    registry: SessionRegistry
    runtime: AnalysisRuntime


def _state(ctx: Context) -> ServerState:
    return ctx.request_context.lifespan_context


def _session(ctx: Context, analysis_id: str) -> AnalysisSession:
    try:
        return _state(ctx).registry.get(analysis_id)
    except (KeyError, ValueError, FileNotFoundError, PermissionError) as error:
        raise ToolError(str(error)) from error


async def _run(ctx: Context, session: AnalysisSession, operation: str, **arguments) -> dict:
    payload = {
        "artifact_path": str(session.path),
        "artifact_type": session.artifact_type,
        "capabilities": session.capabilities,
        "max_workers": _state(ctx).runtime.worker_count,
        **arguments,
    }
    try:
        await ctx.report_progress(0, 1, f"Running {operation}")
        result = await _state(ctx).runtime.run(operation, payload)
        await ctx.report_progress(1, 1, f"Completed {operation}")
        return result
    except ToolError:
        raise
    except Exception as error:
        raise ToolError(str(error) or f"{operation} failed") from error


def _reference_page(result: dict, empty_hint: str) -> ReferencePage:
    if result["total"] == 0:
        result["hint"] = empty_hint
    return ReferencePage.model_validate(result)


def _dalvik_type_name(value: str) -> str:
    if value.startswith("[") or value in "VZBSCIJFD":
        return value
    if value.startswith("L") and value.endswith(";"):
        return value
    return f"L{value.replace('.', '/')};"


def create_server(
    allowed_roots: list[str | Path] | None = None,
    worker_count: int | None = None,
) -> MCPServer:
    registry = SessionRegistry(allowed_roots=allowed_roots)
    runtime = AnalysisRuntime(worker_count=worker_count)

    @asynccontextmanager
    async def lifespan(_server):
        runtime.start()
        try:
            yield ServerState(registry=registry, runtime=runtime)
        finally:
            registry.clear()
            runtime.close()

    server = MCPServer(
        "asc-mcp",
        title="ASC MCP",
        description="Read-only, on-demand static analysis for APK, DEX, JAR, and Android archive files.",
        instructions=SERVER_INSTRUCTIONS,
        version="0.2.0",
        lifespan=lifespan,
    )

    @server.tool(annotations=LIFECYCLE, structured_output=True)
    async def load_artifact(path: ArtifactPath, ctx: Context[ServerState]) -> ArtifactHandle:
        """Start here: open one supported artifact and return its analysis_id and available capabilities."""
        try:
            session = await asyncio.to_thread(registry.open, path)
        except (OSError, ValueError, PermissionError, zipfile.BadZipFile) as error:
            raise ToolError(str(error)) from error
        return ArtifactHandle(
            analysis_id=session.analysis_id,
            name=session.path.name,
            artifact_type=session.artifact_type,
            capabilities=list(session.capabilities),
            size_bytes=session.size_bytes,
            sha256=session.sha256,
            entry_count=session.entry_count,
            dex_count=len(session.dex_files),
        )

    @server.tool(annotations=LIFECYCLE, structured_output=True)
    async def close_artifact(analysis_id: AnalysisId, ctx: Context[ServerState]) -> CloseResult:
        """Release an analysis handle after all queries for that artifact are complete."""
        return CloseResult(analysis_id=analysis_id, closed=_state(ctx).registry.close(analysis_id))

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def server_status(ctx: Context[ServerState]) -> ServerStatus:
        """Inspect allowed roots, worker capacity, and the number of currently open analyses."""
        state = _state(ctx)
        return ServerStatus(
            open_analyses=len(state.registry),
            worker_count=state.runtime.worker_count,
            allowed_roots=[str(path) for path in state.registry.allowed_roots],
        )

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_get_summary(analysis_id: AnalysisId, ctx: Context[ServerState]) -> ArtifactSummary:
        """Use after loading to inspect identity, hashes, capabilities, DEX files, and basic Android metadata."""
        session = _session(ctx, analysis_id)
        result = await _run(ctx, session, "summary", analysis_id=analysis_id, sha256=session.sha256)
        return ArtifactSummary.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_get_manifest(
        analysis_id: AnalysisId,
        ctx: Context[ServerState],
        include_xml: Annotated[
            bool,
            Field(description="Include the complete decoded AndroidManifest.xml text in the xml field."),
        ] = False,
    ) -> ManifestResult:
        """Inspect package, SDK, permissions, and components when the artifact has the manifest capability."""
        result = await _run(ctx, _session(ctx, analysis_id), "manifest", include_xml=include_xml)
        return ManifestResult.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_list_classes(
        analysis_id: AnalysisId,
        ctx: Context[ServerState],
        prefix: Annotated[
            str | None,
            Field(description="Optional package or class prefix, in dotted or Dalvik slash form."),
        ] = None,
        query: Annotated[
            str | None,
            Field(description="Optional case-insensitive substring of the class name; this does not search members."),
        ] = None,
        cursor: PageCursor = None,
        limit: PageLimit = 200,
    ) -> ClassPage:
        """Discover class names before class-specific calls; searches names only, not methods or bytecode."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "list_classes",
            prefix=prefix,
            query=query,
            cursor=cursor,
            limit=limit,
        )
        return ClassPage.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_get_class_outline(
        analysis_id: AnalysisId,
        class_name: ClassName,
        ctx: Context[ServerState],
    ) -> ClassOutline:
        """Inspect one DEX class's declarations, hierarchy, fields, and method signatures without decompiling it."""
        result = await _run(ctx, _session(ctx, analysis_id), "class_outline", class_name=class_name)
        return ClassOutline.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_get_class_source(
        analysis_id: AnalysisId,
        class_name: ClassName,
        ctx: Context[ServerState],
    ) -> ClassSource:
        """Decompile one DEX class; use disassembly instead when exact opcode-level behavior matters."""
        result = await _run(ctx, _session(ctx, analysis_id), "class_source", class_name=class_name)
        return ClassSource.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_find_method_references(
        analysis_id: AnalysisId,
        class_name: ClassName,
        ctx: Context[ServerState],
        method_name: Annotated[
            str | None,
            Field(
                min_length=1,
                description=(
                    "Exact or partial target method name; use <init> for constructors or omit to find calls to every "
                    "method owned by the class."
                ),
                examples=["<init>", "dispatchStart"],
            ),
        ] = None,
        fuzzy_class: Annotated[
            bool,
            Field(description="Allow a partial owning-class match; false requires the class exactly."),
        ] = False,
        exact_name: Annotated[
            bool,
            Field(description="Require an exact method name; false allows a substring match."),
        ] = True,
        descriptor: MethodDescriptor = None,
        cursor: PageCursor = None,
        limit: PageLimit = 200,
    ) -> ReferencePage:
        """Find direct DEX call sites with opcode, offset, and exact-target evidence; this does not find declarations."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "find_references",
            kind="method",
            value=method_name,
            class_name=class_name,
            fuzzy_class=fuzzy_class,
            exact_member=exact_name,
            target_descriptor=descriptor,
            cursor=cursor,
            limit=limit,
        )
        return _reference_page(
            result,
            "No direct method call sites matched. Use apk_get_class_outline to check whether the declaration exists; "
            "reflection and calls from other artifacts are not included.",
        )

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_find_field_references(
        analysis_id: AnalysisId,
        class_name: ClassName,
        ctx: Context[ServerState],
        field_name: Annotated[
            str | None,
            Field(
                min_length=1,
                description=(
                    "Exact or partial target field name; omit to find accesses to every field owned by the class."
                ),
                examples=["mStarting", "apiKey"],
            ),
        ] = None,
        fuzzy_class: Annotated[
            bool,
            Field(description="Allow a partial owning-class match; false requires the class exactly."),
        ] = False,
        exact_name: Annotated[
            bool,
            Field(description="Require an exact field name; false allows a substring match."),
        ] = True,
        field_type: FieldDescriptor = None,
        cursor: PageCursor = None,
        limit: PageLimit = 200,
    ) -> ReferencePage:
        """Find direct DEX field accesses with read/write, opcode, offset, and exact-target evidence."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "find_references",
            kind="field",
            value=field_name,
            class_name=class_name,
            fuzzy_class=fuzzy_class,
            exact_member=exact_name,
            target_descriptor=field_type,
            cursor=cursor,
            limit=limit,
        )
        return _reference_page(
            result,
            "No direct field accesses matched. Use apk_get_class_outline to check whether the field is declared; "
            "reflection and accesses from other artifacts are not included.",
        )

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_find_type_instructions(
        analysis_id: AnalysisId,
        type_name: Annotated[
            str,
            Field(
                min_length=1,
                description=(
                    "Type pattern in Java dotted or Dalvik form; results only cover type-operand instructions."
                ),
                examples=["com.example.Foo", "Lcom/example/Foo;"],
            ),
        ],
        ctx: Context[ServerState],
        cursor: PageCursor = None,
        limit: PageLimit = 200,
    ) -> ReferencePage:
        """Find new-instance, check-cast, const-class, and other type instructions with exact evidence."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "find_references",
            kind="type",
            value=_dalvik_type_name(type_name),
            class_name=None,
            fuzzy_class=False,
            exact_member=False,
            target_descriptor=None,
            cursor=cursor,
            limit=limit,
        )
        return _reference_page(
            result,
            "No explicit type-operand instructions matched. Method calls, field accesses, signatures, declarations, "
            "reflection, and references from other artifacts are not included.",
        )

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_find_string_references(
        analysis_id: AnalysisId,
        value: Annotated[
            str,
            Field(
                min_length=1,
                description="Literal UTF-8 text to locate in DEX strings loaded by const-string instructions.",
                examples=["https://", "api_key"],
            ),
        ],
        ctx: Context[ServerState],
        cursor: PageCursor = None,
        limit: PageLimit = 200,
    ) -> ReferencePage:
        """Find const-string use sites with opcode, offset, and exact-value evidence."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "find_references",
            kind="string",
            value=re.escape(value),
            class_name=None,
            fuzzy_class=False,
            exact_member=False,
            target_descriptor=None,
            cursor=cursor,
            limit=limit,
        )
        return _reference_page(
            result,
            "No const-string use sites matched. Use apk_search_strings to check whether matching text exists in the "
            "DEX string pool without being loaded by code.",
        )

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_search_members(
        analysis_id: AnalysisId,
        kind: Annotated[
            Literal["method", "field"],
            Field(description="Declaration kind to search: method or field."),
        ],
        query: Annotated[
            str,
            Field(description="Case-insensitive member-name substring, such as onCreate or <init>."),
        ],
        ctx: Context[ServerState],
        cursor: PageCursor = None,
        limit: PageLimit = 200,
    ) -> MemberPage:
        """Find declared member names; use the method or field reference tool for their bytecode use sites."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "search_members",
            kind=kind,
            query=query,
            cursor=cursor,
            limit=limit,
        )
        return MemberPage.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_search_strings(
        analysis_id: AnalysisId,
        query: Annotated[
            str,
            Field(description="Case-insensitive substring to match against decoded DEX string-pool values."),
        ],
        ctx: Context[ServerState],
        cursor: PageCursor = None,
        limit: PageLimit = 200,
    ) -> StringPage:
        """Discover DEX string-pool values; use apk_find_string_references to locate const-string use sites."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "search_strings",
            query=query,
            cursor=cursor,
            limit=limit,
        )
        return StringPage.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_get_string_constants(
        analysis_id: AnalysisId,
        class_name: ClassName,
        ctx: Context[ServerState],
    ) -> StringConstantResult:
        """List every const-string instruction and decoded value loaded by methods in one DEX class."""
        result = await _run(ctx, _session(ctx, analysis_id), "string_constants", class_name=class_name)
        return StringConstantResult.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_search_method_bodies(
        analysis_id: AnalysisId,
        query: Annotated[
            str,
            Field(
                description=(
                    "Case-insensitive substring of rendered Dalvik opcode/operand text, such as invoke-virtual, "
                    "const-string, or an operand fragment; do not pass a symbolic owner->member query."
                )
            ),
        ],
        ctx: Context[ServerState],
        cursor: PageCursor = None,
        limit: PageLimit = 200,
    ) -> MethodTextPage:
        """Search rendered Dalvik instructions; use a purpose-specific reference tool for symbolic usages."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "search_method_bodies",
            query=query,
            cursor=cursor,
            limit=limit,
        )
        return MethodTextPage.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_disassemble_method(
        analysis_id: AnalysisId,
        class_name: ClassName,
        method_name: MethodName,
        ctx: Context[ServerState],
        descriptor: MethodDescriptor = None,
    ) -> MethodDisassembly:
        """Inspect exact Dalvik instructions for one method; add descriptor when overloads share its name."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "disassemble_method",
            class_name=class_name,
            method_name=method_name,
            descriptor=descriptor,
        )
        return MethodDisassembly.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_get_class_hierarchy(
        analysis_id: AnalysisId,
        class_name: ClassName,
        ctx: Context[ServerState],
    ) -> ClassHierarchy:
        """Trace superclass, interface, subclass, and implementor relationships for one DEX class."""
        result = await _run(ctx, _session(ctx, analysis_id), "class_hierarchy", class_name=class_name)
        return ClassHierarchy.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_get_call_graph(
        analysis_id: AnalysisId,
        class_name: ClassName,
        method_name: MethodName,
        ctx: Context[ServerState],
        descriptor: MethodDescriptor = None,
        depth: Annotated[
            int,
            Field(ge=1, le=3, description="Caller/callee traversal depth from 1 to 3."),
        ] = 1,
    ) -> CallGraph:
        """Trace bounded caller and callee relationships for one DEX method; use a descriptor for overloads."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "call_graph",
            class_name=class_name,
            method_name=method_name,
            descriptor=descriptor,
            depth=depth,
        )
        return CallGraph.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_list_entries(
        analysis_id: AnalysisId,
        ctx: Context[ServerState],
        kind: Annotated[
            Literal["resource", "asset", "native", "dex", "metadata", "other"] | None,
            Field(description="Optional archive-entry category; omit to list every category."),
        ] = None,
        cursor: PageCursor = None,
        limit: PageLimit = 200,
    ) -> EntryPage:
        """Inventory files and sizes when the opened artifact has the archive capability."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "list_entries",
            kind=kind,
            cursor=cursor,
            limit=limit,
        )
        return EntryPage.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_get_resource_content(
        analysis_id: AnalysisId,
        path: Annotated[
            str,
            Field(description="Exact entry path returned by apk_list_entries, such as res/xml/config.xml."),
        ],
        ctx: Context[ServerState],
        max_bytes: Annotated[
            int,
            Field(ge=1, le=1048576, description="Maximum decoded bytes to return, from 1 byte to 1 MiB."),
        ] = 131072,
    ) -> ResourceContent:
        """Read one archive entry, decoding text or binary XML and base64-encoding other binary content."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "resource_content",
            path=path,
            max_bytes=max_bytes,
        )
        return ResourceContent.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_list_native_libraries(
        analysis_id: AnalysisId,
        ctx: Context[ServerState],
    ) -> NativeLibraryResult:
        """Inventory packaged native libraries and Android ABIs in an archive artifact."""
        result = await _run(ctx, _session(ctx, analysis_id), "native_libraries")
        return NativeLibraryResult.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_get_signing_info(
        analysis_id: AnalysisId,
        ctx: Context[ServerState],
    ) -> SigningResult:
        """Inspect APK signing schemes and certificate fingerprints when the artifact has the signing capability."""
        result = await _run(ctx, _session(ctx, analysis_id), "signing")
        return SigningResult.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_scan_secrets(
        analysis_id: AnalysisId,
        ctx: Context[ServerState],
        include_values: Annotated[
            bool,
            Field(description="Return full matched values; false redacts values to reduce accidental exposure."),
        ] = False,
        limit: PageLimit = 200,
    ) -> SecretScanResult:
        """Scan DEX strings for common credential patterns; findings are heuristic and values default to redacted."""
        result = await _run(
            ctx,
            _session(ctx, analysis_id),
            "scan_secrets",
            include_values=include_values,
            limit=limit,
        )
        return SecretScanResult.model_validate(result)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    async def apk_diff(
        left_analysis_id: Annotated[
            str,
            Field(description="analysis_id returned by load_artifact for the baseline artifact."),
        ],
        right_analysis_id: Annotated[
            str,
            Field(description="analysis_id returned by load_artifact for the comparison artifact."),
        ],
        ctx: Context[ServerState],
    ) -> ArtifactDiff:
        """Compare class inventories and hashes between two simultaneously opened artifact versions."""
        left = _session(ctx, left_analysis_id)
        right = _session(ctx, right_analysis_id)
        payload = {
            "left_id": left_analysis_id,
            "left_path": str(left.path),
            "left_sha256": left.sha256,
            "right_id": right_analysis_id,
            "right_path": str(right.path),
            "right_sha256": right.sha256,
            "max_workers": _state(ctx).runtime.worker_count,
        }
        try:
            result = await _state(ctx).runtime.run("diff", payload)
        except Exception as error:
            raise ToolError(str(error) or "APK comparison failed") from error
        return ArtifactDiff.model_validate(result)

    @server.resource(
        "artifact://{analysis_id}/manifest.xml",
        name="artifact_manifest_xml",
        title="Decoded Android manifest",
        mime_type="application/xml",
    )
    async def manifest_resource(analysis_id: str, ctx: Context) -> str:
        result = await _run(ctx, _session(ctx, analysis_id), "manifest", include_xml=True)
        return result["xml"]

    @server.resource(
        "artifact://{analysis_id}/class/{class_name}",
        name="artifact_class_source",
        title="Decompiled APK class",
        mime_type="text/x-java-source",
    )
    async def class_source_resource(analysis_id: str, class_name: str, ctx: Context) -> str:
        result = await _run(ctx, _session(ctx, analysis_id), "class_source", class_name=class_name)
        return result["source"]

    @server.prompt(name="artifact_triage", title="Triage an Android artifact")
    def artifact_triage_prompt(analysis_id: str) -> str:
        """Guide a broad static-security review of an opened artifact."""
        return (
            f"Triage artifact analysis {analysis_id}. Start with apk_get_summary, then use the reported "
            "capabilities to inspect available manifests, signing, native libraries, suspicious strings, "
            "and references to security-sensitive APIs. Cite exact classes and methods."
        )

    @server.prompt(name="trace_behavior", title="Trace artifact behavior")
    def trace_behavior_prompt(analysis_id: str, class_name: str, method_name: str) -> str:
        """Guide analysis of a class and method behavior."""
        return (
            f"Trace {class_name}->{method_name} in artifact analysis {analysis_id}. Inspect the class outline, "
            "decompiled source, disassembly, and inbound references, then summarize data inputs, side effects, "
            "external calls, and security implications."
        )

    @server.prompt(name="compare_artifacts", title="Compare two Android artifacts")
    def compare_artifacts_prompt(left_analysis_id: str, right_analysis_id: str) -> str:
        """Guide a security-focused comparison between two artifact versions."""
        return (
            f"Compare artifact analyses {left_analysis_id} and {right_analysis_id}. Use apk_diff, summaries, "
            "manifests, signing information, class outlines, and targeted searches to identify behavior and "
            "security changes."
        )

    return server
