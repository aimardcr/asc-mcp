from typing import Literal

from pydantic import BaseModel, Field


class ArtifactHandle(BaseModel):
    analysis_id: str
    name: str
    artifact_type: Literal["apk", "dex", "jar", "aab", "aar", "apks", "xapk", "zip"]
    capabilities: list[str]
    size_bytes: int
    sha256: str
    entry_count: int
    dex_count: int


class CloseResult(BaseModel):
    analysis_id: str
    closed: bool


class ArtifactSummary(BaseModel):
    analysis_id: str
    name: str
    artifact_type: Literal["apk", "dex", "jar", "aab", "aar", "apks", "xapk", "zip"]
    capabilities: list[str]
    size_bytes: int
    sha256: str
    entry_count: int
    dex_files: list[str]
    native_abis: list[str]
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None


class ManifestComponent(BaseModel):
    kind: Literal["activity", "activity-alias", "service", "receiver", "provider"]
    name: str
    exported: bool | None = None
    enabled: bool | None = None
    permission: str | None = Field(
        default=None,
        description="android:permission declared on this component; null does not mean the component is unprotected.",
    )
    effective_permission: str | None = Field(
        default=None,
        description="Component permission after inheriting android:permission from the application.",
    )
    read_permission: str | None = Field(
        default=None,
        description="Provider-specific android:readPermission; null for other component types or when not declared.",
    )
    write_permission: str | None = Field(
        default=None,
        description="Provider-specific android:writePermission; null for other component types or when not declared.",
    )
    effective_read_permission: str | None = Field(
        default=None,
        description="Effective provider read permission after component and application fallback.",
    )
    effective_write_permission: str | None = Field(
        default=None,
        description="Effective provider write permission after component and application fallback.",
    )
    intent_actions: list[str] = Field(default_factory=list)


class ManifestResult(BaseModel):
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    application_name: str | None = None
    application_permission: str | None = Field(
        default=None,
        description="Default android:permission inherited by components that do not declare their own permission.",
    )
    debuggable: bool | None = None
    permissions: list[str] = Field(default_factory=list)
    components: list[ManifestComponent] = Field(default_factory=list)
    xml: str | None = None


class ClassPage(BaseModel):
    classes: list[str]
    total: int
    next_cursor: str | None = None


class MemberReference(BaseModel):
    start: int
    end: int
    kind: Literal["method", "field"]
    declaring_class: str
    name: str
    descriptor: str
    declaration: bool


class ClassSource(BaseModel):
    class_name: str
    dex_name: str
    source: str
    member_references: list[MemberReference] = Field(default_factory=list)


class FieldOutline(BaseModel):
    name: str
    type: str
    access_flags: int
    static: bool


class MethodOutline(BaseModel):
    name: str
    descriptor: str
    access_flags: int
    kind: Literal["direct", "virtual"]
    has_code: bool


class ClassOutline(BaseModel):
    class_name: str
    dex_name: str
    access_flags: int
    superclass: str | None = None
    interfaces: list[str] = Field(default_factory=list)
    fields: list[FieldOutline] = Field(default_factory=list)
    methods: list[MethodOutline] = Field(default_factory=list)


class ReferenceEvidence(BaseModel):
    offset: int = Field(description="Byte offset of the instruction within the caller method.")
    opcode: str
    access: Literal["invoke", "read", "write", "load", "type-use"]
    target_class: str | None = None
    target_name: str | None = None
    target_descriptor: str | None = None
    target_value: str | None = None


class ReferenceHit(BaseModel):
    dex_name: str
    method_class: str
    method_name: str
    method_descriptor: str
    match_type: Literal["string", "type", "method", "field"]
    matches: list[str]
    evidence: list[ReferenceEvidence] = Field(default_factory=list)


class ReferencePage(BaseModel):
    hits: list[ReferenceHit]
    total: int
    next_cursor: str | None = None
    hint: str | None = Field(
        default=None,
        description="Interpretation and recommended next call when no matches were found.",
    )


class MemberHit(BaseModel):
    dex_name: str
    class_name: str
    name: str
    descriptor: str
    access_flags: int


class MemberPage(BaseModel):
    kind: Literal["method", "field"]
    members: list[MemberHit]
    total: int
    next_cursor: str | None = None


class StringHit(BaseModel):
    dex_name: str
    index: int
    value: str


class StringPage(BaseModel):
    strings: list[StringHit]
    total: int
    next_cursor: str | None = None


class ArtifactEntry(BaseModel):
    path: str
    kind: Literal["resource", "asset", "native", "dex", "metadata", "other"]
    size_bytes: int
    compressed_size: int


class EntryPage(BaseModel):
    entries: list[ArtifactEntry]
    total: int
    next_cursor: str | None = None


class ResourceContent(BaseModel):
    path: str
    mime_type: str
    encoding: Literal["utf-8", "base64"]
    content: str
    truncated: bool


class NativeLibrary(BaseModel):
    path: str
    abi: str
    name: str
    size_bytes: int
    compressed_size: int


class NativeLibraryResult(BaseModel):
    libraries: list[NativeLibrary]
    abis: list[str]


class Certificate(BaseModel):
    subject: str
    issuer: str
    serial_number: str
    sha256: str
    not_before: str | None = None
    not_after: str | None = None


class SigningResult(BaseModel):
    signed: bool
    v1: bool
    v2: bool
    v3: bool
    v31: bool
    certificates: list[Certificate] = Field(default_factory=list)


class SecretFinding(BaseModel):
    kind: str
    severity: Literal["low", "medium", "high"]
    dex_name: str
    string_index: int
    value: str


class SecretScanResult(BaseModel):
    findings: list[SecretFinding]
    total: int
    truncated: bool


class ClassHierarchy(BaseModel):
    class_name: str
    superclass_chain: list[str]
    interfaces: list[str]
    subclasses: list[str]
    implementors: list[str]


class Instruction(BaseModel):
    offset: int
    opcode: str
    operands: str


class MethodDisassembly(BaseModel):
    class_name: str
    method_name: str
    descriptor: str
    dex_name: str
    instructions: list[Instruction]


class StringConstant(BaseModel):
    method_name: str
    method_descriptor: str
    offset: int
    value: str


class StringConstantResult(BaseModel):
    class_name: str
    dex_name: str
    constants: list[StringConstant]


class MethodTextHit(BaseModel):
    dex_name: str
    class_name: str
    method_name: str
    method_descriptor: str
    instruction: str


class MethodTextPage(BaseModel):
    hits: list[MethodTextHit]
    total: int
    next_cursor: str | None = None


class CallGraphNode(BaseModel):
    class_name: str
    method_name: str
    descriptor: str


class CallGraphEdge(BaseModel):
    caller: CallGraphNode
    callee: CallGraphNode


class CallGraph(BaseModel):
    root: CallGraphNode
    callers: list[CallGraphNode]
    callees: list[CallGraphNode]
    edges: list[CallGraphEdge]


class ArtifactDiff(BaseModel):
    left_analysis_id: str
    right_analysis_id: str
    added_classes: list[str]
    removed_classes: list[str]
    common_class_count: int
    left_sha256: str
    right_sha256: str


class ServerStatus(BaseModel):
    open_analyses: int
    worker_count: int
    allowed_roots: list[str]
