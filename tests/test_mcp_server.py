import asyncio
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from mcp import StdioServerParameters
from mcp.client import Client

from dex_fixture import make_dex, make_parameter_dex
from asc_mcp.server import create_server
from asc_mcp.service import (
    AndroidAnalysisService,
    _cached_androguard_dexes,
    _cached_call_graph_index,
    _cached_tiny_dexes,
)
from asc_mcp.sessions import SessionRegistry


MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="example.app" android:versionCode="7" android:versionName="1.2">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:name=".App" android:debuggable="false">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter>
    </activity>
  </application>
</manifest>
"""


def make_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr("classes.dex", make_dex())
        archive.writestr("assets/config.txt", "enabled=true")
        archive.writestr("lib/arm64-v8a/libexample.so", b"\x7fELF")


def make_parameter_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr("classes.dex", make_parameter_dex())


def make_jar(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bytecode/classes.dex", make_dex())
        archive.writestr("com/example/JvmOnly.class", b"\xca\xfe\xba\xbe")


def make_aar(path: Path) -> None:
    nested_buffer = io.BytesIO()
    with zipfile.ZipFile(nested_buffer, "w", compression=zipfile.ZIP_DEFLATED) as nested:
        nested.writestr("com/example/Library.class", b"\xca\xfe\xba\xbe")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("classes.jar", nested_buffer.getvalue())


class SessionRegistryTests(unittest.TestCase):
    def test_open_restricts_paths_and_detects_changes(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            apk = Path(directory) / "fixture.apk"
            make_apk(apk)
            registry = SessionRegistry([directory])
            session = registry.open(str(apk))
            self.assertEqual(session.dex_files, ("classes.dex",))
            self.assertEqual(len(session.sha256), 64)

            dex = Path(directory) / "fixture.dex"
            dex.write_bytes(make_dex())
            dex_session = registry.open(str(dex))
            self.assertEqual(dex_session.artifact_type, "dex")
            self.assertEqual(dex_session.capabilities, ("dex",))

            jar = Path(directory) / "fixture.jar"
            make_jar(jar)
            jar_session = registry.open(str(jar))
            self.assertEqual(jar_session.artifact_type, "jar")
            self.assertIn("dex", jar_session.capabilities)
            self.assertIn("jvm-class-inventory", jar_session.capabilities)

            aar = Path(directory) / "fixture.aar"
            make_aar(aar)
            aar_session = registry.open(str(aar))
            self.assertEqual(aar_session.artifact_type, "aar")
            self.assertIn("jvm-class-inventory", aar_session.capabilities)

            outside_apk = Path(outside) / "outside.apk"
            make_apk(outside_apk)
            with self.assertRaises(PermissionError):
                registry.open(str(outside_apk))

            with apk.open("ab") as stream:
                stream.write(b"changed")
            with self.assertRaises(ValueError):
                registry.get(session.analysis_id)


class ServiceCacheTests(unittest.TestCase):
    def test_repeated_queries_reuse_parsed_dex_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.dex"
            path.write_bytes(make_dex())
            service = AndroidAnalysisService(str(path), "dex", ("dex",), 1)

            _cached_tiny_dexes.cache_clear()
            service.search_strings("token", None, 10)
            tiny_hits = _cached_tiny_dexes.cache_info().hits
            service.search_strings("token", None, 10)
            self.assertGreater(_cached_tiny_dexes.cache_info().hits, tiny_hits)

            _cached_androguard_dexes.cache_clear()
            service.disassemble_method("example.Test", "first", "()V")
            androguard_hits = _cached_androguard_dexes.cache_info().hits
            service.disassemble_method("example.Test", "first", "()V")
            self.assertGreater(_cached_androguard_dexes.cache_info().hits, androguard_hits)

            _cached_call_graph_index.cache_clear()
            service.call_graph("example.Test", "first", "()V", 1)
            graph_hits = _cached_call_graph_index.cache_info().hits
            service.call_graph("example.Test", "first", "()V", 1)
            self.assertGreater(_cached_call_graph_index.cache_info().hits, graph_hits)


class ServerSchemaTests(unittest.TestCase):
    def test_server_exposes_typed_analysis_surface(self):
        server = create_server([Path.cwd()], worker_count=1)
        tools = {tool.name: tool for tool in server._tool_manager.list_tools()}
        self.assertEqual(len(tools), 25)
        self.assertNotIn("ctx", tools["load_artifact"].parameters["properties"])
        self.assertIsNotNone(tools["apk_get_class_source"].output_schema)
        self.assertTrue(tools["apk_get_class_source"].annotations.read_only_hint)
        self.assertEqual(
            {template.uri_template for template in server._resource_manager.list_templates()},
            {"artifact://{analysis_id}/manifest.xml", "artifact://{analysis_id}/class/{class_name}"},
        )
        self.assertEqual(
            {prompt.name for prompt in server._prompt_manager.list_prompts()},
            {"artifact_triage", "trace_behavior", "compare_artifacts"},
        )

    def test_every_tool_parameter_has_llm_guidance(self):
        server = create_server([Path.cwd()], worker_count=1)
        self.assertIn("apk_find_method_references finds method call sites", server.instructions)
        for tool in server._tool_manager.list_tools():
            self.assertTrue(tool.description, tool.name)
            for name, schema in tool.parameters.get("properties", {}).items():
                self.assertTrue(schema.get("description"), f"{tool.name}.{name}")

        tools = {tool.name: tool for tool in server._tool_manager.list_tools()}
        self.assertIn("purpose-specific reference tool", tools["apk_search_method_bodies"].description)
        body_query = tools["apk_search_method_bodies"].parameters["properties"]["query"]["description"]
        self.assertIn("do not pass a symbolic owner->member query", body_query)
        descriptor = tools["apk_disassemble_method"].parameters["properties"]["descriptor"]
        self.assertIn("copy it directly from apk_get_class_outline", descriptor["description"])

    def test_reference_tools_make_invalid_combinations_unrepresentable(self):
        server = create_server([Path.cwd()], worker_count=1)
        tools = {tool.name: tool for tool in server._tool_manager.list_tools()}
        expected_parameters = {
            "apk_find_method_references": {
                "analysis_id",
                "class_name",
                "method_name",
                "fuzzy_class",
                "exact_name",
                "descriptor",
                "cursor",
                "limit",
            },
            "apk_find_field_references": {
                "analysis_id",
                "class_name",
                "field_name",
                "fuzzy_class",
                "exact_name",
                "field_type",
                "cursor",
                "limit",
            },
            "apk_find_type_instructions": {"analysis_id", "type_name", "cursor", "limit"},
            "apk_find_string_references": {"analysis_id", "value", "cursor", "limit"},
        }
        self.assertNotIn("apk_find_references", tools)
        for name, expected in expected_parameters.items():
            properties = tools[name].parameters["properties"]
            self.assertEqual(set(properties), expected)
            self.assertNotIn("kind", properties)

        method_name = tools["apk_find_method_references"].parameters["properties"]["method_name"]
        self.assertIn("<init>", method_name["examples"])
        type_description = tools["apk_find_type_instructions"].description
        self.assertIn("new-instance", type_description)
        hint_schema = tools["apk_find_method_references"].output_schema["properties"]["hint"]
        self.assertIn("recommended next call", hint_schema["description"])


class McpIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_outline_descriptor_round_trips_to_method_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "parameters.apk"
            make_parameter_apk(apk)
            server = create_server([directory], worker_count=1)
            async with Client(server) as client:
                opened = await client.call_tool("load_artifact", {"path": str(apk)})
                analysis_id = opened.structured_content["analysis_id"]
                outline = await client.call_tool(
                    "apk_get_class_outline",
                    {"analysis_id": analysis_id, "class_name": "example.Test"},
                )
                descriptor = outline.structured_content["methods"][0]["descriptor"]
                self.assertEqual(descriptor, "(Landroid/content/Context;IZ)V")

                disassembly = await client.call_tool(
                    "apk_disassemble_method",
                    {
                        "analysis_id": analysis_id,
                        "class_name": "example.Test",
                        "method_name": "mix",
                        "descriptor": descriptor,
                    },
                )
                self.assertFalse(disassembly.is_error)
                self.assertEqual(disassembly.structured_content["descriptor"], descriptor)

                call_graph = await client.call_tool(
                    "apk_get_call_graph",
                    {
                        "analysis_id": analysis_id,
                        "class_name": "example.Test",
                        "method_name": "mix",
                        "descriptor": descriptor,
                    },
                )
                self.assertFalse(call_graph.is_error)
                self.assertEqual(call_graph.structured_content["root"]["descriptor"], descriptor)

    async def test_open_inspect_search_and_decompile(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            make_apk(apk)
            server = create_server([directory], worker_count=1)
            async with Client(server) as client:
                listed = await client.list_tools()
                self.assertEqual(len(listed.tools), 25)

                opened = await client.call_tool("load_artifact", {"path": str(apk)})
                self.assertFalse(opened.is_error)
                analysis_id = opened.structured_content["analysis_id"]

                summary = await client.call_tool("apk_get_summary", {"analysis_id": analysis_id})
                self.assertEqual(summary.structured_content["package_name"], "example.app")
                self.assertEqual(summary.structured_content["target_sdk"], "35")

                classes = await client.call_tool("apk_list_classes", {"analysis_id": analysis_id})
                self.assertEqual(classes.structured_content["classes"], ["Lexample/Test;"])

                outline = await client.call_tool(
                    "apk_get_class_outline",
                    {"analysis_id": analysis_id, "class_name": "example.Test"},
                )
                self.assertEqual([item["name"] for item in outline.structured_content["methods"]], ["first", "second"])

                refs = await client.call_tool(
                    "apk_find_string_references",
                    {"analysis_id": analysis_id, "value": "token"},
                )
                self.assertEqual(refs.structured_content["total"], 2)
                self.assertIsNone(refs.structured_content["hint"])
                evidence = refs.structured_content["hits"][0]["evidence"][0]
                self.assertEqual(evidence["opcode"], "const-string")
                self.assertEqual(evidence["access"], "load")
                self.assertEqual(evidence["target_value"], "token")

                missing_refs = await client.call_tool(
                    "apk_find_method_references",
                    {
                        "analysis_id": analysis_id,
                        "class_name": "example.Missing",
                        "method_name": "<init>",
                    },
                )
                self.assertEqual(missing_refs.structured_content["total"], 0)
                self.assertIn("declaration exists", missing_refs.structured_content["hint"])

                source = await client.call_tool(
                    "apk_get_class_source",
                    {"analysis_id": analysis_id, "class_name": "example.Test"},
                )
                self.assertIn("class Test", source.structured_content["source"])

                disassembly = await client.call_tool(
                    "apk_disassemble_method",
                    {"analysis_id": analysis_id, "class_name": "example.Test", "method_name": "first"},
                )
                self.assertEqual(disassembly.structured_content["instructions"][0]["opcode"], "const-string")

                constants = await client.call_tool(
                    "apk_get_string_constants",
                    {"analysis_id": analysis_id, "class_name": "example.Test"},
                )
                self.assertEqual([item["value"] for item in constants.structured_content["constants"]], ["token", "token"])

                body_hits = await client.call_tool(
                    "apk_search_method_bodies",
                    {"analysis_id": analysis_id, "query": "const-string"},
                )
                self.assertEqual(body_hits.structured_content["total"], 2)

                members = await client.call_tool(
                    "apk_search_members",
                    {"analysis_id": analysis_id, "kind": "method", "query": "first"},
                )
                self.assertEqual(members.structured_content["members"][0]["name"], "first")

                strings = await client.call_tool(
                    "apk_search_strings",
                    {"analysis_id": analysis_id, "query": "token"},
                )
                self.assertEqual(strings.structured_content["strings"][0]["value"], "token")

                hierarchy = await client.call_tool(
                    "apk_get_class_hierarchy",
                    {"analysis_id": analysis_id, "class_name": "example.Test"},
                )
                self.assertEqual(hierarchy.structured_content["class_name"], "Lexample/Test;")

                call_graph = await client.call_tool(
                    "apk_get_call_graph",
                    {"analysis_id": analysis_id, "class_name": "example.Test", "method_name": "first"},
                )
                self.assertEqual(call_graph.structured_content["root"]["method_name"], "first")

                entries = await client.call_tool(
                    "apk_list_entries",
                    {"analysis_id": analysis_id, "kind": "asset"},
                )
                self.assertEqual(entries.structured_content["entries"][0]["path"], "assets/config.txt")

                resource = await client.call_tool(
                    "apk_get_resource_content",
                    {"analysis_id": analysis_id, "path": "assets/config.txt"},
                )
                self.assertEqual(resource.structured_content["content"], "enabled=true")

                libraries = await client.call_tool(
                    "apk_list_native_libraries",
                    {"analysis_id": analysis_id},
                )
                self.assertEqual(libraries.structured_content["abis"], ["arm64-v8a"])

                signing = await client.call_tool(
                    "apk_get_signing_info",
                    {"analysis_id": analysis_id},
                )
                self.assertFalse(signing.structured_content["signed"])

                secrets = await client.call_tool(
                    "apk_scan_secrets",
                    {"analysis_id": analysis_id},
                )
                self.assertEqual(secrets.structured_content["total"], 0)

                diff = await client.call_tool(
                    "apk_diff",
                    {"left_analysis_id": analysis_id, "right_analysis_id": analysis_id},
                )
                self.assertEqual(diff.structured_content["common_class_count"], 1)

                manifest = await client.read_resource(f"artifact://{analysis_id}/manifest.xml")
                self.assertIn("example.app", manifest.contents[0].text)

                class_source = await client.read_resource(f"artifact://{analysis_id}/class/example.Test")
                self.assertIn("class Test", class_source.contents[0].text)

                dex = Path(directory) / "fixture.dex"
                dex.write_bytes(make_dex())
                dex_opened = await client.call_tool("load_artifact", {"path": str(dex)})
                dex_id = dex_opened.structured_content["analysis_id"]
                self.assertEqual(dex_opened.structured_content["artifact_type"], "dex")
                dex_summary = await client.call_tool("apk_get_summary", {"analysis_id": dex_id})
                self.assertEqual(dex_summary.structured_content["dex_files"], ["fixture.dex"])
                dex_classes = await client.call_tool("apk_list_classes", {"analysis_id": dex_id})
                self.assertEqual(dex_classes.structured_content["classes"], ["Lexample/Test;"])

                jar = Path(directory) / "fixture.jar"
                make_jar(jar)
                jar_opened = await client.call_tool("load_artifact", {"path": str(jar)})
                jar_id = jar_opened.structured_content["analysis_id"]
                self.assertEqual(jar_opened.structured_content["artifact_type"], "jar")
                jar_classes = await client.call_tool("apk_list_classes", {"analysis_id": jar_id})
                self.assertEqual(
                    jar_classes.structured_content["classes"],
                    ["Lexample/Test;", "Lcom/example/JvmOnly;"],
                )
                jar_manifest = await client.call_tool("apk_get_manifest", {"analysis_id": jar_id})
                self.assertTrue(jar_manifest.is_error)

                aar = Path(directory) / "fixture.aar"
                make_aar(aar)
                aar_opened = await client.call_tool("load_artifact", {"path": str(aar)})
                aar_classes = await client.call_tool(
                    "apk_list_classes",
                    {"analysis_id": aar_opened.structured_content["analysis_id"]},
                )
                self.assertEqual(aar_classes.structured_content["classes"], ["Lcom/example/Library;"])


class StdioIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_module_entrypoint_serves_mcp_over_stdio(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            make_apk(apk)
            parameters = StdioServerParameters(
                command=sys.executable,
                args=["-m", "asc_mcp"],
                cwd=str(Path(__file__).resolve().parents[1]),
                env={"ASC_MCP_ALLOWED_ROOTS": directory, "ASC_MCP_WORKERS": "1"},
            )
            async with Client(parameters) as client:
                tools = await client.list_tools()
                self.assertEqual(len(tools.tools), 25)
                opened = await client.call_tool("load_artifact", {"path": str(apk)})
                analysis_id = opened.structured_content["analysis_id"]
                classes = await client.call_tool("apk_list_classes", {"analysis_id": analysis_id})
                self.assertEqual(classes.structured_content["classes"], ["Lexample/Test;"])


if __name__ == "__main__":
    unittest.main()
