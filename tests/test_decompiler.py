import importlib
import importlib.util
from pathlib import Path
import subprocess
import struct
import sys
import unittest

from dex_fixture import make_dex, make_static_field_dex
from asc_mcp.core.core.dex.dex_manager import DexManager
from asc_mcp.core.utils.dex_parser import parse_encoded_array
from asc_mcp.core.utils.tinydex import DEX

ROOT = Path(__file__).resolve().parents[1]


class RebuildTests(unittest.TestCase):
    def test_rebuilt_dex_keeps_signature_and_checksum_zero(self):
        data = DexManager(make_dex()).extract_and_rebuild('Lexample/Test;')
        self.assertEqual(data[8:32], bytes(24))

    def test_rebuild_keeps_static_values_and_field_operands_aligned(self):
        data = DexManager(make_static_field_dex()).extract_and_rebuild('Lexample/Statics;')
        dex = DEX.parse(memoryview(data), 'rebuilt.dex')
        clazz = dex.classes[0]
        static_fields = [field for field in clazz.fields if field.is_static]
        static_values_off = struct.unpack_from('<I', data, clazz._class_def_off + 28)[0]
        values = parse_encoded_array(memoryview(data), static_values_off, set(), set(), set(), set())

        self.assertEqual([field.name for field in static_fields], ['FIRST', 'SECOND'])
        self.assertEqual([int.from_bytes(value[1], 'little', signed=True) for value in values], [11, 22])

        method = next(method for method in clazz.methods if method.name == 'getSecond')
        field_idx = method.bytecode[2] | (method.bytecode[3] << 8)
        self.assertEqual(dex.fields[field_idx].name, 'SECOND')


@unittest.skipUnless(importlib.util.find_spec('androguard'), 'install requirements.txt for decompiler tests')
class DecompilerTests(unittest.TestCase):
    def test_decompile_keeps_dummy_fast_path_and_class_zero(self):
        script = """
import sys
sys.path.insert(0, 'tests')
from dex_fixture import make_dex
loaded = []
sys.addaudithook(lambda event, args: loaded.append(args[0]) if event == 'import' else None)
from asc_mcp.analysis.asc_handler import AscHandler
for _ in range(2):
    source = AscHandler().getclass(make_dex(), 'Lexample/Test;')
    assert 'class Test' in source
    assert 'void first()' in source
    assert 'void second()' in source
for name in ('email', 'xml.sax.saxutils', 'networkx', 'loguru'):
    assert type(sys.modules[name]).__name__ == 'DummyModule', name
    assert not any(module == name or module.startswith(name + '.') for module in loaded), name
assert sys.modules['mutf8.cmutf8'].decode_modified_utf8.__module__ == '_asc_mcp_mutf8_py'
"""
        result = subprocess.run([sys.executable, '-c', script], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
