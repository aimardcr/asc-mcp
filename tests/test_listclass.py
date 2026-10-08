from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

from dex_fixture import make_dex, make_static_field_dex
from asc_mcp.analysis.artifact_handler import ArtifactHandler


ROOT = Path(__file__).resolve().parents[1]


def make_class_only_dex(descriptors, base=0, version=b"035"):
    header_size = 0x78 if version == b"041" else 0x70
    encoded = [name.encode("utf-8") for name in descriptors]
    buf = bytearray(header_size)

    string_ids = len(buf)
    buf.extend(bytes(4 * len(encoded)))
    type_ids = len(buf)
    buf.extend(bytes(4 * len(encoded)))
    class_defs = len(buf)
    buf.extend(bytes(32 * len(encoded)))
    data_off = len(buf)

    for index, value in enumerate(encoded):
        string_off = base + len(buf)
        struct.pack_into("<I", buf, string_ids + index * 4, string_off)
        struct.pack_into("<I", buf, type_ids + index * 4, index)
        struct.pack_into("<IIIIIIII", buf, class_defs + index * 32,
                         index, 1, 0xffffffff, 0, 0xffffffff, 0, 0, 0)
        buf.append(len(value))
        buf.extend(value)
        buf.append(0)

    buf[:8] = b"dex\n" + version + b"\0"
    struct.pack_into("<IIIIII", buf, 0x20, len(buf), header_size, 0x12345678, 0, 0, 0)
    struct.pack_into(
        "<IIIIIIIIIIIIII",
        buf,
        0x38,
        len(encoded),
        base + string_ids,
        len(encoded),
        base + type_ids,
        0,
        0,
        0,
        0,
        0,
        0,
        len(encoded),
        base + class_defs,
        len(buf) - data_off,
        base + data_off,
    )
    if version == b"041":
        struct.pack_into("<I", buf, 0x74, base)
    return buf


def make_dex041_container():
    first = make_class_only_dex(["Lalpha/First;", "Lshared/Duplicate;"], version=b"041")
    second = make_class_only_dex(
        ["Lbeta/Second;", "Lshared/Duplicate;"],
        base=len(first),
        version=b"041",
    )
    data = first + second
    for header_off in (0, len(first)):
        struct.pack_into("<I", data, header_off + 0x70, len(data))
    return bytes(data)


class ListClassTests(unittest.TestCase):
    def list_classes(self, apk, prefix=None, workers=8):
        return ArtifactHandler(str(apk), max_workers=workers).list_classes(prefix)

    def test_core_filters_normalized_prefix_for_stored_and_deflated_dex(self):
        data = make_class_only_dex([
            "Lcom/xxx/First;",
            "Lcom/xxx/internal/Second;",
            "Lorg/example/Other;",
        ])
        expected = "Lcom/xxx/First;\nLcom/xxx/internal/Second;\n"
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                for prefix in ("com.xxx", "com/xxx", "Lcom/xxx"):
                    with self.subTest(compression=compression, prefix=prefix):
                        with zipfile.ZipFile(apk, "w", compression=compression) as archive:
                            archive.writestr("classes.dex", data)
                        result = self.list_classes(apk, prefix)
                        self.assertEqual("".join(f"{name}\n" for name in result), expected)

    def test_core_preserves_dex_order_for_stored_and_deflated_multidex(self):
        expected = "Lexample/Test;\nLexample/Statics;\nLexample/Test;\n"
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(compression=compression):
                    with zipfile.ZipFile(apk, "w", compression=compression) as archive:
                        archive.writestr("classes.dex", make_dex())
                        archive.writestr("classes2.dex", make_static_field_dex())
                        archive.writestr("classes3.dex", make_dex())
                    result = self.list_classes(apk, workers=2)
                    self.assertEqual("".join(f"{name}\n" for name in result), expected)

    def test_core_does_not_require_site_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("classes.dex", make_dex())
            script = (
                "from asc_mcp.analysis.artifact_handler import ArtifactHandler; "
                f"print(*ArtifactHandler({str(apk)!r}).list_classes(), sep='\\n')"
            )
            result = subprocess.run(
                [sys.executable, "-S", "-c", script],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "Lexample/Test;\n")

    def test_deflate_path_lists_large_dex(self):
        data = bytearray(make_dex())
        data.extend(random.Random(0).randbytes(1024 * 1024))
        struct.pack_into("<I", data, 0x20, len(data))

        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("classes.dex", data)
            self.assertEqual(self.list_classes(apk), ["Lexample/Test;"])

    def test_dex041_container_lists_every_logical_member(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(compression=compression):
                    with zipfile.ZipFile(apk, "w", compression=compression) as archive:
                        archive.writestr("classes.dex", make_dex041_container())
                    self.assertEqual(
                        self.list_classes(apk, workers=1),
                        ["Lalpha/First;", "Lshared/Duplicate;", "Lbeta/Second;", "Lshared/Duplicate;"],
                    )

    def test_bad_class_type_index_is_a_clean_error(self):
        data = bytearray(make_dex())
        class_defs_off = struct.unpack_from("<I", data, 0x64)[0]
        struct.pack_into("<I", data, class_defs_off, 0xffffffff)

        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("classes.dex", data)
            with self.assertRaisesRegex(ValueError, "bad class_def->type_idx"):
                self.list_classes(apk)

    def test_worker_count_must_be_positive(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", make_dex())
            with self.assertRaisesRegex(ValueError, "Worker count must be greater than zero"):
                self.list_classes(apk, workers=0)

    def test_empty_prefix_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", make_dex())
            with self.assertRaisesRegex(ValueError, "Class prefix cannot be empty"):
                self.list_classes(apk, prefix=" ")


if __name__ == "__main__":
    unittest.main()
