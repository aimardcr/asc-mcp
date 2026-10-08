import copy
import importlib.util
import os
import sys
import types
from collections import defaultdict


_DexManager = None
_FindRefManager = None
_decompile_dex_bytes = None
_decompile_dex_bytes_with_metadata = None
_DEX = None


def _install_pure_python_mutf8_shim():
    if "mutf8.cmutf8" in sys.modules:
        return

    pkg_spec = importlib.util.find_spec("mutf8")
    if pkg_spec is None or not pkg_spec.submodule_search_locations:
        return

    pkg_dir = pkg_spec.submodule_search_locations[0]
    py_impl = os.path.join(pkg_dir, "mutf8.py")
    mod_spec = importlib.util.spec_from_file_location("_asc_mcp_mutf8_py", py_impl)
    if mod_spec is None or mod_spec.loader is None:
        return

    module = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(module)

    shim = types.ModuleType("mutf8.cmutf8")
    shim.decode_modified_utf8 = module.decode_modified_utf8
    shim.encode_modified_utf8 = module.encode_modified_utf8
    sys.modules["mutf8.cmutf8"] = shim


def _lazy_import():
    global _DexManager, _FindRefManager, _decompile_dex_bytes, _decompile_dex_bytes_with_metadata, _DEX
    if _DexManager is not None:
        return

    _install_pure_python_mutf8_shim()
    from asc_mcp.core.core.dex.dex_manager import DexManager
    from asc_mcp.core.findrefs.findrefs_manager import FindRefManager
    from asc_mcp.core.utils.tinydex import DEX
    from asc_mcp.core.utils.decompiler import decompile_dex_bytes, decompile_dex_bytes_with_metadata

    _DexManager = DexManager
    _FindRefManager = FindRefManager
    _decompile_dex_bytes = decompile_dex_bytes
    _decompile_dex_bytes_with_metadata = decompile_dex_bytes_with_metadata
    _DEX = DEX


class AscHandler:
    def __init__(self, debug : bool = False):
        self.debug = debug

    def getclass(self, dex_buf : bytes, dalvik_class : str) -> str:
        _lazy_import()
        manager = _DexManager(memoryview(dex_buf), debug=self.debug)
        new_dex_bytes = manager.extract_and_rebuild(dalvik_class)
        return _decompile_dex_bytes(new_dex_bytes, dalvik_class)

    def getclass_with_metadata(self, dex_buf : bytes, dalvik_class : str):
        _lazy_import()
        manager = _DexManager(memoryview(dex_buf), debug=self.debug)
        new_dex_bytes = manager.extract_and_rebuild(dalvik_class)
        return _decompile_dex_bytes_with_metadata(new_dex_bytes, dalvik_class)

    def _format_method(self, dex, midx : int) -> str:
        method = dex.methods[midx]
        return f"{method.cls.fullname}->{method.name}"

    def _method_descriptor(self, dex, midx : int) -> str:
        prototype = dex.methods[midx].prototype
        parameters = "".join(str(item) for item in prototype.parameters_type)
        return_type = dex.types[prototype.return_type_idx].descriptor
        return f"({parameters}){return_type}"

    def _format_matched_name(self, dex, find_type : str, idx : int) -> str:
        if find_type == "string":
            return str(dex.strings[idx])
        if find_type == "type":
            return dex.types[idx].descriptor
        if find_type == "method":
            method = dex.methods[idx]
            return f"{method.cls.fullname}->{method.name}"
        field = dex.fields[idx]
        return f"{field.cls.fullname}->{field.name}"

    def _reference_evidence(self, dex, ref_manager, find_type, target_idx, method_idx, dex_offset):
        from asc_mcp.core.models.dvm_opcode import opcodes

        opcode = opcodes[dex.buf[dex_offset]].name
        evidence = {
            "offset": dex_offset - ref_manager.insn_locator.method_bounds[method_idx],
            "opcode": opcode,
            "access": "type-use",
            "target_class": None,
            "target_name": None,
            "target_descriptor": None,
            "target_value": None,
        }
        if find_type == "method":
            target = dex.methods[target_idx]
            evidence.update(
                access="invoke",
                target_class=target.cls.fullname,
                target_name=str(target.name),
                target_descriptor=self._method_descriptor(dex, target_idx),
            )
        elif find_type == "field":
            target = dex.fields[target_idx]
            evidence.update(
                access="write" if 0x59 <= dex.buf[dex_offset] <= 0x5f or 0x67 <= dex.buf[dex_offset] <= 0x6d else "read",
                target_class=target.cls.fullname,
                target_name=str(target.name),
                target_descriptor=target.type.descriptor,
            )
        elif find_type == "string":
            evidence.update(access="load", target_value=str(dex.strings[target_idx]))
        else:
            evidence["target_descriptor"] = dex.types[target_idx].descriptor
        return evidence

    def findrefs_structured(
        self,
        dex_name : str,
        dex_buf : bytes,
        find_type : str,
        find : dict,
        aggregate : bool = True,
    ) -> list:
        from asc_mcp.core.findrefs.findrefs_manager import FindRefManager
        from asc_mcp.core.utils.tinydex import DEX

        dex = DEX.parse(memoryview(dex_buf), dex_name)
        ref_manager = FindRefManager(dex)
        query = copy.deepcopy(find)
        matched_idxs = ref_manager.find_ref(query, True)
        mids = query[find_type]
        offsets = ref_manager.code_scanner.matched_offsets[find_type] if ref_manager.code_scanner else []
        if not aggregate:
            ret = []
            for i in range(len(mids)):
                midx = mids[i]
                if midx is None:
                    continue
                idx = matched_idxs[i]
                if isinstance(midx, list):
                    midxs = midx
                else:
                    midxs = [midx]
                for mid in midxs:
                    method = dex.methods[mid]
                    evidence = self._reference_evidence(dex, ref_manager, find_type, idx, mid, offsets[i])
                    ret.append(
                        {
                            "dex_name": dex_name,
                            "method_class": method.cls.fullname,
                            "method_name": method.name,
                            "method_descriptor": self._method_descriptor(dex, mid),
                            "match_type": find_type,
                            "matches": [self._format_matched_name(dex, find_type, idx)],
                            "evidence": [evidence],
                        }
                    )
            return ret

        grouped = defaultdict(lambda: {"targets": set(), "evidence": []})
        for i in range(len(mids)):
            midx = mids[i]
            if midx is None:
                continue
            idx = matched_idxs[i]
            if isinstance(midx, list):
                midxs = midx
            else:
                midxs = [midx]
            for mid in midxs:
                grouped[mid]["targets"].add(idx)
                grouped[mid]["evidence"].append(
                    self._reference_evidence(dex, ref_manager, find_type, idx, mid, offsets[i])
                )

        ret = []
        for mid in sorted(grouped):
            method = dex.methods[mid]
            evidence = grouped[mid]["evidence"]
            matches = [
                self._format_matched_name(dex, find_type, idx)
                for idx in sorted(grouped[mid]["targets"])
            ]
            ret.append(
                {
                    "dex_name": dex_name,
                    "method_class": method.cls.fullname,
                    "method_name": method.name,
                    "method_descriptor": self._method_descriptor(dex, mid),
                    "match_type": find_type,
                    "matches": matches,
                    "evidence": evidence,
                }
            )
        return ret

    def findrefs(self, dex_name : str, dex_buf : bytes, find_type : str, find : dict, aggregate : bool = True) -> list:
        rows = self.findrefs_structured(dex_name, dex_buf, find_type, find, aggregate)
        return [
            f"{row['dex_name']} | {row['method_class']}->{row['method_name']} | "
            f"matched=({'; '.join(row['matches'])})"
            for row in rows
        ]
