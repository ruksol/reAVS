from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Iterable


class FakeInstruction:
    def __init__(self, name: str, output: str = "", string: Optional[str] = None, operands: Optional[list] = None):
        self._name = name
        self._output = output
        self._string = string
        self._operands = operands or []

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output

    def get_string(self) -> Optional[str]:
        return self._string

    def get_operands(self) -> list:
        return self._operands


class FakeBC:
    def __init__(self, instructions: Iterable[FakeInstruction]):
        self._instructions = list(instructions)

    def get_instructions(self):
        return list(self._instructions)


class FakeCode:
    def __init__(self, instructions: Iterable[FakeInstruction], registers_size: int = 0):
        self._bc = FakeBC(instructions)
        self._registers_size = registers_size

    def get_bc(self) -> FakeBC:
        return self._bc

    def get_registers_size(self) -> int:
        return self._registers_size


class FakeMethod:
    def __init__(
        self,
        class_name: str,
        name: str,
        desc: str,
        instructions: Optional[Iterable[FakeInstruction]] = None,
        registers_size: int = 0,
        source: Optional[str] = None,
        access_flags: int = 0,
    ):
        self._class_name = class_name
        self._name = name
        self._desc = desc
        self._code = FakeCode(instructions or [], registers_size=registers_size)
        self._source = source or ""
        self._access_flags = access_flags

    def get_code(self) -> FakeCode:
        return self._code

    def get_class_name(self) -> str:
        return self._class_name

    def get_name(self) -> str:
        return self._name

    def get_descriptor(self) -> str:
        return self._desc

    def get_source(self) -> str:
        return self._source

    def get_access_flags(self) -> int:
        return self._access_flags


class FakeEncodedMethod:
    def __init__(self, method: FakeMethod):
        self._method = method

    def get_method(self) -> FakeMethod:
        return self._method


class FakeAnalysis:
    def __init__(self, methods: Iterable[FakeMethod]):
        self._methods = [FakeEncodedMethod(m) for m in methods]

    def get_methods(self):
        return list(self._methods)


@dataclass
class FakeAPK:
    package_name: str = "com.test"
    manifest_xml: Optional[object] = None
    manifest_text: Optional[str] = None
    target_sdk: Optional[str] = None

    def get_package(self) -> str:
        return self.package_name

    def get_android_manifest_xml(self):
        return self.manifest_xml

    def get_manifest(self):
        if self.manifest_text is None:
            raise Exception("manifest missing")
        return self.manifest_text

    def get_target_sdk_version(self):
        return self.target_sdk


@dataclass
class FakeInstructionSpec:
    opcode: str
    regs: List[str]
    target_class: str
    target_name: str
    target_desc: str


def invoke_output(regs: List[str], cls: str, name: str, desc: str) -> str:
    left = ", ".join(list(regs) + [cls]) if regs else cls
    return f"{left}->{name}{desc}"


def ins_invoke(opcode: str, regs: List[str], cls: str, name: str, desc: str) -> FakeInstruction:
    return FakeInstruction(opcode, invoke_output(regs, cls, name, desc))


def ins_move_result(reg: str) -> FakeInstruction:
    return FakeInstruction("move-result", reg)


def ins_const_string(reg: str, value: str) -> FakeInstruction:
    return FakeInstruction("const-string", f"{reg}, \"{value}\"", string=value)


def ins_const_int(reg: str, value: int) -> FakeInstruction:
    hexed = hex(value) if isinstance(value, int) else str(value)
    return FakeInstruction("const/4", f"{reg}, {hexed}")


def ins_new_instance(reg: str, cls: str) -> FakeInstruction:
    return FakeInstruction("new-instance", f"{reg}, {cls}")


def ins_field(opcode: str, reg: str, owner: str, field: str, desc: str) -> FakeInstruction:
    return FakeInstruction(opcode, f"{reg}, {owner}->{field}:{desc}")


def ins_move(opcode: str, dest: str, src: str) -> FakeInstruction:
    return FakeInstruction(opcode, f"{dest}, {src}")


def make_source(lines: Iterable[str]) -> str:
    return "\n".join(lines)
