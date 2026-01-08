from __future__ import annotations

from typing import List, Tuple


def get_const_strings(method) -> List[str]:
    strings: List[str] = []
    if not hasattr(method, "get_code"):
        return strings
    code = method.get_code()
    if not code:
        return strings
    bc = code.get_bc()
    for ins in bc.get_instructions():
        name = ins.get_name()
        if name in ("const-string", "const-string/jumbo"):
            try:
                s = ins.get_string()
                if s is not None:
                    strings.append(s)
            except Exception:
                continue
    return strings


def get_invoked_methods(method) -> List[str]:
    called: List[str] = []
    if not hasattr(method, "get_code"):
        return called
    code = method.get_code()
    if not code:
        return called
    bc = code.get_bc()
    for ins in bc.get_instructions():
        if ins.get_name().startswith("invoke-"):
            try:
                called.append(str(ins.get_output()))
            except Exception:
                continue
    return called


def get_invoke_refs(method) -> List[Tuple[str, str, str, str]]:
    refs: List[Tuple[str, str, str, str]] = []
    if not hasattr(method, "get_code"):
        return refs
    code = method.get_code()
    if not code:
        return refs
    bc = code.get_bc()
    for ins in bc.get_instructions():
        if ins.get_name().startswith("invoke-"):
            try:
                out = str(ins.get_output())
            except Exception:
                continue
            cls, name, desc = _parse_invoke_output(out)
            if cls and name:
                refs.append((cls, name, desc, out))
    return refs


def _parse_invoke_output(output: str) -> Tuple[str, str, str]:
    if "->" not in output:
        return "", "", ""
    left, right = output.split("->", 1)
    cls = left.strip()
    if "(" in right:
        name, desc = right.split("(", 1)
        desc = "(" + desc
    else:
        name, desc = right, ""
    return cls.strip(), name.strip(), desc.strip()


def find_snippet(method, keywords: List[str]) -> str | None:
    if not hasattr(method, "get_source"):
        return None
    try:
        source = method.get_source() or ""
    except Exception:
        return None
    if not source:
        return None
    for line in source.splitlines():
        text = line.strip()
        if not text:
            continue
        for kw in keywords:
            if kw in text:
                return text
    return None


def contains_method_call(invoked: List[str], fragments: List[str]) -> bool:
    for call in invoked:
        for frag in fragments:
            if frag in call:
                return True
    return False


def find_method_calls(invoked: List[str], fragments: List[str]) -> List[str]:
    matches: List[str] = []
    for call in invoked:
        for frag in fragments:
            if frag in call:
                matches.append(call)
                break
    return matches
