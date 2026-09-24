"""Dependency-free JSON Schema validator.

Only the subset needed for MCP tool inputs is supported (string/number/
integer/boolean/array/object/enum/required/const). Nested objects get a
recursive pass. Throws `ValidationError` on the first offending path.
"""

from __future__ import annotations

from typing import Any


class ValidationError(ValueError):
    pass


def validate(schema: dict[str, Any], value: Any, _path: str = "$") -> None:
    if not isinstance(schema, dict):
        return
    _validate(schema, value, _path)


def _validate(schema: dict[str, Any], value: Any, path: str) -> None:
    stype = schema.get("type")
    if stype == "string":
        if not isinstance(value, str):
            raise ValidationError(f"{path}: expected string, got {type(value).__name__}")
        enum = schema.get("enum")
        if enum and value not in enum:
            raise ValidationError(f"{path}: value {value!r} not in allowed {enum}")
    elif stype == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"{path}: expected integer, got {type(value).__name__}")
        if "minimum" in schema and value < schema["minimum"]:
            raise ValidationError(f"{path}: value {value} below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValidationError(f"{path}: value {value} above maximum {schema['maximum']}")
    elif stype == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValidationError(f"{path}: expected number")
    elif stype == "boolean":
        if not isinstance(value, bool):
            raise ValidationError(f"{path}: expected boolean")
    elif stype == "array":
        if not isinstance(value, list):
            raise ValidationError(f"{path}: expected array")
        items = schema.get("items", {})
        for i, item in enumerate(value):
            _validate(items, item, f"{path}[{i}]")
    elif stype == "object":
        if not isinstance(value, dict):
            raise ValidationError(f"{path}: expected object")
        for prop, subschema in (schema.get("properties") or {}).items():
            if prop in value and value[prop] is not None:
                _validate(subschema, value[prop], f"{path}.{prop}")
        for req in schema.get("required", []):
            if req not in value or value[req] is None:
                raise ValidationError(f"{path}: missing required property {req!r}")
    elif stype == "null":
        if value is not None:
            raise ValidationError(f"{path}: expected null")
    if "const" in schema and value != schema["const"]:
        raise ValidationError(f"{path}: expected const {schema['const']!r}")