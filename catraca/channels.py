"""Channel labels declared in config, validated on load.

Format (JSON)::

    {
      "version": 1,
      "channels": {
        "user":    {"integrity": "TRUSTED",    "confidentiality": "*"},
        "crm":     {"integrity": "STRUCTURED", "confidentiality": ["tenant:acme"]},
        "kb":      {"integrity": "UNTRUSTED",  "confidentiality": ["tenant:acme"]}
      }
    }

Any problem stops the load with a message that says what to fix.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Union

from .errors import ConfigError, LabelError
from .labels import Confidentiality, Integrity, Label

_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_CHANNEL_KEYS = {"integrity", "confidentiality", "description"}


@dataclass(frozen=True)
class Channel:
    name: str
    label: Label
    description: str = ""


class ChannelConfig:
    def __init__(self, channels: Mapping[str, Channel]) -> None:
        self._channels = MappingProxyType(dict(channels))

    def __getitem__(self, name: str) -> Channel:
        try:
            return self._channels[name]
        except KeyError:
            known = ", ".join(sorted(self._channels)) or "(none)"
            raise ConfigError(
                f"undeclared channel {name!r}. Declared channels: {known}. "
                "Add it to the config before annotating content from it."
            ) from None

    def __contains__(self, name: object) -> bool:
        return name in self._channels

    def __iter__(self):
        return iter(self._channels)

    def __len__(self) -> int:
        return len(self._channels)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ChannelConfig":
        if not isinstance(data, Mapping):
            raise ConfigError("config must be a JSON object.")
        extra = set(data) - {"version", "channels"}
        if extra:
            raise ConfigError(f"unknown top-level keys: {sorted(extra)}.")
        if data.get("version") != 1:
            raise ConfigError(f"version must be 1, got {data.get('version')!r}.")
        raw = data.get("channels")
        if not isinstance(raw, Mapping) or not raw:
            raise ConfigError("'channels' must be an object with at least one channel.")

        channels = {}
        for name, spec in raw.items():
            where = f"channel {name!r}"
            if not isinstance(name, str) or not _NAME_RE.match(name):
                raise ConfigError(
                    f"{where}: bad name. Use lower case, digits, '_', '.' or '-', starting with a letter."
                )
            if not isinstance(spec, Mapping):
                raise ConfigError(f"{where}: the declaration must be an object.")
            extra = set(spec) - _CHANNEL_KEYS
            if extra:
                raise ConfigError(f"{where}: unknown keys {sorted(extra)}.")
            for required in ("integrity", "confidentiality"):
                if required not in spec:
                    raise ConfigError(f"{where}: missing '{required}'. There's no default for a channel label.")
            try:
                label = Label(
                    Integrity.from_name(spec["integrity"]),
                    Confidentiality.from_json(spec["confidentiality"]),
                )
            except LabelError as exc:
                raise ConfigError(f"{where}: {exc}") from None
            desc = spec.get("description", "")
            if not isinstance(desc, str):
                raise ConfigError(f"{where}: 'description' must be a string.")
            channels[name] = Channel(name, label, desc)
        return cls(channels)

    @classmethod
    def from_json(cls, text: str) -> "ChannelConfig":
        try:
            data = json.loads(text, object_pairs_hook=_no_dupes)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"config isn't valid JSON: {exc}") from None
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "ChannelConfig":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))


def _no_dupes(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ConfigError(f"duplicate key in config: {key!r}.")
        seen[key] = value
    return seen
