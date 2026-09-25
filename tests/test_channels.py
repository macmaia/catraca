"""Channel config, validated on load."""

import json
import os
import tempfile
import unittest

from catraca import ChannelConfig, ConfigError, Integrity

GOOD = {
    "version": 1,
    "channels": {
        "user": {"integrity": "TRUSTED", "confidentiality": "*"},
        "crm": {"integrity": "STRUCTURED", "confidentiality": ["tenant:acme"]},
        "kb": {"integrity": "UNTRUSTED", "confidentiality": ["tenant:acme"], "description": "RAG"},
    },
}


class Loading(unittest.TestCase):
    def test_good(self):
        cfg = ChannelConfig.from_dict(GOOD)
        self.assertEqual(len(cfg), 3)
        self.assertIs(cfg["kb"].label.integrity, Integrity.UNTRUSTED)
        self.assertEqual(cfg["kb"].description, "RAG")

    def test_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "channels.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(GOOD, fh)
            self.assertIn("crm", ChannelConfig.from_file(path))

    def test_undeclared_channel(self):
        with self.assertRaisesRegex(ConfigError, "undeclared channel"):
            ChannelConfig.from_dict(GOOD)["email"]

    def test_bad_configs(self):
        cases = {
            "root not object": [],
            "wrong version": {"version": 2, "channels": GOOD["channels"]},
            "no channels": {"version": 1, "channels": {}},
            "extra root key": {**GOOD, "x": 1},
            "bad name": {"version": 1, "channels": {"User": {"integrity": "TRUSTED", "confidentiality": "*"}}},
            "no integrity": {"version": 1, "channels": {"u": {"confidentiality": "*"}}},
            "no confidentiality": {"version": 1, "channels": {"u": {"integrity": "TRUSTED"}}},
            "bad integrity": {"version": 1, "channels": {"u": {"integrity": "OK", "confidentiality": "*"}}},
            "bad scope": {"version": 1, "channels": {"u": {"integrity": "TRUSTED", "confidentiality": ["acme"]}}},
            "extra channel key": {
                "version": 1,
                "channels": {"u": {"integrity": "TRUSTED", "confidentiality": "*", "trust_me": True}},
            },
            "non-str description": {
                "version": 1,
                "channels": {"u": {"integrity": "TRUSTED", "confidentiality": "*", "description": 1}},
            },
        }
        for name, data in cases.items():
            with self.assertRaises(ConfigError, msg=name):
                ChannelConfig.from_dict(data)

    def test_duplicate_json_key(self):
        text = ('{"version":1,"channels":{"u":{"integrity":"TRUSTED","confidentiality":"*"},'
                '"u":{"integrity":"UNTRUSTED","confidentiality":"*"}}}')
        with self.assertRaisesRegex(ConfigError, "duplicate"):
            ChannelConfig.from_json(text)

    def test_invalid_json(self):
        with self.assertRaises(ConfigError):
            ChannelConfig.from_json("{")


if __name__ == "__main__":
    unittest.main()
