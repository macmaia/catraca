"""How a denial becomes the SDK's error, tested without the SDK.

``_mcp_error`` looks the error class up at run time, so these tests put fake
``mcp`` modules in ``sys.modules``. The ``mcp`` CI job checks the real SDK.
"""

import sys
import types
import unittest
from unittest import mock

from catraca.adapters.mcp import DENIED_CODE, _mcp_error

MSG = "catraca: refused, test"


def _modules(top=None, exceptions=None, mcp_types=None):
    """sys.modules entries for a fake SDK. A missing piece can't be imported."""
    def mod(name, attrs):
        if attrs is None:
            return None
        m = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(m, k, v)
        return m
    return {"mcp": mod("mcp", top if top is not None else {}),
            "mcp.shared": mod("mcp.shared", {}),
            "mcp.shared.exceptions": mod("mcp.shared.exceptions", exceptions),
            "mcp.types": mod("mcp.types", mcp_types)}


class KeywordError(Exception):  # SDK 2.x style
    def __init__(self, *, code, message):
        super().__init__(message)
        self.code = code


class PositionalError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class ErrorData:
    def __init__(self, *, code, message):
        self.code, self.message = code, message


class WrappedError(Exception):  # SDK 1.x: McpError(ErrorData(...)), str() doesn't show the message
    def __init__(self, error):
        super().__init__("")
        self.error = error


class Mute(Exception):  # builds fine, but the message is lost
    def __init__(self, *a, **kw):
        super().__init__("something else")


class FindsTheSdkError(unittest.TestCase):
    def test_keyword_constructor(self):
        with mock.patch.dict(sys.modules, _modules(top={"MCPError": KeywordError})):
            err = _mcp_error(MSG)
        self.assertIsInstance(err, KeywordError)
        self.assertEqual((err.code, str(err)), (DENIED_CODE, MSG))

    def test_positional_constructor(self):
        with mock.patch.dict(sys.modules, _modules(top={"MCPError": PositionalError})):
            err = _mcp_error(MSG)
        self.assertIsInstance(err, PositionalError)
        self.assertEqual((err.code, str(err)), (DENIED_CODE, MSG))

    def test_error_data_wrapper(self):
        fake = _modules(exceptions={"McpError": WrappedError}, mcp_types={"ErrorData": ErrorData})
        with mock.patch.dict(sys.modules, fake):
            err = _mcp_error(MSG)
        self.assertIsInstance(err, WrappedError)
        self.assertEqual((err.error.code, err.error.message), (DENIED_CODE, MSG))

    def test_second_place_when_the_first_has_no_class(self):
        with mock.patch.dict(sys.modules, _modules(exceptions={"MCPError": KeywordError})):
            self.assertIsInstance(_mcp_error(MSG), KeywordError)

    def test_a_class_that_drops_the_message_is_skipped(self):
        fake = _modules(top={"MCPError": Mute}, exceptions={"McpError": PositionalError})
        with mock.patch.dict(sys.modules, fake):
            self.assertIsInstance(_mcp_error(MSG), PositionalError)

    def test_wrapper_without_error_data_falls_back(self):
        # ErrorData can't be imported, so the 1.x shape can't be built.
        with mock.patch.dict(sys.modules, _modules(exceptions={"McpError": WrappedError})):
            err = _mcp_error(MSG)
        self.assertIs(type(err), PermissionError)

    def test_no_sdk_gives_permission_error(self):
        none = {k: None for k in ("mcp", "mcp.shared", "mcp.shared.exceptions", "mcp.types")}
        with mock.patch.dict(sys.modules, none):
            err = _mcp_error(MSG)
        self.assertIs(type(err), PermissionError)
        self.assertEqual(str(err), MSG)

    def test_only_mute_classes_falls_back(self):
        with mock.patch.dict(sys.modules, _modules(top={"MCPError": Mute}, exceptions={"MCPError": Mute,
                                                                                    "McpError": Mute})):
            self.assertIs(type(_mcp_error(MSG)), PermissionError)


if __name__ == "__main__":
    unittest.main()
