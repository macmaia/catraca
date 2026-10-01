"""Adapters that plug the gate into other stacks.

This release ships three: ``catraca.adapters.python`` (a decorator for plain
functions, sync or async), ``catraca.adapters.mcp`` (middleware for MCP
servers) and ``catraca.adapters.mcp_proxy`` (a stdio proxy in front of any MCP
server). None is imported by the core.
"""
