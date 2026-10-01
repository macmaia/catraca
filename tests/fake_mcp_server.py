"""A tiny stdio MCP server for the proxy tests: answers initialize, tools/list
and tools/call, and logs every call it receives to the file in argv[1]."""

import json
import sys

log = open(sys.argv[1], "a", encoding="utf-8")
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue  # a notification
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "send_email", "inputSchema": {"type": "object"}}]}
    elif method == "tools/call":
        log.write(json.dumps(msg["params"]) + "\n")
        log.flush()
        result = {"content": [{"type": "text", "text": "sent"}]}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "no"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
