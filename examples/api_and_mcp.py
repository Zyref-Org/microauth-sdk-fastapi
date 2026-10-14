"""An API and an MCP server in one app, each its own MicroAuth resource.

Scripts call the API at /tasks, and AI agents use the same tasks through the
MCP server at /mcp. MicroAuth sees two resources with their own permissions
and their own server credentials, so a token or key made for one never opens
the other. Each publishes its own metadata:

    /.well-known/oauth-protected-resource       the API, whose resource has no path
    /.well-known/oauth-protected-resource/mcp   the MCP server

Setup:
    1. In the MicroAuth dashboard, under APIs and MCP servers, register an API
       with the identifier http://localhost:8000 and the permissions
       tasks:read and tasks:write, and an MCP server with the resource
       http://localhost:8000/mcp and the same two permissions. Turn on
       "API keys for your users" for both and copy each one's server
       credentials.
    2. pip install "microauth-fastapi[mcp]" uvicorn
    3. Set MICROAUTH_ISSUER, then TASKS_API_CLIENT_ID and TASKS_API_SECRET
       for the API and TASKS_MCP_CLIENT_ID and TASKS_MCP_SECRET for the MCP
       server, and run uvicorn examples.api_and_mcp:app
"""

import os

from fastapi import Depends, FastAPI
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from microauth_fastapi import McpAuth, TokenAuth, TokenClaims, current_identity

app = FastAPI(title="Tasks")

api = TokenAuth(
    app,
    resource="http://localhost:8000",
    api_keys=True,
    resource_client_id=os.environ["TASKS_API_CLIENT_ID"],
    resource_secret=os.environ["TASKS_API_SECRET"],
)

mcp = MCPServer("Tasks", log_level="WARNING")
mcp_auth = McpAuth(
    resource="http://localhost:8000/mcp",
    scopes=["tasks:read"],
    api_keys=True,
    resource_client_id=os.environ["TASKS_MCP_CLIENT_ID"],
    resource_secret=os.environ["TASKS_MCP_SECRET"],
)

TASKS: dict[str, list[str]] = {}


class NewTask(BaseModel):
    title: str


@app.get("/tasks")
def list_tasks(caller: TokenClaims = Depends(api.require("tasks:read"))) -> list[str]:
    return TASKS.get(caller.sub, [])


@app.post("/tasks", status_code=201)
def add_task(new: NewTask, caller: TokenClaims = Depends(api.require("tasks:write"))) -> list[str]:
    TASKS.setdefault(caller.sub, []).append(new.title)
    return TASKS[caller.sub]


@mcp.tool(name="list_tasks")
@mcp_auth.tool("tasks:read", name="list_tasks")
def list_tasks_tool() -> list[str]:
    """List your tasks."""
    return TASKS.get(current_identity().sub, [])


@mcp.tool(name="add_task")
@mcp_auth.tool("tasks:write", name="add_task")
def add_task_tool(title: str) -> list[str]:
    """Add a task to your list."""
    tasks = TASKS.setdefault(current_identity().sub, [])
    tasks.append(title)
    return tasks


mcp_auth.mount(app, mcp)
