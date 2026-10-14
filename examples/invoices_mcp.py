"""An invoicing MCP server protected by MicroAuth.

AI agents connect over Streamable HTTP with a MicroAuth access token issued
for one user. Each tool declares the scopes it needs:

    list_invoices    invoices:read
    create_invoice   invoices:read and invoices:write
    send_invoice     invoices:read and invoices:send

Every request needs invoices:read, so that is what a client asks for first.
When a tool needs more, the client gets a 403 naming the scopes and asks the
user to approve them. Scopes only decide what kind of action a client may
take; the tools themselves make sure people only touch their own invoices.

Clients that can't do OAuth can send an API key instead, made by the user on
their MicroAuth account page. The key's permissions work like scopes, so a
key with only invoices:read can list invoices but not create them.

Setup:
    1. In the MicroAuth dashboard, register an MCP server with the resource
       http://localhost:8000/mcp and the three scopes above. Turn on
       "API keys for your users" and copy the server credentials.
    2. pip install "microauth-fastapi[mcp]" uvicorn
    3. Set MICROAUTH_ISSUER, MICROAUTH_RESOURCE=http://localhost:8000/mcp,
       MICROAUTH_RESOURCE_CLIENT_ID and MICROAUTH_RESOURCE_SECRET, then run
       uvicorn examples.invoices_mcp:app
"""

import itertools
from dataclasses import asdict, dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from microauth_fastapi import McpAuth, current_identity

mcp = MCPServer("Invoices")

# Reads MICROAUTH_ISSUER, MICROAUTH_RESOURCE and, for API keys, the server
# credentials.
auth = McpAuth(scopes=["invoices:read"], api_keys=True)


@dataclass
class Invoice:
    id: int
    owner: str
    customer: str
    amount_cents: int
    status: str = "draft"


INVOICES: dict[int, Invoice] = {}
_ids = itertools.count(1)


def _own_invoice(invoice_id: int) -> Invoice:
    invoice = INVOICES.get(invoice_id)
    # The same answer for a missing invoice and someone else's, so ids can't be probed.
    if invoice is None or invoice.owner != current_identity().sub:
        raise ToolError(f"There is no invoice {invoice_id}")
    return invoice


@mcp.tool()
@auth.tool("invoices:read")
def list_invoices() -> list[dict[str, Any]]:
    """List your invoices."""
    me = current_identity().sub
    return [asdict(invoice) for invoice in INVOICES.values() if invoice.owner == me]


@mcp.tool()
@auth.tool("invoices:write")
def create_invoice(customer: str, amount_cents: int) -> dict[str, Any]:
    """Create a draft invoice for a customer."""
    if amount_cents <= 0:
        raise ToolError("amount_cents must be positive")
    invoice = Invoice(
        id=next(_ids),
        owner=current_identity().sub,
        customer=customer,
        amount_cents=amount_cents,
    )
    INVOICES[invoice.id] = invoice
    return asdict(invoice)


@mcp.tool()
@auth.tool("invoices:send")
def send_invoice(invoice_id: int) -> dict[str, Any]:
    """Send one of your draft invoices to its customer."""
    invoice = _own_invoice(invoice_id)
    if invoice.status != "draft":
        raise ToolError(f"Invoice {invoice_id} was already sent")
    invoice.status = "sent"
    return asdict(invoice)


app = auth.wrap(mcp.streamable_http_app(stateless_http=True, json_response=True))
