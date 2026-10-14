"""A small blog CMS where people sign in with MicroAuth.

Anyone can read posts. Signed in users holding the posts:write permission
(give it to an "editor" role in the MicroAuth dashboard) can write them, and
only users with the "admin" role can delete them.

POST /api/posts takes a signed in browser and an API key alike, so editors
can publish from scripts too. They make keys on /settings/api-keys, which
calls MicroAuth's Account API for them through auth.api_keys:

    curl http://localhost:8000/api/posts -H "Authorization: Bearer cms_..." \
        -H "Content-Type: application/json" \
        -d '{"title": "Hello", "body": "Sent from a script"}'

Setup:
    1. In the MicroAuth dashboard, create a web application with the redirect
       URI http://localhost:8000/auth/callback and the sign out URL
       http://localhost:8000/.
    2. Under APIs and MCP servers, register an API with the identifier
       http://localhost:8000/api and the permission posts:write. Turn on
       "API keys for your users" and copy the API's server credentials.
    3. Set MICROAUTH_ISSUER, MICROAUTH_CLIENT_ID, MICROAUTH_CLIENT_SECRET,
       MICROAUTH_APP_URL=http://localhost:8000, a MICROAUTH_COOKIE_SECRET
       from python -c 'import secrets; print(secrets.token_urlsafe(32))',
       MICROAUTH_RESOURCE=http://localhost:8000/api, and the server
       credentials as MICROAUTH_RESOURCE_CLIENT_ID and
       MICROAUTH_RESOURCE_SECRET.
    4. Run uvicorn examples.blog_cms:app and open http://localhost:8000.
"""

import html
import itertools
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from microauth_fastapi import (
    AccountAPIError,
    ReauthenticationRequired,
    TokenAuth,
    TokenClaims,
    User,
    UserAuth,
)

app = FastAPI(title="Blog CMS")

# Adds /auth/login, /auth/signup, /auth/callback, /auth/logout and /auth/me.
# api_keys=True lets signed in people manage their own keys with auth.api_keys.
auth = UserAuth(app, api_keys=True)

# Reads MICROAUTH_RESOURCE and the server credentials. Routes that use
# api.require(...) accept a signed in browser, an access token or an API key.
api = TokenAuth(app, api_keys=True, sessions=auth)


class Post(BaseModel):
    id: int
    title: str
    body: str
    author_id: str
    author_name: str | None


POSTS: dict[int, Post] = {}
_ids = itertools.count(1)
LIFETIMES = {"30": "30 days", "90": "90 days", "365": "1 year"}


def _layout(user: User | None, content: str, *, no_store: bool = False) -> HTMLResponse:
    if user is None:
        account = (
            '<a href="/auth/login">Sign in</a> or <a href="/auth/signup">create an account</a>'
        )
    else:
        # Signing out is a POST from this site; the SDK refuses it from anywhere else.
        account = (
            f"Signed in as {html.escape(user.name or user.email or user.id)}"
            ' (<a href="/settings/api-keys">API keys</a>)'
            '<form method="post" action="/auth/logout" style="display:inline">'
            " <button>Sign out</button></form>"
        )
    return HTMLResponse(
        f"<!doctype html><title>Blog</title><p>{account}</p><h1>Blog</h1>{content}",
        headers={"Cache-Control": "no-store"} if no_store else None,
    )


@app.get("/", response_class=HTMLResponse)
async def home(user: User | None = Depends(auth.optional)):
    """Public. Shows the editor link only to people who can write."""
    items = "".join(
        f"<li><b>{html.escape(post.title)}</b> by {html.escape(post.author_name or '?')}</li>"
        for post in POSTS.values()
    )
    content = f"<ul>{items or '<li>No posts yet</li>'}</ul>"
    if user is not None and user.has_permission("posts:write"):
        content += '<p><a href="/editor">Write a post</a></p>'
    return _layout(user, content)


@app.get("/editor", response_class=HTMLResponse)
async def editor(user: User = Depends(auth.require(permissions="posts:write", redirect=True))):
    """A page: signed out visitors are sent to sign in and brought back here."""
    form = (
        '<form id="editor">'
        '<p><input name="title" placeholder="Title" maxlength="200" required></p>'
        '<p><textarea name="body" rows="8" cols="60" required></textarea></p>'
        "<p><button>Publish</button></p></form>"
        "<script>"
        'document.getElementById("editor").onsubmit = async (event) => {'
        "  event.preventDefault();"
        "  const post = Object.fromEntries(new FormData(event.target));"
        '  const response = await fetch("/api/posts", {'
        '    method: "POST",'
        '    headers: {"Content-Type": "application/json"},'
        "    body: JSON.stringify(post),"
        "  });"
        '  if (response.ok) location.href = "/";'
        '  else alert("Publishing failed with status " + response.status);'
        "};"
        "</script>"
    )
    return _layout(user, form)


class NewPost(BaseModel):
    title: str = Field(max_length=200)
    body: str = Field(max_length=20_000)


@app.get("/api/posts")
async def list_posts() -> list[Post]:
    return list(POSTS.values())


@app.post("/api/posts", status_code=201)
async def create_post(
    new: NewPost, caller: TokenClaims = Depends(api.require("posts:write"))
) -> Post:
    """The editor page posts here with its session, and scripts with an API key.

    Signed out gets 401 and a missing permission 403, both as problem JSON.
    A key only carries the user's id, so only sessions fill in a name.
    """
    name = caller.claims.get("name") if caller.via == "session" else None
    post = Post(
        id=next(_ids), title=new.title, body=new.body, author_id=caller.sub, author_name=name
    )
    POSTS[post.id] = post
    return post


@app.delete("/api/posts/{post_id}", status_code=204)
async def delete_post(post_id: int, user: User = Depends(auth.require(roles="admin"))) -> None:
    if POSTS.pop(post_id, None) is None:
        raise HTTPException(404, "No such post")


# API keys settings


async def _keys_page(
    request: Request, user: User, *, secret: str | None = None, error: str | None = None
) -> HTMLResponse:
    keys = await auth.api_keys.list(request)
    options = await auth.api_keys.options(request)
    rows = "".join(
        f"<li><b>{html.escape(key.name)}</b> <code>{html.escape(key.prefix)}...</code>"
        f" {html.escape(' '.join(key.permissions))},"
        f" expires {key.expires_at.date() if key.expires_at else 'never'}"
        f'<form method="post" action="/settings/api-keys/{html.escape(key.id)}/revoke"'
        ' style="display:inline"> <button>Revoke</button></form></li>'
        for key in keys
    )
    content = "<h2>API keys</h2>"
    if secret is not None:
        content += (
            "<p>Your new key. Copy it now, it won't be shown again:</p>"
            f"<p><code>{html.escape(secret)}</code></p>"
        )
    if error is not None:
        content += f"<p>{html.escape(error)}</p>"
    content += f"<ul>{rows or '<li>No keys yet</li>'}</ul>"

    ours = next((item for item in options.resources if item.identifier == api.resource), None)
    if ours is None:
        return _layout(user, content + "<p>You can't make keys for this API.</p>", no_store=True)
    boxes = "".join(
        f'<label><input type="checkbox" name="permission" value="{html.escape(p.name)}">'
        f" {html.escape(p.description)}</label><br>"
        for p in ours.permissions
    )
    lifetimes = [
        (days, label)
        for days, label in LIFETIMES.items()
        if options.max_days is None or int(days) <= options.max_days
    ]
    if options.allow_no_expiry:
        lifetimes.append(("never", "Never expires"))
    choices = "".join(f'<option value="{days}">{label}</option>' for days, label in lifetimes)
    content += (
        '<h3>New key</h3><form method="post" action="/settings/api-keys">'
        '<p><input name="name" placeholder="What is it for?" maxlength="64" required></p>'
        f"<p>{boxes}</p><p><select name=days>{choices}</select></p>"
        "<p><button>Create key</button></p></form>"
    )
    return _layout(user, content, no_store=True)


@app.get("/settings/api-keys", response_class=HTMLResponse)
async def api_keys_page(request: Request, user: User = Depends(auth.login_required)):
    return await _keys_page(request, user)


@app.post("/settings/api-keys", response_class=HTMLResponse)
async def create_api_key(request: Request, user: User = Depends(auth.login_required)):
    form = parse_qs((await request.body()).decode("utf-8"))
    days = form.get("days", ["90"])[0]
    try:
        new = await auth.api_keys.create(
            request,
            name=form.get("name", [""])[0],
            resources=[api.resource],
            permissions=form.get("permission", []),
            expires_in_days=int(days) if days.isdigit() else None,
        )
    except ReauthenticationRequired as exc:
        # Making a key needs a sign in from the last 10 minutes.
        return RedirectResponse(exc.login_url, status_code=303)
    except AccountAPIError as exc:
        return await _keys_page(request, user, error=exc.detail)
    return await _keys_page(request, user, secret=new.secret)


@app.post("/settings/api-keys/{key_id}/revoke")
async def revoke_api_key(
    key_id: str, request: Request, user: User = Depends(auth.login_required)
) -> RedirectResponse:
    await auth.api_keys.revoke(request, key_id)
    return RedirectResponse("/settings/api-keys", status_code=303)
