"""A small blog CMS where people sign in with MicroAuth.

Anyone can read posts. Signed in users holding the posts:write permission
(give it to an "editor" role in the MicroAuth dashboard) can write them, and
only users with the "admin" role can delete them.

Setup:
    1. In the MicroAuth dashboard, create a web application with the redirect
       URI http://localhost:8000/auth/callback and the sign out URL
       http://localhost:8000/.
    2. Set MICROAUTH_ISSUER, MICROAUTH_CLIENT_ID, MICROAUTH_CLIENT_SECRET,
       MICROAUTH_APP_URL=http://localhost:8000 and a MICROAUTH_COOKIE_SECRET
       from python -c 'import secrets; print(secrets.token_urlsafe(32))'.
    3. Run uvicorn examples.blog_cms:app and open http://localhost:8000.
"""

import html
import itertools

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from microauth_fastapi import User, UserAuth

app = FastAPI(title="Blog CMS")

# Adds /auth/login, /auth/signup, /auth/callback, /auth/logout and /auth/me.
auth = UserAuth(app)


class Post(BaseModel):
    id: int
    title: str
    body: str
    author_id: str
    author_name: str | None


POSTS: dict[int, Post] = {}
_ids = itertools.count(1)


def _layout(user: User | None, content: str) -> HTMLResponse:
    if user is None:
        account = (
            '<a href="/auth/login">Sign in</a> or <a href="/auth/signup">create an account</a>'
        )
    else:
        # Signing out is a POST from this site; the SDK refuses it from anywhere else.
        account = (
            f"Signed in as {html.escape(user.name or user.email or user.id)}"
            '<form method="post" action="/auth/logout" style="display:inline">'
            " <button>Sign out</button></form>"
        )
    return HTMLResponse(f"<!doctype html><title>Blog</title><p>{account}</p><h1>Blog</h1>{content}")


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
    new: NewPost, user: User = Depends(auth.require(permissions="posts:write"))
) -> Post:
    """Signed out gets 401 and a missing permission 403, both as problem JSON."""
    post = Post(
        id=next(_ids), title=new.title, body=new.body, author_id=user.id, author_name=user.name
    )
    POSTS[post.id] = post
    return post


@app.delete("/api/posts/{post_id}", status_code=204)
async def delete_post(post_id: int, user: User = Depends(auth.require(roles="admin"))) -> None:
    if POSTS.pop(post_id, None) is None:
        raise HTTPException(404, "No such post")
