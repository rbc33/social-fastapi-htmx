from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from database import get_post, insert_post
from models import Posts, Post, UserPost
from sqlite3 import Connection, Row

app = FastAPI()

templates = Jinja2Templates(directory="templates")

conn = Connection("social.db")
conn.row_factory = Row
user_id = 1


@app.get("/")
async def root(request: Request) -> HTMLResponse:
    context = {
        "posts": [
            {
                "post_title": "test",
                "post_text": "text",
            }
        ]
    }
    post = get_post(conn)
    return templates.TemplateResponse(request, "index.html", context=post.model_dump())


@app.get("/posts")
async def post(request: Request) -> HTMLResponse:
    posts = get_post(conn)
    return templates.TemplateResponse(request, "posts.html", context=posts.model_dump())


@app.post("/posts")
async def add_post(post: UserPost, request: Request) -> HTMLResponse:
    post = Post(user_id=user_id, **post.model_dump())
    insert_post(conn, post)
    posts = get_post(conn)
    return templates.TemplateResponse(request, "posts.html", context=posts.model_dump())


if __name__ == "__main__":
    import uvicorn  # type: ignore

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
