from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from database import get_post, insert_post
from models import Posts, Post
from sqlite3 import Connection, Row

app = FastAPI()

templates = Jinja2Templates(directory="templates")

conn = Connection("social.db")
conn.row_factory = Row


@app.get("/")
async def root(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", content={})


@app.get("/posts")
async def post() -> Posts:
    return get_post(conn)


@app.post("/posts")
async def add_post(post: Post) -> Post:
    insert_post(conn, post)
    return post


if __name__ == "__main__":
    import uvicorn  # type: ignore

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
