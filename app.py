import os
from typing import Annotated, Optional
from fastapi import Cookie, Depends, FastAPI, Request, Form, status, Header
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2
from fastapi.templating import Jinja2Templates
from database import get_post, get_user, insert_post, create_user
from models import Posts, Post, User, UserHashedIndex, UserPost, UserHashed
from sqlite3 import Connection, Row
from secrets import token_hex
from passlib.hash import pbkdf2_sha256
import jwt
from dotenv import load_dotenv

_ = load_dotenv()
JWT_KEY = os.getenv("JWT_KEY")
EXPIRATION_TIME = 3600


def decrypt_access_token(access_token: Optional[str]) -> int | None:
    if not access_token:
        return None
    try:
        token = access_token.encode("utf-8")
        data = jwt.decode(token, JWT_KEY, algorithms=["HS256"])
        return data["user_id"]
    except jwt.DecodeError:
        return None


class OAuthCookie(OAuth2):

    def __call__(self, request: Request) -> Optional[int]:
        _, access_token = request.cookies.get("access_token").split()
        return decrypt_access_token(access_token)


oauth_cookie = OAuthCookie()

app = FastAPI()
templates = Jinja2Templates(directory="templates")
conn = Connection("social.db")
conn.row_factory = Row


@app.get("/")
async def root(
    request: Request, access_token: Annotated[str | None, Cookie()] = None
) -> HTMLResponse:
    context = get_post(conn).model_dump()
    if access_token:
        context["login"] = True
    return templates.TemplateResponse(request, "index.html", context)


@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response


@app.get("/posts")
async def post(request: Request) -> HTMLResponse:
    header = request.headers
    print(header)
    context = get_post(conn).model_dump()
    return templates.TemplateResponse(request, "posts.html", context=context)


@app.post("/posts")
async def add_post(
    post: UserPost, request: Request, user_id: int | None = Depends(oauth_cookie)
) -> HTMLResponse:
    post = Post(user_id=user_id, **post.model_dump())
    insert_post(conn, post)
    context = {"post_added": True}
    return templates.TemplateResponse(request, "add_post.html", context=context)


@app.get("/signup")
async def signup_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "signup.html")


@app.post("/signup")
async def add_user(
    username: Annotated[str, Form()], password: Annotated[str, Form()], request: Request
):
    if get_user(conn, username):
        return templates.TemplateResponse(
            request, "signup.html", context={"taken": True, "username": username}
        )
    salt = token_hex(15)
    hash_password = pbkdf2_sha256.hash(password + salt)
    hashed_user = UserHashed(username=username, salt=salt, hash_password=hash_password)
    if create_user(conn, hashed_user):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/login")
async def login_page(request: Request) -> HTMLResponse:
    context = {"login": True}
    return templates.TemplateResponse(request, "login.html", context)


@app.post("/login")
async def log_in(
    username: Annotated[str, Form()], password: Annotated[str, Form()], request: Request
):
    user: UserHashedIndex = get_user(conn, username)
    if not user or not pbkdf2_sha256.verify(password + user.salt, user.hash_password):
        return templates.TemplateResponse(
            request, "login.html", context={"incorrect": True}
        )
    token = jwt.encode(
        {"username": username, "user_id": user.user_id}, JWT_KEY, algorithm="HS256"
    )
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        "access_token",
        f"Bearer {token}",
        max_age=EXPIRATION_TIME,
        httponly=True,
        samesite="lax",
        # secure=True  # Uncomment for production use with HTTPS
    )
    return response


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
