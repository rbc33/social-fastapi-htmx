import os
from typing import Annotated, Dict, Optional
from typing_extensions import Annotated, Doc
from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Form,
    UploadFile,
    status,
    Header,
)
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from database import (
    add_comment,
    check_like,
    delete_like,
    get_comments,
    get_post,
    get_single_post,
    get_user,
    insert_post,
    create_user,
    add_like,
)
from models import (
    InsertPost,
    Like,
    PostId,
    Posts,
    Post,
    User,
    UserHashedIndex,
    UserPost,
    UserHashed,
    UserPostId,
)
from sqlite3 import Connection, Row
from secrets import token_hex
from passlib.hash import pbkdf2_sha256
from uuid import uuid4
from pathlib import Path
import jwt
from dotenv import load_dotenv


JWT_KEY = os.getenv("JWT_KEY")
EXPIRATION_TIME = 3600

ContextType = dict[str, str | int | None | dict | bool]


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
    def __init__(self):
        super().__init__(auto_error=False)

    def __call__(self, request: Request) -> Optional[int]:
        access_token = request.cookies.get("access_token")
        if not access_token:
            return None
        try:
            scheme, token = access_token.split()
            if scheme.lower() != "bearer":
                return None
            return decrypt_access_token(token)
        except ValueError:
            return None


oauth_cookie = OAuthCookie()

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), "static")

templates = Jinja2Templates(directory="templates")

conn = Connection("social.db")
conn.row_factory = Row


@app.post("/token")
async def auth(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    user: UserHashedIndex = get_user(conn, form_data.username)
    if not user or not pbkdf2_sha256.verify(
        form_data.password + user.salt, user.hash_password
    ):
        return {"message": "error getting token"}
    token = jwt.encode(
        {"username": form_data.username, "user_id": user.user_id},
        JWT_KEY,
        algorithm="HS256",
    )

    return {"access_token": token}


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
async def post(
    request: Request, access_token: Annotated[str | None, Cookie()] = None
) -> HTMLResponse:
    user_id = None
    if access_token:
        user_id = decrypt_access_token(access_token)
    context = get_post(conn, user_id).model_dump()
    if access_token:
        context["login"] = True
    # breakpoint()
    return templates.TemplateResponse(request, "posts.html", context=context)


@app.post("/posts")
async def add_post(
    post_title: Annotated[str, Form()],
    post_text: Annotated[str, Form()],
    request: Request,
    post_image: UploadFile | None = None,
    user_id: int | None = Depends(oauth_cookie),
) -> HTMLResponse:
    image_path = None
    if post_image:
        image_path = Path("./static/images") / uuid4().hex
        image_data = await post_image.read()
        image_path.write_bytes(image_data)
        image_path = image_path.name

    post = InsertPost(
        user_id=user_id,
        post_title=post_title,
        post_text=post_text,
        post_image=image_path,
    )
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


@app.post("/like")
async def upload_like(
    post_id: PostId, request: Request, user_id: int = Depends(oauth_cookie)
) -> HTMLResponse:
    like = Like(user_id=user_id, post_id=post_id.post_id)
    if check_like(conn, like):
        delete_like(conn, like)
    else:
        add_like(conn, like)
    context = get_single_post(conn, post_id.post_id, user_id).model_dump()
    context = {"post": context}
    context["login"] = True
    return templates.TemplateResponse(request, "post.html", context)


@app.get("/add_comment_form_{post_id}")
async def get_comment_form(
    post_id: int, request: Request, user_id: int = Depends(oauth_cookie)
) -> HTMLResponse:
    context = get_single_post(conn, post_id, user_id).model_dump()
    context: ContextType
    context = {"post": context}
    context["comment_form"] = True
    context["login"] = True
    return templates.TemplateResponse(request, "./post.html", context=context)


@app.post("/add_comment_{post_id}")
async def post_comment_form(
    post_id: int,
    post_text: Annotated[str, Form()],
    post_title: Annotated[str, Form()],
    request: Request,
    user_id: int = Depends(oauth_cookie),
) -> HTMLResponse:
    post = UserPostId(user_id=user_id, post_text=post_text, post_title=post_title)
    comment_id = insert_post(conn, post)
    add_comment(conn, comment_id, post_id)
    context: ContextType = get_single_post(conn, post_id, user_id).model_dump()
    context = {"post": context}
    context["comment_form"] = False
    context["login"] = True
    return templates.TemplateResponse(request, "./post.html", context=context)


def get_comment_thread_helper(
    access_token: str | None, post_id: int, hide: bool = False
) -> dict:
    user_id = None
    if access_token:
        user_id = decrypt_access_token(access_token)
    context = {}
    context["main_post"] = {
        "posts": [get_single_post(conn, post_id, user_id).model_dump()]
    }
    context["main_post"]["posts"][0]["hide_see_comments"] = not hide
    if hide:
        return context
    comments = get_comments(conn, post_id, user_id).model_dump()
    context["comments"] = comments
    context["login"] = True
    return context


@app.get("/get_thread{post_id}")
async def get_thread(
    post_id: int, request: Request, access_token: Annotated[str | None, Cookie()] = None
) -> HTMLResponse:
    context = get_comment_thread_helper(access_token, post_id)
    return templates.TemplateResponse(request, "/comment_thread.html", context)


@app.get("/hide_thread{post_id}")
async def hide_thread(
    post_id: int, request: Request, access_token: Annotated[str | None, Cookie()] = None
) -> HTMLResponse:
    context = get_comment_thread_helper(access_token, post_id, hide=True)
    return templates.TemplateResponse(request, "/comment_thread.html", context)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
