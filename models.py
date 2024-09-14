from pathlib import PosixPath
from typing import List
from pydantic import BaseModel


class UserPost(BaseModel):
    post_title: str
    post_text: str
    post_image: str | None


class UserPostId(UserPost):
    user_id: int


class Post(UserPost):
    post_id: int
    user_id: int
    num_likes: None | int
    user_liked: None | int
    number_comments: None | int


class InsertPost(UserPost):
    user_id: int


class Posts(BaseModel):
    posts: List[Post]


class PostId(BaseModel):
    post_id: int


class User(BaseModel):
    username: str
    password: str


class UserHashed(BaseModel):
    username: str
    salt: str
    hash_password: str


class UserHashedIndex(UserHashed):
    user_id: int


class Like(BaseModel):
    user_id: int
    post_id: int
