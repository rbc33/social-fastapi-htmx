from typing import List
from pydantic import BaseModel


class UserPost(BaseModel):
    post_title: str
    post_text: str


class Post(UserPost):
    user_id: int


class Posts(BaseModel):
    posts: List[Post]
