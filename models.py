from typing import List
from pydantic import BaseModel


class Post(BaseModel):
    post_title: str
    post_text: str
    user_id: int


class Posts(BaseModel):
    posts: List[Post]
