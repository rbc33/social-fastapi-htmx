import sqlite3
from sqlite3 import Connection
from typing import List
from models import Post, Posts, User, UserHashed, UserHashedIndex


def get_post(connection: Connection) -> Posts:
    with connection:
        cur = connection.cursor()
        cur.execute(
            """
    SELECT post_title, post_text, user_id
    FROM posts;
    """
        )
        # return cur.fetchall()
        return Posts(posts=[Post.model_validate(dict(post)) for post in cur])


def insert_post(connection: Connection, post: Post):

    with connection:
        cur = connection.cursor()
        cur.execute(
            """
            INSERT INTO posts (post_title, post_text, user_id)            
            VALUES
            (:post_title, :post_text, :user_id)
            """,
            post.model_dump(),
        )


def get_user(connection: Connection, username) -> UserHashedIndex | None:
    with connection:
        cur = connection.cursor()
        cur.execute(
            """
            SELECT 
                user_id,
                username,
                salt,
                hash_password
            FROM users 
            WHERE username = ?

            """,
            (username,),
        )
        user = cur.fetchone()
        if user:
            return UserHashedIndex.model_validate(dict(user))


def create_user(connection: Connection, user: UserHashed) -> bool:
    with connection:
        cur = connection.cursor()
        cur.execute(
            """
            INSERT INTO users (username, salt, hash_password)
            VALUES
            (:username, :salt, :hash_password)
            """,
            user.model_dump(),
        )
        return True


if __name__ == "__main__":

    connection = sqlite3.connect("social.db")
    connection.row_factory = sqlite3.Row

    # test_post = {
    #     "post_title": "first post",
    #     "post_text": "This is a test",
    #     "user_id": 1,
    # }
    # insert_post(connection, test_post)

    # print(get_post(connection))
    print(get_user(connection, "test"))
