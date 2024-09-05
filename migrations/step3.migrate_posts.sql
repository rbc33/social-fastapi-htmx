CREATE TABLE temp_posts (
    post_id INTEGER PRIMARY KEY,
    post_title VARCHAR(50),
    post_text VARCHAR(500),
    user_id INTEGER
);

INSERT INTO temp_posts (
    post_id,
    post_title,
    post_text,
    user_id

) SELECT * FROM post;
DROP TABLE post;
CREATE TABLE posts (
    post_id INTEGER PRIMARY KEY,
    post_title VARCHAR(50),
    post_text VARCHAR(500),
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);
DROP TABLE temp_posts;
 