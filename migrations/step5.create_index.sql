CREATE INDEX IF NOT EXISTS username_index ON users (username);
CREATE INDEX IF NOT EXISTS user_post_index ON posts (user_id);
CREATE INDEX IF NOT EXISTS like_user_id ON posts (post_id);
CREATE INDEX IF NOT EXISTS like_post_id ON posts (user_id);