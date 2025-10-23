-- Data migration script

-- Backup old data
CREATE TABLE users_backup AS SELECT * FROM old_users;
CREATE TABLE posts_backup AS SELECT * FROM old_posts;

-- Migrate users data
INSERT INTO users (username, email, password, active, created_at)
SELECT
    username,
    email,
    password_hash,
    CASE WHEN status = 'active' THEN TRUE ELSE FALSE END,
    created_at
FROM old_users
WHERE deleted = FALSE;

-- Migrate posts data
INSERT INTO posts (title, content, status, author_id, created_at, updated_at)
SELECT
    title,
    content,
    CASE
        WHEN published = TRUE THEN 'published'
        ELSE 'draft'
    END,
    author_id,
    created_at,
    updated_at
FROM old_posts
WHERE deleted = FALSE;

-- Update user post counts
UPDATE users
SET post_count = (
    SELECT COUNT(*)
    FROM posts
    WHERE posts.author_id = users.id
);

-- Migrate comments
INSERT INTO comments (content, post_id, author_id, created_at)
SELECT
    content,
    post_id,
    user_id,
    created_at
FROM old_comments
WHERE moderated = TRUE;

-- Clean up old tables
DROP TABLE old_users;
DROP TABLE old_posts;
DROP TABLE old_comments;

-- Update timestamps
UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL;
UPDATE posts SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL;

-- Create audit log
CREATE TABLE migration_log (
    id SERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    table_name VARCHAR(50) NOT NULL,
    records_affected INTEGER DEFAULT 0,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO migration_log (action, table_name, records_affected) VALUES
('MIGRATE', 'users', (SELECT COUNT(*) FROM users)),
('MIGRATE', 'posts', (SELECT COUNT(*) FROM posts)),
('MIGRATE', 'comments', (SELECT COUNT(*) FROM comments));
