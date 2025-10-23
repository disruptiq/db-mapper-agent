"""Database configuration settings."""

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'myapp_db',
        'USER': 'user',
        'PASSWORD': 'password',
        'HOST': 'localhost',
        'PORT': '5432',
    },
    'analytics': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'analytics',
        'USER': 'analytics_user',
        'PASSWORD': 'analytics_pass',
        'HOST': 'analytics-db',
        'PORT': '3306',
    }
}

# Connection pooling settings
DB_CONNECTION_POOL = {
    'max_overflow': 10,
    'pool_size': 5,
    'pool_recycle': 3600,
}

# Raw SQL for custom queries
CUSTOM_QUERIES = {
    'user_stats': """
        SELECT
            COUNT(*) as total_users,
            COUNT(CASE WHEN date_joined > CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as new_users,
            AVG(post_count) as avg_posts
        FROM users
    """,
    'popular_posts': """
        SELECT p.title, COUNT(c.id) as comment_count
        FROM posts p
        LEFT JOIN comments c ON p.id = c.post_id
        WHERE p.status = 'published'
        GROUP BY p.id, p.title
        ORDER BY comment_count DESC
        LIMIT 10
    """
}
