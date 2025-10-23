#!/usr/bin/env python3
"""Data migration script with raw SQL."""

import os
import django
from django.db import connection
from django.core.management.base import BaseCommand

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myapp.settings')
django.setup()

def migrate_user_data():
    """Migrate user data from old table to new structure."""

    with connection.cursor() as cursor:
        # Create backup table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_backup AS
            SELECT * FROM old_users
        """)

        # Migrate data
        cursor.execute("""
            INSERT INTO users (username, email, first_name, last_name, date_joined)
            SELECT username, email, fname, lname, created_at
            FROM old_users
            WHERE active = 1
        """)

        # Update post counts
        cursor.execute("""
            UPDATE users
            SET post_count = (
                SELECT COUNT(*)
                FROM posts
                WHERE posts.author_id = users.id
            )
        """)

        # Clean up
        cursor.execute("DROP TABLE IF EXISTS old_users")

def fix_duplicate_emails():
    """Fix duplicate email addresses."""

    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE users
            SET email = CONCAT(email, '.', id)
            WHERE email IN (
                SELECT email
                FROM users
                GROUP BY email
                HAVING COUNT(*) > 1
            )
        """)

if __name__ == '__main__':
    migrate_user_data()
    fix_duplicate_emails()
    print("Migration completed!")
