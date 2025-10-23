const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize('sqlite::memory:');

const Post = sequelize.define('Post', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  title: {
    type: DataTypes.STRING,
    allowNull: false
  },
  content: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  status: {
    type: DataTypes.ENUM('draft', 'published', 'archived'),
    defaultValue: 'draft'
  },
  publishedAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  authorId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    }
  }
}, {
  tableName: 'posts',
  timestamps: true
});

// Raw SQL queries
Post.getPopularPosts = async () => {
  const [results] = await sequelize.query(`
    SELECT p.title, COUNT(c.id) as commentCount
    FROM posts p
    LEFT JOIN comments c ON p.id = c.postId
    WHERE p.status = 'published'
    GROUP BY p.id, p.title
    ORDER BY commentCount DESC
    LIMIT 10
  `);
  return results;
};

Post.migrateData = async () => {
  await sequelize.query(`
    INSERT INTO posts (title, content, authorId, status, createdAt, updatedAt)
    SELECT title, content, author_id, 'published', created_at, updated_at
    FROM old_posts
    WHERE deleted = false
  `);

  await sequelize.query('DROP TABLE old_posts');
};

module.exports = Post;
