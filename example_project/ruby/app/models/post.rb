class Post < ApplicationRecord
  belongs_to :user
  has_many :comments, dependent: :destroy
  belongs_to :category, optional: true

  enum status: { draft: 0, published: 1, archived: 2 }

  validates :title, presence: true
  validates :content, presence: true
  validates :user, presence: true

  scope :published, -> { where(status: :published) }
  scope :recent, -> { where('created_at > ?', 7.days.ago) }

  before_save :update_published_at, if: :status_changed_to_published?

  def self.popular_posts(limit = 10)
    left_joins(:comments)
      .select('posts.*, COUNT(comments.id) as comment_count')
      .group('posts.id')
      .order('comment_count DESC')
      .limit(limit)
  end

  def self.migrate_legacy_data
    connection.execute(<<~SQL)
      INSERT INTO posts (title, content, user_id, status, created_at, updated_at)
      SELECT title, content, author_id, 1, created_at, updated_at
      FROM legacy_posts
      WHERE deleted = false
    SQL

    connection.execute('DROP TABLE legacy_posts')
  end

  private

  def status_changed_to_published?
    status_changed? && published?
  end

  def update_published_at
    self.published_at = Time.current
  end
end
