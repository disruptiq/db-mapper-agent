class User < ApplicationRecord
  # Database connection configuration
  establish_connection(
    adapter: 'postgresql',
    host: 'localhost',
    username: 'user',
    password: 'password',
    database: 'myapp_development'
  )

  has_many :posts, dependent: :destroy
  has_one :profile, dependent: :destroy
  has_many :comments, dependent: :destroy

  validates :username, presence: true, uniqueness: true
  validates :email, presence: true, uniqueness: true, format: { with: URI::MailTo::EMAIL_REGEXP }

  before_create :set_defaults

  def full_name
    "#{first_name} #{last_name}".strip.presence || username
  end

  def recent_posts(limit = 5)
    posts.where('created_at > ?', 30.days.ago).limit(limit)
  end

  def self.active_users
    where(active: true)
  end

  def self.with_post_counts
    left_joins(:posts)
      .select('users.*, COUNT(posts.id) as post_count')
      .group('users.id')
  end

  private

  def set_defaults
    self.active = true if active.nil?
  end
end
