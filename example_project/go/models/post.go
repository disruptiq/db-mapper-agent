package models

import (
	"time"

	"gorm.io/gorm"
)

type PostStatus string

const (
	Draft     PostStatus = "draft"
	Published PostStatus = "published"
	Archived  PostStatus = "archived"
)

type Post struct {
	ID          uint           `gorm:"primarykey"`
	CreatedAt   time.Time      `gorm:"not null"`
	UpdatedAt   time.Time      `gorm:"not null"`
	DeletedAt   gorm.DeletedAt `gorm:"index"`

	Title       string     `gorm:"not null"`
	Content     string     `gorm:"type:text;not null"`
	Status      PostStatus `gorm:"type:enum('draft','published','archived');default:'draft'"`
	PublishedAt *time.Time `gorm:"default:null"`

	// Foreign keys
	UserID uint `gorm:"not null"`
	User   User `gorm:"foreignKey:UserID"`

	// Associations
	Comments []Comment `gorm:"foreignKey:PostID"`
}

// TableName specifies the table name for Post model
func (Post) TableName() string {
	return "posts"
}

// BeforeSave hook
func (p *Post) BeforeSave(tx *gorm.DB) error {
	if p.Status == Published && p.PublishedAt == nil {
		now := time.Now()
		p.PublishedAt = &now
	}
	return nil
}

func GetPublishedPosts(db *gorm.DB) ([]Post, error) {
	var posts []Post
	err := db.Preload("User").Where("status = ?", Published).Find(&posts).Error
	return posts, err
}

func GetPopularPosts(db *gorm.DB, limit int) ([]Post, error) {
	var posts []Post
	err := db.Raw(`
		SELECT p.*, COUNT(c.id) as comment_count
		FROM posts p
		LEFT JOIN comments c ON p.id = c.post_id
		WHERE p.status = 'published'
		GROUP BY p.id
		ORDER BY comment_count DESC
		LIMIT ?
	`, limit).Scan(&posts).Error
	return posts, err
}
