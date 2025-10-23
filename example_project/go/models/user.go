package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        uint           `gorm:"primarykey"`
	CreatedAt time.Time      `gorm:"not null"`
	UpdatedAt time.Time      `gorm:"not null"`
	DeletedAt gorm.DeletedAt `gorm:"index"`

	Username string `gorm:"uniqueIndex;not null"`
	Email    string `gorm:"uniqueIndex;not null"`
	Password string `gorm:"not null"`
	Active   bool   `gorm:"default:true"`

	// Associations
	Posts    []Post    `gorm:"foreignKey:UserID"`
	Profile  Profile   `gorm:"foreignKey:UserID"`
	Comments []Comment `gorm:"foreignKey:UserID"`
}

// TableName specifies the table name for User model
func (User) TableName() string {
	return "users"
}

// BeforeCreate hook
func (u *User) BeforeCreate(tx *gorm.DB) error {
	u.Active = true
	return nil
}

// Custom methods
func (u *User) FullName() string {
	return u.Username // In a real app, this might combine first/last name
}

func GetActiveUsers(db *gorm.DB) ([]User, error) {
	var users []User
	err := db.Where("active = ?", true).Find(&users).Error
	return users, err
}

func MigrateUserData(db *gorm.DB) error {
	// Raw SQL for data migration
	return db.Exec(`
		INSERT INTO users (username, email, password, active, created_at, updated_at)
		SELECT username, email, password_hash, is_active, created_at, updated_at
		FROM legacy_users
		WHERE deleted = false
	`).Error
}
