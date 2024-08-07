package model

import (
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID            uint           `gorm:"primaryKey"`
	Username      string         `gorm:"unique;not null"`
	PasswordHash  string         `gorm:"not null"`
	Email         string         `gorm:"unique;not null"`
	Notifications []Notification `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
}

type Notification struct {
	ID               uint      `gorm:"primaryKey"`
	UserID           uint      `gorm:"not null"` // Foreign key to User
	Message          string    `gorm:"type:text;not null"`
	NotificationTime time.Time `gorm:"not null"`
}

type Location struct {
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lon"`
}
type Profile struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint `gorm:"unique;not null"` // Foreign key to User
	Age       int  `gorm:"not null"`
	TinderBio string
	Interests string
	Location  Location `gorm:"embedded"`
	User      User     `gorm:"foreignKey:UserID"`
}

type Like struct {
	LikerID uint `gorm:"primaryKey;autoIncrement:false"` // Composite primary key
	LikeeID uint `gorm:"primaryKey;autoIncrement:false"` // Composite primary key
	Liker   User `gorm:"foreignKey:LikerID;references:ID"`
	Likee   User `gorm:"foreignKey:LikeeID;references:ID"`
}

type DisLike struct {
	DisLikerID uint `gorm:"primaryKey;autoIncrement:false"` // Composite primary key
	DisLikeeID uint `gorm:"primaryKey;autoIncrement:false"` // Composite primary key
	DisLiker   User `gorm:"foreignKey:DisLikerID;references:ID"`
	DIsLikee   User `gorm:"foreignKey:DisLikeeID;references:ID"`
}
type Match struct {
	ID    uint `gorm:"primaryKey"`
	User1 uint `gorm:"not null"` // Foreign key to User
	User2 uint `gorm:"not null"` // Foreign key to User
}

// Filter represents the filter model
type Filter struct {
	ID       uint   `gorm:"primaryKey"`
	UserID   uint   `gorm:"unique;not null"`              // Foreign key to User with unique constraint
	User     User   `gorm:"constraint:OnDelete:CASCADE;"` // One-to-one relationship
	Gender   string `gorm:"type:varchar(10)"`             // Gender filter
	LowerAge uint   `gorm:"not null"`                     // Minimum age filter
	UpperAge uint   `gorm:"not null"`                     // Maximum age filter
	Radius   uint   `gorm:"not null"`                     // Radius in kilometers

	// Add other fields if necessary
}

var DB *gorm.DB

func init() {
	var err error
	dsn := "host=db user=yourusername dbname=tinder_clone_db sslmode=disable password=yourpassword"
	// dsn := "host=localhost user=yourusername dbname=tinder_clone_db sslmode=disable password=yourpassword"

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}

	// Automatically migrate your schema
	if err := DB.AutoMigrate(&User{}, &Profile{}, &Like{}, &DisLike{}, &Match{}, &Filter{}, &Notification{}); err != nil {
		panic("failed to migrate database: " + err.Error())
	}
}
