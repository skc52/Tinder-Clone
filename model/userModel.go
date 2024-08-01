package model

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"unique;not null"`
	PasswordHash string `gorm:"not null"`
	Email        string `gorm:"unique;not null"`
}

type Profile struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint `gorm:"unique;not null"` // Foreign key to User
	Age       int  `gorm:"not null"`
	TinderBio string
	Interests string
	Location  string
	User      User `gorm:"foreignKey:UserID"`
}

type Like struct {
	LikerID uint `gorm:"primaryKey;autoIncrement:false"` // Composite primary key
	LikeeID uint `gorm:"primaryKey;autoIncrement:false"` // Composite primary key
	Liker   User `gorm:"foreignKey:LikerID;references:ID"`
	Likee   User `gorm:"foreignKey:LikeeID;references:ID"`
}

type Match struct {
	ID    uint `gorm:"primaryKey"`
	User1 uint `gorm:"not null"` // Foreign key to User
	User2 uint `gorm:"not null"` // Foreign key to User
}

var DB *gorm.DB

func init() {
	var err error
	dsn := "host=db user=yourusername dbname=tinder_clone_db sslmode=disable password=yourpassword"
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}

	// Automatically migrate your schema
	if err := DB.AutoMigrate(&User{}, &Profile{}, &Like{}); err != nil {
		panic("failed to migrate database: " + err.Error())
	}
}
