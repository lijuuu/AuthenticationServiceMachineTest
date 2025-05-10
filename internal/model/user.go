package model

import "time"

type User struct {
	UID             string    `json:"uid" bson:"uid"`
	Email           string    `json:"email,omitempty" bson:"email,omitempty"`
	Phone           string    `json:"phone,omitempty" bson:"phone,omitempty"`
	IsPhoneVerified bool      `json:"isPhoneVerified" bson:"isPhoneVerified"`
	IsEmailVerified bool      `json:"isEmailVerified" bson:"isEmailVerified"`
	IsGuestUser     bool      `json:"isGuestUser" bson:"isGuestUser"`
	Password        *string   `json:"password,omitempty" bson:"password,omitempty"`
	Joints          []string  `json:"joints" bson:"joints"`
	IsBillableUser  bool      `json:"isBillableUser" bson:"isBillableUser"`
	Is2FNeeded      bool      `json:"is2FNeeded" bson:"is2FNeeded"`
	FirstName       *string   `json:"firstName,omitempty" bson:"firstName,omitempty"`
	SecondName      *string   `json:"secondName,omitempty" bson:"secondName,omitempty"`
	UserCreatedDate time.Time `json:"userCreatedDate" bson:"userCreatedDate"`
	UserLastLogin   time.Time `json:"userLastLogin" bson:"userLastLogin"`
	CountryOfOrigin *string   `json:"countryOfOrigin,omitempty" bson:"countryOfOrigin,omitempty"`
	Address         *string   `json:"address,omitempty" bson:"address,omitempty"`
}
