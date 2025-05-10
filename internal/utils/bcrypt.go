package utils

import "golang.org/x/crypto/bcrypt"

func CompareHashAndPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func GenerateFromPassword(password string, cost int) (string, bool) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(h), err == nil
}
