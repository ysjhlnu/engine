package util

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

const TokenExpireDuration = time.Hour * 24 * 7

var MySecret = []byte("cqset1234")

type MyClaims struct {
	Username string `json:"username"`
	Uid      int    `json:"uid"`
	jwt.StandardClaims
}

func ParseToken(tokenString string) (*MyClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &MyClaims{}, func(token *jwt.Token) (i interface{}, err error) {
		return MySecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*MyClaims); ok && token.Valid { // 校验token
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
