package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	APPLICATION_NAME          = "GRPC Auth"
	LOGIN_EXPIRATION_DURATION = time.Duration(1) * time.Hour
)

var JWT_SIGNATURE_KEY = []byte("Quis custodiet ipsos custodes")
var JWT_SIGNING_METHOD = jwt.SigningMethodHS512

type UserData struct {
	Name     string
	Password string
	Group    string
}

type UserClaims struct {
	jwt.RegisteredClaims
	Data UserData
}
type UtilityJwt struct{}

func (uj UtilityJwt) Encode(data UserData) (string, error) {
	claims := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    APPLICATION_NAME,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(LOGIN_EXPIRATION_DURATION)),
		},
		Data: data,
	}
	token := jwt.NewWithClaims(JWT_SIGNING_METHOD, claims)
	signedToken, err := token.SignedString(JWT_SIGNATURE_KEY)
	return signedToken, err
}

func (uj UtilityJwt) Verify(strToken string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(strToken, func(tkn *jwt.Token) (interface{}, error) {
		if method, ok := tkn.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		} else if method != JWT_SIGNING_METHOD {
			return nil, errors.New("invalid signing method")

		}

		return JWT_SIGNATURE_KEY, nil
	})

	if err != nil {
		return jwt.MapClaims{}, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return jwt.MapClaims{}, err
	}
	return claims, nil

}

var instanceJwt *UtilityJwt

func NewUtilityJWT() *UtilityJwt {
	if instanceJwt == nil {
		instanceJwt = &UtilityJwt{}
	}
	return instanceJwt
}
