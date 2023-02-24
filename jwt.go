package multi

import (
	"fmt"

	"github.com/golang-jwt/jwt"
)

var hmacSampleSecret = []byte("updPA0L2uQ56LwHZoyUX")

// JwtAuth
type JwtAuth struct {
	HmacSecret []byte
}

// NewJwtAuth
func NewJwtAuth(hmacSecret []byte) *JwtAuth {
	ja := &JwtAuth{
		HmacSecret: hmacSecret,
	}
	if ja.HmacSecret == nil {
		ja.HmacSecret = hmacSampleSecret
	}
	return ja
}

// GenerateToken
func (ra *JwtAuth) GenerateToken(claims *MultiClaims) (string, int64, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(ra.HmacSecret)
	if err != nil {
		return "", 0, err
	}
	return tokenString, 0, nil
}

// GetTokenByClaims
func (ra *JwtAuth) GetTokenByClaims(cla *MultiClaims) (string, error) {
	return "", ErrForJwt
}

// GetMultiClaims
func (ra *JwtAuth) GetMultiClaims(tokenString string) (*MultiClaims, error) {
	mc := &MultiClaims{}
	token, err := jwt.ParseWithClaims(tokenString, mc, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("不支持的签名方法: %v", token.Header["alg"])
		}
		return ra.HmacSecret, nil
	})
	if err != nil {
		return nil, err
	}

	if _, ok := token.Claims.(*MultiClaims); ok && token.Valid {
		return mc, nil
	} else {
		return nil, ErrTokenInvalid
	}
}

// SetUserTokenMaxCount
func (ra *JwtAuth) SetUserTokenMaxCount(tokenMaxCount int64) error {
	return ErrForJwt
}

// UpdateUserTokenCacheExpire
func (ra *JwtAuth) UpdateUserTokenCacheExpire(token string) error {
	return ErrForJwt
}

// DelUserTokenCache
func (ra *JwtAuth) DelUserTokenCache(token string) error {
	return ErrForJwt
}

// CleanUserTokenCache
func (ra *JwtAuth) CleanUserTokenCache(authorityType int, userId string) error {
	return ErrForJwt
}

// IsRole
func (ra *JwtAuth) IsRole(token string, authorityType int) (bool, error) {
	rcc, err := ra.GetMultiClaims(token)
	if err != nil {
		return false, fmt.Errorf("get User's infomation return error: %w", err)
	}
	return rcc.AuthorityType == authorityType, nil
}

// Close
func (ra *JwtAuth) Close() {
}
