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

//  GetTokenByClaims 获取用户信息
func (ra *JwtAuth) GetTokenByClaims(cla *MultiClaims) (string, error) {
	return "", ErrJwtNotSuportThisFunc
}

//  GetMultiClaims 获取用户信息
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

// SetUserTokenMaxCount 最大登录限制
func (ra *JwtAuth) SetUserTokenMaxCount(tokenMaxCount int64) error {
	return ErrJwtNotSuportThisFunc
}

//UpdateUserTokenCacheExpire 更新过期时间
func (ra *JwtAuth) UpdateUserTokenCacheExpire(token string) error {
	return ErrJwtNotSuportThisFunc
}

// DelUserTokenCache 删除token缓存
func (ra *JwtAuth) DelUserTokenCache(token string) error {
	return ErrJwtNotSuportThisFunc
}

// CleanUserTokenCache 清空token缓存
func (ra *JwtAuth) CleanUserTokenCache(authorityType int, userId string) error {
	return ErrJwtNotSuportThisFunc
}

// IsAdmin
func (ra *JwtAuth) IsAdmin(token string) (bool, error) {
	rcc, err := ra.GetMultiClaims(token)
	if err != nil {
		return false, fmt.Errorf("用户角色是 %w", err)
	}
	return rcc.AuthorityType == AdminAuthority, nil
}

// IsTenancy
func (ra *JwtAuth) IsTenancy(token string) (bool, error) {
	rcc, err := ra.GetMultiClaims(token)
	if err != nil {
		return false, fmt.Errorf("用户角色是 %w", err)
	}
	return rcc.AuthorityType == TenancyAuthority, nil
}

// IsGeneral
func (ra *JwtAuth) IsGeneral(token string) (bool, error) {
	rcc, err := ra.GetMultiClaims(token)
	if err != nil {
		return false, fmt.Errorf("用户角色是 %w", err)
	}
	return rcc.AuthorityType == GeneralAuthority, nil
}

// Close
func (ra *JwtAuth) Close() {
}
