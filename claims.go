package multi

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/snowlyg/helper/arr"
)

const (
	ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
	ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                    // Signature validation failed

	ValidationErrorExpired // EXP validation failed
	ValidationErrorId
	ValidationErrorUsername
	ValidationErrorAuthorityId
	ValidationErrorAuthorityType
	ValidationErrorLoginType
	ValidationErrorAuthType
)

// 自定义结构
// Id 用户id
// Username 用户名
// TenancyId 商户id
// TenancyName 商户名称
// AuthorityId 角色id
// AuthorityType 角色类型
// LoginType 登录类型 web,app,wechat
// AuthType  授权类型 密码,验证码,第三方
// CreationDate 登录时间
// ExpiresIn 有效期
type MultiClaims struct {
	Id            string `json:"id,omitempty" redis:"id"`
	Username      string `json:"username,omitempty" redis:"username"`
	TenancyId     uint   `json:"tenancyId,omitempty" redis:"tenancy_id"`
	TenancyName   string `json:"tenancyName,omitempty" redis:"tenancy_name"`
	AuthorityId   string `json:"authorityId,omitempty" redis:"authority_id"`
	AuthorityType int    `json:"authorityType,omitempty" redis:"authority_type"`
	LoginType     int    `json:"loginType,omitempty" redis:"login_type"`
	AuthType      int    `json:"authType,omitempty" redis:"auth_type"`
	CreationDate  int64  `json:"creationData,omitempty" redis:"creation_data"`
	ExpiresAt     int64  `json:"expiresAt,omitempty" redis:"expires_at"`
}

func New(m *Multi) *MultiClaims {
	claims := &MultiClaims{
		Id:            strconv.FormatUint(uint64(m.Id), 10),
		Username:      m.Username,
		TenancyId:     m.TenancyId,
		TenancyName:   m.TenancyName,
		AuthorityId:   strings.Join(m.AuthorityIds, "-"),
		AuthorityType: m.AuthorityType,
		LoginType:     m.LoginType,
		AuthType:      m.AuthType,
		CreationDate:  time.Now().Local().Unix(),
		ExpiresAt:     m.ExpiresAt,
	}
	return claims
}

func (c *MultiClaims) Valid() error {
	vErr := new(jwt.ValidationError)
	now := time.Now().Unix()
	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now, false) {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= ValidationErrorExpired
	}
	if !c.VerifyId() {
		vErr.Inner = errors.New("id is empty")
		vErr.Errors |= ValidationErrorId
	}
	if !c.VerifyUsername() {
		vErr.Inner = errors.New("username is empty")
		vErr.Errors |= ValidationErrorUsername
	}
	if !c.VerifyAuthorityId() {
		vErr.Inner = errors.New("authority id is empty")
		vErr.Errors |= ValidationErrorAuthorityId
	}
	if !c.VerifyAuthorityType() {
		vErr.Inner = errors.New("authority type is invalid")
		vErr.Errors |= ValidationErrorAuthorityType
	}
	if !c.VerifyLoginType() {
		vErr.Inner = errors.New("login type is invalid")
		vErr.Errors |= ValidationErrorLoginType
	}
	if !c.VerifyAuthType() {
		vErr.Inner = errors.New("auth type is invalid")
		vErr.Errors |= ValidationErrorAuthType
	}
	if valid(vErr) {
		return nil
	}

	return vErr
}

// No errors
func valid(e *jwt.ValidationError) bool {
	return e.Errors == 0
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *MultiClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	return verifyExp(c.ExpiresAt, cmp, req)
}

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}

func (c *MultiClaims) VerifyId() bool {
	return c.Id != ""
}

func (c *MultiClaims) VerifyUsername() bool {
	return c.Username != ""
}

func (c *MultiClaims) VerifyAuthorityId() bool {
	return c.AuthorityId != ""
}

func (c *MultiClaims) VerifyAuthorityType() bool {
	return c.AuthorityType > 0
}

func (c *MultiClaims) VerifyLoginType() bool {
	loginType := arr.NewCheckArrayType(4)
	loginType.AddMutil(LoginTypeWeb, LoginTypeApp, LoginTypeWx, LoginTypeDevice)
	return loginType.Check(c.LoginType)
}

func (c *MultiClaims) VerifyAuthType() bool {
	authType := arr.NewCheckArrayType(4)
	authType.AddMutil(NoAuth, AuthPwd, AuthCode, AuthThirdParty)
	return authType.Check(c.AuthType)
}
