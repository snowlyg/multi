package multi

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

const (
	GtSessionTokenPrefix        = "GST:"           // token perfix
	GtSessionBindUserPrefix     = "GSBU:"          // token perfix for bind user
	GtSessionUserPrefix         = "GSU:"           // user perfix
	GtSessionUserMaxTokenPrefix = "GTUserMaxToken" // user max token prefix
)

var (
	AuthorityTypeSplit                 = "-"
	GtSessionUserMaxTokenDefault int64 = 10
)

var (
	ErrTokenInvalid      = errors.New("TOKEN IS INVALID")
	ErrEmptyToken        = errors.New("TOKEN IS EMPTY")
	ErrOverMaxTokenCount = errors.New("OVER LOGIN DEVICE LIMIT")
	ErrForJwt            = errors.New("JWT NOT SUPPORT THIS FEATURE")
)

// role's type
const (
	NoneAuthority    int = iota //
	AdminAuthority              // admin
	TenancyAuthority            // tenancy
	GeneralAuthority            // general
)

// auth's type
const (
	NoAuth int = iota
	AuthPwd
	AuthCode
	AuthThirdParty
)

// login type
const (
	LoginTypeWeb int = iota
	LoginTypeApp
	LoginTypeWx
	LoginTypeDevice
)

// auth time
var (
	RedisSessionTimeoutWeb    = 4 * time.Hour            // 4 小时
	RedisSessionTimeoutApp    = 7 * 24 * time.Hour       // 7 天
	RedisSessionTimeoutWx     = 5 * 52 * 168 * time.Hour // 1年
	RedisSessionTimeoutDevice = 5 * 52 * 168 * time.Hour // 1年
)

// InitDriver
func InitDriver(c *Config) error {
	if c.TokenMaxCount == 0 {
		c.TokenMaxCount = 10
	}
	switch c.DriverType {
	case "redis":
		driver, err := NewRedisAuth(c.UniversalClient)
		if err != nil {
			return err
		}

		AuthDriver = driver
		err = AuthDriver.SetUserTokenMaxCount(c.TokenMaxCount)
		if err != nil {
			return err
		}
	case "local":
		AuthDriver = NewLocalAuth()
		err := AuthDriver.SetUserTokenMaxCount(c.TokenMaxCount)
		if err != nil {
			return err
		}
	case "jwt":
		AuthDriver = NewJwtAuth(c.HmacSecret)
	default:
		AuthDriver = NewJwtAuth(c.HmacSecret)
	}

	return nil
}

// Multi
type Multi struct {
	Id            uint     `json:"id,omitempty"`
	Username      string   `json:"username,omitempty"`
	TenancyId     uint     `json:"tenancyId,omitempty"`
	TenancyName   string   `json:"tenancyName,omitempty"`
	AuthorityIds  []string `json:"authorityIds,omitempty"`
	AuthorityType int      `json:"authorityType,omitempty"`
	LoginType     int      `json:"loginType,omitempty"`
	AuthType      int      `json:"authType,omitempty"`
	CreationDate  int64    `json:"creationData,omitempty"`
	ExpiresAt     int64    `json:"expiresAt,omitempty"`
}

type Config struct {
	DriverType      string
	TokenMaxCount   int64
	UniversalClient redis.UniversalClient
	HmacSecret      []byte
}

type (
	// TokenValidator provides further token and claims validation.
	TokenValidator interface {
		// ValidateToken accepts the token, the claims extracted from that
		// and any error that may caused by claims validation (e.g. ErrExpired)
		// or the previous validator.
		// A token validator can skip the builtin validation and return a nil error.
		// Usage:
		//  func(v *myValidator) ValidateToken(token []byte, standardClaims Claims, err error) error {
		//    if err!=nil { return err } <- to respect the previous error
		//    // otherwise return nil or any custom error.
		//  }
		//
		// Look `Blocklist`, `Expected` and `Leeway` for builtin implementations.
		ValidateToken(token []byte, err error) error
	}

	// TokenValidatorFunc is the interface-as-function shortcut for a TokenValidator.
	TokenValidatorFunc func(token []byte, err error) error
)

// ValidateToken completes the ValidateToken interface.
// It calls itself.
func (fn TokenValidatorFunc) ValidateToken(token []byte, err error) error {
	return fn(token, err)
}

var AuthDriver Authentication

// Authentication
type Authentication interface {
	GenerateToken(claims *MultiClaims) (string, int64, error)
	DelUserTokenCache(token string) error
	UpdateUserTokenCacheExpire(token string) error
	GetMultiClaims(token string) (*MultiClaims, error)
	GetTokenByClaims(claims *MultiClaims) (string, error)
	CleanUserTokenCache(authorityType int, userId string) error
	SetUserTokenMaxCount(tokenMaxCount int64) error
	IsRole(token string, authorityType int) (bool, error)
	Close()
}

// getTokenExpire
func getTokenExpire(loginType int) time.Duration {
	switch loginType {
	case LoginTypeWeb:
		return RedisSessionTimeoutWeb
	case LoginTypeWx:
		return RedisSessionTimeoutWx
	case LoginTypeApp:
		return RedisSessionTimeoutApp
	case LoginTypeDevice:
		return RedisSessionTimeoutDevice
	default:
		return RedisSessionTimeoutWeb
	}
}

// getUserPrefixKey
func getUserPrefixKey(authorityType int, id string) string {
	return fmt.Sprintf("%s%d_%s", GtSessionUserPrefix, authorityType, id)
}
