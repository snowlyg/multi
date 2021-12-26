package multi

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

const (
	GtSessionTokenPrefix        = "GST:"           // token 缓存前缀
	GtSessionBindUserPrefix     = "GSBU:"          // token 绑定用户前缀
	GtSessionUserPrefix         = "GSU:"           // 用户前缀
	GtSessionUserMaxTokenPrefix = "GTUserMaxToken" // 用户最大 token 数前缀
)

var (
	AuthorityTypeSplit                 = "-"
	GtSessionUserMaxTokenDefault int64 = 10
)

var (
	ErrTokenInvalid      = errors.New("TOKEN不可用")
	ErrEmptyToken        = errors.New("TOKEN为空")
	ErrOverMaxTokenCount = errors.New("已达到同时登录设备上限")
	ErrJwtNotSuportThisFunc = errors.New("JWT验证不支持次方法")
)

const (
	NoneAuthority    int = iota // 空授权
	AdminAuthority              // 管理员
	TenancyAuthority            // 商户
	GeneralAuthority            //普通用户
)

const (
	NoAuth int = iota
	AuthPwd
	AuthCode
	AuthThirdParty
)

const (
	LoginTypeWeb int = iota
	LoginTypeApp
	LoginTypeWx
	LoginTypeDevice
)

var (
	RedisSessionTimeoutWeb    = 4 * time.Hour            // 4 小时
	RedisSessionTimeoutApp    = 7 * 24 * time.Hour       // 7 天
	RedisSessionTimeoutWx     = 5 * 52 * 168 * time.Hour // 1年
	RedisSessionTimeoutDevice = 5 * 52 * 168 * time.Hour // 1年
)

// InitDriver 认证驱动
// redis 需要设置redis
// local 使用本地内存
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

// Authentication  认证
type Authentication interface {
	GenerateToken(claims *MultiClaims) (string, int64, error)   // 生成 token
	DelUserTokenCache(token string) error                       // 清除用户当前token信息
	UpdateUserTokenCacheExpire(token string) error              // 更新token 过期时间
	GetMultiClaims(token string) (*MultiClaims, error)          // 获取token用户信息
	GetTokenByClaims(claims *MultiClaims) (string, error)       // 通过用户信息获取token
	CleanUserTokenCache(authorityType int, userId string) error // 清除用户所有 token
	SetUserTokenMaxCount(tokenMaxCount int64) error             // 设置最大登录限制
	IsAdmin(token string) (bool, error)
	IsTenancy(token string) (bool, error)
	IsGeneral(token string) (bool, error)
	Close()
}

// GetTokenExpire 过期时间
func GetTokenExpire(loginType int) time.Duration {
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

// GetUserPrefixKey
func GetUserPrefixKey(authorityType int, id string) string {
	return fmt.Sprintf("%s%d_%s", GtSessionUserPrefix, authorityType, id)
}
