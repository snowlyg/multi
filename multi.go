package multi

import (
	"context"
	"errors"
	"time"

	iriscontext "github.com/kataras/iris/v12/context"

	"github.com/go-redis/redis/v8"
)

func init() {
	iriscontext.SetHandlerName("iris/middleware/multi.*", "iris.multi")
}

const (
	GtSessionTokenPrefix        = "GST:"           // token 缓存前缀
	GtSessionBindUserPrefix     = "GSBU:"          // token 绑定用户前缀
	GtSessionUserPrefix         = "GSU:"           // 用户前缀
	GtSessionUserMaxTokenPrefix = "GTUserMaxToken" // 用户最大 token 数前缀
)

var (
	ctx                                = context.Background()
	ErrTokenInvalid                    = errors.New("token is invalid")
	GtSessionUserMaxTokenDefault int64 = 10
)

const (
	NoneAuthority    string = "" // 空授权
	AdminAuthority   string = "" // 管理员
	TenancyAuthority string = "" // 商户
	GeneralScope     string = "" //普通用户
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
)

var (
	RedisSessionTimeoutWeb = 30 * time.Minute
	RedisSessionTimeoutApp = 24 * time.Hour
	RedisSessionTimeoutWx  = 5 * 52 * 168 * time.Hour
)

// Custom claims structure
type CustomClaims struct {
	ID           string `json:"id" redis:"id"`
	Username     string `json:"username" redis:"username"`
	AuthorityId  string `json:"authority_id" redis:"authority_id"`
	LoginType    int    `json:"login_type" redis:"login_type"`
	AuthType     int    `json:"auth_type" redis:"auth_type"`
	CreationDate int64  `json:"creation_data" redis:"creation_data"`
	ExpiresIn    int64  `json:"expires_in" redis:"expires_in"`
}

type Config struct {
	DrvierType       string
	UniversalOptions *redis.UniversalOptions
}

type VerifiedToken struct {
	Token   []byte // The original token.
	Header  []byte // The header (decoded) part.
	Payload []byte // The payload (decoded) part.
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

// InitDriver 认证驱动
// redis 需要设置redis
// local 使用本地内存
func InitDriver(c *Config) error {
	switch c.DrvierType {
	case "redis":
		driver, err := NewRedisAuth(c.UniversalOptions)
		if err != nil {
			return err
		}
		AuthDriver = driver
	case "local":
		AuthDriver = NewLocalAuth()
	default:
		AuthDriver = NewLocalAuth()
	}
	return nil
}

// Authentication  认证
type Authentication interface {
	ToCache(token string, rcc *CustomClaims) error
	SyncUserTokenCache(token string) error
	DelUserTokenCache(token string) error
	UserTokenExpired(token string) error
	UpdateUserTokenCacheExpire(token string) error
	GetCustomClaims(token string) (*CustomClaims, error)
	GetAuthId(token string) (uint, error)
	IsUserTokenOver(userId string) bool
	CleanUserTokenCache(userId string) error
	Close()
}
