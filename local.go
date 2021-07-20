package multi

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

type tokens []string
type skeys []string

var localCache *cache.Cache

type LocalAuth struct {
	Cache *cache.Cache
}

func NewLocalAuth() *LocalAuth {
	if localCache == nil {
		localCache = cache.New(4*time.Hour, 24*time.Minute)
	}
	return &LocalAuth{
		Cache: localCache,
	}
}

// GenerateToken
func (la *LocalAuth) GenerateToken(claims *CustomClaims) (string, int64, error) {
	if la.IsUserTokenOver(claims.ID) {
		return "", 0, errors.New("已达到同时登录设备上限")
	}
	token, err := GetToken()
	if err != nil {
		return "", 0, err
	}
	err = la.ToCache(token, claims)
	if err != nil {
		return "", 0, err
	}
	if err = la.SyncUserTokenCache(token); err != nil {
		return "", 0, err
	}

	return token, int64(claims.ExpiresIn), err
}

// GetAuthId
func (la *LocalAuth) GetAuthId(token string) (uint, error) {
	sess, err := la.GetCustomClaims(token)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseInt(sess.ID, 10, 64)
	if err != nil {
		return 0, err
	}
	return uint(id), nil
}

func (la *LocalAuth) ToCache(token string, rcc *CustomClaims) error {
	sKey := GtSessionTokenPrefix + token
	la.Cache.Set(sKey, rcc, la.getTokenExpire(rcc.LoginType))
	return nil
}

func (la *LocalAuth) SyncUserTokenCache(token string) error {
	rcc, err := la.GetCustomClaims(token)
	if err != nil {
		return err
	}

	sKey := GtSessionUserPrefix + rcc.ID
	ts := tokens{}
	if uTokens, uFound := la.Cache.Get(sKey); uFound {
		ts = uTokens.(tokens)
	}
	ts = append(ts, token)

	la.Cache.Set(sKey, ts, la.getTokenExpire(rcc.LoginType))

	sKey2 := GtSessionBindUserPrefix + token
	sys := skeys{}
	if keys, found := la.Cache.Get(sKey2); found {
		sys = keys.(skeys)
	}
	sys = append(sys, sKey)
	la.Cache.Set(sKey2, sys, la.getTokenExpire(rcc.LoginType))
	return nil
}

func (la *LocalAuth) DelUserTokenCache(token string) error {
	rcc, err := la.GetCustomClaims(token)
	if err != nil {
		return err
	}
	if rcc == nil {
		return errors.New("token cache is nil")
	}
	sKey := GtSessionUserPrefix + rcc.ID
	exp := la.getTokenExpire(rcc.LoginType)
	if utokens, ufound := la.Cache.Get(sKey); ufound {
		t := utokens.(tokens)
		for index, u := range t {
			if u == token {
				utokens = append(t[0:index], t[index:]...)
				la.Cache.Set(sKey, utokens, exp)
			}
		}
	}
	err = la.DelTokenCache(token)
	if err != nil {
		return err
	}

	return nil
}

// DelTokenCache 删除token缓存
func (la *LocalAuth) DelTokenCache(token string) error {
	la.Cache.Delete(GtSessionBindUserPrefix + token)
	la.Cache.Delete(GtSessionTokenPrefix + token)
	return nil
}

func (la *LocalAuth) UserTokenExpired(token string) error {
	rsv2, err := la.GetCustomClaims(token)
	if err != nil {
		return err
	}
	if rsv2 == nil {
		return errors.New("token cache is nil")
	}

	exp := la.getTokenExpire(rsv2.LoginType)
	uKey := GtSessionBindUserPrefix + token
	if sKeys, found := la.Cache.Get(uKey); !found {
		return errors.New("token skey is empty")
	} else {
		for _, v := range sKeys.(skeys) {
			if !strings.Contains(v, GtSessionUserPrefix) {
				continue
			}
			if utokens, ufound := la.Cache.Get(v); ufound {
				t := utokens.(tokens)
				for index, u := range t {
					if u == token {
						utokens = append(t[0:index], t[index:]...)
						la.Cache.Set(v, utokens, exp)
					}
				}
			}
		}
	}

	la.Cache.Delete(uKey)
	return nil
}

func (la *LocalAuth) UpdateUserTokenCacheExpire(token string) error {
	rsv2, err := la.GetCustomClaims(token)
	if err != nil {
		return err
	}
	if rsv2 == nil {
		return errors.New("token cache is nil")
	}
	la.Cache.Set(GtSessionTokenPrefix+token, rsv2, la.getTokenExpire(rsv2.LoginType))

	return nil
}

// getTokenExpire 过期时间
func (la *LocalAuth) getTokenExpire(loginType int) time.Duration {
	timeout := RedisSessionTimeoutApp
	if loginType == LoginTypeWeb {
		timeout = RedisSessionTimeoutWeb
	} else if loginType == LoginTypeWx {
		timeout = RedisSessionTimeoutWx
	}
	return timeout
}

func (la *LocalAuth) GetCustomClaims(token string) (*CustomClaims, error) {
	sKey := GtSessionTokenPrefix + token
	if food, found := la.Cache.Get(sKey); !found {
		return nil, ErrTokenInvalid
	} else {
		return food.(*CustomClaims), nil
	}
}

func (la *LocalAuth) IsUserTokenOver(userId string) bool {
	return la.getUserTokenCount(userId) >= la.getUserTokenMaxCount()
}

// getUserTokenCount 获取登录数量
func (la *LocalAuth) getUserTokenCount(userId string) int64 {
	if userTokens, found := la.Cache.Get(GtSessionUserPrefix + userId); !found {
		return 0
	} else {
		return int64(len(userTokens.(tokens)))
	}
}

// getUserTokenMaxCount 最大登录限制
func (la *LocalAuth) getUserTokenMaxCount() int64 {
	if count, found := la.Cache.Get(GtSessionUserMaxTokenPrefix); !found {
		return GtSessionUserMaxTokenDefault
	} else {
		return count.(int64)
	}
}

// CleanUserTokenCache 清空token缓存
func (la *LocalAuth) CleanUserTokenCache(userId string) error {
	sKey := GtSessionUserPrefix + userId
	if userTokens, found := la.Cache.Get(sKey); !found {
		return nil
	} else {
		for _, token := range userTokens.(tokens) {
			err := la.DelTokenCache(token)
			if err != nil {
				continue
			}
		}
	}
	la.Cache.Delete(sKey)

	return nil
}

// IsAdmin
func (la *LocalAuth) IsAdmin(token string) (bool, error) {
	rcc, err := la.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == AdminAuthority, nil
}

// IsTenancy
func (la *LocalAuth) IsTenancy(token string) (bool, error) {
	rcc, err := la.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == TenancyAuthority, nil
}

// IsGeneral
func (la *LocalAuth) IsGeneral(token string) (bool, error) {
	rcc, err := la.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == GeneralAuthority, nil
}

// 兼容 redis
func (la *LocalAuth) Close() {}
