package multi

import (
	"errors"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
)

type tokens []string

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
	if la.isUserTokenOver(claims.ID) {
		return "", 0, errors.New("已达到同时登录设备上限")
	}
	token, err := GetToken()
	if err != nil {
		return "", 0, err
	}
	err = la.toCache(token, claims)
	if err != nil {
		return "", 0, err
	}
	if err = la.syncUserTokenCache(token); err != nil {
		return "", 0, err
	}

	return token, int64(claims.ExpiresIn), err
}

func (la *LocalAuth) toCache(token string, rcc *CustomClaims) error {
	sKey := GtSessionTokenPrefix + token
	la.Cache.Set(sKey, rcc, getTokenExpire(rcc.LoginType))
	return nil
}

func (la *LocalAuth) syncUserTokenCache(token string) error {
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
	la.Cache.Set(sKey, ts, cache.NoExpiration)

	la.Cache.Set(GtSessionBindUserPrefix+token, sKey, getTokenExpire(rcc.LoginType))
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
	if utokens, ufound := la.Cache.Get(sKey); ufound {
		t := utokens.(tokens)
		for index, u := range t {
			if u == token {
				if len(t) == 1 {
					utokens = nil
				} else {
					utokens = append(t[0:index], t[index:]...)
				}
			}
		}
		la.Cache.Set(sKey, utokens, cache.NoExpiration)
	}
	err = la.delTokenCache(token)
	if err != nil {
		return err
	}

	return nil
}

// delTokenCache 删除token缓存
func (la *LocalAuth) delTokenCache(token string) error {
	la.Cache.Delete(GtSessionBindUserPrefix + token)
	la.Cache.Delete(GtSessionTokenPrefix + token)
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
	la.Cache.Set(GtSessionBindUserPrefix+token, rsv2, getTokenExpire(rsv2.LoginType))
	la.Cache.Set(GtSessionTokenPrefix+token, rsv2, getTokenExpire(rsv2.LoginType))

	return nil
}

func (la *LocalAuth) GetCustomClaims(token string) (*CustomClaims, error) {
	sKey := GtSessionTokenPrefix + token
	if food, found := la.Cache.Get(sKey); !found {
		return nil, ErrTokenInvalid
	} else {
		return food.(*CustomClaims), nil
	}
}

func (la *LocalAuth) isUserTokenOver(userId string) bool {
	return la.getUserTokenCount(userId) >= la.getUserTokenMaxCount()
}

// getUserTokenCount 获取登录数量
func (la *LocalAuth) getUserTokenCount(userId string) int64 {
	return la.checkMaxCount(GtSessionUserPrefix + userId)
}

func (la *LocalAuth) checkMaxCount(userPrefixKey string) int64 {
	if utokens, ufound := la.Cache.Get(userPrefixKey); ufound {
		if utokens == nil {
			return 0
		}
		t := utokens.(tokens)
		for index, u := range t {
			if _, found := la.Cache.Get(GtSessionTokenPrefix + u); !found {
				if len(t) == 1 {
					utokens = nil
				} else {
					utokens = append(t[0:index], t[index:]...)
				}
			}
		}
		la.Cache.Set(userPrefixKey, utokens, cache.NoExpiration)
		return int64(len(t))
	}
	return 0
}

// getUserTokenMaxCount 最大登录限制
func (la *LocalAuth) getUserTokenMaxCount() int64 {
	if count, found := la.Cache.Get(GtSessionUserMaxTokenPrefix); !found {
		return GtSessionUserMaxTokenDefault
	} else {
		return count.(int64)
	}
}

// SetUserTokenMaxCount 最大登录限制
func (la *LocalAuth) SetUserTokenMaxCount(tokenMaxCount int64) error {
	la.Cache.Set(GtSessionUserMaxTokenPrefix, tokenMaxCount, cache.NoExpiration)
	return nil
}

// CleanUserTokenCache 清空token缓存
func (la *LocalAuth) CleanUserTokenCache(userId string) error {
	sKey := GtSessionUserPrefix + userId
	if userTokens, found := la.Cache.Get(sKey); !found {
		return nil
	} else {
		for _, token := range userTokens.(tokens) {
			err := la.delTokenCache(token)
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
