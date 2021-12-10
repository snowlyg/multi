package gin

import (
	"errors"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/snowlyg/multi"
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
func (la *LocalAuth) GenerateToken(claims *multi.CustomClaims) (string, int64, error) {
	if la.isUserTokenOver(claims.AuthorityType, claims.ID) {
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

func (la *LocalAuth) toCache(token string, rcc *multi.CustomClaims) error {
	sKey := multi.GtSessionTokenPrefix + token
	la.Cache.Set(sKey, rcc, multi.GetTokenExpire(rcc.LoginType))
	return nil
}

func (la *LocalAuth) syncUserTokenCache(token string) error {
	rcc, err := la.GetCustomClaims(token)
	if err != nil {
		return err
	}

	userPrefixKey := multi.GetUserPrefixKey(rcc.AuthorityType, rcc.ID)
	ts := tokens{}
	if uTokens, uFound := la.Cache.Get(userPrefixKey); uFound {
		ts = uTokens.(tokens)
	}
	ts = append(ts, token)
	la.Cache.Set(userPrefixKey, ts, cache.NoExpiration)

	la.Cache.Set(multi.GtSessionBindUserPrefix+token, userPrefixKey, multi.GetTokenExpire(rcc.LoginType))
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

	userPrefixKey := multi.GetUserPrefixKey(rcc.AuthorityType, rcc.ID)
	if utokens, ufound := la.Cache.Get(userPrefixKey); ufound {
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
		la.Cache.Set(userPrefixKey, utokens, cache.NoExpiration)
	}
	err = la.delTokenCache(token)
	if err != nil {
		return err
	}

	return nil
}

// delTokenCache 删除token缓存
func (la *LocalAuth) delTokenCache(token string) error {
	la.Cache.Delete(multi.GtSessionBindUserPrefix + token)
	la.Cache.Delete(multi.GtSessionTokenPrefix + token)
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
	la.Cache.Set(multi.GtSessionBindUserPrefix+token, rsv2, multi.GetTokenExpire(rsv2.LoginType))
	la.Cache.Set(multi.GtSessionTokenPrefix+token, rsv2, multi.GetTokenExpire(rsv2.LoginType))

	return nil
}

func (la *LocalAuth) GetCustomClaims(token string) (*multi.CustomClaims, error) {
	sKey := multi.GtSessionTokenPrefix + token
	if food, found := la.Cache.Get(sKey); !found {
		return nil, multi.ErrTokenInvalid
	} else {
		return food.(*multi.CustomClaims), nil
	}
}

//  GetTokenByClaims 获取用户信息
func (la *LocalAuth) GetTokenByClaims(cla *multi.CustomClaims) (string, error) {
	userTokens, err := la.getUserTokens(cla.AuthorityType, cla.ID)
	if err != nil {
		return "", err
	}
	clas, err := la.getCustomClaimses(userTokens)
	if err != nil {
		return "", err
	}
	for token, existCla := range clas {
		if cla.AuthType == existCla.AuthType &&
			cla.ID == existCla.ID &&
			cla.AuthorityType == existCla.AuthorityType &&
			cla.TenancyId == existCla.TenancyId &&
			cla.AuthorityId == existCla.AuthorityId &&
			cla.LoginType == existCla.LoginType {
			return token, nil
		}
	}
	return "", nil
}

// getUserTokens 获取登录数量
func (la *LocalAuth) getUserTokens(authorityType int, userId string) (tokens, error) {
	if utokens, ufound := la.Cache.Get(multi.GetUserPrefixKey(authorityType, userId)); ufound {
		if utokens != nil {
			return utokens.(tokens), nil
		}
	}
	return nil, nil
}

//  getCustomClaimses 获取用户信息
func (la *LocalAuth) getCustomClaimses(tokens tokens) (map[string]*multi.CustomClaims, error) {
	clas := make(map[string]*multi.CustomClaims, la.getUserTokenMaxCount())
	for _, token := range tokens {
		cla, err := la.GetCustomClaims(token)
		if err != nil {
			continue
		}
		clas[token] = cla
	}

	return clas, nil
}

func (la *LocalAuth) isUserTokenOver(authorityType int, userId string) bool {
	return la.getUserTokenCount(authorityType, userId) >= la.getUserTokenMaxCount()
}

// getUserTokenCount 获取登录数量
func (la *LocalAuth) getUserTokenCount(authorityType int, userId string) int64 {
	return la.checkMaxCount(authorityType, userId)
}

func (la *LocalAuth) checkMaxCount(authorityType int, userId string) int64 {
	utokens, _ := la.getUserTokens(authorityType, userId)
	if utokens == nil {
		return 0
	}
	for index, u := range utokens {
		if _, found := la.Cache.Get(multi.GtSessionTokenPrefix + u); !found {
			if len(utokens) == 1 {
				utokens = nil
			} else {
				utokens = append(utokens[0:index], utokens[index:]...)
			}
		}
	}
	la.Cache.Set(multi.GetUserPrefixKey(authorityType, userId), utokens, cache.NoExpiration)
	return int64(len(utokens))

}

// getUserTokenMaxCount 最大登录限制
func (la *LocalAuth) getUserTokenMaxCount() int64 {
	if count, found := la.Cache.Get(multi.GtSessionUserMaxTokenPrefix); !found {
		return multi.GtSessionUserMaxTokenDefault
	} else {
		return count.(int64)
	}
}

// SetUserTokenMaxCount 最大登录限制
func (la *LocalAuth) SetUserTokenMaxCount(tokenMaxCount int64) error {
	la.Cache.Set(multi.GtSessionUserMaxTokenPrefix, tokenMaxCount, cache.NoExpiration)
	return nil
}

// CleanUserTokenCache 清空token缓存
func (la *LocalAuth) CleanUserTokenCache(authorityType int, userId string) error {
	utokens, _ := la.getUserTokens(authorityType, userId)
	if utokens == nil {
		return nil
	}

	for _, token := range utokens {
		err := la.delTokenCache(token)
		if err != nil {
			continue
		}
	}
	la.Cache.Delete(multi.GetUserPrefixKey(authorityType, userId))

	return nil
}

// IsAdmin
func (la *LocalAuth) IsAdmin(token string) (bool, error) {
	rcc, err := la.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == multi.AdminAuthority, nil
}

// IsTenancy
func (la *LocalAuth) IsTenancy(token string) (bool, error) {
	rcc, err := la.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == multi.TenancyAuthority, nil
}

// IsGeneral
func (la *LocalAuth) IsGeneral(token string) (bool, error) {
	rcc, err := la.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == multi.GeneralAuthority, nil
}

// 兼容 redis
func (la *LocalAuth) Close() {}
