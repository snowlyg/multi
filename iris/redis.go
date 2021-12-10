package iris

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"github.com/snowlyg/multi"
)

// RedisAuth
type RedisAuth struct {
	Client redis.UniversalClient
}

// NewRedisAuth
func NewRedisAuth(client redis.UniversalClient) (*RedisAuth, error) {
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, fmt.Errorf("redis ping %w", err)
	}
	return &RedisAuth{
		Client: client,
	}, nil
}

// GenerateToken
func (ra *RedisAuth) GenerateToken(claims *multi.CustomClaims) (string, int64, error) {
	// 判断是否存在token
	token, err := ra.GetTokenByClaims(claims)
	if err != nil {
		return "", int64(claims.ExpiresIn), err
	}

	// 如果为 token 空生成新的 token
	if token == "" {
		if isOver, err := ra.isUserTokenOver(claims.AuthorityType, claims.ID); err != nil {
			return "", int64(claims.ExpiresIn), err
		} else if isOver {
			return "", int64(claims.ExpiresIn), multi.ErrOverMaxTokenCount
		}

		token, err = GetToken()
		if err != nil {
			return "", int64(claims.ExpiresIn), err
		}
	}

	err = ra.toCache(token, claims)
	if err != nil {
		return "", int64(claims.ExpiresIn), err
	}

	if err = ra.syncUserTokenCache(token); err != nil {
		return "", int64(claims.ExpiresIn), err
	}

	return token, int64(claims.ExpiresIn), nil
}

// toCache 缓存 token
func (ra *RedisAuth) toCache(token string, cla *multi.CustomClaims) error {
	sKey := multi.GtSessionTokenPrefix + token
	if _, err := ra.Client.HMSet(context.Background(), sKey,
		"id", cla.ID,
		"login_type", cla.LoginType,
		"auth_type", cla.AuthType,
		"username", cla.Username,
		"tenancy_id", cla.TenancyId,
		"tenancy_name", cla.TenancyName,
		"authority_id", cla.AuthorityId,
		"authority_type", cla.AuthorityType,
		"creation_data", cla.CreationDate,
		"expires_in", cla.ExpiresIn,
	).Result(); err != nil {
		return fmt.Errorf("to cache token %w", err)
	}
	err := ra.setExpire(sKey, cla.LoginType)
	if err != nil {
		return err
	}

	return nil
}

//  GetTokenByClaims 获取用户信息
func (ra *RedisAuth) GetTokenByClaims(cla *multi.CustomClaims) (string, error) {
	userTokens, err := ra.getUserTokens(cla.AuthorityType, cla.ID)
	if err != nil {
		return "", err
	}
	clas, err := ra.getCustomClaimses(userTokens)
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

//  getCustomClaimses 获取用户信息
func (ra *RedisAuth) getCustomClaimses(tokens []string) (map[string]*multi.CustomClaims, error) {
	clas := make(map[string]*multi.CustomClaims, ra.getUserTokenMaxCount())
	for _, token := range tokens {
		cla, err := ra.GetCustomClaims(token)
		if err != nil {
			continue
		}
		clas[token] = cla
	}

	return clas, nil
}

//  GetCustomClaims 获取用户信息
func (ra *RedisAuth) GetCustomClaims(token string) (*multi.CustomClaims, error) {
	cla := new(multi.CustomClaims)
	if err := ra.Client.HGetAll(context.Background(), multi.GtSessionTokenPrefix+token).Scan(cla); err != nil {
		return nil, fmt.Errorf("get custom claims redis hgetall %w", err)
	}

	if cla == nil || cla.ID == "" {
		return nil, multi.ErrEmptyToken
	}

	return cla, nil
}

// isUserTokenOver 超过登录设备限制
func (ra *RedisAuth) isUserTokenOver(authorityType int, userId string) (bool, error) {
	max, err := ra.getUserTokenCount(authorityType, userId)
	if err != nil {
		return true, err
	}
	return max >= ra.getUserTokenMaxCount(), nil
}

// getUserTokens 获取登录数量
func (ra *RedisAuth) getUserTokens(authorityType int, userId string) ([]string, error) {
	userTokens, err := ra.Client.SMembers(context.Background(), multi.GetUserPrefixKey(authorityType, userId)).Result()
	if err != nil {
		return nil, fmt.Errorf("get user token count menbers  %w", err)
	}
	return userTokens, nil
}

// getUserTokenCount 获取登录数量
func (ra *RedisAuth) getUserTokenCount(authorityType int, userId string) (int64, error) {
	var count int64
	userTokens, err := ra.getUserTokens(authorityType, userId)
	if err != nil {
		return count, fmt.Errorf("get user token count menbers  %w", err)
	}
	userPrefixKey := multi.GetUserPrefixKey(authorityType, userId)
	for _, token := range userTokens {
		if ra.checkUserTokenCount(token, userPrefixKey) == 1 {
			count++
		}
	}
	return count, nil
}

// checkUserTokenCount 验证登录数量,清除 userPrefixKey 下无效 token
func (ra *RedisAuth) checkUserTokenCount(token, userPrefixKey string) int64 {
	mun, err := ra.Client.Exists(context.Background(), multi.GtSessionTokenPrefix+token).Result()
	if err != nil || mun == 0 {
		ra.Client.SRem(context.Background(), userPrefixKey, token)
	}
	return mun
}

// getUserTokenMaxCount 最大登录限制
func (ra *RedisAuth) getUserTokenMaxCount() int64 {
	count, err := ra.Client.Get(context.Background(), multi.GtSessionUserMaxTokenPrefix).Int64()
	if err != nil {
		return multi.GtSessionUserMaxTokenDefault
	}
	return count
}

// SetUserTokenMaxCount 最大登录限制
func (ra *RedisAuth) SetUserTokenMaxCount(tokenMaxCount int64) error {
	err := ra.Client.Set(context.Background(), multi.GtSessionUserMaxTokenPrefix, tokenMaxCount, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

// syncUserTokenCache 同步 token 到用户缓存
func (ra *RedisAuth) syncUserTokenCache(token string) error {
	cla, err := ra.GetCustomClaims(token)
	if err != nil {
		return fmt.Errorf("sysnc user token cache %w", err)
	}
	userPrefixKey := multi.GetUserPrefixKey(cla.AuthorityType, cla.ID)
	if _, err := ra.Client.SAdd(context.Background(), userPrefixKey, token).Result(); err != nil {
		return fmt.Errorf("sync user token cache redis sadd %w", err)
	}

	bindUserPrefixKey := multi.GtSessionBindUserPrefix + token
	_, err = ra.Client.Set(context.Background(), bindUserPrefixKey, userPrefixKey, multi.GetTokenExpire(cla.LoginType)).Result()
	if err != nil {
		return fmt.Errorf("sync user token cache %w", err)
	}
	return nil
}

//UpdateUserTokenCacheExpire 更新过期时间
func (ra *RedisAuth) UpdateUserTokenCacheExpire(token string) error {
	rcc, err := ra.GetCustomClaims(token)
	if err != nil {
		return fmt.Errorf("update user token cache expire %w", err)
	}
	if rcc == nil {
		return errors.New("token cache is nil")
	}
	if err = ra.setExpire(multi.GtSessionTokenPrefix+token, rcc.LoginType); err != nil {
		return fmt.Errorf("update user token cache expire redis expire %w", err)
	}
	if err = ra.setExpire(multi.GtSessionBindUserPrefix+token, rcc.LoginType); err != nil {
		return fmt.Errorf("update user token cache expire redis expire %w", err)
	}
	return nil
}

func (ra *RedisAuth) setExpire(key string, loginType int) error {
	if _, err := ra.Client.Expire(context.Background(), key, multi.GetTokenExpire(loginType)).Result(); err != nil {
		return fmt.Errorf("update user token cache expire redis expire %w", err)
	}
	return nil
}

// DelUserTokenCache 删除token缓存
func (ra *RedisAuth) DelUserTokenCache(token string) error {
	cla, err := ra.GetCustomClaims(token)
	if err != nil {
		return err
	}
	if cla == nil {
		return errors.New("del user token, reids cache is nil")
	}

	err = ra.delUserTokenPrefixToken(cla.AuthorityType, cla.ID, token)
	if err != nil {
		return err
	}

	err = ra.delTokenCache(token)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	return nil
}

// delUserTokenPrefixToken 删除 user token缓存
func (ra *RedisAuth) delUserTokenPrefixToken(authorityType int, id, token string) error {
	_, err := ra.Client.SRem(context.Background(), multi.GetUserPrefixKey(authorityType, id), token).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis srem %w", err)
	}
	return nil
}

// delTokenCache 删除token缓存
func (ra *RedisAuth) delTokenCache(token string) error {
	sKey2 := multi.GtSessionBindUserPrefix + token
	_, err := ra.Client.Del(context.Background(), sKey2).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis del2  %w", err)
	}

	sKey3 := multi.GtSessionTokenPrefix + token
	_, err = ra.Client.Del(context.Background(), sKey3).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis del3  %w", err)
	}

	return nil
}

// CleanUserTokenCache 清空token缓存
func (ra *RedisAuth) CleanUserTokenCache(authorityType int, userId string) error {
	allTokens, err := ra.getUserTokens(authorityType, userId)
	if err != nil {
		return fmt.Errorf("clean user token cache redis smembers  %w", err)
	}
	_, err = ra.Client.Del(context.Background(), multi.GetUserPrefixKey(authorityType, userId)).Result()
	if err != nil {
		return fmt.Errorf("clean user token cache redis del  %w", err)
	}

	for _, token := range allTokens {
		err = ra.delTokenCache(token)
		if err != nil {
			return err
		}
	}
	return nil
}

// IsAdmin
func (ra *RedisAuth) IsAdmin(token string) (bool, error) {
	rcc, err := ra.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == multi.AdminAuthority, nil
}

// IsTenancy
func (ra *RedisAuth) IsTenancy(token string) (bool, error) {
	rcc, err := ra.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == multi.TenancyAuthority, nil
}

// IsGeneral
func (ra *RedisAuth) IsGeneral(token string) (bool, error) {
	rcc, err := ra.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == multi.GeneralAuthority, nil
}

// Close
func (ra *RedisAuth) Close() {
	ra.Client.Close()
}
