package multi

import (
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
)

// RedisAuth
type RedisAuth struct {
	Client redis.UniversalClient
}

// NewRedisAuth
func NewRedisAuth(options *redis.UniversalOptions) (*RedisAuth, error) {
	client := redis.NewUniversalClient(options)
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("redis ping %w", err)
	}
	return &RedisAuth{
		Client: client,
	}, nil
}

// GenerateToken
func (ra *RedisAuth) GenerateToken(claims *CustomClaims) (string, int64, error) {
	isOver, err := ra.isUserTokenOver(claims.ID)
	if err != nil {
		return "", int64(claims.ExpiresIn), err
	}
	if isOver {
		return "", int64(claims.ExpiresIn), errors.New("已达到同时登录设备上限")
	}
	token, err := GetToken()
	if err != nil {
		return "", int64(claims.ExpiresIn), err
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
func (ra *RedisAuth) toCache(token string, rcc *CustomClaims) error {
	sKey := GtSessionTokenPrefix + token
	if _, err := ra.Client.HMSet(ctx, sKey,
		"id", rcc.ID,
		"login_type", rcc.LoginType,
		"auth_type", rcc.AuthType,
		"username", rcc.Username,
		"tenancy_id", rcc.TenancyId,
		"tenancy_name", rcc.TenancyName,
		"authority_id", rcc.AuthorityId,
		"authority_type", rcc.AuthorityType,
		"creation_data", rcc.CreationDate,
		"expires_in", rcc.ExpiresIn,
	).Result(); err != nil {
		return fmt.Errorf("to cache token %w", err)
	}
	err := ra.setExpire(sKey, rcc.LoginType)
	if err != nil {
		return err
	}

	return nil
}

//  GetCustomClaims session
func (ra *RedisAuth) GetCustomClaims(token string) (*CustomClaims, error) {
	_, err := ra.checkTokenHash(token)
	if err != nil {
		return nil, err
	}
	pp := new(CustomClaims)
	if err := ra.Client.HGetAll(ctx, GtSessionTokenPrefix+token).Scan(pp); err != nil {
		return nil, fmt.Errorf("get custom claims redis hgetall %w", err)
	}
	return pp, nil
}

func (ra *RedisAuth) checkTokenHash(token string) (int64, error) {
	mun, err := ra.Client.Exists(ctx, GtSessionTokenPrefix+token).Result()
	if err != nil || mun == 0 {
		err = ra.delTokenCache(token)
		if err != nil {
			return mun, err
		}
		return mun, ErrTokenInvalid
	}
	return mun, nil
}

// isUserTokenOver 超过登录设备限制
func (ra *RedisAuth) isUserTokenOver(userId string) (bool, error) {
	max, err := ra.getUserTokenCount(userId)
	if err != nil {
		return true, err
	}
	return max >= ra.getUserTokenMaxCount(), nil
}

// getUserTokenCount 获取登录数量
func (ra *RedisAuth) getUserTokenCount(userId string) (int64, error) {
	userPrefixKey := GtSessionUserPrefix + userId
	var count int64
	var allTokens []string
	allTokens, err := ra.Client.SMembers(ctx, userPrefixKey).Result()
	if err != nil {
		return count, fmt.Errorf("get user token count menbers  %w", err)
	}
	for _, token := range allTokens {
		if ra.checkUserTokenCount(token, userPrefixKey) == 1 {
			count++
		}
	}
	return count, nil
}

func (ra *RedisAuth) checkUserTokenCount(token, userPrefixKey string) int64 {
	mun, err := ra.Client.Exists(ctx, GtSessionTokenPrefix+token).Result()
	if err != nil || mun == 0 {
		ra.Client.SRem(ctx, userPrefixKey, token)
	}
	return mun
}

// getUserTokenMaxCount 最大登录限制
func (ra *RedisAuth) getUserTokenMaxCount() int64 {
	count, err := ra.Client.Get(ctx, GtSessionUserMaxTokenPrefix).Int64()
	if err != nil {
		return GtSessionUserMaxTokenDefault
	}
	return count
}

// SetUserTokenMaxCount 最大登录限制
func (ra *RedisAuth) SetUserTokenMaxCount(tokenMaxCount int64) error {
	err := ra.Client.Set(ctx, GtSessionUserMaxTokenPrefix, tokenMaxCount, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

// syncUserTokenCache 同步 token 到用户缓存
func (ra *RedisAuth) syncUserTokenCache(token string) error {
	rcc, err := ra.GetCustomClaims(token)
	if err != nil {
		return fmt.Errorf("sysnc user token cache %w", err)
	}
	sKey := GtSessionUserPrefix + rcc.ID
	if _, err := ra.Client.SAdd(ctx, sKey, token).Result(); err != nil {
		return fmt.Errorf("sync user token cache redis sadd %w", err)
	}

	sKey2 := GtSessionBindUserPrefix + token
	_, err = ra.Client.Set(ctx, sKey2, sKey, getTokenExpire(rcc.LoginType)).Result()
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
	if err = ra.setExpire(GtSessionTokenPrefix+token, rcc.LoginType); err != nil {
		return fmt.Errorf("update user token cache expire redis expire %w", err)
	}
	if err = ra.setExpire(GtSessionBindUserPrefix+token, rcc.LoginType); err != nil {
		return fmt.Errorf("update user token cache expire redis expire %w", err)
	}
	return nil
}

func (ra *RedisAuth) setExpire(key string, loginType int) error {
	if _, err := ra.Client.Expire(ctx, key, getTokenExpire(loginType)).Result(); err != nil {
		return fmt.Errorf("update user token cache expire redis expire %w", err)
	}
	return nil
}

// DelUserTokenCache 删除token缓存
func (ra *RedisAuth) DelUserTokenCache(token string) error {
	rcc, err := ra.GetCustomClaims(token)
	if err != nil {
		return err
	}
	if rcc == nil {
		return errors.New("del user token, reids cache is nil")
	}

	_, err = ra.Client.SRem(ctx, GtSessionUserPrefix+rcc.ID, token).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis srem %w", err)
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

// delTokenCache 删除token缓存
func (ra *RedisAuth) delTokenCache(token string) error {
	sKey2 := GtSessionBindUserPrefix + token
	_, err := ra.Client.Del(ctx, sKey2).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis del2  %w", err)
	}

	sKey3 := GtSessionTokenPrefix + token
	_, err = ra.Client.Del(ctx, sKey3).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis del3  %w", err)
	}

	return nil
}

// CleanUserTokenCache 清空token缓存
func (ra *RedisAuth) CleanUserTokenCache(userId string) error {
	sKey := GtSessionUserPrefix + userId
	var allTokens []string
	allTokens, err := ra.Client.SMembers(ctx, sKey).Result()
	if err != nil {
		return fmt.Errorf("clean user token cache redis smembers  %w", err)
	}
	_, err = ra.Client.Del(ctx, sKey).Result()
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
	return rcc.AuthorityType == AdminAuthority, nil
}

// IsTenancy
func (ra *RedisAuth) IsTenancy(token string) (bool, error) {
	rcc, err := ra.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == TenancyAuthority, nil
}

// IsGeneral
func (ra *RedisAuth) IsGeneral(token string) (bool, error) {
	rcc, err := ra.GetCustomClaims(token)
	if err != nil {
		return false, fmt.Errorf("get auth id %w", err)
	}
	return rcc.AuthorityType == GeneralAuthority, nil
}

// Close
func (ra *RedisAuth) Close() {
	ra.Client.Close()
}
