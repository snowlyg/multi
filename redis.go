package multi

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, fmt.Errorf("redis ping %w", err)
	}
	return &RedisAuth{
		Client: client,
	}, nil
}

// GenerateToken
func (ra *RedisAuth) GenerateToken(claims *CustomClaims) (string, int64, error) {
	if ra.IsUserTokenOver(claims.ID) {
		return "", 0, errors.New("已达到同时登录设备上限")
	}
	token, err := GetToken()
	if err != nil {
		return "", 0, err
	}
	err = ra.ToCache(token, claims)
	if err != nil {
		return "", 0, err
	}
	if err = ra.SyncUserTokenCache(token); err != nil {
		return "", 0, err
	}

	return token, int64(claims.ExpiresIn), err
}

// ToCache 缓存 token
func (ra *RedisAuth) ToCache(token string, rcc *CustomClaims) error {
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
	err := ra.SetExpire(sKey, rcc.LoginType)
	if err != nil {
		return err
	}

	return nil
}

// GetAuthId
func (ra *RedisAuth) GetAuthId(token string) (uint, error) {
	sess, err := ra.GetCustomClaims(token)
	if err != nil {
		return 0, fmt.Errorf("get auth id %w", err)
	}
	id, err := strconv.ParseInt(sess.ID, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("get auth id parse int %w", err)
	}
	return uint(id), nil
}

//  GetCustomClaims session
func (ra *RedisAuth) GetCustomClaims(token string) (*CustomClaims, error) {
	sKey := GtSessionTokenPrefix + token
	_, err := ra.Client.Exists(context.Background(), sKey).Result()
	if err != nil {
		ra.UserTokenExpired(token)
		return nil, ErrTokenInvalid
	}
	pp := new(CustomClaims)
	if err := ra.Client.HGetAll(ctx, sKey).Scan(pp); err != nil {
		return nil, fmt.Errorf("get custom claims redis hgetall %w", err)
	}
	return pp, nil
}

// IsUserTokenOver 超过登录设备限制
func (ra *RedisAuth) IsUserTokenOver(userId string) bool {
	return ra.getUserTokenCount(userId) >= ra.getUserTokenMaxCount()
}

// getUserTokenCount 获取登录数量
func (ra *RedisAuth) getUserTokenCount(userId string) int64 {
	count, err := ra.Client.SCard(ctx, GtSessionUserPrefix+userId).Result()
	if err != nil {
		return 0
	}
	return count
}

// getUserTokenMaxCount 最大登录限制
func (ra *RedisAuth) getUserTokenMaxCount() int64 {
	count, err := ra.Client.Get(ctx, GtSessionUserMaxTokenPrefix).Int64()
	if err != nil {
		return GtSessionUserMaxTokenDefault
	}
	return count
}

// UserTokenExpired 过期 token
func (ra *RedisAuth) UserTokenExpired(token string) error {
	uKey := GtSessionBindUserPrefix + token
	sKeys, err := ra.Client.SMembers(ctx, uKey).Result()
	if err != nil {
		return fmt.Errorf("user token expired %w", err)
	}
	for _, v := range sKeys {
		if !strings.Contains(v, GtSessionUserPrefix) {
			continue
		}
		_, err = ra.Client.SRem(ctx, v, token).Result()
		if err != nil {
			continue
		}
	}
	if _, err = ra.Client.Del(ctx, uKey).Result(); err != nil {
		return err
	}
	return nil
}

// SyncUserTokenCache 同步 token 到用户缓存
func (ra *RedisAuth) SyncUserTokenCache(token string) error {
	rcc, err := ra.GetCustomClaims(token)
	if err != nil {
		return fmt.Errorf("sysnc user token cache %w", err)
	}
	sKey := GtSessionUserPrefix + rcc.ID
	if _, err := ra.Client.SAdd(ctx, sKey, token).Result(); err != nil {
		return fmt.Errorf("sync user token cache redis sadd %w", err)
	}

	sKey2 := GtSessionBindUserPrefix + token
	_, err = ra.Client.SAdd(ctx, sKey2, sKey).Result()
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
	if err = ra.SetExpire(GtSessionTokenPrefix+token, rcc.LoginType); err != nil {
		return fmt.Errorf("update user token cache expire redis expire %w", err)
	}
	return nil
}

func (ra *RedisAuth) SetExpire(key string, loginType int) error {
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
	sKey := GtSessionUserPrefix + rcc.ID
	_, err = ra.Client.SRem(ctx, sKey, token).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis srem %w", err)
	}
	err = ra.DelTokenCache(token)
	if err != nil {
		return err
	}

	return nil
}

// DelTokenCache 删除token缓存
func (ra *RedisAuth) DelTokenCache(token string) error {
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
		err = ra.DelTokenCache(token)
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
