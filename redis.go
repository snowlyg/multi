package multi

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
)

// RedisAuth
type RedisAuth struct {
	Client redis.UniversalClient
}

// NewRedisAuth
func NewRedisAuth(client redis.UniversalClient) (*RedisAuth, error) {
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("redis client is nil")
	}
	return &RedisAuth{
		Client: client,
	}, nil
}

// GenerateToken
func (ra *RedisAuth) GenerateToken(claims *MultiClaims) (string, int64, error) {
	token, err := ra.GetTokenByClaims(claims)
	if err != nil {
		return "", int64(claims.ExpiresAt), err
	}

	if token == "" {
		if isOver, err := ra.isUserTokenOver(claims.AuthorityType, claims.Id); err != nil {
			return "", int64(claims.ExpiresAt), err
		} else if isOver {
			return "", int64(claims.ExpiresAt), ErrOverMaxTokenCount
		}

		token, err = GetToken()
		if err != nil {
			return "", int64(claims.ExpiresAt), err
		}
	}

	err = ra.toCache(token, claims)
	if err != nil {
		return "", int64(claims.ExpiresAt), err
	}

	if err = ra.syncUserTokenCache(token); err != nil {
		return "", int64(claims.ExpiresAt), err
	}

	return token, int64(claims.ExpiresAt), nil
}

// toCache
func (ra *RedisAuth) toCache(token string, cla *MultiClaims) error {
	sKey := GtSessionTokenPrefix + token
	if _, err := ra.Client.HMSet(context.Background(), sKey,
		"id", cla.Id,
		"login_type", cla.LoginType,
		"auth_type", cla.AuthType,
		"username", cla.Username,
		"tenancy_id", cla.TenancyId,
		"tenancy_name", cla.TenancyName,
		"authority_id", cla.AuthorityId,
		"authority_type", cla.AuthorityType,
		"creation_data", cla.CreationDate,
		"expires_at", cla.ExpiresAt,
	).Result(); err != nil {
		return fmt.Errorf("to cache token %w", err)
	}
	err := ra.setExpire(sKey, cla.LoginType)
	if err != nil {
		return err
	}

	return nil
}

// GetTokenByClaims
func (ra *RedisAuth) GetTokenByClaims(cla *MultiClaims) (string, error) {
	userTokens, err := ra.getUserTokens(cla.AuthorityType, cla.Id)
	if err != nil {
		return "", err
	}
	clas, err := ra.getMultiClaimses(userTokens)
	if err != nil {
		return "", err
	}
	for token, existCla := range clas {
		if cla.AuthType == existCla.AuthType &&
			cla.Id == existCla.Id &&
			cla.AuthorityType == existCla.AuthorityType &&
			cla.TenancyId == existCla.TenancyId &&
			cla.AuthorityId == existCla.AuthorityId &&
			cla.LoginType == existCla.LoginType {
			return token, nil
		}
	}
	return "", nil
}

// getMultiClaimses
func (ra *RedisAuth) getMultiClaimses(tokens []string) (map[string]*MultiClaims, error) {
	clas := make(map[string]*MultiClaims, ra.getUserTokenMaxCount())
	for _, token := range tokens {
		cla, err := ra.GetMultiClaims(token)
		if err != nil {
			continue
		}
		clas[token] = cla
	}

	return clas, nil
}

// GetMultiClaims
func (ra *RedisAuth) GetMultiClaims(token string) (*MultiClaims, error) {
	cla := new(MultiClaims)
	if err := ra.Client.HGetAll(context.Background(), GtSessionTokenPrefix+token).Scan(cla); err != nil {
		return nil, fmt.Errorf("get custom claims redis hgetall %w", err)
	}

	if cla == nil || cla.Id == "" {
		return nil, ErrEmptyToken
	}

	return cla, nil
}

// isUserTokenOver
func (ra *RedisAuth) isUserTokenOver(authorityType int, userId string) (bool, error) {
	max, err := ra.getUserTokenCount(authorityType, userId)
	if err != nil {
		return true, err
	}
	return max >= ra.getUserTokenMaxCount(), nil
}

// getUserTokens
func (ra *RedisAuth) getUserTokens(authorityType int, userId string) ([]string, error) {
	userTokens, err := ra.Client.SMembers(context.Background(), getUserPrefixKey(authorityType, userId)).Result()
	if err != nil {
		return nil, fmt.Errorf("get user token count menbers  %w", err)
	}
	return userTokens, nil
}

// getUserTokenCount
func (ra *RedisAuth) getUserTokenCount(authorityType int, userId string) (int64, error) {
	var count int64
	userTokens, err := ra.getUserTokens(authorityType, userId)
	if err != nil {
		return count, fmt.Errorf("get user token count menbers  %w", err)
	}
	userPrefixKey := getUserPrefixKey(authorityType, userId)
	for _, token := range userTokens {
		if ra.checkUserTokenCount(token, userPrefixKey) == 1 {
			count++
		}
	}
	return count, nil
}

// checkUserTokenCount
func (ra *RedisAuth) checkUserTokenCount(token, userPrefixKey string) int64 {
	mun, err := ra.Client.Exists(context.Background(), GtSessionTokenPrefix+token).Result()
	if err != nil || mun == 0 {
		ra.Client.SRem(context.Background(), userPrefixKey, token)
	}
	return mun
}

// getUserTokenMaxCount
func (ra *RedisAuth) getUserTokenMaxCount() int64 {
	count, err := ra.Client.Get(context.Background(), GtSessionUserMaxTokenPrefix).Int64()
	if err != nil {
		return GtSessionUserMaxTokenDefault
	}
	return count
}

// SetUserTokenMaxCount
func (ra *RedisAuth) SetUserTokenMaxCount(tokenMaxCount int64) error {
	err := ra.Client.Set(context.Background(), GtSessionUserMaxTokenPrefix, tokenMaxCount, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

// syncUserTokenCache
func (ra *RedisAuth) syncUserTokenCache(token string) error {
	cla, err := ra.GetMultiClaims(token)
	if err != nil {
		return fmt.Errorf("sysnc user token cache %w", err)
	}
	userPrefixKey := getUserPrefixKey(cla.AuthorityType, cla.Id)
	if _, err := ra.Client.SAdd(context.Background(), userPrefixKey, token).Result(); err != nil {
		return fmt.Errorf("sync user token cache redis sadd %w", err)
	}

	bindUserPrefixKey := GtSessionBindUserPrefix + token
	_, err = ra.Client.Set(context.Background(), bindUserPrefixKey, userPrefixKey, getTokenExpire(cla.LoginType)).Result()
	if err != nil {
		return fmt.Errorf("sync user token cache %w", err)
	}
	return nil
}

// UpdateUserTokenCacheExpire
func (ra *RedisAuth) UpdateUserTokenCacheExpire(token string) error {
	rcc, err := ra.GetMultiClaims(token)
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
	if _, err := ra.Client.Expire(context.Background(), key, getTokenExpire(loginType)).Result(); err != nil {
		return fmt.Errorf("update user token cache expire redis expire %w", err)
	}
	return nil
}

// DelUserTokenCache
func (ra *RedisAuth) DelUserTokenCache(token string) error {
	cla, err := ra.GetMultiClaims(token)
	if err != nil {
		return err
	}
	if cla == nil {
		return errors.New("del user token, reids cache is nil")
	}

	err = ra.delUserTokenPrefixToken(cla.AuthorityType, cla.Id, token)
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

// delUserTokenPrefixToken
func (ra *RedisAuth) delUserTokenPrefixToken(authorityType int, id, token string) error {
	_, err := ra.Client.SRem(context.Background(), getUserPrefixKey(authorityType, id), token).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis srem %w", err)
	}
	return nil
}

// delTokenCache
func (ra *RedisAuth) delTokenCache(token string) error {
	sKey2 := GtSessionBindUserPrefix + token
	_, err := ra.Client.Del(context.Background(), sKey2).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis del2  %w", err)
	}

	sKey3 := GtSessionTokenPrefix + token
	_, err = ra.Client.Del(context.Background(), sKey3).Result()
	if err != nil {
		return fmt.Errorf("del user token cache redis del3  %w", err)
	}

	return nil
}

// CleanUserTokenCache
func (ra *RedisAuth) CleanUserTokenCache(authorityType int, userId string) error {
	allTokens, err := ra.getUserTokens(authorityType, userId)
	if err != nil {
		return fmt.Errorf("clean user token cache redis smembers  %w", err)
	}
	_, err = ra.Client.Del(context.Background(), getUserPrefixKey(authorityType, userId)).Result()
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

// IsRole
func (ra *RedisAuth) IsRole(token string, authorityType int) (bool, error) {
	rcc, err := ra.GetMultiClaims(token)
	if err != nil {
		return false, fmt.Errorf("get User's infomation return error: %w", err)
	}
	return rcc.AuthorityType == authorityType, nil
}

// Close
func (ra *RedisAuth) Close() {
	ra.Client.Close()
}
