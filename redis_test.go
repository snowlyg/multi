package multi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
)

var (
	wg      sync.WaitGroup
	options = &redis.UniversalOptions{
		DB:          1,
		Addrs:       []string{"127.0.0.1:6379"},
		Password:    "Chindeo",
		PoolSize:    10,
		IdleTimeout: 300 * time.Second,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := net.Dial(network, addr)
			if err == nil {
				go func() {
					time.Sleep(5 * time.Second)
					conn.Close()
				}()
			}
			return conn, err
		},
	}

	redisAuth, _ = NewRedisAuth(redis.NewUniversalClient(options))
	rToken       = "TVRReU1EVTFOek13TmpFd09UWXlPRFF4TmcuTWpBeU1TMHdOeTB5T1ZRd09Ub3pNRG95T1Nzd09Eb3dNQQ.MTQyMDU1NzMwNjEwOTYyODrtrt"
	redisClaims  = &CustomClaims{
		ID:            "121321",
		Username:      "username",
		TenancyId:     1,
		TenancyName:   "username",
		AuthorityId:   "999",
		AuthorityType: AdminAuthority,
		LoginType:     LoginTypeWeb,
		AuthType:      AuthPwd,
		CreationDate:  10000,
		ExpiresIn:     10000,
	}
	ruserKey = getUserPrefixKey(redisClaims.AuthorityType, redisClaims.ID)
)

func TestRedisGenerateToken(t *testing.T) {
	defer redisAuth.CleanUserTokenCache(redisClaims.AuthorityType, redisClaims.ID)
	t.Run("test generate token", func(t *testing.T) {
		token, expiresIn, err := redisAuth.GenerateToken(redisClaims)
		if err != nil {
			t.Fatalf("generate token %v", err)
		}
		if token == "" {
			t.Error("generate token is empty")
		}

		t.Logf("token:%s\n", token)

		if expiresIn != redisClaims.ExpiresIn {
			t.Errorf("generate token expires want %v but get %v", redisClaims.ExpiresIn, expiresIn)
		}
		cc, err := redisAuth.GetCustomClaims(token)
		if err != nil {
			t.Fatalf("get custom claims  %v", err)
		}

		if cc.ID != redisClaims.ID {
			t.Errorf("get custom id want %v but get %v", redisClaims.ID, cc.ID)
		}
		if cc.Username != redisClaims.Username {
			t.Errorf("get custom username want %v but get %v", redisClaims.Username, cc.Username)
		}
		if cc.TenancyName != redisClaims.TenancyName {
			t.Errorf("get custom tenancy_id want %v but get %v", redisClaims.TenancyName, cc.TenancyName)
		}
		if cc.TenancyId != redisClaims.TenancyId {
			t.Errorf("get custom tenancy_id want %v but get %v", redisClaims.TenancyId, cc.TenancyId)
		}
		if cc.AuthorityId != redisClaims.AuthorityId {
			t.Errorf("get custom authority_id want %v but get %v", redisClaims.AuthorityId, cc.AuthorityId)
		}
		if cc.AuthorityType != redisClaims.AuthorityType {
			t.Errorf("get custom authority_type want %v but get %v", redisClaims.AuthorityType, cc.AuthorityType)
		}
		if cc.LoginType != redisClaims.LoginType {
			t.Errorf("get custom login_type want %v but get %v", redisClaims.LoginType, cc.LoginType)
		}
		if cc.AuthType != redisClaims.AuthType {
			t.Errorf("get custom auth_type want %v but get %v", redisClaims.AuthType, cc.AuthType)
		}
		if cc.CreationDate != redisClaims.CreationDate {
			t.Errorf("get custom creation_data want %v but get %v", redisClaims.CreationDate, cc.CreationDate)
		}
		if cc.ExpiresIn != redisClaims.ExpiresIn {
			t.Errorf("get custom expires_in want %v but get %v", redisClaims.ExpiresIn, cc.ExpiresIn)
		}

		if uTokens, err := redisAuth.Client.SMembers(context.Background(), ruserKey).Result(); err != nil {
			t.Fatalf("user prefix value get %s", err)
		} else {
			if len(uTokens) == 0 || uTokens[0] != token {
				t.Errorf("user prefix value want %v but get %v", ruserKey, uTokens)
			}
		}
		bindKey := GtSessionBindUserPrefix + token
		key, err := redisAuth.Client.Get(context.Background(), bindKey).Result()
		if err != nil {
			t.Fatal(err)
		}
		if key != ruserKey {
			t.Errorf("bind user prefix value want %v but get %v", ruserKey, key)
		}

	})
}

func TestRedisToCache(t *testing.T) {
	defer redisAuth.Client.Del(context.Background(), GtSessionTokenPrefix+rToken)
	t.Run("test generate token", func(t *testing.T) {
		err := redisAuth.toCache(rToken, redisClaims)
		if err != nil {
			t.Fatalf("generate token %v", err)
		}
		cc, err := redisAuth.GetCustomClaims(rToken)
		if err != nil {
			t.Fatalf("get custom claims  %v", err)
		}

		if cc.ID != redisClaims.ID {
			t.Errorf("get custom id want %v but get %v", redisClaims.ID, cc.ID)
		}
		if cc.Username != redisClaims.Username {
			t.Errorf("get custom username want %v but get %v", redisClaims.Username, cc.Username)
		}
		if cc.TenancyName != redisClaims.TenancyName {
			t.Errorf("get custom tenancy_id want %v but get %v", redisClaims.TenancyName, cc.TenancyName)
		}
		if cc.TenancyId != redisClaims.TenancyId {
			t.Errorf("get custom tenancy_id want %v but get %v", redisClaims.TenancyId, cc.TenancyId)
		}
		if cc.AuthorityId != redisClaims.AuthorityId {
			t.Errorf("get custom authority_id want %v but get %v", redisClaims.AuthorityId, cc.AuthorityId)
		}
		if cc.AuthorityType != redisClaims.AuthorityType {
			t.Errorf("get custom authority_type want %v but get %v", redisClaims.AuthorityType, cc.AuthorityType)
		}
		if cc.LoginType != redisClaims.LoginType {
			t.Errorf("get custom login_type want %v but get %v", redisClaims.LoginType, cc.LoginType)
		}
		if cc.AuthType != redisClaims.AuthType {
			t.Errorf("get custom auth_type want %v but get %v", redisClaims.AuthType, cc.AuthType)
		}
		if cc.CreationDate != redisClaims.CreationDate {
			t.Errorf("get custom creation_data want %v but get %v", redisClaims.CreationDate, cc.CreationDate)
		}
		if cc.ExpiresIn != redisClaims.ExpiresIn {
			t.Errorf("get custom expires_in want %v but get %v", redisClaims.ExpiresIn, cc.ExpiresIn)
		}
	})
}

func TestRedisDelUserTokenCache(t *testing.T) {
	cc := &CustomClaims{
		ID:            "221",
		Username:      "username",
		TenancyId:     1,
		TenancyName:   "username",
		AuthorityId:   "999",
		AuthorityType: AdminAuthority,
		LoginType:     LoginTypeWeb,
		AuthType:      AuthPwd,
		CreationDate:  10000,
		ExpiresIn:     10000,
	}
	defer redisAuth.CleanUserTokenCache(cc.AuthorityType, cc.ID)
	t.Run("test del user token token", func(t *testing.T) {
		token, _, _ := redisAuth.GenerateToken(cc)
		if token == "" {
			t.Error("generate token is empty")
		}

		err := redisAuth.DelUserTokenCache(token)
		if err != nil {
			t.Fatalf("del user token cache  %v", err)
		}
		_, err = redisAuth.GetCustomClaims(token)
		if !errors.Is(err, ErrEmptyToken) {
			t.Fatalf("get custom claims err want '%v' but get  '%v'", ErrEmptyToken, err)
		}

		if uTokens, err := redisAuth.Client.SMembers(context.Background(), GtSessionUserPrefix+cc.ID).Result(); err != nil {
			t.Fatalf("user prefix value wantget %v", err)
		} else if len(uTokens) != 0 {
			t.Errorf("user prefix value want empty but get %+v", uTokens)
		}
		bindKey := GtSessionBindUserPrefix + token
		key, _ := redisAuth.Client.Get(context.Background(), bindKey).Result()
		if key != "" {
			t.Errorf("bind user prefix value want empty but get %v", key)
		}
	})
}

func TestRedisIsUserTokenOver(t *testing.T) {
	cc := &CustomClaims{
		ID:            "3232",
		Username:      "username",
		TenancyId:     1,
		TenancyName:   "username",
		AuthorityId:   "999",
		AuthorityType: AdminAuthority,
		LoginType:     LoginTypeWeb,
		AuthType:      AuthPwd,
		CreationDate:  10000,
		ExpiresIn:     10000,
	}
	defer redisAuth.CleanUserTokenCache(cc.AuthorityType, cc.ID)
	if err := redisAuth.SetUserTokenMaxCount(10); err != nil {
		t.Fatalf("set user token max count %v", err)
	}
	for i := 0; i < 4; i++ {
		cc.LoginType = i
		wg.Add(1)
		go func(i int) {
			redisAuth.GenerateToken(cc)
			wg.Done()
		}(i)
		wg.Wait()
	}
	t.Run("test redis is user token over", func(t *testing.T) {
		isOver, err := redisAuth.isUserTokenOver(cc.AuthorityType, cc.ID)
		if err != nil {
			t.Fatalf("is user token over get %v", err)
		}
		if isOver {
			t.Error("user token want not over  but get over")
		}
		count, err := redisAuth.getUserTokenCount(cc.AuthorityType, cc.ID)
		if err != nil {
			t.Fatalf("user token count get %v", err)
		}
		if count != 4 {
			t.Errorf("user token count want %v but get %v", 4, count)
		}
	})
}

func TestRedisSetUserTokenMaxCount(t *testing.T) {
	defer redisAuth.CleanUserTokenCache(redisClaims.AuthorityType, redisClaims.ID)
	if err := redisAuth.SetUserTokenMaxCount(10); err != nil {
		t.Fatalf("set user token max count %v", err)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		redisClaims.LoginType = i
		go func(i int) {
			redisAuth.GenerateToken(redisClaims)
			wg.Done()
		}(i)
		wg.Wait()
	}
	t.Run("test redis set user token max count", func(t *testing.T) {
		if err := redisAuth.SetUserTokenMaxCount(3); err != nil {
			t.Fatalf("set user token max count %v", err)
		}
		count := redisAuth.getUserTokenMaxCount()
		if count != 3 {
			t.Errorf("user token max count want %v  but get %v", 3, count)
		}
		isOver, err := redisAuth.isUserTokenOver(redisClaims.AuthorityType, redisClaims.ID)
		if err != nil {
			t.Fatalf("is user token over get %v", err)
		}
		if !isOver {
			t.Error("user token want over but get not over")
		}
	})
}
func TestRedisCleanUserTokenCache(t *testing.T) {
	defer redisAuth.CleanUserTokenCache(redisClaims.AuthorityType, redisClaims.ID)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		redisClaims.LoginType = i
		go func(i int) {
			redisAuth.GenerateToken(redisClaims)
			wg.Done()
		}(i)
		wg.Wait()
	}
	t.Run("test del user token", func(t *testing.T) {
		if err := redisAuth.CleanUserTokenCache(redisClaims.AuthorityType, redisClaims.ID); err != nil {
			t.Fatalf("clear user token cache %v", err)
		}
		count, err := redisAuth.getUserTokenCount(redisClaims.AuthorityType, redisClaims.ID)
		if err != nil {
			t.Fatalf("user token count get %v", err)
		}
		if count != 0 {
			t.Error("user token count want 0 but get not 0")
		}
	})
}

func TestRedisGetCustomClaims(t *testing.T) {
	defer redisAuth.CleanUserTokenCache(redisClaims.AuthorityType, redisClaims.ID)
	var token string
	redisClaims.LoginType = 3
	token, _, err := redisAuth.GenerateToken(redisClaims)
	if err != nil {
		t.Fatalf("get custom claims  %v", err)
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		redisClaims.LoginType = i
		go func(i int) {
			redisAuth.GenerateToken(redisClaims)
			wg.Done()
		}(i)
		wg.Wait()
	}
	t.Run("test get custom claims", func(t *testing.T) {
		for i := 0; i < 4; i++ {
			go func() {
				cc, err := redisAuth.GetCustomClaims(token)
				if err != nil {
					t.Errorf("get custom claims  %v", err)
				}
				fmt.Printf("test check token hash get %+v\n", cc)
			}()
		}
		time.Sleep(3 * time.Second)
	})
}

func TestRedisGetUserTokens(t *testing.T) {
	cc := &CustomClaims{
		ID:            "121321",
		Username:      "username",
		TenancyId:     1,
		TenancyName:   "username",
		AuthorityId:   "999",
		AuthorityType: AdminAuthority,
		LoginType:     LoginTypeDevice,
		AuthType:      AuthPwd,
		CreationDate:  10000,
		ExpiresIn:     10000,
	}
	defer redisAuth.CleanUserTokenCache(cc.AuthorityType, cc.ID)
	defer redisAuth.CleanUserTokenCache(redisClaims.AuthorityType, redisClaims.ID)
	token, _, err := redisAuth.GenerateToken(redisClaims)
	if err != nil {
		t.Fatalf("get user tokens by claims generate token %v \n", err)
	}

	if token == "" {
		t.Fatal("get user tokens by claims generate token is empty \n")
	}

	token3232, _, err := redisAuth.GenerateToken(cc)
	if err != nil {
		t.Fatalf("get user tokens by claims generate token %v \n", err)
	}

	if token3232 == "" {
		t.Fatal("get user tokens by claims generate token is empty \n")
	}

	t.Run("test get user tokens by claims", func(t *testing.T) {
		tokens, err := redisAuth.getUserTokens(redisClaims.AuthorityType, redisClaims.ID)
		if err != nil {
			t.Fatalf("get user tokens by claims %v", err)
		}

		if len(tokens) != 2 {
			t.Fatalf("get user tokens by claims want len 2 but get %d", len(tokens))
		}
	})
}

func TestRedisGetTokenByClaims(t *testing.T) {
	cc := &CustomClaims{
		ID:            "3232",
		Username:      "username",
		TenancyId:     1,
		TenancyName:   "username",
		AuthorityId:   "999",
		AuthorityType: AdminAuthority,
		LoginType:     LoginTypeWeb,
		AuthType:      AuthPwd,
		CreationDate:  10000,
		ExpiresIn:     10000,
	}
	defer redisAuth.CleanUserTokenCache(cc.AuthorityType, cc.ID)
	defer redisAuth.CleanUserTokenCache(redisClaims.AuthorityType, redisClaims.ID)
	token, _, err := redisAuth.GenerateToken(redisClaims)
	if err != nil {
		t.Fatalf("get token by claims generate token %v \n", err)
	}

	if token == "" {
		t.Fatal("get token by claims generate token is empty \n")
	}

	token3232, _, err := redisAuth.GenerateToken(cc)
	if err != nil {
		t.Fatalf("get token by claims generate token %v \n", err)
	}

	if token3232 == "" {
		t.Fatal("get token by claims generate token is empty \n")
	}

	t.Run("test get token by claims", func(t *testing.T) {
		userToken, err := redisAuth.GetTokenByClaims(redisClaims)
		if err != nil {
			t.Fatalf("get token by claims %v", err)
		}

		if token != userToken {
			t.Errorf("get token by claims token want %s but get %s", token, userToken)
		}
		if token == token3232 {
			t.Errorf("get token by claims token not want %s but get %s", token3232, token)
		}
	})

}
func TestRedisGetCustomClaimses(t *testing.T) {
	defer redisAuth.CleanUserTokenCache(redisClaims.AuthorityType, redisClaims.ID)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		redisClaims.LoginType = i
		go func(i int) {
			redisAuth.GenerateToken(redisClaims)
			wg.Done()
		}(i)
		wg.Wait()
	}
	userTokens, err := redisAuth.getUserTokens(redisClaims.AuthorityType, redisClaims.ID)
	if err != nil {
		t.Fatal("get custom claimses generate token is empty \n")
	}
	t.Run("test get custom claimses", func(t *testing.T) {
		clas, err := redisAuth.getCustomClaimses(userTokens)
		if err != nil {
			t.Fatalf("get custom claimses %v", err)
		}

		if len(userTokens) != 2 {
			t.Fatalf("get custom claimses want len 2 but get %d", len(userTokens))
		}
		if len(clas) != 2 {
			t.Fatalf("get custom claimses want len 2 but get %d", len(clas))
		}
	})

}
