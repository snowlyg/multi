package multi

import (
	"errors"
	"testing"
)

var (
	localAuth    = NewLocalAuth()
	tToken       = "TVRReU1EVTFOek13TmpFd09UWXlPRFF4TmcuTWpBeU1TMHdOeTB5T1ZRd09Ub3pNRG95T1Nzd09Eb3dNQQ.MTQyMDU1NzMwNjEwOTYyODQxNg"
	customClaims = &CustomClaims{
		ID:            "1",
		Username:      "username",
		TenancyId:     1,
		TenancyName:   "username",
		AuthorityId:   "999",
		AuthorityType: AdminAuthority,
		LoginType:     LoginTypeWeb,
		AuthType:      LoginTypeWeb,
		CreationDate:  10000,
		ExpiresIn:     10000,
	}
	userKey = GtSessionUserPrefix + customClaims.ID
)

func TestNewLocalAuth(t *testing.T) {
	t.Run("test new local auth", func(t *testing.T) {
		if NewLocalAuth() == nil {
			t.Error("new local auth get nil")
		}
	})
}

func TestGenerateToken(t *testing.T) {
	t.Run("test generate token", func(t *testing.T) {
		token, expiresIn, err := localAuth.GenerateToken(customClaims)
		if err != nil {
			t.Fatalf("generate token %v", err)
		}
		if token == "" {
			t.Error("generate token is empty")
		}

		if expiresIn != customClaims.ExpiresIn {
			t.Errorf("generate token expires want %v but get %v", customClaims.ExpiresIn, expiresIn)
		}
		cc, err := localAuth.GetCustomClaims(token)
		if err != nil {
			t.Fatalf("get custom claims  %v", err)
		}

		if cc.ID != customClaims.ID {
			t.Errorf("get custom id want %v but get %v", customClaims.ID, cc.ID)
		}
		if cc.Username != customClaims.Username {
			t.Errorf("get custom username want %v but get %v", customClaims.Username, cc.Username)
		}
		if cc.TenancyName != customClaims.TenancyName {
			t.Errorf("get custom tenancy_id want %v but get %v", customClaims.TenancyName, cc.TenancyName)
		}
		if cc.TenancyId != customClaims.TenancyId {
			t.Errorf("get custom tenancy_id want %v but get %v", customClaims.TenancyId, cc.TenancyId)
		}
		if cc.AuthorityId != customClaims.AuthorityId {
			t.Errorf("get custom authority_id want %v but get %v", customClaims.AuthorityId, cc.AuthorityId)
		}
		if cc.AuthorityType != customClaims.AuthorityType {
			t.Errorf("get custom authority_type want %v but get %v", customClaims.AuthorityType, cc.AuthorityType)
		}
		if cc.LoginType != customClaims.LoginType {
			t.Errorf("get custom login_type want %v but get %v", customClaims.LoginType, cc.LoginType)
		}
		if cc.AuthType != customClaims.AuthType {
			t.Errorf("get custom auth_type want %v but get %v", customClaims.AuthType, cc.AuthType)
		}
		if cc.CreationDate != customClaims.CreationDate {
			t.Errorf("get custom creation_data want %v but get %v", customClaims.CreationDate, cc.CreationDate)
		}
		if cc.ExpiresIn != customClaims.ExpiresIn {
			t.Errorf("get custom expires_in want %v but get %v", customClaims.ExpiresIn, cc.ExpiresIn)
		}

		if uTokens, uFound := localAuth.Cache.Get(userKey); uFound {
			ts := uTokens.(tokens)
			if len(ts) == 0 || ts[0] != token {
				t.Errorf("user prefix value want %v but get %v", userKey, uTokens)
			}
		} else {
			t.Error("user prefix value is emptpy")
		}
		bindKey := GtSessionBindUserPrefix + token
		if uTokens, uFound := localAuth.Cache.Get(bindKey); uFound {
			if uTokens != userKey {
				t.Errorf("bind user prefix value want %v but get %v", userKey, uTokens)
			}
		} else {
			t.Error("bind user prefix value is emptpy")
		}
	})
}

func TestToCache(t *testing.T) {
	t.Run("test to cache", func(t *testing.T) {
		err := localAuth.toCache(tToken, customClaims)
		if err != nil {
			t.Fatalf("generate token %v", err)
		}
		cc, err := localAuth.GetCustomClaims(tToken)
		if err != nil {
			t.Fatalf("get custom claims  %v", err)
		}

		if cc.ID != customClaims.ID {
			t.Errorf("get custom id want %v but get %v", customClaims.ID, cc.ID)
		}
		if cc.Username != customClaims.Username {
			t.Errorf("get custom username want %v but get %v", customClaims.Username, cc.Username)
		}
		if cc.TenancyName != customClaims.TenancyName {
			t.Errorf("get custom tenancy_id want %v but get %v", customClaims.TenancyName, cc.TenancyName)
		}
		if cc.TenancyId != customClaims.TenancyId {
			t.Errorf("get custom tenancy_id want %v but get %v", customClaims.TenancyId, cc.TenancyId)
		}
		if cc.AuthorityId != customClaims.AuthorityId {
			t.Errorf("get custom authority_id want %v but get %v", customClaims.AuthorityId, cc.AuthorityId)
		}
		if cc.AuthorityType != customClaims.AuthorityType {
			t.Errorf("get custom authority_type want %v but get %v", customClaims.AuthorityType, cc.AuthorityType)
		}
		if cc.LoginType != customClaims.LoginType {
			t.Errorf("get custom login_type want %v but get %v", customClaims.LoginType, cc.LoginType)
		}
		if cc.AuthType != customClaims.AuthType {
			t.Errorf("get custom auth_type want %v but get %v", customClaims.AuthType, cc.AuthType)
		}
		if cc.CreationDate != customClaims.CreationDate {
			t.Errorf("get custom creation_data want %v but get %v", customClaims.CreationDate, cc.CreationDate)
		}
		if cc.ExpiresIn != customClaims.ExpiresIn {
			t.Errorf("get custom expires_in want %v but get %v", customClaims.ExpiresIn, cc.ExpiresIn)
		}
	})
}

func TestDelUserTokenCache(t *testing.T) {
	cc := &CustomClaims{
		ID:            "2",
		Username:      "username",
		TenancyId:     1,
		TenancyName:   "username",
		AuthorityId:   "999",
		AuthorityType: AdminAuthority,
		LoginType:     LoginTypeWeb,
		AuthType:      LoginTypeWeb,
		CreationDate:  10000,
		ExpiresIn:     10000,
	}
	t.Run("test del user token", func(t *testing.T) {
		token, _, _ := localAuth.GenerateToken(cc)
		if token == "" {
			t.Error("generate token is empty")
		}

		err := localAuth.DelUserTokenCache(token)
		if err != nil {
			t.Fatalf("del user token cache  %v", err)
		}
		_, err = localAuth.GetCustomClaims(token)
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("get custom claims err want %v but get  %v", ErrTokenInvalid, err)
		}

		if uTokens, uFound := localAuth.Cache.Get(GtSessionUserPrefix + cc.ID); uFound && uTokens != nil {
			t.Errorf("user prefix value want empty but get %v", uTokens)
		}
		bindKey := GtSessionBindUserPrefix + token
		if key, uFound := localAuth.Cache.Get(bindKey); uFound {
			t.Errorf("bind user prefix value want empty but get %v", key)
		}
	})
}

func TestIsUserTokenOver(t *testing.T) {
	cc := &CustomClaims{
		ID:            "3",
		Username:      "username",
		TenancyId:     1,
		TenancyName:   "username",
		AuthorityId:   "999",
		AuthorityType: AdminAuthority,
		LoginType:     LoginTypeWeb,
		AuthType:      LoginTypeWeb,
		CreationDate:  10000,
		ExpiresIn:     10000,
	}
	for i := 0; i < 6; i++ {
		localAuth.GenerateToken(cc)
	}
	t.Run("test is user token over", func(t *testing.T) {
		if localAuth.isUserTokenOver(cc.ID) {
			t.Error("user token want not over  but get over")
		}
		count := localAuth.getUserTokenCount(cc.ID)
		if count != 6 {
			t.Errorf("user token count want %v  but get %v", 6, count)
		}
	})
}

func TestSetUserTokenMaxCount(t *testing.T) {
	for i := 0; i < 6; i++ {
		localAuth.GenerateToken(customClaims)
	}
	t.Run("testset user token max count", func(t *testing.T) {
		if err := localAuth.SetUserTokenMaxCount(5); err != nil {
			t.Fatalf("set user token max count %v", err)
		}
		count := localAuth.getUserTokenMaxCount()
		if count != 5 {
			t.Errorf("user token max count want %v  but get %v", 5, count)
		}
		if !localAuth.isUserTokenOver(customClaims.ID) {
			t.Error("user token want over but get not over")
		}
	})
}
func TestCleanUserTokenCache(t *testing.T) {
	for i := 0; i < 6; i++ {
		localAuth.GenerateToken(customClaims)
	}
	t.Run("test clean user token cache", func(t *testing.T) {
		if err := localAuth.CleanUserTokenCache(customClaims.ID); err != nil {
			t.Fatalf("clear user token cache %v", err)
		}
		if localAuth.getUserTokenCount(customClaims.ID) != 0 {
			t.Error("user token count want 0 but get not 0")
		}
	})
}