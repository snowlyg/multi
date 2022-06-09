package multi

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Run("Test claims new", func(t *testing.T) {
		cla := New(&Multi{
			Id:            uint(8457585),
			Username:      "username",
			TenancyId:     1,
			TenancyName:   "username",
			AuthorityIds:  []string{"999"},
			AuthorityType: AdminAuthority,
			LoginType:     LoginTypeWeb,
			AuthType:      LoginTypeWeb,
			ExpiresAt:     time.Now().Local().Add(RedisSessionTimeoutWeb).Unix(),
		})
		if cla == nil {
			t.Error("claims init return is nil")
		}
	})
}

func TestValid(t *testing.T) {
	t.Run("Test claims new", func(t *testing.T) {
		cla := New(&Multi{
			Id:            uint(8457585),
			Username:      "username",
			TenancyId:     1,
			TenancyName:   "username",
			AuthorityIds:  []string{"999"},
			AuthorityType: AdminAuthority,
			LoginType:     LoginTypeWeb,
			AuthType:      LoginTypeWeb,
			ExpiresAt:     time.Now().Local().Add(RedisSessionTimeoutWeb).Unix(),
		})
		if err := cla.Valid(); err != nil {
			t.Error(err)
		}
	})
}
