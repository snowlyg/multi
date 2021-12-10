package iris

import "github.com/snowlyg/multi"

// InitDriver 认证驱动
// redis 需要设置redis
// local 使用本地内存
func InitDriver(c *multi.Config) error {
	if c.TokenMaxCount == 0 {
		c.TokenMaxCount = 10
	}
	switch c.DriverType {
	case "redis":
		driver, err := NewRedisAuth(c.UniversalClient)
		if err != nil {
			return err
		}
		multi.AuthDriver = driver
	case "local":
		multi.AuthDriver = NewLocalAuth()
	default:
		multi.AuthDriver = NewLocalAuth()
	}
	err := multi.AuthDriver.SetUserTokenMaxCount(c.TokenMaxCount)
	if err != nil {
		return err
	}
	return nil
}
