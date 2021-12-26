package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/kataras/iris/v12"
	"github.com/snowlyg/multi"
	multi_iris "github.com/snowlyg/multi/iris"
)

// init 初始化认证驱动
// 驱动类型： 可选 redis ,local
func init() {
	options := &redis.UniversalOptions{
		Addrs:       []string{"127.0.0.1:6379"},
		Password:    "",
		PoolSize:    10,
		IdleTimeout: 300 * time.Second,
		// Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 	conn, err := net.Dial(network, addr)
		// 	if err == nil {
		// 		go func() {
		// 			time.Sleep(5 * time.Second)
		// 			conn.Close()
		// 		}()
		// 	}
		// 	return conn, err
		// },
	}

	err := multi.InitDriver(&multi.Config{
		DriverType:      "redis",
		UniversalClient: redis.NewUniversalClient(options)})
	if err != nil {
		panic(fmt.Sprintf("auth is not init get err %v\n", err))
	}
}

func auth() iris.Handler {
	verifier := multi_iris.NewVerifier()
	verifier.Extractors = []multi_iris.TokenExtractor{multi_iris.FromHeader} // extract token only from Authorization: Bearer $token
	return verifier.Verify()
}

func main() {
	app := iris.New()

	app.Get("/", generateToken())

	protectedAPI := app.Party("/protected")
	// Register the verify middleware to allow access only to authorized clients.
	protectedAPI.Use(auth())
	// ^ or UseRouter(verifyMiddleware) to disallow unauthorized http error handlers too.

	protectedAPI.Get("/", protected)
	// Invalidate the token through server-side, even if it's not expired yet.
	protectedAPI.Get("/logout", logout)

	// http://localhost:8080
	// http://localhost:8080/protected (or Authorization: Bearer $token)
	// http://localhost:8080/protected/logout
	// http://localhost:8080/protected (401)
	app.Listen(":8080")
}

func generateToken() iris.Handler {
	return func(ctx iris.Context) {
		claims := &multi.MultiClaims{
			Id:            "1",
			Username:      "your name",
			AuthorityId:   "your authority id",
			TenancyId:     1,
			TenancyName:   "your tenancy name",
			AuthorityType: multi.AdminAuthority,
			LoginType:     multi.LoginTypeWeb,
			AuthType:      multi.AuthPwd,
			CreationDate:  time.Now().Local().Unix(),
			ExpiresAt:     time.Now().Local().Add(multi.RedisSessionTimeoutWeb).Unix(),
		}

		token, _, err := multi.AuthDriver.GenerateToken(claims)
		if err != nil {
			ctx.StopWithStatus(http.StatusInternalServerError)
			return
		}

		ctx.WriteString(token)
	}
}

func protected(ctx iris.Context) {
	claims := multi_iris.Get(ctx)
	ctx.Writef("claims=%+v\n", claims)
}

func logout(ctx iris.Context) {
	token := multi_iris.GetVerifiedToken(ctx)
	if token == nil {
		ctx.WriteString("授权凭证为空")
		return
	}
	err := multi.AuthDriver.DelUserTokenCache(string(token))
	if err != nil {
		ctx.WriteString(err.Error())
		return
	}
	ctx.Writef("token invalidated, a new token is required to access the protected API")
}
