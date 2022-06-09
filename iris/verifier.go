package iris

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/kataras/iris/v12/context"
	"github.com/snowlyg/multi"
)

const (
	claimsContextKey        = "iris.multi.claims"
	verifiedTokenContextKey = "iris.multi.token"
)

// Get returns the claims decoded by a verifier.
func Get(ctx *context.Context) *multi.MultiClaims {
	if v := ctx.Values().Get(claimsContextKey).(*multi.MultiClaims); v != nil {
		return v
	}
	return nil
}

// GetAuthorityType 角色类型
func GetAuthorityType(ctx *context.Context) int {
	if v := Get(ctx); v != nil {
		return v.AuthorityType
	}
	return 0
}

// GetAuthorityId 角色id
func GetAuthorityId(ctx *context.Context) []string {
	if v := Get(ctx); v != nil {
		return strings.Split(v.AuthorityId, multi.AuthorityTypeSplit)
	}
	return nil
}

// GetUserId 用户id
func GetUserId(ctx *context.Context) uint {
	v := Get(ctx)
	if v == nil {
		return 0
	}
	id, err := strconv.Atoi(v.Id)
	if err != nil {
		return 0
	}
	return uint(id)
}

// GetUsername 用户名
func GetUsername(ctx *context.Context) string {
	if v := Get(ctx); v != nil {
		return v.Username
	}
	return ""
}

// GetTenancyId 商户id
func GetTenancyId(ctx *context.Context) uint {
	if v := Get(ctx); v != nil {
		return v.TenancyId
	}
	return 0
}

// GetTenancyName 商户名称
func GetTenancyName(ctx *context.Context) string {
	if v := Get(ctx); v != nil {
		return v.TenancyName
	}
	return ""
}

// GetCreationDate 登录时间
func GetCreationDate(ctx *context.Context) int64 {
	if v := Get(ctx); v != nil {
		return v.CreationDate
	}
	return 0
}

// GetExpiresIn 有效期
func GetExpiresIn(ctx *context.Context) int64 {
	if v := Get(ctx); v != nil {
		return v.ExpiresAt
	}
	return 0
}

func GetVerifiedToken(ctx *context.Context) []byte {
	v := ctx.Values().Get(verifiedTokenContextKey)
	if v == nil {
		return nil
	}
	if tok, ok := v.([]byte); ok {
		return tok
	}
	return nil
}

func IsRole(ctx *context.Context, authorityType int) bool {
	v := GetVerifiedToken(ctx)
	if v == nil {
		return false
	}
	b, err := multi.AuthDriver.IsRole(string(v), authorityType)
	if err != nil {
		return false
	}
	return b
}

func IsAdmin(ctx *context.Context) bool {
	return IsRole(ctx, multi.AdminAuthority)
}

type Verifier struct {
	Extractors   []TokenExtractor
	Validators   []multi.TokenValidator
	ErrorHandler func(ctx *context.Context, err error)
}

func NewVerifier(validators ...multi.TokenValidator) *Verifier {
	return &Verifier{
		Extractors: []TokenExtractor{FromHeader, FromQuery},
		ErrorHandler: func(ctx *context.Context, err error) {
			ctx.StopWithError(http.StatusUnauthorized, err)
		},
		Validators: validators,
	}
}

// Invalidate
func (v *Verifier) invalidate(ctx *context.Context) {
	if verifiedToken := GetVerifiedToken(ctx); verifiedToken != nil {
		ctx.Values().Remove(claimsContextKey)
		ctx.Values().Remove(verifiedTokenContextKey)
		ctx.SetUser(nil)
		ctx.SetLogoutFunc(nil)
	}
}

// RequestToken extracts the token from the
func (v *Verifier) RequestToken(ctx *context.Context) (token string) {
	for _, extract := range v.Extractors {
		if token = extract(ctx); token != "" {
			break // ok we found it.
		}
	}

	return
}

func (v *Verifier) VerifyToken(token []byte, validators ...multi.TokenValidator) ([]byte, *multi.MultiClaims, error) {
	if len(token) == 0 {
		return nil, nil, multi.ErrEmptyToken
	}
	var err error
	for _, validator := range validators {
		// A token validator can skip the builtin validation and return a nil error,
		// in that case the previous error is skipped.
		if err = validator.ValidateToken(token, err); err != nil {
			break
		}
	}

	if err != nil {
		// Exit on parsing standard claims error(when Plain is missing) or standard claims validation error or custom validators.
		return nil, nil, err
	}

	rcc, err := multi.AuthDriver.GetMultiClaims(string(token))
	if err != nil {
		return nil, nil, err
	}

	err = rcc.Valid()
	if err != nil {
		return nil, nil, err
	}

	return token, rcc, nil
}

func (v *Verifier) Verify(validators ...multi.TokenValidator) context.Handler {
	return func(ctx *context.Context) {
		token := []byte(v.RequestToken(ctx))
		verifiedToken, rcc, err := v.VerifyToken(token, validators...)
		if err != nil {
			v.invalidate(ctx)
			v.ErrorHandler(ctx, err)
			return
		}

		ctx.Values().Set(claimsContextKey, rcc)
		ctx.Values().Set(verifiedTokenContextKey, verifiedToken)
		ctx.Next()
	}
}
