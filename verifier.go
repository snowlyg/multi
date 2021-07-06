package multi

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/bwmarrin/snowflake"
	"github.com/gin-gonic/gin"
)

const (
	claimsContextKey        = "iris.multi.claims"
	verifiedTokenContextKey = "iris.multi.token"
)

// Get returns the claims decoded by a verifier.
func Get(ctx *gin.Context) *CustomClaims {
	if v, b := ctx.Get(claimsContextKey); b {
		if tok, ok := v.(*CustomClaims); ok {
			return tok
		}
	}
	return nil
}

// GetAuthorityType 角色名
func GetAuthorityType(ctx *gin.Context) int {
	if v := Get(ctx); v != nil {
		return v.AuthorityType
	}
	return 0
}

// GetAuthorityId 角色id
func GetAuthorityId(ctx *gin.Context) string {
	if v := Get(ctx); v != nil {
		return v.AuthorityId
	}
	return ""
}

// GetUserId 用户id
func GetUserId(ctx *gin.Context) uint {
	if v := Get(ctx); v != nil {
		id, err := strconv.Atoi(v.ID)
		if err != nil {
			return 0
		}
		return uint(id)
	}
	return 0
}

// GetUsername 用户名
func GetUsername(ctx *gin.Context) string {
	if v := Get(ctx); v != nil {
		return v.Username
	}
	return ""
}

// GetTenancyId 商户id
func GetTenancyId(ctx *gin.Context) uint {
	if v := Get(ctx); v != nil {
		return v.TenancyId
	}
	return 0
}

// GetTenancyName 商户名称
func GetTenancyName(ctx *gin.Context) string {
	if v := Get(ctx); v != nil {
		return v.TenancyName
	}
	return ""
}

// GetCreationDate 登录时间
func GetCreationDate(ctx *gin.Context) int64 {
	if v := Get(ctx); v != nil {
		return v.CreationDate
	}
	return 0
}

// GetExpiresIn 有效期
func GetExpiresIn(ctx *gin.Context) int64 {
	if v := Get(ctx); v != nil {
		return v.ExpiresIn
	}
	return 0
}

func GetVerifiedToken(ctx *gin.Context) []byte {
	if v, b := ctx.Get(verifiedTokenContextKey); b {
		if tok, ok := v.([]byte); ok {
			return tok
		}
	}
	return nil
}

func IsTenancy(ctx *gin.Context) bool {
	if v := GetVerifiedToken(ctx); v != nil {
		b, err := AuthDriver.IsTenancy(string(v))
		if err != nil {
			return false
		}
		return b
	}
	return false
}

func IsGeneral(ctx *gin.Context) bool {
	if v := GetVerifiedToken(ctx); v != nil {
		b, err := AuthDriver.IsGeneral(string(v))
		if err != nil {
			return false
		}
		return b
	}
	return false
}

func IsAdmin(ctx *gin.Context) bool {
	if v := GetVerifiedToken(ctx); v != nil {
		b, err := AuthDriver.IsAdmin(string(v))
		if err != nil {
			return false
		}
		return b
	}
	return false
}

type Verifier struct {
	Extractors   []TokenExtractor
	Validators   []TokenValidator
	ErrorHandler func(ctx *gin.Context, err error)
}

func NewVerifier(validators ...TokenValidator) *Verifier {
	return &Verifier{
		Extractors: []TokenExtractor{FromHeader, FromQuery},
		ErrorHandler: func(ctx *gin.Context, err error) {
			ctx.AbortWithError(http.StatusUnauthorized, err)
		},
		Validators: validators,
	}
}

// Invalidate
func (v *Verifier) invalidate(ctx *gin.Context) {
	if verifiedToken := GetVerifiedToken(ctx); verifiedToken != nil {
		ctx.Set(claimsContextKey, "")
		ctx.Set(verifiedTokenContextKey, "")
	}
}

// RequestToken extracts the token from the
func (v *Verifier) RequestToken(ctx *gin.Context) (token string) {
	for _, extract := range v.Extractors {
		if token = extract(ctx); token != "" {
			break // ok we found it.
		}
	}

	return
}

func (v *Verifier) VerifyToken(token []byte, validators ...TokenValidator) ([]byte, *CustomClaims, error) {
	if len(token) == 0 {
		return nil, nil, errors.New("mutil: token is empty")
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

	rcc, err := AuthDriver.GetCustomClaims(string(token))
	if err != nil {
		AuthDriver.DelUserTokenCache(string(token))
		return nil, nil, err
	}

	if rcc == nil || rcc.ID == "" {
		return nil, nil, errors.New("mutil: invalid token")
	}

	return token, rcc, nil
}

func GetToken() (string, error) {
	node, err := snowflake.NewNode(1)
	if err != nil {
		return "", fmt.Errorf("mutil: create token %w", err)
	}
	now := Base64Encode([]byte(time.Now().Local().Format(time.RFC3339)))
	nodeId := Base64Encode(node.Generate().Bytes())
	token := Base64Encode(joinParts(nodeId, now))
	token = joinParts(token, nodeId)
	return string(token), nil
}

func (v *Verifier) Verify(validators ...TokenValidator) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token := []byte(v.RequestToken(ctx))
		verifiedToken, rcc, err := v.VerifyToken(token, validators...)
		if err != nil {
			v.invalidate(ctx)
			v.ErrorHandler(ctx, err)
			return
		}

		ctx.Set(claimsContextKey, rcc)
		ctx.Set(verifiedTokenContextKey, verifiedToken)
		ctx.Next()
	}
}

var (
	sep    = []byte(".")
	pad    = []byte("=")
	padStr = string(pad)
)

func joinParts(parts ...[]byte) []byte {
	return bytes.Join(parts, sep)
}

func Base64Encode(src []byte) []byte {
	buf := make([]byte, base64.URLEncoding.EncodedLen(len(src)))
	base64.URLEncoding.Encode(buf, src)

	return bytes.TrimRight(buf, padStr) // JWT: no trailing '='.
}

// Base64Decode decodes "src" to jwt base64 url format.
// We could use the base64.RawURLEncoding but the below is a bit faster.
func Base64Decode(src []byte) ([]byte, error) {
	if n := len(src) % 4; n > 0 {
		// JWT: Because of no trailing '=' let's suffix it
		// with the correct number of those '=' before decoding.
		src = append(src, bytes.Repeat(pad, 4-n)...)
	}

	buf := make([]byte, base64.URLEncoding.DecodedLen(len(src)))
	n, err := base64.URLEncoding.Decode(buf, src)
	return buf[:n], err
}
