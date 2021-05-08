package multi

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/bwmarrin/snowflake"
	"github.com/kataras/iris/v12/context"
)

const (
	claimsContextKey        = "iris.multi.claims"
	verifiedTokenContextKey = "iris.multi.token"
)

// Get returns the claims decoded by a verifier.
func Get(ctx *context.Context) *CustomClaims {
	if v := ctx.Values().Get(claimsContextKey).(*CustomClaims); v != nil {
		return v
	}
	return nil
}

func GetAuthorityType(ctx *context.Context) int {
	if v := Get(ctx); v != nil {
		return v.AuthorityType
	}
	return 0
}

func GetVerifiedToken(ctx *context.Context) []byte {
	if v := ctx.Values().Get(verifiedTokenContextKey); v != nil {
		if tok, ok := v.([]byte); ok {
			return tok
		}
	}
	return nil
}

func IsTenancy(ctx *context.Context) bool {
	if v := GetVerifiedToken(ctx); v != nil {
		b, err := AuthDriver.IsTenancy(string(v))
		if err != nil {
			return false
		}
		return b
	}
	return false
}

func IsGeneral(ctx *context.Context) bool {
	if v := GetVerifiedToken(ctx); v != nil {
		b, err := AuthDriver.IsGeneral(string(v))
		if err != nil {
			return false
		}
		return b
	}
	return false
}

func IsAdmin(ctx *context.Context) bool {
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
	ErrorHandler func(ctx *context.Context, err error)
}

func NewVerifier(validators ...TokenValidator) *Verifier {
	return &Verifier{
		Extractors: []TokenExtractor{FromHeader, FromQuery},
		ErrorHandler: func(ctx *context.Context, err error) {
			ctx.StopWithError(401, context.PrivateError(err))
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

	if rcc == nil {
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
	token := joinParts(nodeId, now)
	return string(token), nil
}

func (v *Verifier) Verify(validators ...TokenValidator) context.Handler {
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
