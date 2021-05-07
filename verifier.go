package multi

import (
	"errors"
	"fmt"

	"github.com/bwmarrin/snowflake"
	"github.com/kataras/iris/v12/context"
)

const (
	claimsContextKey        = "iris.multi.claims"
	verifiedTokenContextKey = "iris.multi.token"
)

// Get returns the claims decoded by a verifier.
func Get(ctx *context.Context) interface{} {
	if v := ctx.Values().Get(claimsContextKey); v != nil {
		return v
	}

	return nil
}

func GetVerifiedToken(ctx *context.Context) []byte {
	if v := ctx.Values().Get(verifiedTokenContextKey); v != nil {
		if tok, ok := v.([]byte); ok {
			return tok
		}
	}

	return nil
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
	return node.Generate().Base64(), nil
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
