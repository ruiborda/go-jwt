package input

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/ruiborda/go-jwt/src/application/usecases"
	"github.com/ruiborda/go-jwt/src/domain/entity"
	errors2 "github.com/ruiborda/go-jwt/src/domain/errors"
	"github.com/ruiborda/go-jwt/src/domain/vo"
)

type JWTHS256InputPort[T any] struct {
	Secret []byte
	Token  string
	jwt    *entity.Jwt[T]
}

func NewJWTHS256InputPort[T any](secret []byte) *JWTHS256InputPort[T] {
	return &JWTHS256InputPort[T]{Secret: secret}
}

func (this JWTHS256InputPort[T]) Sign(message string) *vo.Signature {
	mac := hmac.New(sha256.New, this.Secret)
	mac.Write([]byte(message))
	signature := mac.Sum(nil)
	sigEnc := base64.RawURLEncoding.EncodeToString(signature)
	return vo.NewSignature(sigEnc)
}

func (this *JWTHS256InputPort[T]) SetSecret(secret []byte) usecases.JWTUseCase[T] {
	this.Secret = secret
	return this
}

func (this *JWTHS256InputPort[T]) SetJwt(jwt *entity.Jwt[T]) usecases.JWTUseCase[T] {
	this.jwt = jwt
	return this
}

func (this JWTHS256InputPort[T]) CreateJwt(joseHeader *entity.JOSEHeader, claims *entity.JWTClaims[T]) (*entity.Jwt[T], error) {
	sig := this.Sign(entity.GenerateUnsignedToken(joseHeader, claims))

	jwt := entity.NewJwt[T](joseHeader, claims, sig)
	if jwt == nil {
		return nil, errors.New("error al crear el JWT")
	}
	this.jwt = jwt

	return jwt, nil
}

func (this JWTHS256InputPort[T]) VerifyTokenSignature() error {
	expected := this.Sign(this.jwt.Token.GetUnsignedToken())

	if !hmac.Equal([]byte(expected.TokenSignatureEncoded), []byte(this.jwt.Token.EncodedSignature)) {
		return errors2.InvalidSignature{}
	}
	return nil
}
