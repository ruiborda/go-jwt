package usecases

import (
	"github.com/ruiborda/go-jwt/src/domain/entity"
	"github.com/ruiborda/go-jwt/src/domain/vo"
)

type JWTUseCase[T any] interface {
	Sign(message string) *vo.Signature
	SetSecret(secret []byte) JWTUseCase[T]
	SetJwt(jwt *entity.Jwt[T]) JWTUseCase[T]
	CreateJwt(joseHeader *entity.JOSEHeader, claims *entity.JWTClaims[T]) (*entity.Jwt[T], error)
	VerifyTokenSignature() error
}
