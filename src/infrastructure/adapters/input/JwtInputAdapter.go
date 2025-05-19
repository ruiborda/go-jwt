package input

import (
	"errors"
	"github.com/ruiborda/go-jwt/src/application/usecases"
	"github.com/ruiborda/go-jwt/src/domain/entity"
)

type JwtInputAdapter[T any] struct {
	JwtUseCase usecases.JWTUseCase[T]
}

func NewJwtInputAdapter[T any](jwtUseCase usecases.JWTUseCase[T]) *JwtInputAdapter[T] {
	return &JwtInputAdapter[T]{JwtUseCase: jwtUseCase}
}

func (this *JwtInputAdapter[T]) VerifyToken(token string) error {
	jwt := entity.NewJwtFromToken[T](token)
	if jwt == nil {
		return errors.New("Error al crear el token")
	}
	errCurrentlyValid := jwt.IsCurrentlyValid()
	if errCurrentlyValid != nil {
		return errCurrentlyValid
	}

	this.JwtUseCase.SetJwt(jwt)
	return this.JwtUseCase.VerifyTokenSignature()
}

func (this *JwtInputAdapter[T]) CreateJwt(joseHeader *entity.JOSEHeader, claims *entity.JWTClaims[T]) (*entity.Jwt[T], error) {
	jwt, err := this.JwtUseCase.CreateJwt(joseHeader, claims)
	if err != nil {
		return nil, err
	}

	return jwt, nil
}
