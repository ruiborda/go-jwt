package entity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/ruiborda/go-jwt/src/domain/vo"
	"log/slog"
	"time"
)

type Jwt[T any] struct {
	Header    *JOSEHeader   `json:"header"`
	Claims    *JWTClaims[T] `json:"claims"`
	Signature *vo.Signature `json:"signature"`
	Token     *vo.Token     `json:"token"`
}

func NewJwt[T any](header *JOSEHeader, claims *JWTClaims[T], signature *vo.Signature) *Jwt[T] {
	return &Jwt[T]{
		Header:    header,
		Claims:    claims,
		Signature: signature,
		Token:     vo.NewToken(header.GetEncodedHeader() + "." + claims.GetEncodedClaims() + "." + signature.TokenSignatureEncoded),
	}
}

func NewJwtFromToken[T any](token string) *Jwt[T] {
	encodedToken := vo.NewToken(token)
	if encodedToken == nil {
		slog.Error("Error al crear el token", "token", token)
		return nil
	}
	decodedHeader, err := base64.RawURLEncoding.DecodeString(encodedToken.EncodedHeader)
	if err != nil {
		slog.Error("Error al decodificar el encabezado del token", "error", err)
		return nil
	}
	decodedClaims, err := base64.RawURLEncoding.DecodeString(encodedToken.EncodedClaims)
	if err != nil {
		slog.Error("Error al decodificar los reclamos del token", "error", err)
		return nil
	}
	var jwtHeader *JOSEHeader
	err = json.Unmarshal(decodedHeader, &jwtHeader)
	if err != nil {
		slog.Error("Error al deserializar el encabezado del token", "error", err)
		return nil
	}
	var jwtClaims *JWTClaims[T]
	err = json.Unmarshal(decodedClaims, &jwtClaims)
	if err != nil {
		slog.Error("Error al deserializar los reclamos del token", "error", err)
		return nil
	}
	signatureObj := vo.NewSignature(encodedToken.EncodedSignature)
	return &Jwt[T]{
		Header:    jwtHeader,
		Claims:    jwtClaims,
		Signature: signatureObj,
		Token:     encodedToken,
	}
}

func (j *Jwt[T]) IsCurrentlyValid() error {
	now := time.Now().Unix()
	exp := j.Claims.RegisteredClaims.ExpirationTime
	nbf := j.Claims.RegisteredClaims.NotBefore

	if exp > 0 && now >= exp {
		return errors.New("token expired")
	}

	if nbf > 0 && now < nbf {
		return errors.New("token not yet valid")
	}

	return nil
}

func GenerateUnsignedToken[T any](header *JOSEHeader, claims *JWTClaims[T]) string {
	encodedHeader := header.GetEncodedHeader()
	encodedClaims := claims.GetEncodedClaims()
	return encodedHeader + "." + encodedClaims
}
