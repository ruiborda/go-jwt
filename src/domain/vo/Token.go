package vo

import "strings"

type Token struct {
	EncodedHeader    string
	EncodedClaims    string
	EncodedSignature string
}

func NewToken(token string) *Token {
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return nil
	}

	return &Token{
		EncodedHeader:    tokenParts[0],
		EncodedClaims:    tokenParts[1],
		EncodedSignature: tokenParts[2],
	}
}

func (this *Token) GetToken() string {
	return this.EncodedHeader + "." + this.EncodedClaims + "." + this.EncodedSignature
}

func (this *Token) GetUnsignedToken() string {
	return this.EncodedHeader + "." + this.EncodedClaims
}
