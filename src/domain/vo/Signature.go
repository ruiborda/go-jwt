package vo

type Signature struct {
	TokenSignatureEncoded string
}

func NewSignature(tokenSignatureEncoded string) *Signature {
	return &Signature{
		TokenSignatureEncoded: tokenSignatureEncoded,
	}
}
