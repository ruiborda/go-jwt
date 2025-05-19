package errors

type InvalidSignature struct {
}

func (this InvalidSignature) Error() string {
	return "invalid signature"
}
