package errors

type InvalidTokenFormat struct {
}

func (this InvalidTokenFormat) Error() string {
	return "invalid token format"
}
