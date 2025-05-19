package entity

import (
	"encoding/base64"
	"encoding/json"
	"github.com/ruiborda/go-jwt/src/domain/vo"
	"log/slog"
)

type JOSEHeader struct {
	Type      vo.Type      `json:"typ,omitempty"`
	Algorithm vo.Algorithm `json:"alg"`
}

func (j *JOSEHeader) GetEncodedHeader() string {
	encodedHeader, err := json.Marshal(j)
	if err != nil {
		slog.Error("Error al serializar el encabezado JOSE", "error", err.Error())
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(encodedHeader)
}
