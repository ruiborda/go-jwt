package entity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
)

type JWTClaims[T any] struct {
	RegisteredClaims *RegisteredClaims
	PrivateClaims    T
}

func (cs *JWTClaims[T]) MarshalJSON() ([]byte, error) {
	// 1. Convertir RegisteredClaims a un mapa
	regClaimsMap := make(map[string]interface{})
	if !reflect.ValueOf(cs.RegisteredClaims).IsZero() {
		regClaimsJSON, err := json.Marshal(cs.RegisteredClaims)
		if err != nil {
			return nil, fmt.Errorf("error al serializar RegisteredClaims: %w", err)
		}
		// *** CORRECCIÓN APLICADA AQUÍ: Pasar el puntero ®ClaimsMap ***
		if err := json.Unmarshal(regClaimsJSON, &regClaimsMap); err != nil {
			return nil, fmt.Errorf("error al deserializar RegisteredClaims a mapa: %w", err)
		}
	}

	// 2. Convertir PrivateClaims (T) a un mapa
	privClaimsMap := make(map[string]interface{})
	if !reflect.ValueOf(cs.PrivateClaims).IsZero() {
		privClaimsJSON, err := json.Marshal(cs.PrivateClaims)
		if err == nil && string(privClaimsJSON) != "null" && string(privClaimsJSON) != "{}" {
			// Pasar el puntero &privClaimsMap (ya estaba bien aquí)
			if err := json.Unmarshal(privClaimsJSON, &privClaimsMap); err != nil {
				return nil, fmt.Errorf("error al deserializar PrivateClaims a mapa: %w", err)
			}
		} else if err != nil {
			return nil, fmt.Errorf("error al serializar PrivateClaims (tipo %T): %w", cs.PrivateClaims, err)
		}
	}

	// 3. Fusionar los mapas
	mergedMap := make(map[string]interface{}, len(regClaimsMap)+len(privClaimsMap))
	for k, v := range regClaimsMap {
		mergedMap[k] = v
	}
	for k, v := range privClaimsMap {
		if _, exists := regClaimsMap[k]; exists {
			fmt.Printf("Advertencia: Claim privado '%s' colisiona con un Claim Registrado.\n", k)
		}
		mergedMap[k] = v
	}

	// 4. Serializar el mapa fusionado
	return json.Marshal(mergedMap)
}

func (cs *JWTClaims[T]) UnmarshalJSON(data []byte) error {
	genericMap := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &genericMap); err != nil {
		return fmt.Errorf("error al deserializar JSON general: %w", err)
	}

	regClaimsMap := make(map[string]json.RawMessage)
	privClaimsMap := make(map[string]json.RawMessage)

	regType := reflect.TypeOf(RegisteredClaims{})
	registeredFieldNames := make(map[string]struct{})
	for i := 0; i < regType.NumField(); i++ {
		field := regType.Field(i)
		jsonTag := field.Tag.Get("json")
		parts := strings.Split(jsonTag, ",")
		if len(parts) > 0 && parts[0] != "" && parts[0] != "-" {
			registeredFieldNames[parts[0]] = struct{}{}
		}
	}

	for key, rawValue := range genericMap {
		if _, isRegistered := registeredFieldNames[key]; isRegistered {
			regClaimsMap[key] = rawValue
		} else {
			privClaimsMap[key] = rawValue
		}
	}

	if len(regClaimsMap) > 0 {
		regJSON, err := json.Marshal(regClaimsMap)
		if err != nil {
			return fmt.Errorf("error al re-serializar mapa de RegisteredClaims: %w", err)
		}
		decoder := json.NewDecoder(bytes.NewReader(regJSON))
		decoder.UseNumber()
		if err := decoder.Decode(&cs.RegisteredClaims); err != nil {
			return fmt.Errorf("error al deserializar RegisteredClaims desde mapa: %w", err)
		}
	} else {
		cs.RegisteredClaims = &RegisteredClaims{}
	}

	if len(privClaimsMap) > 0 {
		privJSON, err := json.Marshal(privClaimsMap)
		if err != nil {
			return fmt.Errorf("error al re-serializar mapa de PrivateClaims: %w", err)
		}
		var zeroT T
		cs.PrivateClaims = zeroT
		if err := json.Unmarshal(privJSON, &cs.PrivateClaims); err != nil {
			return fmt.Errorf("error al deserializar PrivateClaims (tipo %T) desde mapa: %w", cs.PrivateClaims, err)
		}
	} else {
		var zeroT T
		cs.PrivateClaims = zeroT
	}

	return nil
}

func (cs *JWTClaims[T]) GetEncodedClaims() string {
	encodedClaims, err := json.Marshal(cs)
	if err != nil {
		slog.Error("Error al serializar JWTClaims", "error", err.Error())
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encodedClaims)
}
