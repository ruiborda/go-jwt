package input

import (
	"encoding/json"
	"github.com/ruiborda/go-jwt/src/application/ports/input"
	"github.com/ruiborda/go-jwt/src/application/usecases"
	"github.com/ruiborda/go-jwt/src/domain/entity"
	"github.com/ruiborda/go-jwt/src/domain/vo"
	"reflect"
	"testing"
	"time"
)

type SimplePrivateClaims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

func TestJwtInputAdapter_CreateJwt(t *testing.T) {

	type args[T any] struct {
		joseHeader *entity.JOSEHeader
		claims     *entity.JWTClaims[T]
	}
	type testCase[T any] struct {
		name    string
		this    *JwtInputAdapter[T]
		args    args[T]
		want    *entity.Jwt[T]
		wantErr bool
	}

	inputPort := input.NewJWTHS256InputPort[*SimplePrivateClaims]([]byte("secret"))
	inputAdapter := NewJwtInputAdapter[*SimplePrivateClaims](inputPort)

	tests := []testCase[*SimplePrivateClaims]{
		{
			name: "Create JWT",
			this: inputAdapter,
			args: args[*SimplePrivateClaims]{
				joseHeader: &entity.JOSEHeader{
					Algorithm: "HS256",
					Type:      "JWT",
				},
				claims: &entity.JWTClaims[*SimplePrivateClaims]{
					RegisteredClaims: &entity.RegisteredClaims{
						Issuer:         "issuer",
						Subject:        "subject",
						ExpirationTime: 11,
					},
					PrivateClaims: &SimplePrivateClaims{
						Username: "user",
						Roles:    []string{"admin", "user"},
					},
				},
			},
			want: &entity.Jwt[*SimplePrivateClaims]{
				Header: &entity.JOSEHeader{
					Algorithm: "HS256",
					Type:      "JWT",
				},
				Claims: &entity.JWTClaims[*SimplePrivateClaims]{
					RegisteredClaims: &entity.RegisteredClaims{
						Issuer:         "issuer",
						Subject:        "subject",
						ExpirationTime: 11,
					},
					PrivateClaims: &SimplePrivateClaims{
						Username: "user",
						Roles:    []string{"admin", "user"},
					},
				},
				Signature: vo.NewSignature("4YCS_z6Sd2njtE0th_NQ_i0VZlTGHrOlv4Z5HRJB62k"),
				Token:     vo.NewToken("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjExLCJpc3MiOiJpc3N1ZXIiLCJyb2xlcyI6WyJhZG1pbiIsInVzZXIiXSwic3ViIjoic3ViamVjdCIsInVzZXJuYW1lIjoidXNlciJ9.4YCS_z6Sd2njtE0th_NQ_i0VZlTGHrOlv4Z5HRJB62k"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.this.CreateJwt(tt.args.joseHeader, tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateJwt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateJwt() got = %v, want %v", got, tt.want)
				gotJson, _ := json.MarshalIndent(got, "", "  ")
				t.Errorf("CreateJwt() gotJson = %v", string(gotJson))
				wantJson, _ := json.MarshalIndent(tt.want, "", "  ")
				t.Errorf("CreateJwt() wantJson = %v", string(wantJson))
			}
		})
	}
}

func TestJwtInputAdapter_VerifyToken(t *testing.T) {
	type args struct {
		token func() string
	}
	type testCase[T any] struct {
		name    string
		this    *JwtInputAdapter[T]
		args    args
		wantErr bool
	}
	inputPort := input.NewJWTHS256InputPort[*SimplePrivateClaims]([]byte("secret"))
	inputAdapter := NewJwtInputAdapter[*SimplePrivateClaims](inputPort)
	tests := []testCase[*SimplePrivateClaims]{
		{
			name: "Valid Token",
			this: inputAdapter,
			args: args{
				token: func() string {
					jwt, err := inputAdapter.CreateJwt(
						&entity.JOSEHeader{
							Algorithm: "HS256",
							Type:      "JWT",
						},
						&entity.JWTClaims[*SimplePrivateClaims]{
							RegisteredClaims: &entity.RegisteredClaims{
								Issuer:         "issuer",
								Subject:        "subject",
								ExpirationTime: time.Now().Add(time.Second * 5).Unix(),
							},
							PrivateClaims: &SimplePrivateClaims{
								Username: "user",
								Roles:    []string{"admin", "user"},
							},
						},
					)
					if err != nil {
						t.Errorf("Error creating JWT: %v", err)
					}
					return jwt.Token.GetToken()
				},
			},
			wantErr: false,
		},
		{
			name: "Expired Token",
			this: inputAdapter,
			args: args{
				token: func() string {
					jwt, err := inputAdapter.CreateJwt(
						&entity.JOSEHeader{
							Algorithm: "HS256",
							Type:      "JWT",
						},
						&entity.JWTClaims[*SimplePrivateClaims]{
							RegisteredClaims: &entity.RegisteredClaims{
								Issuer:         "issuer",
								Subject:        "subject",
								ExpirationTime: time.Now().Add(-time.Second * 5).Unix(),
							},
							PrivateClaims: &SimplePrivateClaims{
								Username: "user",
								Roles:    []string{"admin", "user"},
							},
						},
					)
					if err != nil {
						t.Errorf("Error creating JWT: %v", err)
					}
					return jwt.Token.GetToken()
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.this.VerifyToken(tt.args.token()); (err != nil) != tt.wantErr {
				t.Errorf("VerifyToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewJwtInputAdapter(t *testing.T) {
	type args[T any] struct {
		jwtUseCase usecases.JWTUseCase[*SimplePrivateClaims]
	}
	type testCase[T any] struct {
		name string
		args args[T]
		want *JwtInputAdapter[T]
	}
	tests := []testCase[*SimplePrivateClaims]{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewJwtInputAdapter(tt.args.jwtUseCase); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewJwtInputAdapter() = %v, want %v", got, tt.want)
			}
		})
	}
}
