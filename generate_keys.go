// generate_keys.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func main() {
	// Generar clave RSA de 2048 bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generando clave privada: %v", err)
	}

	// Guardar private.pem
	privFile, err := os.Create("private.pem")
	if err != nil {
		log.Fatalf("No se puede crear private.pem: %v", err)
	}
	defer privFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Error escribiendo private.pem: %v", err)
	}

	// Guardar public.pem
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Error serializando clave pública: %v", err)
	}
	pubFile, err := os.Create("public.pem")
	if err != nil {
		log.Fatalf("No se puede crear public.pem: %v", err)
	}
	defer pubFile.Close()

	if err := pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1}); err != nil {
		log.Fatalf("Error escribiendo public.pem: %v", err)
	}

	log.Println("Claves RSA generadas: private.pem, public.pem")
}
