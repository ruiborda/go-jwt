// filecrypto.go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// --- Carga claves ---

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// --- Funciones de cifrado híbrido ---

func encryptFile(path string, pub *rsa.PublicKey) error {
	plain, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	// 1) Generar clave AES-256
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return err
	}

	// 2) Cifrar datos con AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	cipherText := gcm.Seal(nil, nonce, plain, nil)

	// 3) Cifrar clave AES con RSA-OAEP
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return err
	}

	// 4) Empaquetar: [4B largoEncKey][encKey][nonce][cipherText]
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint32(len(encKey)))
	buf.Write(encKey)
	buf.Write(nonce)
	buf.Write(cipherText)

	// 5) Escribir .go.enc y borrar original
	outPath := path + ".enc"
	if err := ioutil.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		return err
	}
	return os.Remove(path)
}

func decryptFile(path string, priv *rsa.PrivateKey) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	r := bytes.NewReader(data)

	// 1) Leer largo de la clave cifrada
	var keyLen uint32
	if err := binary.Read(r, binary.BigEndian, &keyLen); err != nil {
		return err
	}

	// 2) Leer y descifrar la clave AES
	encKey := make([]byte, keyLen)
	if _, err := io.ReadFull(r, encKey); err != nil {
		return err
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		return err
	}

	// 3) Leer nonce y resto de ciphertext
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(r, nonce); err != nil {
		return err
	}
	cipherText, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	// 4) Descifrar y restaurar fichero .go
	plain, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}
	orig := strings.TrimSuffix(path, ".enc")
	if err := ioutil.WriteFile(orig, plain, 0644); err != nil {
		return err
	}
	return os.Remove(path)
}

// --- Main: recorrido recursivo ---

func main() {
	mode := flag.String("mode", "encrypt", "encrypt o decrypt")
	keyPath := flag.String("key", "", "ruta a public.pem (encrypt) o private.pem (decrypt)")
	srcDir := flag.String("path", "./src", "directorio raíz a procesar")
	flag.Parse()

	if *keyPath == "" {
		log.Fatal("Debes indicar -key con la ruta a la clave")
	}

	switch *mode {
	case "encrypt":
		pub, err := loadPublicKey(*keyPath)
		if err != nil {
			log.Fatalf("Error cargando clave pública: %v", err)
		}
		filepath.Walk(*srcDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			if err := encryptFile(path, pub); err != nil {
				log.Printf("Error cifrando %s: %v", path, err)
			} else {
				log.Printf("Cifrado: %s → %s.enc", path, path)
			}
			return nil
		})
	case "decrypt":
		priv, err := loadPrivateKey(*keyPath)
		if err != nil {
			log.Fatalf("Error cargando clave privada: %v", err)
		}
		filepath.Walk(*srcDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".enc") {
				return nil
			}
			if err := decryptFile(path, priv); err != nil {
				log.Printf("Error descifrando %s: %v", path, err)
			} else {
				log.Printf("Descifrado: %s → %s", path, path)
			}
			return nil
		})
	default:
		log.Fatalf("Modo desconocido: %s. Usa encrypt o decrypt.", *mode)
	}
}
