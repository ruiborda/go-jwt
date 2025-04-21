# Generación de claves RSA
```bash
go run generate_keys.go
```

# Cifrar todos los .go bajo ./src

```bash
go run filecrypto.go -mode=encrypt -key=public.pem -path=./src
```

# Descifrar todos los .go.enc bajo ./src

```bash
go run filecrypto.go -mode=decrypt -key=private.pem -path=./src
```

# hexagonal

```bash
mkdir -p application/ports/input \
         application/ports/output \
         application/usecases \
         domain/entity \
         infrastructure/adapters/input \
         infrastructure/adapters/output
```