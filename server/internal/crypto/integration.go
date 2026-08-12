package tenantcrypto

import (
	"context"

	"github.com/gin-gonic/gin"
)

type contextKey string

const encryptorKey contextKey = "tenant_encryptor"

// WithEncryptor stores the Encryptor in the Gin context.
func WithEncryptor(c *gin.Context, enc *Encryptor) {
	c.Set(string(encryptorKey), enc)
}

// EncryptorFromGin retrieves the Encryptor from a Gin context.
// Returns nil if not set (encryption disabled).
func EncryptorFromGin(c *gin.Context) *Encryptor {
	v, exists := c.Get(string(encryptorKey))
	if !exists {
		return nil
	}
	enc, _ := v.(*Encryptor)
	return enc
}

// EncryptorFromCtx retrieves the Encryptor from a standard context.
func EncryptorFromCtx(ctx context.Context) *Encryptor {
	v := ctx.Value(encryptorKey)
	if v == nil {
		return nil
	}
	enc, _ := v.(*Encryptor)
	return enc
}

// ContextWithEncryptor stores the Encryptor in a standard context.
func ContextWithEncryptor(ctx context.Context, enc *Encryptor) context.Context {
	return context.WithValue(ctx, encryptorKey, enc)
}
