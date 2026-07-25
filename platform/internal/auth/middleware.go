package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const ContextClaimsKey = "authClaims"

// RequireAuth rejects requests without a valid "Authorization: Bearer <jwt>" header.
func RequireAuth(issuer *TokenIssuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or malformed Authorization header"})
			return
		}

		claims, err := issuer.Verify(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		c.Set(ContextClaimsKey, claims)
		c.Next()
	}
}

func ClaimsFromContext(c *gin.Context) *Claims {
	v, ok := c.Get(ContextClaimsKey)
	if !ok {
		return nil
	}
	claims, ok := v.(*Claims)
	if !ok {
		return nil
	}
	return claims
}
