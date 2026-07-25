package auth

import (
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestIssueAndVerify(t *testing.T) {
	issuer := NewTokenIssuer("test-secret-at-least-16-bytes")

	token, err := issuer.Issue("user-1", "alice", true)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	claims, err := issuer.Verify(token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if claims.UserID != "user-1" || claims.Username != "alice" || !claims.IsAdmin {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	issuer := NewTokenIssuer("test-secret-at-least-16-bytes")
	other := NewTokenIssuer("a-completely-different-secret!!")

	token, _ := issuer.Issue("user-1", "alice", false)
	if _, err := other.Verify(token); err == nil {
		t.Error("expected verification with a different secret to fail")
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	issuer := NewTokenIssuer("test-secret-at-least-16-bytes")

	// Forge a token with alg:none the way a naive JWT library would accept it.
	claims := Claims{UserID: "attacker", Username: "attacker", IsAdmin: true}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	forged, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to construct alg:none token: %v", err)
	}
	if !strings.Contains(forged, ".") {
		t.Fatalf("malformed forged token")
	}

	if _, err := issuer.Verify(forged); err == nil {
		t.Error("expected alg:none token to be rejected")
	}
}
