package auth

import "testing"

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if !CheckPassword(hash, "correct horse battery staple") {
		t.Error("expected correct password to match")
	}
	if CheckPassword(hash, "wrong password") {
		t.Error("expected wrong password to not match")
	}
}
