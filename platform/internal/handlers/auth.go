package handlers

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"

	"github.com/ctf-demo/platform/internal/auth"
)

var (
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)
	emailRe    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

// dummyBcryptHash has no matching plaintext; it exists only to give the
// "user not found" path a bcrypt compare to run, for timing consistency.
const dummyBcryptHash = "$2a$12$C6UzMDM.H6dfI/f/IKcEeO6bmVwqmC2NuZO4C0/K1r5v0aB7v3iCS"

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	Token    string `json:"token"`
	UserID   string `json:"userId"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"isAdmin"`
}

func Register(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req registerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		if !usernameRe.MatchString(req.Username) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username must be 3-32 characters, letters/numbers/underscore only"})
			return
		}
		if !emailRe.MatchString(req.Email) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email address"})
			return
		}
		if len(req.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
			return
		}

		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not process password"})
			return
		}

		var userID string
		err = deps.Pool.QueryRow(c.Request.Context(),
			`INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id`,
			req.Username, req.Email, hash,
		).Scan(&userID)
		if err != nil {
			// Unique violation on username/email — don't leak which field collided.
			c.JSON(http.StatusConflict, gin.H{"error": "username or email already registered"})
			return
		}

		token, err := deps.Tokens.Issue(userID, req.Username, false)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
			return
		}

		c.JSON(http.StatusCreated, authResponse{Token: token, UserID: userID, Username: req.Username, IsAdmin: false})
	}
}

func Login(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req loginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		userID, passwordHash, isAdmin, err := lookupUserByUsername(c.Request.Context(), deps, req.Username)
		if err != nil {
			// Run a bcrypt compare against a dummy hash even when the user
			// doesn't exist, so login takes the same time either way and
			// timing can't be used to enumerate usernames.
			auth.CheckPassword(dummyBcryptHash, req.Password)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		if !auth.CheckPassword(passwordHash, req.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		token, err := deps.Tokens.Issue(userID, req.Username, isAdmin)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue token"})
			return
		}

		c.JSON(http.StatusOK, authResponse{Token: token, UserID: userID, Username: req.Username, IsAdmin: isAdmin})
	}
}

func lookupUserByUsername(ctx context.Context, deps *Deps, username string) (id, passwordHash string, isAdmin bool, err error) {
	err = deps.Pool.QueryRow(ctx,
		`SELECT id, password_hash, is_admin FROM users WHERE username = $1`, username,
	).Scan(&id, &passwordHash, &isAdmin)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, errors.New("not found")
	}
	return id, passwordHash, isAdmin, err
}
