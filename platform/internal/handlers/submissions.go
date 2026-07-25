package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctf-demo/platform/internal/auth"
)

const pgUniqueViolation = "23505"

type submitFlagRequest struct {
	ChallengeID string `json:"challengeId"`
	Flag        string `json:"flag"`
}

type submitFlagResponse struct {
	Correct       bool `json:"correct"`
	AlreadySolved bool `json:"alreadySolved"`
	PointsAwarded int  `json:"pointsAwarded"`
}

func SubmitFlag(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := auth.ClaimsFromContext(c)

		var req submitFlagRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.ChallengeID == "" || req.Flag == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "challengeId and flag are required"})
			return
		}

		var flagHash string
		var points int
		err := deps.Pool.QueryRow(c.Request.Context(),
			`SELECT flag_hash, points FROM challenges WHERE id = $1`, req.ChallengeID,
		).Scan(&flagHash, &points)
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "challenge not found"})
			return
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not load challenge"})
			return
		}

		var alreadySolved bool
		if err := deps.Pool.QueryRow(c.Request.Context(),
			`SELECT EXISTS(SELECT 1 FROM submissions WHERE user_id = $1 AND challenge_id = $2 AND correct)`,
			claims.UserID, req.ChallengeID,
		).Scan(&alreadySolved); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not check submission history"})
			return
		}

		// bcrypt.CompareHashAndPassword against the stored flag hash — this is
		// the flag equivalent of the password check: the same constant-time,
		// no-plaintext-at-rest approach.
		correct := auth.CheckPassword(flagHash, req.Flag)

		_, err = deps.Pool.Exec(c.Request.Context(),
			`INSERT INTO submissions (user_id, challenge_id, correct) VALUES ($1, $2, $3)`,
			claims.UserID, req.ChallengeID, correct)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
				// Concurrent request already recorded the first correct solve.
				alreadySolved = true
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "could not record submission"})
				return
			}
		}

		resp := submitFlagResponse{Correct: correct, AlreadySolved: alreadySolved}
		if correct && !alreadySolved {
			resp.PointsAwarded = points
		}
		c.JSON(http.StatusOK, resp)
	}
}
