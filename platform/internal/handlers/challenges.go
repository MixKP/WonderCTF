package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ctf-demo/platform/internal/auth"
	"github.com/ctf-demo/platform/internal/models"
)

func ListChallenges(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := auth.ClaimsFromContext(c)

		rows, err := deps.Pool.Query(c.Request.Context(), `
			SELECT c.id, c.category, c.title, c.description, c.points, c.url,
			       EXISTS (
			           SELECT 1 FROM submissions s
			           WHERE s.challenge_id = c.id AND s.user_id = $1 AND s.correct
			       ) AS solved
			FROM challenges c
			ORDER BY c.id`, claims.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not load challenges"})
			return
		}
		defer rows.Close()

		challenges := make([]models.Challenge, 0)
		for rows.Next() {
			var ch models.Challenge
			if err := rows.Scan(&ch.ID, &ch.Category, &ch.Title, &ch.Description, &ch.Points, &ch.URL, &ch.Solved); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "could not load challenges"})
				return
			}
			challenges = append(challenges, ch)
		}

		c.JSON(http.StatusOK, challenges)
	}
}

func GetChallenge(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := auth.ClaimsFromContext(c)
		id := c.Param("id")

		var ch models.Challenge
		err := deps.Pool.QueryRow(c.Request.Context(), `
			SELECT c.id, c.category, c.title, c.description, c.points, c.url,
			       EXISTS (
			           SELECT 1 FROM submissions s
			           WHERE s.challenge_id = c.id AND s.user_id = $2 AND s.correct
			       ) AS solved
			FROM challenges c
			WHERE c.id = $1`, id, claims.UserID,
		).Scan(&ch.ID, &ch.Category, &ch.Title, &ch.Description, &ch.Points, &ch.URL, &ch.Solved)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "challenge not found"})
			return
		}

		c.JSON(http.StatusOK, ch)
	}
}
