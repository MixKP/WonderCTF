package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ctf-demo/platform/internal/models"
)

func GetScoreboard(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := deps.Pool.Query(c.Request.Context(), `
			SELECT user_id, username, score, solved_count, last_solve_at
			FROM scoreboard
			LIMIT 100`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not load scoreboard"})
			return
		}
		defer rows.Close()

		entries := make([]models.ScoreboardEntry, 0)
		for rows.Next() {
			var e models.ScoreboardEntry
			if err := rows.Scan(&e.UserID, &e.Username, &e.Score, &e.SolvedCount, &e.LastSolveAt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "could not load scoreboard"})
				return
			}
			entries = append(entries, e)
		}

		c.JSON(http.StatusOK, entries)
	}
}
