// Package models defines the platform's core domain types.
package models

import "time"

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	IsAdmin      bool      `json:"isAdmin"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Challenge struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Points      int    `json:"points"`
	URL         string `json:"url"`
	FlagHash    string `json:"-"`
	Solved      bool   `json:"solved"`
}

type Submission struct {
	ID          string    `json:"id"`
	UserID      string    `json:"userId"`
	ChallengeID string    `json:"challengeId"`
	Correct     bool      `json:"correct"`
	SubmittedAt time.Time `json:"submittedAt"`
}

type ScoreboardEntry struct {
	UserID      string     `json:"userId"`
	Username    string     `json:"username"`
	Score       int        `json:"score"`
	SolvedCount int        `json:"solvedCount"`
	LastSolveAt *time.Time `json:"lastSolveAt,omitempty"`
}
