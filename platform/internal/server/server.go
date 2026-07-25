// Package server wires the platform's HTTP routes and middleware together.
package server

import (
	"github.com/gin-gonic/gin"

	"github.com/ctf-demo/platform/internal/auth"
	"github.com/ctf-demo/platform/internal/handlers"
	"github.com/ctf-demo/platform/internal/middleware"
)

func New(deps *handlers.Deps, corsOrigin string) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), middleware.RequestLogging(), middleware.CORS(corsOrigin))

	// Tight limiter on auth endpoints (brute-force defense), looser on the rest.
	authLimiter := middleware.NewIPRateLimiter(1, 5)
	apiLimiter := middleware.NewIPRateLimiter(10, 30)

	r.GET("/healthz", func(c *gin.Context) { c.Status(200) })

	api := r.Group("/api")
	{
		authGroup := api.Group("/auth")
		authGroup.Use(authLimiter.Middleware())
		authGroup.POST("/register", handlers.Register(deps))
		authGroup.POST("/login", handlers.Login(deps))

		protected := api.Group("")
		protected.Use(apiLimiter.Middleware(), auth.RequireAuth(deps.Tokens))
		protected.GET("/challenges", handlers.ListChallenges(deps))
		protected.GET("/challenges/:id", handlers.GetChallenge(deps))
		protected.POST("/submissions", handlers.SubmitFlag(deps))
		protected.GET("/scoreboard", handlers.GetScoreboard(deps))
	}

	return r
}
