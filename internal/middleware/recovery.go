package middleware

import (
	"log"
	"net/http"

	"hermes/internal/vo"

	"github.com/gin-gonic/gin"
)

// Recovery returns a middleware that recovers from panics and returns 500 with ErrorVO.
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v", err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, vo.ErrorVO{
					Code:    "INTERNAL_ERROR",
					Message: "internal server error",
				})
			}
		}()
		c.Next()
	}
}