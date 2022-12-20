package server

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

func GinLogger(sugar *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		c.Next()
		cost := time.Since(start)
		sugar.Infow(
			path,
			"status", c.Writer.Status(),
			"method", c.Request.Method,
			"path", path,
			"query", query,
			"errors", c.Errors.ByType(gin.ErrorTypePrivate).String(),
			"cost", cost,
		)
	}
}

func GinRecovery(sugar *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						if strings.Contains(
							strings.ToLower(se.Error()), "broken pipe",
						) || strings.Contains(
							strings.ToLower(se.Error()),
							"connection reset by peer",
						) {
							brokenPipe = true
						}
					}
				}

				httpRequest, _ := httputil.DumpRequest(c.Request, false)
				if brokenPipe {
					sugar.Error(
						c.Request.URL.Path,
						zap.Any("error", err),
						zap.String("request", string(httpRequest)),
					)
					c.Error(err.(error))
					c.Abort()
					return
				}

				sugar.Errorw(
					"[Recovery from panic]",
					"error", err,
					"request", string(httpRequest),
					"stack", string(debug.Stack()),
				)
				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		c.Next()
	}
}
