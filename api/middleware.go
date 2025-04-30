package api

import (
	"errors"
	"fmt"
	"net/http"
	"simple_bank/token"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"
	authorizationPayloadKey = "authorization_payload"
)

func contextAbortWithStatusJSON(ctx *gin.Context, err error) {
	ctx.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse(err))
}

func authMiddleware(tokenMaker token.Maker) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authorizationHeader := ctx.GetHeader(authorizationHeaderKey)
		if len(authorizationHeader) == 0 {
			err := errors.New("authorization header is not provided")
			contextAbortWithStatusJSON(ctx, err)
			return
		}

		fields := strings.Fields(authorizationHeader)
		if len(fields) < 2 {
			err := errors.New("invalid authorization header format")
			contextAbortWithStatusJSON(ctx, err)
			return
		}

		authorizationType := strings.ToLower(fields[0])
		if authorizationType != authorizationTypeBearer {
			err := fmt.Errorf("unsupported authorization type %s", authorizationType)
			contextAbortWithStatusJSON(ctx, err)
			return
		}

		accessToken := fields[1]
		payload, err := tokenMaker.VerifyToken(accessToken)
		if err != nil {
			contextAbortWithStatusJSON(ctx, err)
			return
		}

		ctx.Set(authorizationPayloadKey, payload)
		ctx.Next()
	}
}
