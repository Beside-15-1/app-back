package routes

import (
	"joosum-backend/app/auth"
	"joosum-backend/app/user"

	"github.com/gin-gonic/gin"
)

// PublicRoutes func for describe group of public routes.
func PublicRoutes(router *gin.Engine) {

	router.GET("/", user.GetMainPage)
	googleHandler := auth.GoogleHandler{}
	authHandler := auth.AuthHandler{}
	appleHandler := auth.AppleHandler{}
	naverHandler := auth.NaverHandler{}
	kakaoHandler := auth.KakaoHandler{}

	authRouter := router.Group("/auth")
	{
		authRouter.POST("/apple", appleHandler.VerifyAndIssueToken)
		authRouter.POST("/google", googleHandler.VerifyGoogleAccessToken)
		authRouter.POST("/naver", naverHandler.VerifyNaverAccessToken)
		authRouter.POST("/kakao", kakaoHandler.VerifyKakaoAccessToken)
		authRouter.POST("/signup", authHandler.SignUp)
	}

}
