package main

import (
	"github.com/go-playground/validator/v10"
	_ "github.com/joho/godotenv/autoload" // load .env file automatically
	"joosum-backend/pkg/config"
	"joosum-backend/pkg/middleware"
	"joosum-backend/pkg/routes"
	"joosum-backend/pkg/util"
)

// @title Joosum App
// @description This is API Docs for Joosum App.
// @termsOfService http://swagger.io/terms/
// @contact.name Pink boss
// @contact.email pinkjoosum@gmail.com
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @BasePath /api
func main() {
	config.EnvConfig()

	util.StartMongoDB()
	util.LoadApplePublicKeys()
	util.Validate = validator.New()

	router := config.GetRouter()
	if *config.Env == "prod" {
		router.Use(middleware.LoggingMiddleware()) // 커스텀 로깅 미들웨어 적용
	}

	routes.PublicRoutes(router)
	routes.SwaggerRoutes(router)

	// SwaggerRoutes 보다 위에 있으면 swagger 문서가 보이지 않음
	routes.PrivateRoutes(router)

	router.Run(":5001") // listen and serve on 0.0.0.0:5001 (for windows "localhost:5001")
}
