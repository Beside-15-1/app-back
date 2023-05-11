package main

import (
	"joosum-backend/pkg/config"
	"joosum-backend/pkg/routes"
	"joosum-backend/pkg/util"

	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload" // load .env file automatically
)

// @title API
// @version 1.0
// @description This is an auto-generated API Docs for Golang net/http Template.
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @contact.email your@mail.com
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @BasePath /api
func main() {
	config.EnvConfig()

	util.StartMongoDB()

	router := gin.Default()
	routes.PublicRoutes(router)
	routes.SwaggerRoutes(router)

	router.Run(":5001") // listen and serve on 0.0.0.0:5001 (for windows "localhost:5001")
}
