package server

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/yuaanlin/zju-bs-project-backend/controller"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func CreateServer() *gin.Engine {

	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, _ := config.Build()
	sugar := logger.Sugar()

	r := gin.New()

	err := r.SetTrustedProxies(nil)
	if err != nil {
		panic(err)
	}

	r.Use(GinLogger(sugar))
	r.Use(GinRecovery(sugar))

	r.Use(
		cors.New(
			cors.Config{
				AllowOrigins:     []string{"*"},
				AllowMethods:     []string{"POST", "GET", "PUT", "DELETE", "OPTIONS"},
				AllowHeaders:     []string{"*"},
				ExposeHeaders:    []string{"*"},
				AllowCredentials: true,
			},
		),
	)

	ctr := controller.New(sugar)

	r.Use(ctr.AuthMiddleware)

	user := r.Group("/user")
	{
		user.POST("/login", ctr.Login)
		user.POST("/register", ctr.Register)
	}

	places := r.Group("/places")
	{
		places.GET("/", ctr.GetPlaces)
		places.GET("/:placeId", ctr.GetPlace)
		places.POST("/", ctr.CreatePlace)
		places.DELETE("/:placeId", ctr.DeletePlace)
	}

	rooms := places.Group("/:placeId/rooms")
	{
		rooms.GET("/", ctr.GetRooms)
		rooms.GET("/:roomId", ctr.GetRoom)
		rooms.POST("/", ctr.CreateRoom)
		rooms.DELETE("/:roomId", ctr.DeleteRoom)
	}

	devices := rooms.Group("/:roomId/devices")
	{
		devices.GET("/", ctr.GetDevices)
		devices.GET("/:deviceId", ctr.GetDevice)
		devices.POST("/", ctr.CreateDevice)
		devices.PUT("/:deviceId", ctr.UpdateDevice)
		devices.DELETE("/:deviceId", ctr.DeleteDevice)
	}

	r.GET("/images/places/:placeId/rooms/:roomId", ctr.GetRoomImage)

	return r
}
