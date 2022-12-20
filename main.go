package main

import (
	"github.com/yuaanlin/zju-bs-project-backend/server"
	"os"
)

const defaultPort = "8080"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	panic(server.CreateServer().Run(":" + port))
}
