package main

import (
	"context"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/lijuuu/AuthenticationServiceMachineTest/config"
	api "github.com/lijuuu/AuthenticationServiceMachineTest/internal/api"
	firebaseclient "github.com/lijuuu/AuthenticationServiceMachineTest/internal/firebase"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/repository"
	services "github.com/lijuuu/AuthenticationServiceMachineTest/internal/service"
)

func main() {
	ctx := context.Background()

	configs, err := config.LoadConfig("config/config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// init firebase clients
	fbClients, err := firebaseclient.NewFirebaseClients(ctx, configs)
	if err != nil {
		log.Fatalf("failed to init firebase clients: %v", err)
	}

	// init repo
	repo, err := repository.NewFirebaseRepository(ctx, configs, fbClients)
	if err != nil {
		log.Fatalf("failed to init repo: %v", err)
	}
	defer repo.Close()

	// init service
	authService := services.NewAuthService(ctx, repo)

	// init handler
	authHandler := api.NewHandler(authService)

	// start gin and attach routes
	engine := gin.Default()
	api.RegisterAuthRoutes(engine, authHandler, fbClients.AuthClient, ctx, *configs)

	engine.Run(configs.Server.Port)
}
