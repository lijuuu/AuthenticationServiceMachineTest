package main

import (
	"log"

	"github.com/lijuuu/AuthenticationServiceMachineTest/config"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/api"
)

func main() {
	cfg, err := config.LoadConfig("./config/config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	api.StartSafeServer(cfg.Server.Port)

}
