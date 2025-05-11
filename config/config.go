package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port string `yaml:"port"`
	} `yaml:"server"`
	Firebase struct {
		CredentialsPath string `yaml:"credentials_path"`
	} `yaml:"firebase"`
	Resend struct {
		APIKey string `yaml:"-"`
		From   string `yaml:"from"`
	} `yaml:"resend"`
	Twilio struct {
		AccountSID  string `yaml:"-"`
		AuthToken   string `yaml:"-"`
		PhoneNumber string `yaml:"-"`
	} `yaml:"twilio"`
}

func LoadConfig(path string) (*Config, error) {
	// load .env
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("failed to load .env file: %w", err)
	}

	// read yaml
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml: %w", err)
	}

	// env override
	cfg.Resend.APIKey = os.Getenv("RESEND_API_KEY")
	cfg.Twilio.AccountSID = os.Getenv("TWILIO_ACCOUNT_SID")
	cfg.Twilio.AuthToken = os.Getenv("TWILIO_AUTH_TOKEN")
	cfg.Twilio.PhoneNumber = os.Getenv("TWILIO_PHONE_NUMBER")

	// validations
	if cfg.Resend.APIKey == "" {
		return nil, fmt.Errorf("missing RESEND_API_KEY env")
	}
	if cfg.Twilio.AccountSID == "" || cfg.Twilio.AuthToken == "" || cfg.Twilio.PhoneNumber == "" {
		return nil, fmt.Errorf("missing Twilio credentials in env")
	}

	return &cfg, nil
}
