package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type FirebaseCredentials struct {
	Type                string `json:"type"`
	ProjectID           string `json:"project_id"`
	PrivateKeyID        string `json:"private_key_id"`
	PrivateKey          string `json:"private_key"`
	ClientEmail         string `json:"client_email"`
	ClientID            string `json:"client_id"`
	AuthURI             string `json:"auth_uri"`
	TokenURI            string `json:"token_uri"`
	AuthProviderCertURL string `json:"auth_provider_x509_cert_url"`
	ClientCertURL       string `json:"client_x509_cert_url"`
	UniverseDomain      string `json:"universe_domain"`
}

type Config struct {
	Server struct {
		Port string `yaml:"port"`
	} `yaml:"server"`
	Firebase struct {
		CredentialsPath string              `yaml:"credentials_path"`
		Credentials     FirebaseCredentials // loaded from file
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

	JWTSecret   string
	Environment string
}

func LoadConfig(path string) (*Config, error) {
	// load .env
	err := godotenv.Load()
	if err != nil {
		log.Println("failed to load .env")
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

	// load env overrides
	cfg.Resend.APIKey = os.Getenv("RESEND_API_KEY")
	cfg.Twilio.AccountSID = os.Getenv("TWILIO_ACCOUNT_SID")
	cfg.Twilio.AuthToken = os.Getenv("TWILIO_AUTH_TOKEN")
	cfg.Twilio.PhoneNumber = os.Getenv("TWILIO_PHONE_NUMBER")
	cfg.Environment = os.Getenv("ENVIRONMENT")

	log.Println("Environment is ", cfg.Environment)
	if cfg.Environment == "production" {
		cfg.Firebase.CredentialsPath = "/etc/secrets/serviceAccountKey.json"
	}

	// load firebase credentials from json file
	firebaseCredsData, err := os.ReadFile(cfg.Firebase.CredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read firebase credentials file: %w", err)
	}
	if err := json.Unmarshal(firebaseCredsData, &cfg.Firebase.Credentials); err != nil {
		return nil, fmt.Errorf("failed to unmarshal firebase credentials json: %w", err)
	}

	// validations
	if cfg.Resend.APIKey == "" {
		return nil, fmt.Errorf("missing RESEND_API_KEY env")
	}
	if cfg.Twilio.AccountSID == "" || cfg.Twilio.AuthToken == "" || cfg.Twilio.PhoneNumber == "" {
		return nil, fmt.Errorf("missing Twilio credentials in env")
	}
	if cfg.Firebase.Credentials.PrivateKey == "" || cfg.Firebase.Credentials.ClientEmail == "" {
		return nil, fmt.Errorf("invalid firebase credentials json")
	}

	if cfg.JWTSecret == " " {
		cfg.JWTSecret = "supersecretjwt"
	}

	return &cfg, nil
}
