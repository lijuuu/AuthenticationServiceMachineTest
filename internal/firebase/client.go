package firebaseclient

import (
	"context"
	"fmt"

	"github.com/lijuuu/AuthenticationServiceMachineTest/config"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/option"
)

type FirebaseClients struct {
	App             *firebase.App
	AuthClient      *auth.Client
	FirestoreClient *firestore.Client
}

func NewFirebaseClients(ctx context.Context, cfg *config.Config) (*FirebaseClients, error) {
	opt := option.WithCredentialsFile(cfg.Firebase.CredentialsPath)

	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return nil, fmt.Errorf("error initializing Firebase app: %v", err)
	}

	firestoreClient, err := app.Firestore(ctx)
	if err != nil {
		return nil, fmt.Errorf("error initializing Firestore client: %v", err)
	}

	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("error initializing Auth client: %v", err)
	}

	return &FirebaseClients{
		App:             app,
		AuthClient:      authClient,
		FirestoreClient: firestoreClient,
	}, nil
}
