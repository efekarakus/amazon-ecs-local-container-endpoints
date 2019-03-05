package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/awslabs/amazon-ecs-local-container-endpoints/handlers"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.Info("Running...") // TODO: print version?
	credentials, err := handlers.NewCredentialService()
	if err != nil {
		logrus.Fatal("Failed to create Credentials Server")
	}
	http.HandleFunc("/role/", handlers.ServeHTTP(credentials.GetRoleHandler()))
	http.HandleFunc("/creds", handlers.ServeHTTP(credentials.GetTemporaryCredentialHandler()))

	port := "80"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}
	err = http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
	if err != nil {
		logrus.Fatal("HTTP Server exited with error: ", err)
	}
}
