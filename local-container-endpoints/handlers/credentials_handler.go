// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/sirupsen/logrus"
)

const (
	temporaryCredentialsDuration = 3600
)

// CredentialService vends credentials to containers
type CredentialService struct {
	iamClient iamiface.IAMAPI
	stsClient stsiface.STSAPI
}

// NewCredentialService returns a struct that handles credentials requests
func NewCredentialService() (*CredentialService, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}
	return &CredentialService{
		iamClient: iam.New(sess),
		stsClient: sts.New(sess),
	}, nil
}

// GetRoleHandler returns the Task IAM Role handler
func (service *CredentialService) GetRoleHandler() func(w http.ResponseWriter, r *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		logrus.Debug("Received role credentials request")
		response, err := service.getRoleCredentials(r.URL.Path)
		if err != nil {
			return err
		}

		writeJSONResponse(w, response)
		return nil
	}
}

func (service *CredentialService) getRoleCredentials(urlPath string) (*credentialResponse, error) {
	// URL Path format = /role/<role name>
	regExpr := regexp.MustCompile(`/role/([\w+=,.@-]+)`)
	urlParts := regExpr.FindStringSubmatch(urlPath)

	if len(urlParts) < 2 {
		return nil, HttpError{
			Code: http.StatusBadRequest,
			Err:  fmt.Errorf("Invalid URL path %s; expected '/role/<IAM Role Name>'", urlPath),
		}
	}

	roleName := urlParts[1]
	logrus.Debugf("Requesting credentials for %s", roleName)

	output, err := service.iamClient.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, err
	}

	creds, err := service.stsClient.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         output.Role.Arn,
		DurationSeconds: aws.Int64(temporaryCredentialsDuration),
		RoleSessionName: aws.String(fmt.Sprintf("ecs-local-%s", roleName)),
	})

	if err != nil {
		return nil, err
	}

	return &credentialResponse{
		AccessKeyId:     aws.StringValue(creds.Credentials.AccessKeyId),
		SecretAccessKey: aws.StringValue(creds.Credentials.SecretAccessKey),
		RoleArn:         aws.StringValue(output.Role.Arn),
		Token:           aws.StringValue(creds.Credentials.SessionToken),
		Expiration:      creds.Credentials.Expiration.Format(time.RFC3339),
	}, nil
}

// GetTemporaryCredentialHandler returns a handler which vends temporary credentials for the local IAM identity
func (service *CredentialService) GetTemporaryCredentialHandler() func(w http.ResponseWriter, r *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		logrus.Debug("Received temporary local credentials request")
		creds, err := service.stsClient.GetSessionToken(&sts.GetSessionTokenInput{
			DurationSeconds: aws.Int64(temporaryCredentialsDuration),
		})

		if err != nil {
			return err
		}

		response := credentialResponse{
			AccessKeyId:     aws.StringValue(creds.Credentials.AccessKeyId),
			SecretAccessKey: aws.StringValue(creds.Credentials.SecretAccessKey),
			RoleArn:         "", // Creds don't come from assuming a role
			Token:           aws.StringValue(creds.Credentials.SessionToken),
			Expiration:      creds.Credentials.Expiration.Format(time.RFC3339),
		}

		writeJSONResponse(w, response)
		return nil
	}
}
