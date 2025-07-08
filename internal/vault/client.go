package vault

import (
	"net/http"
)

type VaultClient struct {
	baseUrl       string
	client        http.Client
	authMountPath string
	tokenCreds    tokenAuth
	ldapCreds     ldapAuth
	userAuth      userAuth
}

type ldapAuth struct {
	username string
	password string
}
type tokenAuth struct {
	token string
}

type userAuth struct {
	username string
	password string
}

func NewClient(baseUrl string) (*VaultClient, error) {
	return nil, nil
}
