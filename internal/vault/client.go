package vault

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/go-resty/resty/v2"
)

type VaultClient struct {
	baseUrl       *url.URL
	client        *resty.Client
	authMountPath string
	authType      string
	tokenCreds    *tokenAuth
	ldapCreds     *ldapAuth
	userAuth      *userAuth
	ctx           context.Context
	sessionToken  tokenInfo
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
	serverUrl, err := url.Parse(baseUrl)
	if err != nil {
		return nil, err
	}
	restyClient := resty.New()
	restyClient.BaseURL = serverUrl.String()
	client := &VaultClient{
		baseUrl: serverUrl,
		client:  restyClient,
		ctx:     context.TODO(),
	}
	return client, nil
}

func (c *VaultClient) WithTokenAuth(token string) error {
	c.tokenCreds = &tokenAuth{
		token: token,
	}
	c.authType = "token"
	return nil
}
func (c *VaultClient) Insecure() error {
	if c.client == nil {
		return fmt.Errorf("client should be initialized before calling this")
	}
	var origTlsConfig *tls.Config
	origTransport, err := c.client.Transport()
	if err != nil {
		return err
	}
	if origTransport == nil {
		origTlsConfig = new(tls.Config)
	} else {
		origTlsConfig = origTransport.TLSClientConfig
	}
	if origTlsConfig == nil {
		origTlsConfig = new(tls.Config)
	}
	origTlsConfig.InsecureSkipVerify = true
	c.client.SetTLSClientConfig(origTlsConfig)
	return nil
}

func (c *VaultClient) WithLdapAuth(username, password, mountPath string) error {
	if mountPath != "" {
		c.authMountPath = mountPath
	} else {
		c.authMountPath = "auth/ldap/"
	}
	c.authType = "ldap"
	c.ldapCreds = &ldapAuth{
		username: username,
		password: password,
	}
	return nil
}
func (c *VaultClient) WithUserAuth(username, password, mountPath string) error {
	if mountPath != "" {
		c.authMountPath = mountPath
	} else {
		c.authMountPath = "auth/userpass/"
	}
	c.authType = "userpass"
	c.userAuth = &userAuth{
		username: username,
		password: password,
	}
	return nil
}

func (c *VaultClient) Authenticate() error {
	switch c.authType {
	case "ldap":
		err := c.authLdap()
		if err != nil {
			return err
		}
	case "token":
		c.client.HeaderAuthorizationKey = "X-Vault-Token"
		c.client.SetAuthToken(c.tokenCreds.token)
		c.sessionToken.token = c.tokenCreds.token
		c.sessionToken.renew = false
		c.sessionToken.exp = time.Now().Add(10 * time.Hour)
	case "userpass":
		err := c.authUser()
		if err != nil {
			return err
		}
	}
	return nil
}
func (c *VaultClient) authLdap() error {
	loginPath := fmt.Sprintf("v1/%s/login/%s", c.authMountPath, c.ldapCreds.username)
	body := map[string]string{
		"password": c.ldapCreds.password,
	}
	fullUrl, err := c.baseUrl.Parse(loginPath)
	if err != nil {
		return err
	}
	req := c.client.NewRequest()
	req.Body = body
	respData := new(LdapAuthRespBody)
	req.SetResult(respData)
	var reqError error
	req.SetError(reqError)
	resp, err := req.Post(fullUrl.String())
	if err != nil {
		return err
	}
	if resp.IsError() {
		return resp.Error().(error)
	}
	c.sessionToken.token = respData.Auth.ClientToken
	c.sessionToken.renew = respData.Auth.Renewable
	tokenDur := time.Duration(respData.Auth.LeaseDuration * int64(time.Second))
	tokenDur = tokenDur - (5 * time.Second)
	tokenExp := time.Now().Add(tokenDur)
	c.sessionToken.exp = tokenExp
	c.client.SetAuthToken(respData.Auth.ClientToken)
	return nil
}

type tokenInfo struct {
	token string
	renew bool
	exp   time.Time
}

func (c *VaultClient) authUser() error {
	loginPath := fmt.Sprintf("v1/%slogin/%s", c.authMountPath, c.userAuth.username)
	body := map[string]string{
		"password": c.userAuth.password,
	}
	fullUrl, err := c.baseUrl.Parse(loginPath)
	if err != nil {
		return err
	}
	req := c.client.NewRequest()
	req.Body = body
	respData := new(UserpassAuthRespBody)
	// var reqError error
	req.SetResult(respData)
	// req.SetError(reqError)
	resp, err := req.Post(fullUrl.String())
	if err != nil {
		return err
	}
	if resp.IsError() {
		return resp.Error().(error)
	}
	c.sessionToken.token = respData.Auth.ClientToken
	c.sessionToken.renew = respData.Auth.Renewable
	tokenDur := time.Duration(respData.Auth.LeaseDuration * int64(time.Second))
	tokenDur = tokenDur - (5 * time.Second)
	tokenExp := time.Now().Add(tokenDur)
	c.sessionToken.exp = tokenExp
	c.client.SetAuthToken(respData.Auth.ClientToken)
	return nil
}
