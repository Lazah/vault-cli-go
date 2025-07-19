package vault

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

type VaultClient struct {
	baseUrl       *url.URL
	apiClient     *resty.Client
	authMountPath string
	authType      string
	tokenCreds    *tokenAuth
	passwdCreds   *passwdAuth
	ctx           context.Context
	sessionToken  *tokenInfo
}
type tokenAuth struct {
	token string
}

type passwdAuth struct {
	username string
	password string
}

type LdapAuthRespBody struct {
	LeaseId       string         `json:"lease_id,omitempty"`
	Renewable     bool           `json:"renewable,omitempty"`
	LeaseDuration int            `json:"lease_duration,omitempty"`
	Auth          *ldapTokenData `json:"auth,omitempty"`
}
type ldapTokenData struct {
	ClientToken   string            `json:"client_token,omitempty"`
	Policies      []string          `json:"policies,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	LeaseDuration int64             `json:"lease_duration,omitempty"`
	Renewable     bool              `json:"renewable,omitempty"`
}

type UserpassAuthRespBody struct {
	RequestId     string `json:"request_id,omitempty"`
	LeaseId       string `json:"lease_id,omitempty"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int64  `json:"lease_duration,omitempty"`
	Auth          *userpassAuthData
}

type userpassAuthData struct {
	ClientToken   string            `json:"client_token,omitempty"`
	Accessor      string            `json:"accessor,omitempty"`
	Policies      []string          `json:"policies,omitempty"`
	TokenPolicies []string          `json:"token_policies,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	LeaseDuration int64             `json:"lease_duration,omitempty"`
	Renewable     bool              `json:"renewable,omitempty"`
}

type TokenRenewResp struct {
	Kv2Resp
	Auth *tokenRenewData `json:"auth,omitempty"`
}

type tokenRenewData struct {
	ClientToken   string `json:"client_token,omitempty"`
	Policies      []string
	Metadata      map[string]string
	LeaseDuration int64 `json:"lease_duration,omitempty"`
	Renewable     bool
}

func NewClient(baseUrl string) (*VaultClient, error) {
	serverUrl, err := url.Parse(baseUrl)
	if err != nil {
		return nil, err
	}
	restyClient := resty.New()
	restyClient.BaseURL = serverUrl.String()
	restyClient.SetTimeout(1 * time.Minute)
	restyClient.SetRetryCount(3)
	restyClient.AddRetryCondition(func(r *resty.Response, err error) bool {
		if (r.StatusCode() == http.StatusBadGateway) ||
			(r.StatusCode() == http.StatusGatewayTimeout) {
			return true
		}
		return false
	})
	sessionInfo := new(tokenInfo)
	tMutex := new(sync.Mutex)
	client := &VaultClient{
		baseUrl:      serverUrl,
		apiClient:    restyClient,
		ctx:          context.TODO(),
		sessionToken: sessionInfo,
	}
	client.sessionToken.tokenMutex = tMutex
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
	if c.apiClient == nil {
		return fmt.Errorf("client should be initialized before calling this")
	}
	var origTlsConfig *tls.Config
	origTransport, err := c.apiClient.Transport()
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
	c.apiClient.SetTLSClientConfig(origTlsConfig)
	return nil
}

func (c *VaultClient) WithLdapAuth(username, password, mountPath string) error {
	if mountPath != "" {
		c.authMountPath = mountPath
	} else {
		c.authMountPath = "auth/ldap/"
	}
	c.authType = "ldap"
	c.passwdCreds = &passwdAuth{
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
	c.passwdCreds = &passwdAuth{
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
		c.apiClient.SetAuthToken(c.tokenCreds.token)
		c.sessionToken.token = c.tokenCreds.token
		c.sessionToken.renew = false
		c.sessionToken.exp = time.Now().Add(10 * time.Hour)
	case "userpass":
		err := c.authUser()
		if err != nil {
			return err
		}
	}
	c.sessionToken.maxTtl = false
	return nil
}
func (c *VaultClient) authLdap() error {
	loginPath := fmt.Sprintf("v1/%s/login/%s", c.authMountPath, c.passwdCreds.username)
	body := map[string]string{
		"password": c.passwdCreds.password,
	}
	fullUrl, err := c.baseUrl.Parse(loginPath)
	if err != nil {
		return err
	}
	req := c.apiClient.NewRequest()
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
	tokenDur = tokenDur - (30 * time.Second)
	tokenExp := time.Now().Add(tokenDur)
	c.sessionToken.acquired = time.Now()
	c.sessionToken.exp = tokenExp
	c.apiClient.SetAuthToken(respData.Auth.ClientToken)
	return nil
}

type tokenInfo struct {
	token      string
	renew      bool
	acquired   time.Time
	exp        time.Time
	maxTtl     bool
	tokenMutex *sync.Mutex
}

func (c *VaultClient) authUser() error {
	loginPath := fmt.Sprintf("v1/%slogin/%s", c.authMountPath, c.passwdCreds.username)
	body := map[string]string{
		"password": c.passwdCreds.password,
	}
	fullUrl, err := c.baseUrl.Parse(loginPath)
	if err != nil {
		return err
	}
	req := c.apiClient.NewRequest()
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
		return fmt.Errorf(
			"an erro occured while performing user authentication:'%s'",
			resp.Status(),
		)
	}
	c.sessionToken.token = respData.Auth.ClientToken
	c.sessionToken.renew = respData.Auth.Renewable
	tokenDur := time.Duration(respData.Auth.LeaseDuration * int64(time.Second))
	tokenDur = tokenDur - (30 * time.Second)
	tokenExp := time.Now().Add(tokenDur)
	c.sessionToken.exp = tokenExp
	c.sessionToken.acquired = time.Now()
	c.apiClient.SetAuthToken(respData.Auth.ClientToken)
	return nil
}

func (c *VaultClient) RenewCurrentToken() (bool, int, error) {
	recentTime := time.Now()
	freshBuffer := c.sessionToken.acquired.Add(60 * time.Second)
	tokenRecent := recentTime.Before(freshBuffer)
	if tokenRecent {
		return false, 0, nil
	}
	renewUrl, err := c.baseUrl.Parse("v1/auth/token/renew-self")
	if err != nil {
		return false, 0, err
	}
	body := map[string]any{
		"increment": "10m",
	}
	req := c.apiClient.NewRequest()
	req.SetBody(body)
	resp, err := req.Post(renewUrl.String())
	if err != nil {
		msg := fmt.Errorf("an error occured while renewing token: %w", err)
		return false, resp.StatusCode(), msg
	}
	if resp.IsError() {
		msg := fmt.Errorf("failed to renew  token: %s", resp.Status())
		return false, resp.StatusCode(), msg
	}
	var tokenData *Kv2Resp
	err = json.Unmarshal(resp.Body(), &tokenData)
	if err != nil {
		msg := fmt.Errorf("failed to parse token renew response: %w", err)
		return false, resp.StatusCode(), msg
	}
	if tokenData == nil {
		return false, resp.StatusCode(), fmt.Errorf("token response was nil")
	}
	if tokenData.Auth == nil {
		return false, resp.StatusCode(), fmt.Errorf("token data was nil")
	}
	exceedTtl := checkMaxTtl(tokenData.Warnings)
	if exceedTtl {
		c.sessionToken.maxTtl = true
	}
	c.sessionToken.token = tokenData.Auth.ClientToken
	c.sessionToken.renew = tokenData.Auth.Renewable
	tokenDur := time.Duration(int64(tokenData.Auth.LeaseDuration) * int64(time.Second))
	tokenDur = tokenDur - (30 * time.Second)
	tokenExp := time.Now().Add(tokenDur)
	c.sessionToken.exp = tokenExp
	c.sessionToken.acquired = time.Now()
	c.apiClient.SetAuthToken(tokenData.Auth.ClientToken)
	return true, resp.StatusCode(), nil
}

func checkMaxTtl(warns []string) bool {
	match := regexp.MustCompile("exceeded the effective max_ttl")
	for _, warn := range warns {
		if match.FindStringIndex(warn) != nil {
			return true
		}
	}
	return false
}

func (c *VaultClient) RevokeToken() error {
	revokeUrl, err := c.baseUrl.Parse("v1/auth/token/revoke-self")
	if err != nil {
		return err
	}

	req := c.apiClient.NewRequest()
	resp, err := req.Post(revokeUrl.String())
	if err != nil {
		msg := fmt.Errorf("an error occured while revoking token: %w", err)
		return msg
	}
	if resp.IsError() {
		msg := fmt.Errorf("failed to revoke  token: %s", resp.Status())
		return msg
	}
	return nil
}
