package vault

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
	Auth *tokenRenewData
}

type tokenRenewData struct {
	ClientToken   string `json:"client_token,omitempty"`
	Policies      []string
	Metadata      map[string]string
	LeaseDuration int64 `json:"lease_duration,omitempty"`
	Renewable     bool
}
