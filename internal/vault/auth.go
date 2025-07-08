package vault

type LdapAuthRespBody struct {
	LeaseId       string        `json:"lease_id,omitempty"`
	Renewable     bool          `json:"renewable,omitempty"`
	LeaseDuration int           `json:"lease_duration,omitempty"`
	Auth          *ldapAuthData `json:"auth,omitempty"`
}
type ldapAuthData struct {
	ClientToken   string            `json:"client_token,omitempty"`
	Policies      []string          `json:"policies,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	LeaseDuration int64             `json:"lease_duration,omitempty"`
	Renewable     bool              `json:"renewable,omitempty"`
}
