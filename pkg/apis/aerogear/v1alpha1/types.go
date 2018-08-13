package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	Group             = "aerogear.org"
	Version           = "v1alpha1"
	KeycloakKind      = "Keycloak"
	KeycloakVersion   = "4.1.0"
	KeycloakFinalizer = "finalizer.org.aerogear.keycloak"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type KeycloakList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Keycloak `json:"items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// crd:gen:Kind=Keycloak:Group=aerogear.org
type Keycloak struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              KeycloakSpec   `json:"spec"`
	Status            KeycloakStatus `json:"status,omitempty"`
}

func (k *Keycloak) Defaults() {

}

type KeycloakSpec struct {
	Version          string          `json:"version"`
	InstanceName     string          `json:"instanceName"`
	InstanceUID      string          `json:"instanceUID"`
	AdminCredentials string          `json:"adminCredentials"`
	Realms           []KeycloakRealm `json:"realms"`
}

type KeycloakRealm struct {
	Name      string             `json:"name"`
	AuthTypes []AuthTypes        `json:"authMethods"`
	Users     []KeycloakUser     `json:"users"`
	Clients   map[string]*Client `json:"clients"`
}

type AuthTypes struct {
	Provider     string `json:"provider"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
}

type KeycloakUser struct {
	UserName     string   `json:"userName"`
	Roles        []string `json:"roles"`
	OutputSecret string   `json:"outputSecret"`
}

type KeycloakClient struct {
	Name         string            `json:"name"`
	ClientType   string            `json:"clientType"`
	Config       map[string]string `json:"config"`
	OutputSecret string            `json:"outputSecret"`
}

type GenericStatus struct {
	Phase    StatusPhase `json:"phase"`
	Message  string      `json:"message"`
	Attempts int         `json:"attempts"`
	// marked as true when all work is done on it
	Ready bool `json:"ready"`
}

type KeycloakStatus struct {
	GenericStatus
	SharedConfig StatusSharedConfig `json:"sharedConfig"`
}

type StatusPhase string

var (
	NoPhase                 StatusPhase = ""
	PhaseAccepted           StatusPhase = "accepted"
	PhaseComplete           StatusPhase = "complete"
	PhaseFailed             StatusPhase = "failed"
	PhaseModified           StatusPhase = "modified"
	PhaseProvisioning       StatusPhase = "provisioning"
	PhaseDeprovisioning     StatusPhase = "deprovisioning"
	PhaseDeprovisioned      StatusPhase = "deprovisioned"
	PhaseDeprovisionFailed  StatusPhase = "deprovisionFailed"
	PhaseCredentialsPending StatusPhase = "credentialsPending"
	PhaseCredentialsCreated StatusPhase = "credentialsCreated"
)

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type Attributes struct {
}

type Config struct {
	UserinfoTokenClaim string `json:"userinfo.token.claim"`
	UserAttribute      string `json:"user.attribute"`
	IDTokenClaim       string `json:"id.token.claim"`
	AccessTokenClaim   string `json:"access.token.claim"`
	ClaimName          string `json:"claim.name"`
	JSONTypeLabel      string `json:"jsonType.label"`
}

type ProtocolMapper struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Protocol        string `json:"protocol"`
	ProtocolMapper  string `json:"protocolMapper"`
	ConsentRequired bool   `json:"consentRequired"`
	ConsentText     string `json:"consentText,omitempty"`
	Config          Config `json:"config"`
}

type Access struct {
	View      bool `json:"view"`
	Configure bool `json:"configure"`
	Manage    bool `json:"manage"`
}

type Client struct {
	ID                        string           `json:"id"`
	ClientID                  string           `json:"clientId"`
	Name                      string           `json:"name"`
	BaseURL                   string           `json:"baseUrl,omitempty"`
	SurrogateAuthRequired     bool             `json:"surrogateAuthRequired"`
	Enabled                   bool             `json:"enabled"`
	ClientAuthenticatorType   string           `json:"clientAuthenticatorType"`
	DefaultRoles              []string         `json:"defaultRoles,omitempty"`
	RedirectUris              []string         `json:"redirectUris"`
	WebOrigins                []string         `json:"webOrigins"`
	NotBefore                 int              `json:"notBefore"`
	BearerOnly                bool             `json:"bearerOnly"`
	ConsentRequired           bool             `json:"consentRequired"`
	StandardFlowEnabled       bool             `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool             `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool             `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool             `json:"serviceAccountsEnabled"`
	PublicClient              bool             `json:"publicClient"`
	FrontchannelLogout        bool             `json:"frontchannelLogout"`
	Protocol                  string           `json:"protocol,omitempty"`
	Attributes                Attributes       `json:"attributes"`
	FullScopeAllowed          bool             `json:"fullScopeAllowed"`
	NodeReRegistrationTimeout int              `json:"nodeReRegistrationTimeout"`
	ProtocolMappers           []ProtocolMapper `json:"protocolMappers"`
	UseTemplateConfig         bool             `json:"useTemplateConfig"`
	UseTemplateScope          bool             `json:"useTemplateScope"`
	UseTemplateMappers        bool             `json:"useTemplateMappers"`
	Access                    Access           `json:"access"`
}

type ClientPair struct {
	KcClient  *Client
	ObjClient *Client
}
