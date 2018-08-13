package keycloak

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"time"

	"crypto/tls"
	"fmt"

	"github.com/aerogear/keycloak-operator/pkg/apis/aerogear/v1alpha1"
)

var (
	keycloakAuthURL = "auth/realms/master/protocol/openid-connect/token"
)

func NewKeycloakResourceClient() {

}

type Requester interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	requester Requester
	URL       string
	token     string
}

func (c *Client) ListRealms() (map[string]*v1alpha1.KeycloakRealm, error) {
	req, err := http.NewRequest(
		"GET",
		c.URL+"/admin/realms",
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+c.token)
	res, err := c.requester.Do(req)
	if err != nil {
		logrus.Infof("error on request %+v", err)
		return nil, errors.Wrap(err, "error performing realms list request")
	}
	logrus.Infof(c.token)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, errors.New("failed to list realms: " + " (" + strconv.Itoa(res.StatusCode) + ") " + res.Status)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		logrus.Infof("error reading response %+v", err)
		return nil, errors.Wrap(err, "error reading realms list response")
	}

	logrus.Infof("realms list: %+v\n", string(body))
	// err = json.Unmarshal(body, tokenRes)
	// if err != nil {
	// 	return nil, errors.Wrap(err, "error parsing realms list response")
	// }

	return map[string]*v1alpha1.KeycloakRealm{}, nil
}

func (c *Client) GetRealm(name string) (*v1alpha1.KeycloakRealm, error) {
	return &v1alpha1.KeycloakRealm{}, nil
}

func (c *Client) UpdateRealm(realm *v1alpha1.KeycloakRealm) error {
	return nil
}

func (c *Client) DeleteRealm(name string) error {
	return nil
}

func (c *Client) login(user, pass string) error {
	form := url.Values{}
	form.Add("username", user)
	form.Add("password", pass)
	form.Add("client_id", "admin-cli")
	form.Add("grant_type", "password")

	req, err := http.NewRequest(
		"POST",
		c.URL+"/auth/realms/master/protocol/openid-connect/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return errors.Wrap(err, "error creating login request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.requester.Do(req)

	if err != nil {
		logrus.Infof("error on request %+v", err)
		return errors.Wrap(err, "error performing token request")
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		logrus.Infof("error reading response %+v", err)
		return errors.Wrap(err, "error reading token response")
	}
	tokenRes := &v1alpha1.TokenResponse{}

	err = json.Unmarshal(body, tokenRes)
	if err != nil {
		return errors.Wrap(err, "error parsing token response")
	}

	if tokenRes.Error != "" {
		logrus.Infof("error with request: " + tokenRes.ErrorDescription)
		return errors.New(tokenRes.ErrorDescription)
	}

	c.token = tokenRes.AccessToken

	return nil
}

func (c *Client) GetClient(clientId string, realmName string) (*v1alpha1.Client, error) {
	// u, err := url.ParseRequestURI(c.URL)
	// if err != nil {
	// 	return nil, errors.Wrap(err, fmt.Sprintf("failed to parse request URI: %s", c.URL))
	// }

	// u.Path = fmt.Sprintf("/auth/admin/realms/%s/clients/%s", realmName, clientId)
	// urlStr := u.String()
	// form := url.Values{}
	// req, err := http.NewRequest("GET", urlStr, strings.NewReader(form.Encode()))
	// req.Header.Add("Authorization", fmt.Sprintf("%s %s", c.token.TokenType, c.token.AccessToken))

	// resp, err := c.requester.Do(req)
	// if err != nil {
	// 	return nil, errors.Wrap(err, fmt.Sprintf("failed to get response from %s", urlStr))
	// }

	// defer resp.Body.Close()

	// body, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, errors.Wrap(err, "failed to get response body")
	// }

	// client := v1alpha1.Client{}
	// if err := json.Unmarshal(body, &client); err != nil {
	// 	return nil, errors.Wrap(err, "failed to unmarshal client")
	// }

	return nil, nil
}

func (c *Client) DeleteClient(clientId string, realmName string) error {
	req, err := http.NewRequest(
		"DELETE",
		fmt.Sprintf("%s/auth/admin/realms/%s/clients/%s", c.URL, realmName, clientId),
		nil,
	)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+c.token)
	res, err := c.requester.Do(req)
	if err != nil {
		logrus.Infof("error on request %+v", err)
		return errors.Wrap(err, "error performing delete client request")
	}

	if res.StatusCode != 204 {
		return errors.New("failed to delete client: " + " (" + strconv.Itoa(res.StatusCode) + ") " + res.Status)
	}

	logrus.Info("Deleted client: " + " (" + strconv.Itoa(res.StatusCode) + ") " + res.Status)

	return nil
}

func (c *Client) ListClients(realmName string) (map[string]*v1alpha1.Client, error) {
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/auth/admin/realms/%s/clients", c.URL, realmName),
		nil,
	)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+c.token)
	res, err := c.requester.Do(req)
	if err != nil {
		logrus.Infof("error on request %+v", err)
		return nil, errors.Wrap(err, "error performing clients list request")
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, errors.New("failed to list clients: " + " (" + strconv.Itoa(res.StatusCode) + ") " + res.Status)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		logrus.Infof("error reading response %+v", err)
		return nil, errors.Wrap(err, "error reading realms list response")
	}

	clients := []v1alpha1.Client{}
	if err := json.Unmarshal(body, &clients); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal clients list")
	}

	clientMap := map[string]*v1alpha1.Client{}
	for i := 0; i < len(clients); i++ {
		clientMap[clients[i].ClientID] = &clients[i]
	}

	return clientMap, nil
}

func defaultRequester() Requester {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{Transport: transport, Timeout: time.Second * 10}
	return c
}

type KeycloakInterface interface {
	ListRealms() (map[string]*v1alpha1.KeycloakRealm, error)
	GetRealm(realmName string) (*v1alpha1.KeycloakRealm, error)
	UpdateRealm(realm *v1alpha1.KeycloakRealm) error
	DeleteRealm(realmName string) error

	GetClient(clientId, realmName string) (*v1alpha1.Client, error)
	DeleteClient(clientId, realmName string) error
	ListClients(realmName string) (map[string]*v1alpha1.Client, error)
}

type KeycloakClientFactory interface {
	AuthenticatedClient(kc v1alpha1.Keycloak, user, pass, url string) (KeycloakInterface, error)
}

type KeycloakFactory struct {
}

func (kf *KeycloakFactory) AuthenticatedClient(kc v1alpha1.Keycloak, user, pass, url string) (KeycloakInterface, error) {
	client := &Client{
		URL:       url,
		requester: defaultRequester(),
	}
	logrus.Infof("going to login")
	client.login(user, pass)

	return client, nil
}
