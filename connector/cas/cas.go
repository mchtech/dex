// Package cas provides authentication strategies using CAS.
package cas

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/dexidp/dex/connector"
	"github.com/pkg/errors"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/transform"
	"gopkg.in/cas.v2"
)

// Config holds configuration options for CAS logins.
type Config struct {
	Portal  string            `json:"portal"`
	Spec    string            `json:"spec"`
	Mapping map[string]string `json:"mapping"`
}

// Open returns a strategy for logging in through CAS.
func (c *Config) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	casURL, err := url.Parse(c.Portal)
	if err != nil {
		return "", fmt.Errorf("failed to parse casURL %q: %v", c.Portal, err)
	}

	if c.Spec == "custom" && len(c.Mapping) == 0 {
		return nil, fmt.Errorf("cas attribute mapping is empty")
	}

	return &casConnector{
		client:     http.DefaultClient,
		portal:     casURL,
		spec:       c.Spec,
		mapping:    c.Mapping,
		logger:     logger.With(slog.Group("connector", "type", "cas", "id", id)),
		pathSuffix: "/" + id,
	}, nil
}

var _ connector.CallbackConnector = (*casConnector)(nil)

type casConnector struct {
	client     *http.Client
	spec       string
	portal     *url.URL
	mapping    map[string]string
	logger     *slog.Logger
	pathSuffix string
}

// LoginURL returns the URL to redirect the user to login with.
func (m *casConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	u.Path += m.pathSuffix
	// context = $callbackURL + $m.pathSuffix
	v := u.Query()
	v.Set("context", u.String()) // without query params
	v.Set("state", state)
	u.RawQuery = v.Encode()

	loginURL := *m.portal
	loginURL.Path += "/login"
	// service = $callbackURL + $m.pathSuffix ? state=$state & context=$callbackURL + $m.pathSuffix
	q := loginURL.Query()
	q.Set("service", u.String()) // service = ...?state=...&context=...
	loginURL.RawQuery = q.Encode()
	return loginURL.String(), nil
}

// HandleCallback parses the request and returns the user's identity
func (m *casConnector) HandleCallback(s connector.Scopes, r *http.Request) (connector.Identity, error) {
	state := r.URL.Query().Get("state")
	ticket := r.URL.Query().Get("ticket")

	// service=context = $callbackURL + $m.pathSuffix
	serviceURL, err := url.Parse(r.URL.Query().Get("context"))
	if err != nil {
		return connector.Identity{}, fmt.Errorf("failed to parse serviceURL %q: %v", r.URL.Query().Get("context"), err)
	}
	// service = $callbackURL + $m.pathSuffix ? state=$state & context=$callbackURL + $m.pathSuffix
	q := serviceURL.Query()
	q.Set("context", serviceURL.String())
	q.Set("state", state)
	serviceURL.RawQuery = q.Encode()

	user, err := m.getCasUserByTicket(ticket, serviceURL)
	if err != nil {
		return connector.Identity{}, err
	}
	m.logger.Info("cas user", "user", user)
	return user, nil
}

func (m *casConnector) getCasUserByTicket(ticket string, serviceURL *url.URL) (connector.Identity, error) {
	validator := cas.NewServiceTicketValidator(m.client, m.portal)
	id := connector.Identity{}
	switch m.spec {
	case "", "standard":

		var resp *cas.AuthenticationResponse

		// validate ticket
		resp, err := validator.ValidateTicket(serviceURL, ticket)
		if err != nil {
			return id, errors.Wrapf(err, "failed to validate ticket via %q with ticket %q", serviceURL, ticket)
		}

		// fill identity
		id.UserID = resp.User
		id.Groups = resp.MemberOf
		if len(m.mapping) == 0 {
			return id, nil
		}
		if username, ok := m.mapping["username"]; ok {
			id.Username = resp.Attributes.Get(username)
			if id.Username == "" && username == "userid" {
				id.Username = resp.User
			}
		}
		if preferredUsername, ok := m.mapping["preferred_username"]; ok {
			id.PreferredUsername = resp.Attributes.Get(preferredUsername)
			if id.PreferredUsername == "" && preferredUsername == "userid" {
				id.PreferredUsername = resp.User
			}
		}
		if email, ok := m.mapping["email"]; ok {
			id.Email = resp.Attributes.Get(email)
			if id.Email != "" {
				id.EmailVerified = true
			}
		}
		// override memberOf
		if groups, ok := m.mapping["groups"]; ok {
			id.Groups = resp.Attributes[groups]
		}
		return id, nil

	case "custom":

		validateURL, err := validator.ValidateUrl(serviceURL, ticket)
		if err != nil {
			return id, fmt.Errorf("failed to construct validate url with service url %q and ticket %q: %v", serviceURL, ticket, err)
		}

		u, err := url.Parse(validateURL)
		if err != nil {
			return id, fmt.Errorf("failed to parse validate url %q: %v", validateURL, err)
		}

		// set charset
		q := u.Query()
		q.Set("codetype", "utf8")
		u.RawQuery = q.Encode()
		validateURL = u.String()

		// validate ticket
		resp, err := m.client.Get(validateURL)
		if err != nil {
			return id, fmt.Errorf("failed to validate ticket via %q: %v", validateURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return id, fmt.Errorf("failed to validate ticket: unexpected status code %d: %s", resp.StatusCode, string(body))
		}

		// construct cas attributes struct
		sfs := []reflect.StructField{}
		for k, v := range m.mapping {
			if k == "groups" {
				tags := strings.Split(v, ",")
				for i, tag := range tags {
					sfs = append(sfs, reflect.StructField{
						Name: fmt.Sprintf("Group%d", i),
						Type: reflect.TypeOf(""),
						Tag:  reflect.StructTag(fmt.Sprintf(`xml:"%s"`, tag)),
					})
				}
				continue
			}
			sfs = append(sfs, reflect.StructField{
				Name: strings.ToTitle(k),
				Type: reflect.TypeOf(""),
				Tag:  reflect.StructTag(fmt.Sprintf(`xml:"%s"`, v)),
			})
		}
		instance := reflect.New(reflect.StructOf(sfs))

		// decode xml
		decoder := xml.NewDecoder(resp.Body)
		decoder.CharsetReader = func(cs string, input io.Reader) (io.Reader, error) {
			if enc, _ := charset.Lookup(cs); enc != nil {
				return transform.NewReader(input, enc.NewDecoder()), nil
			}
			m.logger.Warn("unsupported charset", "name", cs)
			return transform.NewReader(input, encoding.Nop.NewDecoder()), nil
		}
		if err := decoder.Decode(instance.Interface()); err != nil {
			return id, fmt.Errorf("failed to decode validate response: %v", err)
		}

		// fill id
		if _, ok := m.mapping["userid"]; ok {
			id.UserID = instance.Elem().FieldByName(strings.ToTitle("userid")).String()
		}
		if _, ok := m.mapping["username"]; ok {
			id.Username = instance.Elem().FieldByName(strings.ToTitle("username")).String()
		}
		if _, ok := m.mapping["preferred_username"]; ok {
			id.PreferredUsername = instance.Elem().FieldByName(strings.ToTitle("preferred_username")).String()
		}
		if _, ok := m.mapping["email"]; ok {
			id.Email = instance.Elem().FieldByName(strings.ToTitle("email")).String()
			if id.Email != "" {
				id.EmailVerified = true
			}
		}
		if v, ok := m.mapping["groups"]; ok {
			count := len(strings.Split(v, ","))
			for i := 0; i < count; i++ {
				id.Groups = append(id.Groups, instance.Elem().FieldByName(fmt.Sprintf("Group%d", i)).String())
			}
		}

		// validate
		if id.UserID == "" {
			return id, fmt.Errorf("cas return empty userid")
		}
		return id, nil

	default:
		return id, fmt.Errorf("unsupported cas spec: %s", m.spec)
	}
}
