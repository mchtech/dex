// Package authproxy implements a connector which relies on external
// authentication (e.g. mod_auth in Apache2) and returns an identity with the
// HTTP header X-Remote-User as verified email.
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
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/transform"
	"gopkg.in/cas.v2"
)

// Config holds the configuration parameters for a connector which returns an
// identity with the HTTP header X-Remote-User as verified email,
// X-Remote-Group and configured staticGroups as user's group.
// Headers retrieved to fetch user's email and group can be configured
// with userHeader and groupHeader.
type Config struct {
	Portal  string            `json:"portal"`
	Spec    string            `json:"spec"`
	Mapping map[string]string `json:"mapping"`
}

// Open returns an authentication strategy which requires no user interaction.
func (c *Config) Open(id string, logger *slog.Logger) (connector.Connector, error) {

	if c.Spec == "custom" && len(c.Mapping) == 0 {
		return nil, fmt.Errorf("cas attribute mapping is empty")
	}

	return &callback{
		portal:     c.Portal,
		spec:       c.Spec,
		mapping:    c.Mapping,
		logger:     logger.With(slog.Group("connector", "type", "cas", "id", id)),
		pathSuffix: "/" + id,
	}, nil
}

// Callback is a connector which returns an identity with the HTTP header
// X-Remote-User as verified email.
type callback struct {
	portal     string
	spec       string
	mapping    map[string]string
	logger     *slog.Logger
	pathSuffix string
}

// LoginURL returns the URL to redirect the user to login with.
func (m *callback) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
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

	casURL, err := url.Parse(m.portal)
	if err != nil {
		return "", fmt.Errorf("failed to parse casURL %q: %v", m.portal, err)
	}
	casURL.Path += "/login"
	// service = $callbackURL + $m.pathSuffix ? state=$state & context=$callbackURL + $m.pathSuffix
	q := casURL.Query()
	q.Set("service", u.String()) // service = ...?state=...&context=...
	casURL.RawQuery = q.Encode()

	return casURL.String(), nil
}

// HandleCallback parses the request and returns the user's identity
func (m *callback) HandleCallback(s connector.Scopes, r *http.Request) (connector.Identity, error) {

	state := r.URL.Query().Get("state")
	ticket := r.URL.Query().Get("ticket")

	casURL, err := url.Parse(m.portal)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("failed to parse casURL %q: %v", m.portal, err)
	}
	// service=context = $callbackURL + $m.pathSuffix
	serviceURL, err := url.Parse(r.URL.Query().Get("context"))
	if err != nil {
		return connector.Identity{}, fmt.Errorf("failed to parse serviceURL %q: %v", r.URL.Query().Get("ext"), err)
	}
	// service = $callbackURL + $m.pathSuffix ? state=$state & context=$callbackURL + $m.pathSuffix
	q := serviceURL.Query()
	q.Set("context", serviceURL.String())
	q.Set("state", state)
	serviceURL.RawQuery = q.Encode()

	user, err := m.getCasUserByTicket(ticket, casURL, serviceURL)
	if err != nil {
		return connector.Identity{}, err
	}
	m.logger.Info("cas user", "user", user)
	return user, nil
}

func (m *callback) getCasUserByTicket(ticket string, casUrl, serviceUrl *url.URL) (id connector.Identity, err error) {

	validator := cas.NewServiceTicketValidator(http.DefaultClient, casUrl)

	switch m.spec {
	case "", "standard":

		var (
			resp *cas.AuthenticationResponse
		)

		// validate ticket
		if resp, err = validator.ValidateTicket(serviceUrl, ticket); err != nil {
			err = fmt.Errorf("failed to validate ticket via %q with ticket %q: %v", serviceUrl, ticket, err)
			return
		}

		// fill identity
		id.UserID = resp.User
		id.Groups = resp.MemberOf
		if len(m.mapping) == 0 {
			return
		}
		if username, ok := m.mapping["username"]; ok {
			id.Username = resp.Attributes.Get(username)
		}
		if preferredUsername, ok := m.mapping["preferred_username"]; ok {
			id.PreferredUsername = resp.Attributes.Get(preferredUsername)
		}
		if email, ok := m.mapping["email"]; ok {
			id.Email = resp.Attributes.Get(email)
			if id.Email != "" {
				id.EmailVerified = true
			}
		}
		return

	case "custom":

		var (
			resp        *http.Response
			body        []byte
			validateURL string
			u           *url.URL
		)

		if validateURL, err = validator.ValidateUrl(serviceUrl, ticket); err != nil {
			err = fmt.Errorf("failed to construct validate url with service url %q and ticket %q: %v", serviceUrl, ticket, err)
			return
		}

		if u, err = url.Parse(validateURL); err != nil {
			err = fmt.Errorf("failed to parse validate url %q: %v", validateURL, err)
			return
		}

		// set charset
		q := u.Query()
		q.Set("codetype", "utf8")
		u.RawQuery = q.Encode()
		validateURL = u.String()

		// validate ticket
		if resp, err = http.DefaultClient.Get(validateURL); err != nil {
			err = fmt.Errorf("failed to validate ticket via %q: %v", validateURL, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ = io.ReadAll(resp.Body)
			err = fmt.Errorf("failed to validate ticket: unexpected status code %d: %s", resp.StatusCode, string(body))
			return
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
		if err = decoder.Decode(instance.Interface()); err != nil {
			err = fmt.Errorf("failed to decode validate response: %v", err)
			return
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
			err = fmt.Errorf("cas return empty userid")
		}
		return

	default:
		err = fmt.Errorf("unsupported cas spec: %s", m.spec)
		return

	}
}
