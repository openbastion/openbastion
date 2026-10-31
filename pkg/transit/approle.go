package transit

// AppRole (ADR-0058): the service logs in itself, with a role_id and a secret_id read from files,
// renews the token it gets, and logs in again once that token has reached its maximum life.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type appRole struct {
	mount, roleIDFile, secretIDFile string
}

func (a *appRole) read() (roleID, secretID string, err error) {
	if roleID, err = readSecretFile("TRANSIT_ROLE_ID_FILE", "role_id", a.roleIDFile); err != nil {
		return "", "", err
	}
	if secretID, err = readSecretFile("TRANSIT_SECRET_ID_FILE", "secret_id", a.secretIDFile); err != nil {
		return "", "", err
	}
	return roleID, secretID, nil
}

// Login logs in by AppRole (auth/<mount>/login), with the two files read again, and takes the token
// it gets for every call that follows. It returns that token's life — zero for one without an end.
// The error holds neither the role_id, nor the secret_id, nor any token.
func (c *Client) Login(ctx context.Context) (time.Duration, error) {
	if c.approle == nil {
		return 0, errors.New("transit login: the service does not log in by AppRole")
	}
	roleID, secretID, err := c.approle.read()
	if err != nil {
		return 0, err
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := c.doAs(ctx, "", "login", http.MethodPost, "/v1/auth/"+c.approle.mount+"/login", map[string]string{"role_id": roleID, "secret_id": secretID}, &out); err != nil {
		return 0, errors.New(strings.NewReplacer(secretID, "[secret_id]", roleID, "[role_id]").Replace(err.Error()))
	}
	if out.Auth.ClientToken == "" || strings.ContainsAny(out.Auth.ClientToken, " \t\r\n") {
		return 0, fmt.Errorf("transit login at %s: the answer holds no token", c.base)
	}
	c.tokenMu.Lock()
	c.token = out.Auth.ClientToken
	c.tokenMu.Unlock()
	return time.Duration(out.Auth.LeaseDuration) * time.Second, nil
}

// keepLoggedIn is KeepAlive with AppRole: the token is renewed at half its life; a renewal refused,
// or that gives less than the token had when it was logged in (it has reached its maximum), makes
// the service log in again. A login that fails is tried again at a quarter of the time left, never
// sooner than the floor, and every failure is said.
func (c *Client) keepLoggedIn(ctx context.Context, logf func(format string, args ...any)) {
	full, renewable, err := c.TokenLife(ctx)
	if err != nil || c.currentToken() == "" {
		if full, err = c.Login(ctx); err != nil {
			logf("transit: AppRole: no token (%v): every key operation fails until a login succeeds", err)
			full = 0
		}
		renewable = true
	}
	if err == nil && full <= 0 {
		logf("transit: AppRole: the token has no end: it is not renewed")
		return
	}
	if err == nil {
		logf("transit: AppRole: the token is renewed at half its life (now %s left), and a new one is logged in once it reaches its maximum", full)
	}
	deadline := time.Now().Add(full)
	wait := full / 2
	if wait < c.renewFloor {
		wait = c.renewFloor
	}
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if renewable {
			if next, err := c.RenewSelf(ctx); err == nil && next >= full {
				deadline, wait = time.Now().Add(next), next/2
				continue
			}
		}
		life, err := c.Login(ctx)
		if err == nil && life > 0 {
			full, renewable = life, true
			deadline, wait = time.Now().Add(life), life/2
			logf("transit: AppRole: a new token is logged in (%s): it is used from now on", life)
			continue
		}
		if err == nil {
			logf("transit: AppRole: the new token has no end: it is not renewed")
			return
		}
		wait = time.Until(deadline) / 4
		if wait < c.renewFloor {
			wait = c.renewFloor
		}
		logf("transit: AppRole: no new token (%v): tried again in %s; the current one ends at %s", err, wait.Round(time.Second), deadline.UTC().Format(time.RFC3339))
	}
}
