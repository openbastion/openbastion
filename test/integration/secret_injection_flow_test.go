package integration_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Proves the complete Vault -> SSH proxy -> target path, including MFA step-up
// through the public Gateway and the non-disclosure marker in Command Recorder.
func TestSecretInjectionFlow_VaultCredentialIsTypedButNotRecorded_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "vault-stepup")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-stepup")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authz-stepup")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authn-stepup")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "recorder-stepup")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "broker-stepup")
	proxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "proxy-stepup")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "gateway-stepup")

	key := testKMSKeyHex(t)
	vault := startService(t, root, vaultBin, "18301", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:18303")
	audit := startService(t, root, auditBin, "18302")
	auditSpy := startAuditSpy(t, audit.baseURL)
	authz := startService(t, root, authzBin, "18303")
	authn := startService(t, root, authnBin, "18304", "SKIP_DEMO_SEED=1", "MFA_SECRET_KEY_HEX="+key, "MFA_REQUIRED_ROLES=dba")
	recorder := startService(t, root, recorderBin, "18307", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
	proxy := startServiceWithExtraPort(t, root, proxyBin, "18305", "18306", "VAULT_URL="+vault.baseURL, "AUDIT_URL="+auditSpy.baseURL, "RECORDER_URL="+recorder.baseURL, "PROXY_SERVICE_ID=ssh-proxy", "RECORDING_POLICY=required", "SSH_PUBLIC_ENDPOINT=127.0.0.1:18306")
	broker := startService(t, root, brokerBin, "18308", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL, "AUDIT_URL="+audit.baseURL, "SSH_PROXY_URL="+proxy.baseURL, "AUTHENTICATION_URL="+authn.baseURL)
	gateway := startService(t, root, gatewayBin, "18309", "AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL, "COMMAND_RECORDER_URL="+recorder.baseURL)

	const accountID = "acc_stepup_it"
	const credential = "demo-value-42"
	target := startFakeTargetSSHServer(t, credential)
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "stepup-test-account", "root", target, credential, []string{"vault-admin"})
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "secret:inject:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "recording:session:*", "allow")
	authCreateUser(t, authn.baseURL, "stepup-operator", "Step-up Operator", "operator-password", []string{"dba"})

	status, login := postJSONTo(t, gateway.baseURL+"/auth/login", map[string]string{"username": "stepup-operator", "password": "operator-password"})
	if status != http.StatusUnauthorized || login["mfa"] != "enrollment_required" {
		t.Fatalf("MFA enrollment challenge: %d %#v", status, login)
	}
	loginChallenge := login["challenge"].(string)
	status, issued := postJSONTo(t, authn.baseURL+"/auth/v1/mfa/enrollment-codes", map[string]string{"source": "local", "loginName": "stepup-operator"})
	if status != http.StatusOK || issued["enrollmentCode"] == nil {
		t.Fatalf("enrollment code: %d %#v", status, issued)
	}
	status, enrolled := postJSONTo(t, gateway.baseURL+"/auth/mfa/enroll", map[string]string{"challenge": loginChallenge, "enrollmentCode": issued["enrollmentCode"].(string), "factor": "totp"})
	if status != http.StatusOK || enrolled["secret"] == nil {
		t.Fatalf("enroll TOTP: %d %#v", status, enrolled)
	}
	totpSecret := enrolled["secret"].(string)
	enrollmentStep := time.Now().Unix() / 30
	status, confirmed := postJSONTo(t, gateway.baseURL+"/auth/mfa/enroll/confirm", map[string]string{"challenge": loginChallenge, "code": totpCode(t, totpSecret, time.Unix(enrollmentStep*30+1, 0))})
	loginStep := enrollmentStep + 1
	if status != http.StatusOK || confirmed["accessToken"] == nil {
		t.Fatalf("confirm TOTP: %d %#v", status, confirmed)
	}
	status, login = postJSONTo(t, gateway.baseURL+"/auth/login", map[string]string{"username": "stepup-operator", "password": "operator-password"})
	if status != http.StatusUnauthorized || login["mfa"] != "required" {
		t.Fatalf("MFA login challenge: %d %#v", status, login)
	}
	status, authenticated := postJSONTo(t, gateway.baseURL+"/auth/mfa/verify", map[string]string{"challenge": login["challenge"].(string), "code": totpCode(t, totpSecret, time.Unix(loginStep*30+1, 0))})
	if status != http.StatusOK || authenticated["accessToken"] == nil {
		t.Fatalf("verify login MFA: %d %#v", status, authenticated)
	}
	token := authenticated["accessToken"].(string)

	sess, status := gatewayCreateSession(t, gateway.baseURL, token, "forged-actor", []string{"platform-admin"}, accountID)
	if status != http.StatusCreated || sess == nil {
		t.Fatalf("create session: %d %#v", status, sess)
	}
	_, ticket, status := gatewayConnect(t, gateway.baseURL, token, sess.ID)
	if status != http.StatusOK || ticket == "" {
		t.Fatalf("connect: %d", status)
	}
	client, err := ssh.Dial("tcp", "127.0.0.1:18306", &ssh.ClientConfig{User: "operator", Auth: []ssh.AuthMethod{ssh.Password(ticket)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	sshSession, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sshSession.Close()
	if err := sshSession.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sshSession.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sshSession.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sshSession.Shell(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 16)
	go func() {
		reader := bufio.NewReader(stdout)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			lines <- line
		}
	}()
	_, _ = fmt.Fprintln(stdin, "ready-check")
	waitForTargetLine(t, lines, "echo:ready-check")
	waitForTOTPStep(t, loginStep)

	request, _ := http.NewRequest(http.MethodPost, gateway.baseURL+"/sessions/"+sess.ID+"/secret-injection-step-up", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var stepUp map[string]any
	_ = json.NewDecoder(response.Body).Decode(&stepUp)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || stepUp["challenge"] == nil {
		t.Fatalf("step-up: %d Cache-Control=%q %#v", response.StatusCode, response.Header.Get("Cache-Control"), stepUp)
	}
	factors, _ := stepUp["factors"].([]any)
	if len(factors) != 1 || factors[0] != "totp" {
		t.Fatalf("factors: %#v", factors)
	}

	proof, _ := json.Marshal(map[string]any{"challenge": stepUp["challenge"], "factor": "totp", "totp_code": totpCode(t, totpSecret, time.Unix((loginStep+1)*30+1, 0))})
	request, _ = http.NewRequest(http.MethodPost, gateway.baseURL+"/sessions/"+sess.ID+"/secret-injection", bytes.NewReader(proof))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("Cache-Control") != "no-store" || body.Len() != 0 {
		t.Fatalf("inject: %d Cache-Control=%q body=%q", response.StatusCode, response.Header.Get("Cache-Control"), body.String())
	}
	waitForTargetLine(t, lines, "echo:"+credential)

	// The Audit Service commits the terminal event, but the acknowledgement is lost on
	// the response path. The proxy must report outcome_unknown and must not type again.
	auditSpy.dropNextAck("session.secret_injected")
	waitForTOTPStepTimeout(t, loginStep+2, 75*time.Second)
	unknownStatus, unknownHeaders, unknownBody := injectSecretWithTOTP(t, gateway.baseURL, sess.ID, token, totpSecret, loginStep+2)
	var unknown map[string]any
	if err := json.Unmarshal(unknownBody, &unknown); err != nil {
		t.Fatalf("outcome_unknown response is not JSON: %v body=%q", err, unknownBody)
	}
	injectionID, _ := unknown["injection_id"].(string)
	if unknownStatus != http.StatusOK || unknownHeaders.Get("Cache-Control") != "no-store" ||
		unknown["status"] != "outcome_unknown" || len(injectionID) != 32 ||
		!strings.Contains(fmt.Sprint(unknown["message"]), "Do not retry") {
		t.Fatalf("lost acknowledgement response: status=%d headers=%v body=%s", unknownStatus, unknownHeaders, unknownBody)
	}
	waitForTargetLine(t, lines, "echo:"+credential)
	waitForNoTargetLine(t, lines, "echo:"+credential, 750*time.Millisecond)
	if auditSpy.ackDrops() != 1 || auditSpy.count("session.secret_injected", sess.ID) != 2 || auditSpy.count("session.secret_injection_started", sess.ID) != 2 {
		t.Fatalf("expected exactly one committed terminal event for each attempt and one lost acknowledgement: drops=%d started=%d terminal=%d", auditSpy.ackDrops(), auditSpy.count("session.secret_injection_started", sess.ID), auditSpy.count("session.secret_injected", sess.ID))
	}

	readRequest, _ := http.NewRequest(http.MethodGet, gateway.baseURL+"/sessions/"+sess.ID+"/recording?page=1&pageSize=100", nil)
	readRequest.Header.Set("Authorization", "Bearer "+token)
	readResponse, err := http.DefaultClient.Do(readRequest)
	if err != nil {
		t.Fatal(err)
	}
	var recording map[string]any
	_ = json.NewDecoder(readResponse.Body).Decode(&recording)
	readResponse.Body.Close()
	if readResponse.StatusCode != http.StatusOK {
		t.Fatalf("recording: %d %#v", readResponse.StatusCode, recording)
	}
	entries, _ := recording["entries"].([]any)
	marker := "[vault secret " + accountID + " injection requested via ssh operation "
	foundMarker := false
	for _, raw := range entries {
		entry, _ := raw.(map[string]any)
		command := fmt.Sprint(entry["command"])
		if strings.Contains(command, credential) {
			t.Fatalf("credential recorded: %q", command)
		}
		if strings.Contains(command, marker) && len(command) >= len(marker)+32 && strings.Contains(command, "]") {
			foundMarker = true
		}
	}
	if !foundMarker {
		t.Fatalf("marker missing from recording: %#v", recording)
	}
	for name, output := range map[string]string{"Gateway": gateway.out.String(), "Broker": broker.out.String(), "proxy": proxy.out.String(), "recorder": recorder.out.String(), "audit": audit.out.String()} {
		if strings.Contains(output, credential) {
			t.Fatalf("credential leaked to %s log", name)
		}
	}
	chain, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
	if err != nil {
		t.Fatal(err)
	}
	chain.Body.Close()
	if chain.StatusCode != http.StatusOK {
		t.Fatalf("audit chain: %d", chain.StatusCode)
	}
}

func waitForTargetLine(t *testing.T, lines <-chan string, expected string) string {
	t.Helper()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line := <-lines:
			if strings.Contains(line, expected) {
				return line
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for target output %q", expected)
			return ""
		}
	}
}

func injectSecretWithTOTP(t *testing.T, gatewayURL, sessionID, token, totpSecret string, step int64) (int, http.Header, []byte) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, gatewayURL+"/sessions/"+sessionID+"/secret-injection-step-up", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var stepUp map[string]any
	_ = json.NewDecoder(response.Body).Decode(&stepUp)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || stepUp["challenge"] == nil {
		t.Fatalf("step-up: %d Cache-Control=%q %#v", response.StatusCode, response.Header.Get("Cache-Control"), stepUp)
	}
	proof, _ := json.Marshal(map[string]any{
		"challenge": stepUp["challenge"], "factor": "totp",
		"totp_code": totpCode(t, totpSecret, time.Unix(step*30+1, 0)),
	})
	request, _ = http.NewRequest(http.MethodPost, gatewayURL+"/sessions/"+sessionID+"/secret-injection", bytes.NewReader(proof))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(response.Body)
	response.Body.Close()
	return response.StatusCode, response.Header.Clone(), body.Bytes()
}

func waitForNoTargetLine(t *testing.T, lines <-chan string, expected string, duration time.Duration) {
	t.Helper()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	for {
		select {
		case line := <-lines:
			if strings.Contains(line, expected) {
				t.Fatalf("target received an unexpected replay after outcome_unknown: %q", line)
			}
		case <-timer.C:
			return
		}
	}
}

func waitForTOTPStep(t *testing.T, minimumStep int64) {
	waitForTOTPStepTimeout(t, minimumStep, 35*time.Second)
}

func waitForTOTPStepTimeout(t *testing.T, minimumStep int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Unix()/30 < minimumStep {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for TOTP step %d", minimumStep)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
