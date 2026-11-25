package integration_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/openbastion/openbastion/pkg/mtls"
)

// TestADR0138WorkflowApproval_MTLSPostgres proves the ordinary approval path through
// independently running services. The Broker and Workflow use separate PostgreSQL
// databases; Authentication, Authorization and Vault are real processes; every
// service-to-service call is mutually authenticated. The public Gateway remains HTTP,
// as in production behind the TLS-terminating edge proxy.
//
// The three database URLs are intentionally explicit: each service owns its schema and
// the Audit chain's external anchor must be unique to the database under test.
func TestADR0138WorkflowApproval_MTLSPostgres(t *testing.T) {
	workflowDSN := os.Getenv("ADR0138_WORKFLOW_DATABASE_URL")
	brokerDSN := os.Getenv("ADR0138_BROKER_DATABASE_URL")
	auditDSN := os.Getenv("ADR0138_AUDIT_DATABASE_URL")
	if workflowDSN == "" || brokerDSN == "" || auditDSN == "" {
		t.Skip("set ADR0138_WORKFLOW_DATABASE_URL, ADR0138_BROKER_DATABASE_URL and ADR0138_AUDIT_DATABASE_URL to dedicated PostgreSQL databases")
	}

	root := repoRoot(t)
	bins := map[string]string{}
	for name, pkg := range map[string]string{
		"audit":    "./services/recording-audit/audit-service/cmd/audit-service",
		"authz":    "./services/access/authorization/cmd/authorization",
		"authn":    "./services/access/authentication/cmd/authentication",
		"vault":    "./services/vault/password-vault/cmd/password-vault",
		"workflow": "./services/access/workflow-service/cmd/workflow-service",
		"broker":   "./services/access/session-broker/cmd/session-broker",
		"gateway":  "./services/access/api-gateway/cmd/api-gateway",
	} {
		bins[name] = buildBinary(t, root, pkg, "adr0138-"+name)
	}
	// Mint short-lived certificates only after the potentially slow first-time builds.
	pki := newTestPKI(t)

	const (
		auditPort    = "19961"
		authzPort    = "19962"
		authnPort    = "19963"
		vaultPort    = "19964"
		workflowPort = "19965"
		brokerPort   = "19966"
		gatewayPort  = "19967"
		accountID    = "acc_adr0138_e2e"
	)

	anchorFile := filepath.Join(t.TempDir(), "audit-chain.anchor")
	auditKey := strings.Repeat("31", 32)
	audit := startMTLSService(t, root, bins["audit"], auditPort, pki, mtls.AuditService,
		"DATABASE_URL="+auditDSN,
		"AUDIT_CHAIN_KEY_HEX="+auditKey,
		"AUDIT_ANCHOR_FILE="+anchorFile,
	)
	authz := startMTLSService(t, root, bins["authz"], authzPort, pki, mtls.Authorization)
	authn := startMTLSService(t, root, bins["authn"], authnPort, pki, mtls.Authentication,
		"SKIP_DEMO_SEED=1",
		"AUDIT_URL="+audit.baseURL,
		"AUTHORIZATION_URL="+authz.baseURL,
	)
	vault := startMTLSService(t, root, bins["vault"], vaultPort, pki, mtls.PasswordVault,
		"SKIP_DEMO_SEED=1",
		"AUTHORIZATION_URL="+authz.baseURL,
		"AUDIT_URL="+audit.baseURL,
	)
	workflow := startMTLSService(t, root, bins["workflow"], workflowPort, pki, mtls.WorkflowService,
		"DATABASE_URL="+workflowDSN,
		"AUTHENTICATION_URL="+authn.baseURL,
		"AUTHORIZATION_URL="+authz.baseURL,
		"AUDIT_URL="+audit.baseURL,
	)
	broker := startMTLSService(t, root, bins["broker"], brokerPort, pki, mtls.SessionBroker,
		"DATABASE_URL="+brokerDSN,
		"AUTHENTICATION_URL="+authn.baseURL,
		"AUTHORIZATION_URL="+authz.baseURL,
		"VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+audit.baseURL,
		"WORKFLOW_SERVICE_URL="+workflow.baseURL,
		"APPROVAL_TICKET_PATTERN=(INC|CHG)[0-9]{7}",
	)
	// The Gateway's public listener is deliberately plain HTTP: TLS terminates at the
	// edge proxy. pki.env still gives its upstream client the api-gateway identity.
	uiDir := filepath.Join(root, "web/admin-ui/dist")
	_, uiBuildErr := os.Stat(filepath.Join(uiDir, "index.html"))
	gatewayEnv := pki.env(mtls.APIGateway,
		"AUTHENTICATION_URL="+authn.baseURL,
		"SESSION_BROKER_URL="+broker.baseURL,
		"VAULT_URL="+vault.baseURL,
		"AUTHORIZATION_URL="+authz.baseURL,
		"WORKFLOW_SERVICE_URL="+workflow.baseURL,
		"AUDIT_URL="+audit.baseURL,
		"CLIENT_LOGIN_BURST=100",
		"CLIENT_LOGIN_RATE_PER_MINUTE=60",
		"CLIENT_REQUEST_BURST=1000",
		"CLIENT_REQUEST_RATE_PER_MINUTE=1000",
	)
	if uiBuildErr == nil {
		gatewayEnv = append(gatewayEnv, "ADMIN_UI_DIR="+uiDir)
	}
	gateway := startService(t, root, bins["gateway"], gatewayPort, gatewayEnv...)

	adminClient := pki.clientAs(t, mtls.AdminCLI)
	mtlsCreateUser(t, adminClient, authn.baseURL, "adr0138-admin", "adr0138-admin-password", []string{"platform-admin", "vault-admin", "change-manager"})
	mtlsCreateUser(t, adminClient, authn.baseURL, "adr0138-requester", "adr0138-requester-password", []string{"dba"})
	mtlsCreateUser(t, adminClient, authn.baseURL, "adr0138-manager-b", "adr0138-manager-b-password", []string{"change-manager"})

	adminToken, status := gatewayLogin(t, gateway.baseURL, "adr0138-admin", "adr0138-admin-password")
	if status != http.StatusOK {
		t.Fatalf("admin login: %d", status)
	}
	requesterToken, status := gatewayLogin(t, gateway.baseURL, "adr0138-requester", "adr0138-requester-password")
	if status != http.StatusOK {
		t.Fatalf("requester login: %d", status)
	}
	managerAToken := adminToken
	managerBToken, status := gatewayLogin(t, gateway.baseURL, "adr0138-manager-b", "adr0138-manager-b-password")
	if status != http.StatusOK {
		t.Fatalf("manager B login: %d", status)
	}
	requesterID, managerAID, managerBID := userIDOf(t, requesterToken), userIDOf(t, adminToken), userIDOf(t, managerBToken)

	for _, policy := range []struct{ name, role, resource string }{
		{"adr0138-vault-admin", "vault-admin", "vault:account-admin:*"},
		{"adr0138-hierarchy-admin", "platform-admin", "approval-hierarchy:all"},
		{"adr0138-requester", "dba", "vault:account:" + accountID},
		{"adr0138-manager", "change-manager", "session-approve:account:" + accountID},
	} {
		if got := gatewayCreatePolicy(t, gateway.baseURL, adminToken, policy.name, policy.role, policy.resource, "allow", "forged-creator"); got != http.StatusCreated {
			t.Fatalf("create policy %s: %d", policy.name, got)
		}
	}

	capabilities := gatewayCapabilities(t, gateway.baseURL, adminToken)
	for _, name := range []string{"approvalHierarchy.read", "approvalHierarchy.manage", "approvalHierarchy.reports"} {
		if !capabilities[name] {
			t.Fatalf("Gateway did not expose %s to the hierarchy administrator: %v", name, capabilities)
		}
	}
	if uiBuildErr == nil {
		assertGatewayAdminUI(t, gateway.baseURL)
	}

	if got := gatewayOnboardAccount(t, gateway.baseURL, adminToken, accountID, "ADR-0138 E2E account", "root", "127.0.0.1", "not-a-real-secret"); got != http.StatusCreated {
		t.Fatalf("onboard account: %d", got)
	}
	if got, body := gatewaySetApproval(t, gateway.baseURL, adminToken, accountID, `{"approvalRequired":true}`); got != http.StatusOK {
		t.Fatalf("require account approval: %d %s", got, body)
	}

	// The public Gateway forwards only the manager ID and revision precondition;
	// the browser performs the first assignment through the real Admin UI when a
	// headless Chrome is available. API fallback keeps the PostgreSQL/mTLS test useful
	// in minimal environments without a browser binary.
	managerURL := gateway.baseURL + "/approval-hierarchy/users/" + requesterID + "/manager"
	etag, status, body := gatewayManagerETag(t, managerURL, adminToken)
	baseRevision := parseHierarchyRevision(t, etag)
	if status != http.StatusOK {
		t.Fatalf("initial hierarchy read: status=%d etag=%q body=%s", status, etag, body)
	}
	var browserPage *cdpPage
	chrome := findChrome()
	if os.Getenv("OPENBASTION_ADR0138_BROWSER_REQUIRED") == "1" && (chrome == "" || uiBuildErr != nil) {
		t.Fatalf("the PostgreSQL CI gate requires Chromium and a built Admin UI (chrome=%q, uiBuildErr=%v)", chrome, uiBuildErr)
	}
	if chrome != "" && uiBuildErr == nil {
		browserPage = startHeadlessChrome(t, chrome)
		browserPage.dump = os.Getenv("ADMIN_UI_BROWSER_DUMP")
		browserPage.viewport(1440, 1000)
		browserPage.call("Page.navigate", map[string]any{"url": gateway.baseURL + "/ui/"})
		browserPage.signIn("adr0138-admin", "adr0138-admin-password")
		browserPage.clickButton("Accès privilégiés")
		browserPage.waitTrue("hierarchy tab", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Hiérarchie")`, 15*time.Second)
		clickBrowserTab(t, browserPage, "Hiérarchie")
		browserPage.waitTrue("hierarchy manager form", `!!document.querySelector('section[aria-labelledby="hierarchy-manager-title"] form')`, 15*time.Second)
		browserPage.fill(`section[aria-labelledby="hierarchy-manager-title"] form:first-of-type input`, requesterID)
		browserPage.clickButton("Consulter")
		browserPage.waitTrue("unassigned user lookup", `document.body.innerText.includes("Aucun supérieur défini")`, 15*time.Second)
		browserPage.fill(`section[aria-labelledby="hierarchy-manager-title"] form:last-of-type input`, managerAID)
		browserPage.clickButton("Enregistrer le supérieur")
		browserPage.waitTrue("hierarchy confirmation", `!!document.querySelector('[role="alertdialog"]')`, 10*time.Second)
		browserPage.eval(`(() => { const d = document.querySelector('[role="alertdialog"]'); const b = [...d.querySelectorAll("button")].find((x) => x.innerText.trim() === "Enregistrer le supérieur"); if (!b) throw new Error("missing hierarchy confirmation"); b.click(); return true; })()`)
		browserPage.waitTrue("hierarchy assignment success", `document.body.innerText.includes("Supérieur direct actuel : `+managerAID+`")`, 15*time.Second)
	} else {
		t.Logf("Chromium/Admin UI unavailable; executing the API/PostgreSQL/mTLS fallback (chrome=%q, uiBuildErr=%v)", chrome, uiBuildErr)
		etag, status, body = gatewaySetManager(t, managerURL, adminToken, managerAID, etag)
		if status != http.StatusOK {
			t.Fatalf("assign manager A: status=%d etag=%q body=%s", status, etag, body)
		}
	}
	etag, status, body = gatewayManagerETag(t, managerURL, adminToken)
	if status != http.StatusOK || parseHierarchyRevision(t, etag) != baseRevision+1 {
		t.Fatalf("verify manager A assignment: status=%d etag=%q body=%s", status, etag, body)
	}

	// The requester attempts to smuggle manager B in the request body. The Gateway
	// and Workflow derive the approver exclusively from the managed hierarchy.
	requestBody := map[string]any{
		"targetAccountId": accountID, "protocol": "ssh", "justification": "ADR-0138 end-to-end approval",
		"durationMinutes": 30, "ticket": "CHG0138001", "approverUserId": managerBID,
	}
	status, sessionRaw := gatewayJSONRequest(t, gateway.baseURL, http.MethodPost, "/sessions", requesterToken, requestBody, nil)
	if status != http.StatusCreated {
		t.Fatalf("create approval-required session: %d %s", status, sessionRaw)
	}
	var created struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(sessionRaw), &created); err != nil {
		t.Fatalf("decode created session: %v (%s)", err, sessionRaw)
	}
	if created.ID == "" || created.Status != "pending_approval" {
		t.Fatalf("unexpected pending session: %+v", created)
	}

	workflowDB := openE2EDatabase(t, workflowDSN)
	var assignedApprover string
	var hierarchyRevision int64
	waitUntil(t, 15*time.Second, "durable Workflow approval snapshot", func() bool {
		err := workflowDB.QueryRow(`SELECT approver_user_id, hierarchy_revision FROM workflow_approvals WHERE workflow_request_id = $1`, created.ID).Scan(&assignedApprover, &hierarchyRevision)
		return err == nil
	})
	if assignedApprover != managerAID || hierarchyRevision != int64(baseRevision+1) {
		t.Fatalf("initial Workflow snapshot: approver=%s hierarchyRevision=%d, want %s / %d", assignedApprover, hierarchyRevision, managerAID, baseRevision+1)
	}

	// Change the hierarchy only after Workflow has committed its snapshot. The
	// existing request must remain assigned to manager A at revision 1.
	etag, status, body = gatewaySetManager(t, managerURL, adminToken, managerBID, etag)
	if status != http.StatusOK || parseHierarchyRevision(t, etag) != baseRevision+2 {
		t.Fatalf("replace manager after request: status=%d etag=%q body=%s", status, etag, body)
	}

	status, raw := gatewayList(t, gateway.baseURL, managerAToken, "status=pending_approval&page=1&pageSize=100")
	if status != http.StatusOK {
		t.Fatalf("manager A approval queue: %d %s", status, raw)
	}
	var managerAPage pendingList
	if err := json.Unmarshal([]byte(raw), &managerAPage); err != nil || len(managerAPage.Items) != 1 || managerAPage.Items[0].ID != created.ID {
		t.Fatalf("manager A lost the snapshotted request after hierarchy update: %s (%v)", raw, err)
	}
	status, raw = gatewayList(t, gateway.baseURL, managerBToken, "status=pending_approval&page=1&pageSize=100")
	if status != http.StatusOK {
		t.Fatalf("manager B approval queue: %d %s", status, raw)
	}
	var managerBPage pendingList
	if err := json.Unmarshal([]byte(raw), &managerBPage); err != nil || len(managerBPage.Items) != 0 {
		t.Fatalf("manager B inherited an existing request after hierarchy update: %s (%v)", raw, err)
	}
	status, raw = gatewayList(t, gateway.baseURL, requesterToken, "status=pending_approval&page=1&pageSize=100")
	if status != http.StatusOK {
		t.Fatalf("requester approval queue: %d %s", status, raw)
	}
	var requesterPage pendingList
	if err := json.Unmarshal([]byte(raw), &requesterPage); err != nil || len(requesterPage.Items) != 0 {
		t.Fatalf("requester saw an approval assigned to another user: %s (%v)", raw, err)
	}

	if status, raw = gatewayDecide(t, gateway.baseURL, managerBToken, created.ID, "approve", `{"decidedBy":"`+managerAID+`","actorRoles":["platform-admin"]}`); status != http.StatusForbidden {
		t.Fatalf("new manager must not decide an already snapshotted request: %d %s", status, raw)
	}
	if status, raw = gatewayDecide(t, gateway.baseURL, requesterToken, created.ID, "approve", `{"decidedBy":"`+managerAID+`","actorRoles":["platform-admin"]}`); status != http.StatusForbidden {
		t.Fatalf("requester must not self-approve: %d %s", status, raw)
	}
	if browserPage != nil {
		// Remount Accounts so the real UI reloads its bounded approval queue after
		// the session was created by the API above.
		browserPage.clickButton("Vue d’ensemble")
		browserPage.clickButton("Accès privilégiés")
		browserPage.waitTrue("approval requests tab", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim().startsWith("Demandes"))`, 15*time.Second)
		clickBrowserTab(t, browserPage, "Demandes")
		browserPage.waitTrue("pending request in Admin UI", `document.body.innerText.includes(`+fmt.Sprintf("%q", created.ID)+`)`, 20*time.Second)
		browserPage.clickButton("Approuver")
		browserPage.waitTrue("approval confirmation dialog", `!!document.querySelector('[role="alertdialog"]')`, 10*time.Second)
		browserPage.eval(`(() => { const d = document.querySelector('[role="alertdialog"]'); const b = [...d.querySelectorAll("button")].find((x) => x.innerText.trim() === "Confirmer l'approbation"); if (!b) throw new Error("missing approval confirmation"); b.click(); return true; })()`)
		browserPage.waitTrue("Admin UI approval success", `document.body.innerText.includes(`+fmt.Sprintf("%q", created.ID+" approuvée")+`)`, 15*time.Second)
	} else if status, raw = gatewayDecide(t, gateway.baseURL, managerAToken, created.ID, "approve", `{"decidedBy":"forged-user","actorRoles":["platform-admin"]}`); status != http.StatusOK {
		t.Fatalf("snapshotted manager approval: %d %s", status, raw)
	}

	waitUntil(t, 10*time.Second, "approved session state", func() bool {
		session := gatewayGetSession(t, gateway.baseURL, requesterToken, created.ID)
		return session["status"] == "active" && session["decidedBy"] == managerAID
	})

	// PostgreSQL proves the immutable snapshot, final decision, and durable outbox
	// completion independently of the API response.
	var finalDecision, decidedBy string
	if err := workflowDB.QueryRow(`SELECT a.approver_user_id, a.status, a.decided_by, a.hierarchy_revision
		FROM workflow_approvals a JOIN workflow_requests r ON r.id = a.workflow_request_id
		WHERE r.resource_id = $1`, created.ID).Scan(&assignedApprover, &finalDecision, &decidedBy, &hierarchyRevision); err != nil {
		t.Fatalf("read workflow snapshot: %v", err)
	}
	if assignedApprover != managerAID || finalDecision != "approved" || decidedBy != managerAID || hierarchyRevision != int64(baseRevision+1) {
		t.Fatalf("workflow snapshot/decision mismatch: approver=%s status=%s decidedBy=%s hierarchyRevision=%d", assignedApprover, finalDecision, decidedBy, hierarchyRevision)
	}
	brokerDB := openE2EDatabase(t, brokerDSN)
	var pendingOutbox int
	if err := brokerDB.QueryRow(`SELECT count(*) FROM session_workflow_outbox WHERE session_id = $1`, created.ID).Scan(&pendingOutbox); err != nil {
		t.Fatalf("read broker workflow outbox: %v", err)
	}
	if pendingOutbox != 0 {
		t.Fatalf("workflow dispatch outbox still contains %d row(s)", pendingOutbox)
	}

	// Every Workflow event is signed by Audit Service, attributed to the actual
	// mTLS emitter, and independently verifiable against the external anchor.
	auditDB := openE2EDatabase(t, auditDSN)
	waitUntil(t, 10*time.Second, "signed Workflow decision audit event", func() bool {
		var count int
		err := auditDB.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'workflow.approval_decided' AND resource_id = $1 AND emitter = 'workflow-service'`, created.ID).Scan(&count)
		return err == nil && count > 0
	})
	for _, action := range []string{"workflow.approver_resolved", "workflow.approval_requested", "workflow.approval_decided"} {
		var count int
		if err := auditDB.QueryRow(`SELECT count(*) FROM audit_events
			WHERE action = $1 AND resource_id = $2 AND emitter = 'workflow-service'
			AND chain_key_id <> '' AND octet_length(hash) = 32 AND hash_version >= 3`, action, created.ID).Scan(&count); err != nil {
			t.Fatalf("query signed audit event %s: %v", action, err)
		}
		if count == 0 {
			t.Fatalf("missing signed Workflow audit event %s for %s", action, created.ID)
		}
	}
	verifyClient := pki.clientAs(t, mtls.AdminCLI)
	status, verifyBody, err := call(verifyClient, http.MethodGet, audit.baseURL+"/audit/v1/verify-chain", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("verify signed audit chain: status=%d body=%s err=%v", status, verifyBody, err)
	}
}

func clickBrowserTab(t *testing.T, page *cdpPage, label string) {
	t.Helper()
	encoded, _ := json.Marshal(label)
	var point struct {
		X float64 `json:"x"`
		Y float64 `json:"y"`
	}
	if err := json.Unmarshal(page.eval(`(() => { const b = [...document.querySelectorAll('[role="tab"]')].find((x) => x.innerText.trim().startsWith(`+string(encoded)+`)); if (!b) throw new Error("missing tab"); const r = b.getBoundingClientRect(); return {x:r.left+r.width/2,y:r.top+r.height/2}; })()`), &point); err != nil {
		t.Fatalf("locate Admin UI tab %q: %v", label, err)
	}
	page.clickAt(point.X, point.Y)
}

func gatewayCapabilities(t *testing.T, baseURL, token string) map[string]bool {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/auth/me/capabilities", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("read Gateway capabilities: %v", err)
	}
	defer resp.Body.Close()
	var payload struct {
		Capabilities map[string]bool `json:"capabilities"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&payload) != nil {
		t.Fatalf("read Gateway capabilities: status %d", resp.StatusCode)
	}
	return payload.Capabilities
}

func assertGatewayAdminUI(t *testing.T, baseURL string) {
	t.Helper()
	resp, err := http.Get(baseURL + "/ui/")
	if err != nil {
		t.Fatalf("load Admin UI through Gateway: %v", err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "OpenBastion") ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatalf("Admin UI entry point not served with its same-origin CSP: status=%d", resp.StatusCode)
	}
	assets := regexp.MustCompile(`(?:src|href)="(/ui/assets/[^"]+)"`).FindAllStringSubmatch(string(page), -1)
	if len(assets) < 2 {
		t.Fatalf("Admin UI entry point did not reference its JS and CSS assets: %s", page)
	}
	for _, asset := range assets {
		assetResp, err := http.Get(baseURL + asset[1])
		if err != nil {
			t.Fatalf("load Admin UI asset %s: %v", asset[1], err)
		}
		_, _ = io.Copy(io.Discard, assetResp.Body)
		_ = assetResp.Body.Close()
		if assetResp.StatusCode != http.StatusOK {
			t.Fatalf("Admin UI asset %s: status %d", asset[1], assetResp.StatusCode)
		}
	}
}

func gatewayJSONRequest(t *testing.T, baseURL, method, path, token string, body any, headers map[string]string) (int, string) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func parseHierarchyRevision(t *testing.T, etag string) uint64 {
	t.Helper()
	value := strings.TrimSuffix(strings.TrimPrefix(etag, `"hierarchy-`), `"`)
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil || value == etag || strconv.FormatUint(revision, 10) != value {
		t.Fatalf("invalid hierarchy ETag %q: %v", etag, err)
	}
	return revision
}

func gatewayManagerETag(t *testing.T, managerURL, token string) (etag string, status int, body string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, managerURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("read approval manager: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.Header.Get("ETag"), resp.StatusCode, string(data)
}

func gatewaySetManager(t *testing.T, managerURL, token, managerID, etag string) (newETag string, status int, body string) {
	t.Helper()
	encoded, _ := json.Marshal(map[string]string{"managerUserId": managerID})
	req, _ := http.NewRequest(http.MethodPut, managerURL, bytes.NewReader(encoded))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", etag)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("set approval manager: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.Header.Get("ETag"), resp.StatusCode, string(data)
}

func openE2EDatabase(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping PostgreSQL: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
