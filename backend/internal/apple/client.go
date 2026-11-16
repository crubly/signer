package apple

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
	"howett.net/plist"
)

const (
	gsaURL              = "https://gsa.apple.com/grandslam/GsService2"
	devServicesBaseURL  = "https://developerservices2.apple.com/services/QH65B2"
	xcodeClientID       = "X2464616693961918"
	xcodeUserAgent      = "Xcode"
	xcodeAppBundleID    = "com.apple.gs.xcode.auth"
	defaultAnisetteURL  = "https://ani.sidestore.io"
)

// SRP-6a 2048-bit prime (RFC 5054) and generator g=2
var (
	srpNHex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
		"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
		"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
		"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
		"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
		"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
		"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
		"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
	srpN = func() *big.Int {
		n, _ := new(big.Int).SetString(srpNHex, 16)
		return n
	}()
	srpG = big.NewInt(2)
)

type AnisetteHeaders struct {
	MachineID       string `json:"X-Apple-I-MD"`
	OneTimePassword string `json:"X-Apple-I-MD-M"`
	RoutingInfo     string `json:"X-Apple-I-MD-RINFO"`
	LocalUserID     string `json:"X-Apple-I-MD-LU"`
	DeviceID        string `json:"X-Mme-Device-Id"`
	ClientInfo      string `json:"X-Mme-Client-Info"`
	Serial          string `json:"X-Apple-I-SRL-NO"`
	ClientTime      string `json:"X-Apple-I-Client-Time"`
}

type PendingAuth struct {
	AppleID    string
	Password   string
	Anisette   AnisetteHeaders
	SessionID  string
	DSID       string
	IDMSToken  string
	SessionKey []byte
	Cookies    []*http.Cookie
	A          *big.Int
	aPriv      *big.Int
}

type AuthResult struct {
	Needs2FA  bool
	DSID      string
	GSToken   string
	Anisette  AnisetteHeaders
	Cookies   map[string]string
}

type Team struct {
	TeamID   string `plist:"teamId" json:"team_id"`
	Name     string `plist:"name" json:"name"`
	Type     string `plist:"type" json:"type"`
	Status   string `plist:"status" json:"status"`
}

type AppID struct {
	AppIDID    string `plist:"appIdId" json:"app_id_id"`
	Name       string `plist:"name" json:"name"`
	Identifier string `plist:"identifier" json:"identifier"`
}

type DevCert struct {
	CertID       string `plist:"certificateId" json:"certificate_id"`
	Name         string `plist:"name" json:"name"`
	SerialNumber string `plist:"serialNumber" json:"serial_number"`
	CertContent  []byte `plist:"certContent" json:"-"`
	Status       string `plist:"statusString" json:"status"`
	ExpiresDate  string `plist:"expirationDate" json:"expiration_date"`
}

type Client struct {
	httpClient  *http.Client
	anisetteURL string
}

func NewClient(anisetteURL string) *Client {
	if anisetteURL == "" {
		anisetteURL = defaultAnisetteURL
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &Client{
		httpClient:  &http.Client{Timeout: 30 * time.Second, Transport: tr},
		anisetteURL: strings.TrimRight(anisetteURL, "/"),
	}
}

func (c *Client) SetAnisetteURL(u string) {
	if u != "" {
		c.anisetteURL = strings.TrimRight(u, "/")
	}
}

func (c *Client) FetchAnisette() (AnisetteHeaders, error) {
	var h AnisetteHeaders
	req, err := http.NewRequest(http.MethodGet, c.anisetteURL, nil)
	if err != nil {
		return h, err
	}
	req.Header.Set("User-Agent", "Signer/1.0")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return h, fmt.Errorf("anisette fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return h, fmt.Errorf("anisette server HTTP %d: %s", resp.StatusCode, string(body))
	}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return h, fmt.Errorf("anisette decode error: %w", err)
	}
	if h.ClientTime == "" {
		h.ClientTime = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	if h.ClientInfo == "" {
		h.ClientInfo = "<MacBookPro18,1> <macOS;14.5;23F79> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
	}
	if h.DeviceID == "" {
		h.DeviceID = strings.ToUpper(uuid.NewString())
	}
	return h, nil
}

// StartLogin initiates Apple GrandSlam SRP-6a authentication.
func (c *Client) StartLogin(appleID, password string) (*AuthResult, *PendingAuth, error) {
	anisette, err := c.FetchAnisette()
	if err != nil {
		return nil, nil, err
	}
	return c.startLoginWithAnisette(appleID, password, anisette, nil)
}

func (c *Client) startLoginWithAnisette(appleID, password string, anisette AnisetteHeaders, extraCookies []*http.Cookie) (*AuthResult, *PendingAuth, error) {

	// Generate SRP ephemeral keypair: a, A = g^a mod N
	aBytes := make([]byte, 32)
	if _, err := rand.Read(aBytes); err != nil {
		return nil, nil, err
	}
	aPriv := new(big.Int).SetBytes(aBytes)
	A := new(big.Int).Exp(srpG, aPriv, srpN)
	aPubBytes := padBigInt(A, 256)

	initPayload := map[string]any{
		"Header": map[string]any{
			"Version": "1.0.1",
		},
		"Request": map[string]any{
			"CPD": map[string]any{
				"bootstrap": true,
				"icscrec":   true,
				"pbe":       false,
				"prkgen":    true,
				"svct":      "iCloud",
				"X-Apple-I-Client-Time": anisette.ClientTime,
				"X-Apple-I-MD":          anisette.MachineID,
				"X-Apple-I-MD-M":        anisette.OneTimePassword,
				"X-Apple-I-MD-RINFO":    anisette.RoutingInfo,
				"X-Apple-I-MD-LU":       anisette.LocalUserID,
				"X-Mme-Device-Id":       anisette.DeviceID,
			},
			"A2k": aPubBytes,
			"o":   "init",
			"ps":  []string{"s2k", "s2k_fo"},
			"u":   appleID,
		},
	}

	respMap, cookies, err := c.postGSAPlistWithCookies(initPayload, anisette, extraCookies)
	if err != nil {
		return nil, nil, err
	}
	if len(extraCookies) > 0 {
		cookies = append(extraCookies, cookies...)
	}

	respDict, ok := respMap["Response"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("invalid GSA init response")
	}
	if status, ok := respDict["Status"].(map[string]any); ok {
		if ec, _ := toInt(status["ec"]); ec != 0 {
			em, _ := status["em"].(string)
			return nil, nil, fmt.Errorf("Apple ID error (%d): %s", ec, em)
		}
	}

	saltBytes, _ := respDict["s"].([]byte)
	bBytes, _ := respDict["B"].([]byte)
	iterCount, _ := toInt(respDict["i"])
	cStr, _ := respDict["c"].(string)
	spStr, _ := respDict["sp"].(string)
	if len(saltBytes) == 0 || len(bBytes) == 0 || iterCount == 0 {
		return nil, nil, errors.New("incomplete SRP challenge from Apple")
	}

	// Compute SRP-6a shared secret & M1
	pwHash := sha256.Sum256([]byte(password))
	var derived []byte
	if spStr == "s2k_fo" {
		hexDigest := fmt.Sprintf("%x", pwHash)
		derived = pbkdf2.Key([]byte(hexDigest), saltBytes, iterCount, 32, sha256.New)
	} else {
		derived = pbkdf2.Key(pwHash[:], saltBytes, iterCount, 32, sha256.New)
	}

	B := new(big.Int).SetBytes(bBytes)
	bPadded := padBigInt(B, 256)

	// k = H(N | pad(g))
	kHash := sha256.New()
	kHash.Write(padBigInt(srpN, 256))
	kHash.Write(padBigInt(srpG, 256))
	k := new(big.Int).SetBytes(kHash.Sum(nil))

	// u = H(pad(A) | pad(B))
	uHash := sha256.New()
	uHash.Write(aPubBytes)
	uHash.Write(bPadded)
	u := new(big.Int).SetBytes(uHash.Sum(nil))

	// x = H(salt | H(":" | derived))  [Apple GSA SRP omits username here]
	idHash := sha256.New()
	idHash.Write([]byte(":"))
	idHash.Write(derived)
	xHash := sha256.New()
	xHash.Write(saltBytes)
	xHash.Write(idHash.Sum(nil))
	x := new(big.Int).SetBytes(xHash.Sum(nil))

	// S = (B - k * g^x)^(a + u*x) mod N
	gx := new(big.Int).Exp(srpG, x, srpN)
	kgx := new(big.Int).Mod(new(big.Int).Mul(k, gx), srpN)
	base := new(big.Int).Mod(new(big.Int).Sub(B, kgx), srpN)
	if base.Sign() < 0 {
		base.Add(base, srpN)
	}
	exp := new(big.Int).Add(aPriv, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, srpN)
	K := sha256.Sum256(padBigInt(S, 256))

	// M1 = H(H(N) XOR H(g) | H(username) | salt | A | B | K)
	hN := sha256.Sum256(padBigInt(srpN, 256))
	hG := sha256.Sum256(padBigInt(srpG, 256))
	hNG := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hNG[i] = hN[i] ^ hG[i]
	}
	hU := sha256.Sum256([]byte(appleID))
	m1Hash := sha256.New()
	m1Hash.Write(hNG)
	m1Hash.Write(hU[:])
	m1Hash.Write(saltBytes)
	m1Hash.Write(aPubBytes)
	m1Hash.Write(bPadded)
	m1Hash.Write(K[:])
	M1 := m1Hash.Sum(nil)

	completePayload := map[string]any{
		"Header": map[string]any{
			"Version": "1.0.1",
		},
		"Request": map[string]any{
			"CPD": initPayload["Request"].(map[string]any)["CPD"],
			"M1":  M1,
			"c":   cStr,
			"o":   "complete",
			"u":   appleID,
		},
	}

	compMap, compCookies, err := c.postGSAPlistWithCookies(completePayload, anisette, cookies)
	if err != nil {
		return nil, nil, err
	}
	if len(compCookies) > 0 {
		cookies = append(cookies, compCookies...)
	}

	compResp, ok := compMap["Response"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("invalid GSA complete response")
	}
	if status, ok := compResp["Status"].(map[string]any); ok {
		if ec, _ := toInt(status["ec"]); ec != 0 {
			em, _ := status["em"].(string)
			return nil, nil, fmt.Errorf("Apple ID auth failed (%d): %s", ec, em)
		}
		if au, _ := status["au"].(string); au == "trustedDeviceSecondaryAuth" || au == "secondaryAuth" {
			dsid, _ := compResp["dsid"].(string)
			idms := ""
			if spdEnc, ok := compResp["spd"].([]byte); ok && len(spdEnc) > 0 {
				if spdMap, err := decryptSPD(K[:], spdEnc); err == nil {
					if v, ok := spdMap["adsid"].(string); ok && v != "" {
						dsid = v
					}
					if v, ok := spdMap["GsIdmsToken"].(string); ok {
						idms = v
					}
				}
			}
			pending := &PendingAuth{
				AppleID:    appleID,
				Password:   password,
				Anisette:   anisette,
				DSID:       dsid,
				IDMSToken:  idms,
				SessionKey: append([]byte(nil), K[:]...),
				Cookies:    cookies,
				A:          A,
				aPriv:      aPriv,
			}
			// Trigger trusted device 2FA prompt
			_ = c.requestTrustedDevice2FA(pending)
			return &AuthResult{Needs2FA: true, DSID: dsid, Anisette: anisette}, pending, nil
		}
	}

	// Extract spd (encrypted with K) if present
	dsid, _ := compResp["dsid"].(string)
	gsToken := ""
	if spdEnc, ok := compResp["spd"].([]byte); ok && len(spdEnc) > 0 {
		if spdMap, err := decryptSPD(K[:], spdEnc); err == nil {
			if v, ok := spdMap["adsid"].(string); ok && v != "" {
				dsid = v
			}
			if v, ok := spdMap["GsIdmsToken"].(string); ok {
				gsToken = v
			}
		}
	}
	cookieMap := map[string]string{}
	for _, ck := range cookies {
		cookieMap[ck.Name] = ck.Value
	}

	if xcodeTok, err := c.fetchXcodeGSToken(dsid, gsToken, K[:], anisette); err == nil && xcodeTok != "" {
		gsToken = xcodeTok
	}

	return &AuthResult{
		Needs2FA: false,
		DSID:     dsid,
		GSToken:  gsToken,
		Anisette: anisette,
		Cookies:  cookieMap,
	}, nil, nil
}

func (c *Client) requestTrustedDevice2FA(p *PendingAuth) error {
	req, err := http.NewRequest(http.MethodGet, "https://gsa.apple.com/auth/verify/trusteddevice", nil)
	if err != nil {
		return err
	}
	c.applyAnisetteHeaders(req, p.Anisette)
	req.Header.Set("X-Apple-Identity-Token", base64.StdEncoding.EncodeToString([]byte(p.DSID+":"+p.IDMSToken)))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Submit2FA submits the 6-digit trusted device verification code.
func (c *Client) Submit2FA(p *PendingAuth, code string) (*AuthResult, error) {
	if p == nil {
		return nil, errors.New("no pending 2FA session")
	}
	req, err := http.NewRequest(http.MethodPost, "https://gsa.apple.com/auth/verify/trusteddevice/securitycode", strings.NewReader(fmt.Sprintf(`{"securityCode":{"code":"%s"}}`, code)))
	if err != nil {
		return nil, err
	}
	c.applyAnisetteHeaders(req, p.Anisette)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Apple-Identity-Token", base64.StdEncoding.EncodeToString([]byte(p.DSID+":"+p.IDMSToken)))
	for _, ck := range p.Cookies {
		req.AddCookie(ck)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("2FA verification failed (HTTP %d): %s", resp.StatusCode, string(body))
	}
	allCookies := append([]*http.Cookie(nil), p.Cookies...)
	allCookies = append(allCookies, resp.Cookies()...)
	cookieMap := map[string]string{}
	for _, ck := range allCookies {
		cookieMap[ck.Name] = ck.Value
	}

	// Re-run SRP with the 2FA-verified cookies & same Anisette to obtain post-2FA GsIdmsToken + Xcode app token
	res2, _, err2 := c.startLoginWithAnisette(p.AppleID, p.Password, p.Anisette, allCookies)
	if err2 == nil && !res2.Needs2FA && res2.GSToken != "" {
		return res2, nil
	}
	log.Printf("post-2FA SRP retry result: err=%v, needs2FA=%v", err2, res2 != nil && res2.Needs2FA)

	gsToken := p.IDMSToken
	xcodeTok, err := c.fetchXcodeGSToken(p.DSID, p.IDMSToken, p.SessionKey, p.Anisette)
	if err != nil {
		log.Printf("fetchXcodeGSToken after 2FA failed: %v", err)
	} else if xcodeTok != "" {
		gsToken = xcodeTok
	}
	return &AuthResult{
		Needs2FA: false,
		DSID:     p.DSID,
		GSToken:  gsToken,
		Anisette: p.Anisette,
		Cookies:  cookieMap,
	}, nil
}

func (c *Client) fetchXcodeGSToken(dsid, idmsToken string, sessionKey []byte, anisette AnisetteHeaders) (string, error) {
	if dsid == "" || idmsToken == "" || len(sessionKey) == 0 {
		return "", errors.New("missing session data for apptokens")
	}
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write([]byte("apptokens"))
	mac.Write([]byte(dsid))
	mac.Write([]byte(xcodeAppBundleID))
	checksum := mac.Sum(nil)

	payload := map[string]any{
		"Header": map[string]any{
			"Version": "1.0.1",
		},
		"Request": map[string]any{
			"CPD": map[string]any{
				"bootstrap":             true,
				"icscrec":               true,
				"pbe":                   false,
				"prkgen":                true,
				"svct":                  "iCloud",
				"X-Apple-I-Client-Time": anisette.ClientTime,
				"X-Apple-I-MD":          anisette.MachineID,
				"X-Apple-I-MD-M":        anisette.OneTimePassword,
				"X-Apple-I-MD-RINFO":    anisette.RoutingInfo,
				"X-Apple-I-MD-LU":       anisette.LocalUserID,
				"X-Mme-Device-Id":       anisette.DeviceID,
			},
			"app":      []string{xcodeAppBundleID},
			"checksum": checksum,
			"o":        "apptokens",
			"t":        idmsToken,
			"u":        dsid,
		},
	}

	respMap, _, err := c.postGSAPlist(payload, anisette)
	if err != nil {
		return "", err
	}
	respDict, ok := respMap["Response"].(map[string]any)
	if !ok {
		return "", errors.New("invalid apptokens response")
	}
	if status, ok := respDict["Status"].(map[string]any); ok {
		if ec, _ := toInt(status["ec"]); ec != 0 {
			em, _ := status["em"].(string)
			return "", fmt.Errorf("apptokens error (%d): %s", ec, em)
		}
	}
	etEnc, ok := respDict["et"].([]byte)
	if !ok || len(etEnc) == 0 {
		return "", errors.New("missing encrypted token in apptokens response")
	}
	etMap, err := decryptSPD(sessionKey, etEnc)
	if err != nil {
		return "", err
	}
	if tMap, ok := etMap["t"].(map[string]any); ok {
		if appMap, ok := tMap[xcodeAppBundleID].(map[string]any); ok {
			if tok, ok := appMap["token"].(string); ok && tok != "" {
				return tok, nil
			}
		}
	}
	return "", errors.New("xcode token not found in apptokens")
}

// ListTeams fetches Apple Developer teams for the authenticated account.
func (c *Client) ListTeams(dsid, gsToken string, anisette AnisetteHeaders) ([]Team, error) {
	resp, err := c.postDevService("listTeams.action", map[string]any{}, dsid, gsToken, anisette)
	if err != nil {
		return nil, err
	}
	rawTeams, _ := resp["teams"].([]any)
	var teams []Team
	for _, item := range rawTeams {
		if m, ok := item.(map[string]any); ok {
			t := Team{
				TeamID: fmt.Sprint(m["teamId"]),
				Name:   fmt.Sprint(m["name"]),
				Type:   fmt.Sprint(m["type"]),
				Status: fmt.Sprint(m["status"]),
			}
			teams = append(teams, t)
		}
	}
	return teams, nil
}

// ListAppIDs fetches registered App IDs (including App Extensions) for the team.
func (c *Client) ListAppIDs(teamID, dsid, gsToken string, anisette AnisetteHeaders) ([]AppID, error) {
	resp, err := c.postDevService("ios/listAppIds.action", map[string]any{
		"teamId": teamID,
	}, dsid, gsToken, anisette)
	if err != nil {
		return nil, err
	}
	raw, _ := resp["appIds"].([]any)
	var out []AppID
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			out = append(out, AppID{
				AppIDID:    fmt.Sprint(m["appIdId"]),
				Name:       fmt.Sprint(m["name"]),
				Identifier: fmt.Sprint(m["identifier"]),
			})
		}
	}
	return out, nil
}

// DeleteAppID removes an App ID (or App Extension ID) from the Apple Developer account.
func (c *Client) DeleteAppID(teamID, appIDID, dsid, gsToken string, anisette AnisetteHeaders) error {
	_, err := c.postDevService("ios/deleteAppId.action", map[string]any{
		"teamId":  teamID,
		"appIdId": appIDID,
	}, dsid, gsToken, anisette)
	return err
}

// ListDevCerts lists development certificates on the Apple Developer account.
func (c *Client) ListDevCerts(teamID, dsid, gsToken string, anisette AnisetteHeaders) ([]DevCert, error) {
	resp, err := c.postDevService("ios/listAllDevelopmentCerts.action", map[string]any{
		"teamId": teamID,
	}, dsid, gsToken, anisette)
	if err != nil {
		return nil, err
	}
	raw, _ := resp["certificates"].([]any)
	var out []DevCert
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			certBytes, _ := m["certContent"].([]byte)
			out = append(out, DevCert{
				CertID:       fmt.Sprint(m["certificateId"]),
				Name:         fmt.Sprint(m["name"]),
				SerialNumber: fmt.Sprint(m["serialNumber"]),
				CertContent:  certBytes,
				Status:       fmt.Sprint(m["statusString"]),
			})
		}
	}
	return out, nil
}

// RevokeDevCert revokes a development certificate by serial number.
func (c *Client) RevokeDevCert(teamID, serial, dsid, gsToken string, anisette AnisetteHeaders) error {
	_, err := c.postDevService("ios/revokeDevelopmentCert.action", map[string]any{
		"teamId":       teamID,
		"serialNumber": serial,
	}, dsid, gsToken, anisette)
	return err
}

// AddDevice registers an iOS device UDID under the Apple Developer team (ignores already-registered errors).
func (c *Client) AddDevice(teamID, deviceName, udid, dsid, gsToken string, anisette AnisetteHeaders) error {
	if udid == "" {
		return nil
	}
	if deviceName == "" {
		deviceName = "iPhone"
	}
	_, err := c.postDevService("ios/addDevice.action", map[string]any{
		"teamId":       teamID,
		"deviceNumber": udid,
		"deviceName":   deviceName,
	}, dsid, gsToken, anisette)
	if err != nil && (strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "35")) {
		return nil
	}
	return err
}

// SubmitDevelopmentCSR submits a CSR to Apple and returns the certificate request/cert ID.
func (c *Client) SubmitDevelopmentCSR(teamID string, csrPEM []byte, dsid, gsToken string, anisette AnisetteHeaders) (string, error) {
	resp, err := c.postDevService("ios/submitDevelopmentCSR.action", map[string]any{
		"teamId":         teamID,
		"csrContent":     string(csrPEM),
		"machineId":      anisette.DeviceID,
		"machineName":    "SignedServer",
	}, dsid, gsToken, anisette)
	if err != nil {
		return "", err
	}
	if reqMap, ok := resp["certRequest"].(map[string]any); ok {
		if id, ok := reqMap["certificateId"].(string); ok && id != "" {
			return id, nil
		}
		if id, ok := reqMap["certRequestId"].(string); ok && id != "" {
			return id, nil
		}
	}
	return "", nil
}

// AddAppID registers an App ID on the Apple Developer team.
func (c *Client) AddAppID(teamID, name, bundleID, dsid, gsToken string, anisette AnisetteHeaders) (AppID, error) {
	resp, err := c.postDevService("ios/addAppId.action", map[string]any{
		"teamId":     teamID,
		"name":       name,
		"identifier": bundleID,
	}, dsid, gsToken, anisette)
	if err != nil {
		return AppID{}, err
	}
	if m, ok := resp["appId"].(map[string]any); ok {
		return AppID{
			AppIDID:    fmt.Sprint(m["appIdId"]),
			Name:       fmt.Sprint(m["name"]),
			Identifier: fmt.Sprint(m["identifier"]),
		}, nil
	}
	return AppID{}, errors.New("missing appId in Apple response")
}

// DownloadProvisioningProfile downloads the team provisioning profile for an App ID.
func (c *Client) DownloadProvisioningProfile(teamID, appIDID, dsid, gsToken string, anisette AnisetteHeaders) ([]byte, error) {
	resp, err := c.postDevService("ios/downloadTeamProvisioningProfile.action", map[string]any{
		"teamId":  teamID,
		"appIdId": appIDID,
	}, dsid, gsToken, anisette)
	if err != nil {
		return nil, err
	}
	if prof, ok := resp["provisioningProfile"].(map[string]any); ok {
		if raw, ok := prof["encodedProfile"].([]byte); ok && len(raw) > 0 {
			return raw, nil
		}
	}
	return nil, errors.New("missing encodedProfile in Apple response")
}

// GenerateCSR creates an RSA 2048 private key and a PEM-encoded CSR.
func GenerateCSR(commonName string) (privateKeyPEM []byte, csrPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return privateKeyPEM, csrPEM, nil
}

func (c *Client) postGSAPlist(payload map[string]any, anisette AnisetteHeaders) (map[string]any, []*http.Cookie, error) {
	return c.postGSAPlistWithCookies(payload, anisette, nil)
}

func (c *Client) postGSAPlistWithCookies(payload map[string]any, anisette AnisetteHeaders, cookies []*http.Cookie) (map[string]any, []*http.Cookie, error) {
	var buf bytes.Buffer
	enc := plist.NewEncoder(&buf)
	if err := enc.Encode(payload); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, gsaURL, &buf)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0")
	c.applyAnisetteHeaders(req, anisette)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	var out map[string]any
	if _, err := plist.Unmarshal(body, &out); err != nil {
		return nil, nil, fmt.Errorf("plist decode error: %w", err)
	}
	return out, resp.Cookies(), nil
}

func (c *Client) postDevService(action string, extra map[string]any, dsid, gsToken string, anisette AnisetteHeaders) (map[string]any, error) {
	payload := map[string]any{
		"clientId":      xcodeClientID,
		"protocolVersion": "QH65B2",
		"requestId":     strings.ToUpper(uuid.NewString()),
		"userLocale":    []string{"en_US"},
	}
	for k, v := range extra {
		payload[k] = v
	}
	var buf bytes.Buffer
	if err := plist.NewEncoder(&buf).Encode(payload); err != nil {
		return nil, err
	}
	endpoint := devServicesBaseURL + "/" + strings.TrimLeft(action, "/")
	req, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("Accept", "text/x-xml-plist")
	req.Header.Set("User-Agent", xcodeUserAgent)
	req.Header.Set("X-Apple-GS-Token", gsToken)
	req.Header.Set("X-Apple-I-Identity-Id", dsid)
	c.applyAnisetteHeaders(req, anisette)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if _, err := plist.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("devservices plist error: %w", err)
	}
	if rc, ok := toInt(out["resultCode"]); ok && rc != 0 {
		msg, _ := out["resultString"].(string)
		return nil, fmt.Errorf("Apple DevServices error (%d): %s", rc, msg)
	}
	return out, nil
}

func (c *Client) applyAnisetteHeaders(req *http.Request, a AnisetteHeaders) {
	if a.MachineID != "" {
		req.Header.Set("X-Apple-I-MD", a.MachineID)
	}
	if a.OneTimePassword != "" {
		req.Header.Set("X-Apple-I-MD-M", a.OneTimePassword)
	}
	if a.RoutingInfo != "" {
		req.Header.Set("X-Apple-I-MD-RINFO", a.RoutingInfo)
	}
	if a.LocalUserID != "" {
		req.Header.Set("X-Apple-I-MD-LU", a.LocalUserID)
	}
	if a.DeviceID != "" {
		req.Header.Set("X-Mme-Device-Id", a.DeviceID)
	}
	if a.ClientInfo != "" {
		req.Header.Set("X-Mme-Client-Info", a.ClientInfo)
	}
	if a.ClientTime != "" {
		req.Header.Set("X-Apple-I-Client-Time", a.ClientTime)
	}
}

func decryptSPD(sessionKey, spdEnc []byte) (map[string]any, error) {
	kMac := hmac.New(sha256.New, sessionKey)
	kMac.Write([]byte("extra data key:"))
	aesKey := kMac.Sum(nil)

	ivMac := hmac.New(sha256.New, sessionKey)
	ivMac.Write([]byte("extra data iv:"))
	iv := ivMac.Sum(nil)[:16]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	if len(spdEnc)%aes.BlockSize != 0 {
		return nil, errors.New("invalid spd ciphertext length")
	}
	plain := make([]byte, len(spdEnc))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, spdEnc)
	// PKCS7 unpad
	if len(plain) > 0 {
		pad := int(plain[len(plain)-1])
		if pad > 0 && pad <= aes.BlockSize && pad <= len(plain) {
			plain = plain[:len(plain)-pad]
		}
	}
	var out map[string]any
	if _, err := plist.Unmarshal(plain, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func padBigInt(v *big.Int, size int) []byte {
	b := v.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func toInt(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case uint64:
		return int(t), true
	default:
		return 0, false
	}
}
