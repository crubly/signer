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
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
	"howett.net/plist"
)

const (
	gsaURL             = "https://gsa.apple.com/grandslam/GsService2"
	gsaValidateURL     = "https://gsa.apple.com/grandslam/GsService2/validate"
	gsaTrustedDevURL   = "https://gsa.apple.com/auth/verify/trusteddevice"
	gsaSMSRequestURL   = "https://gsa.apple.com/auth/verify/phone/put?mode=sms"
	gsaSMSVerifyURL    = "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put"
	devServicesBaseURL = "https://developerservices2.apple.com/services/QH65B2"
	servicesV1BaseURL  = "https://developerservices2.apple.com/services/v1"
	xcodeClientID      = "XABBG36SBA"
	xcodeVersion       = "11.2 (11B41)"
	xcodeUserAgent     = "Xcode"
	xcodeAppBundleID   = "com.apple.gs.xcode.auth"
	defaultAnisetteURL = "https://ani.sidestore.io"
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
	OneTimePassword string `json:"X-Apple-I-MD"`
	MachineID       string `json:"X-Apple-I-MD-M"`
	RoutingInfo     string `json:"X-Apple-I-MD-RINFO"`
	LocalUserID     string `json:"X-Apple-I-MD-LU"`
	DeviceID        string `json:"X-Mme-Device-Id"`
	ClientInfo      string `json:"X-MMe-Client-Info"`
	Serial          string `json:"X-Apple-I-SRL-NO"`
	ClientTime      string `json:"X-Apple-I-Client-Time"`
	Locale          string `json:"X-Apple-Locale"`
	TimeZone        string `json:"X-Apple-I-TimeZone"`
}

type PendingAuth struct {
	AppleID   string
	Password  string
	Anisette  AnisetteHeaders
	SessionID string
	DSID      string
	IDMSToken string
	AuthType  string // "trustedDeviceSecondaryAuth" or "secondaryAuth" (SMS)
}

type AuthResult struct {
	Needs2FA bool
	AuthMethod string // "trusted_device" or "sms"
	DSID     string
	GSToken  string
	Anisette AnisetteHeaders
}

type Team struct {
	TeamID string `plist:"teamId" json:"team_id"`
	Name   string `plist:"name" json:"name"`
	Type   string `plist:"type" json:"type"`
	Status string `plist:"status" json:"status"`
}

type AppID struct {
	AppIDID    string `plist:"appIdId" json:"app_id_id"`
	Name       string `plist:"name" json:"name"`
	Identifier string `plist:"identifier" json:"identifier"`
}

type DevCert struct {
	CertID       string `json:"certificate_id"`
	Name         string `json:"name"`
	SerialNumber string `json:"serial_number"`
	MachineName  string `json:"machine_name"`
	CertContent  []byte `json:"-"`
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
	req.Header.Set("User-Agent", "Signed/1.0")
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
	normalizeAnisette(&h)
	return h, nil
}

func normalizeAnisette(h *AnisetteHeaders) {
	h.ClientTime = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if h.ClientInfo == "" {
		h.ClientInfo = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
	}
	if h.DeviceID == "" {
		h.DeviceID = strings.ToUpper(uuid.NewString())
	}
	if h.RoutingInfo == "" {
		h.RoutingInfo = "17106176"
	}
	if h.Serial == "" {
		h.Serial = "0"
	}
	if h.Locale == "" {
		h.Locale = "en_US"
	}
	if h.TimeZone == "" {
		h.TimeZone = "UTC"
	}
}

func buildCPDDict(a AnisetteHeaders) map[string]any {
	rinfoInt, err := strconv.Atoi(a.RoutingInfo)
	if err != nil {
		rinfoInt = 17106176
	}
	return map[string]any{
		"bootstrap":             true,
		"icscrec":               true,
		"loc":                   a.Locale,
		"pbe":                   false,
		"prkgen":                true,
		"svct":                  "iCloud",
		"X-Apple-I-Client-Time": a.ClientTime,
		"X-Apple-Locale":        a.Locale,
		"X-Apple-I-TimeZone":    a.TimeZone,
		"X-Apple-I-MD":          a.OneTimePassword,
		"X-Apple-I-MD-LU":       a.LocalUserID,
		"X-Apple-I-MD-M":        a.MachineID,
		"X-Apple-I-MD-RINFO":    rinfoInt,
		"X-Mme-Device-Id":       a.DeviceID,
		"X-Apple-I-SRL-NO":      a.Serial,
	}
}

// StartLogin initiates Apple GrandSlam SRP-6a authentication (matching AltSign).
func (c *Client) StartLogin(appleID, password string) (*AuthResult, *PendingAuth, error) {
	anisette, err := c.FetchAnisette()
	if err != nil {
		return nil, nil, err
	}
	return c.startLoginWithAnisette(appleID, password, anisette)
}

func (c *Client) startLoginWithAnisette(appleID, password string, anisette AnisetteHeaders) (*AuthResult, *PendingAuth, error) {
	normalizeAnisette(&anisette)
	cpdDict := buildCPDDict(anisette)

	// Generate SRP ephemeral keypair: a, A = g^a mod N
	aBytes := make([]byte, 32)
	if _, err := rand.Read(aBytes); err != nil {
		return nil, nil, err
	}
	aPriv := new(big.Int).SetBytes(aBytes)
	A := new(big.Int).Exp(srpG, aPriv, srpN)
	aPubBytes := padBigInt(A, 256)

	initReq := map[string]any{
		"A2k": aPubBytes,
		"ps":  []string{"s2k", "s2k_fo"},
		"cpd": cpdDict,
		"u":   appleID,
		"o":   "init",
	}

	respDict, err := c.sendGSARequest(initReq, anisette)
	if err != nil {
		return nil, nil, err
	}

	saltBytes, _ := respDict["s"].([]byte)
	bBytes, _ := respDict["B"].([]byte)
	iterCount, _ := toInt(respDict["i"])
	cStr, _ := respDict["c"].(string)
	spStr, _ := respDict["sp"].(string)
	if len(saltBytes) == 0 || len(bBytes) == 0 || iterCount == 0 {
		return nil, nil, errors.New("incomplete SRP challenge from Apple")
	}

	// Compute SRP-6a shared secret & M1 (noUsernameInX = true)
	pwHash := sha256.Sum256([]byte(password))
	var derived []byte
	if spStr == "s2k" {
		derived = pbkdf2.Key(pwHash[:], saltBytes, iterCount, 32, sha256.New)
	} else {
		hexDigest := fmt.Sprintf("%x", pwHash)
		derived = pbkdf2.Key([]byte(hexDigest), saltBytes, iterCount, 32, sha256.New)
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

	// x = H(salt | H(":" | derived))
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

	compReq := map[string]any{
		"c":   cStr,
		"M1":  M1,
		"cpd": cpdDict,
		"u":   appleID,
		"o":   "complete",
	}

	compResp, err := c.sendGSARequest(compReq, anisette)
	if err != nil {
		return nil, nil, err
	}

	spdEnc, ok := compResp["spd"].([]byte)
	if !ok || len(spdEnc) == 0 {
		return nil, nil, errors.New("missing spd in GSA complete response")
	}
	spdMap, err := decryptSPD(K[:], spdEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt spd: %w", err)
	}

	adsid, _ := spdMap["adsid"].(string)
	idmsToken, _ := spdMap["GsIdmsToken"].(string)
	if adsid == "" || idmsToken == "" {
		return nil, nil, errors.New("missing adsid or GsIdmsToken in spd")
	}

	if status, ok := compResp["Status"].(map[string]any); ok {
		if au, _ := status["au"].(string); au == "trustedDeviceSecondaryAuth" || au == "secondaryAuth" {
			pending := &PendingAuth{
				AppleID:   appleID,
				Password:  password,
				Anisette:  anisette,
				DSID:      adsid,
				IDMSToken: idmsToken,
				AuthType:  au,
			}
			method := "trusted_device"
			if au == "secondaryAuth" {
				method = "sms"
				if err := c.requestSMS2FA(pending); err != nil {
					log.Printf("requestSMS2FA warning: %v", err)
				}
			} else {
				if err := c.requestTrustedDevice2FA(pending); err != nil {
					log.Printf("requestTrustedDevice2FA warning: %v", err)
				}
			}
			return &AuthResult{Needs2FA: true, AuthMethod: method, DSID: adsid, Anisette: anisette}, pending, nil
		}
	}

	sk, _ := spdMap["sk"].([]byte)
	cVal := spdMap["c"]
	if len(sk) == 0 || cVal == nil {
		return nil, nil, errors.New("missing sk or c in decrypted spd")
	}

	xcodeTok, err := c.fetchXcodeAuthToken(adsid, idmsToken, sk, cVal, cpdDict, anisette)
	if err != nil {
		return nil, nil, fmt.Errorf("fetchXcodeAuthToken failed: %w", err)
	}

	return &AuthResult{
		Needs2FA: false,
		DSID:     adsid,
		GSToken:  xcodeTok,
		Anisette: anisette,
	}, nil, nil
}

func (c *Client) apply2FAHeaders(req *http.Request, dsid, idmsToken string, a AnisetteHeaders) {
	encodedIdentity := base64.StdEncoding.EncodeToString([]byte(dsid + ":" + idmsToken))
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("User-Agent", xcodeUserAgent)
	req.Header.Set("Accept", "text/x-xml-plist")
	req.Header.Set("Accept-Language", "en-us")
	req.Header.Set("X-Apple-App-Info", xcodeAppBundleID)
	req.Header.Set("X-Xcode-Version", xcodeVersion)
	req.Header.Set("X-Apple-Identity-Token", encodedIdentity)
	c.applyAnisetteHeaders(req, a)
}

func (c *Client) requestTrustedDevice2FA(p *PendingAuth) error {
	req, err := http.NewRequest(http.MethodGet, gsaTrustedDevURL, nil)
	if err != nil {
		return err
	}
	normalizeAnisette(&p.Anisette)
	c.apply2FAHeaders(req, p.DSID, p.IDMSToken, p.Anisette)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) requestSMS2FA(p *PendingAuth) error {
	bodyXML := map[string]any{
		"serverInfo": map[string]any{
			"phoneNumber.id": "1",
		},
	}
	var buf bytes.Buffer
	if err := plist.NewEncoder(&buf).Encode(bodyXML); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, gsaSMSRequestURL, &buf)
	if err != nil {
		return err
	}
	normalizeAnisette(&p.Anisette)
	c.apply2FAHeaders(req, p.DSID, p.IDMSToken, p.Anisette)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// Submit2FA validates the 6-digit code via GsService2/validate (trusted device) or /auth/verify/phone/securitycode (SMS),
// then restarts SRP authentication using the now-trusted Anisette data to fetch the Xcode GS token.
func (c *Client) Submit2FA(p *PendingAuth, code string) (*AuthResult, error) {
	if p == nil {
		return nil, errors.New("no pending 2FA session")
	}
	normalizeAnisette(&p.Anisette)

	if p.AuthType == "secondaryAuth" {
		if err := c.verifySMS2FA(p, code); err != nil {
			return nil, err
		}
	} else {
		if err := c.verifyTrustedDevice2FA(p, code); err != nil {
			return nil, err
		}
	}

	// Restart authentication with the same Anisette — now 2FA-trusted on GSA!
	res, _, err := c.startLoginWithAnisette(p.AppleID, p.Password, p.Anisette)
	if err != nil {
		return nil, fmt.Errorf("post-2FA login failed: %w", err)
	}
	if res.Needs2FA {
		return nil, errors.New("Apple still requested 2FA after code validation")
	}
	return res, nil
}

func (c *Client) verifyTrustedDevice2FA(p *PendingAuth, code string) error {
	req, err := http.NewRequest(http.MethodGet, gsaValidateURL, nil)
	if err != nil {
		return err
	}
	c.apply2FAHeaders(req, p.DSID, p.IDMSToken, p.Anisette)
	req.Header.Set("security-code", code)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var valDict map[string]any
	if _, err := plist.Unmarshal(body, &valDict); err != nil {
		return fmt.Errorf("2FA validate plist decode error (HTTP %d): %w", resp.StatusCode, err)
	}
	if ec, ok := toInt(valDict["ec"]); ok && ec != 0 {
		em, _ := valDict["em"].(string)
		if ec == -21669 {
			return errors.New("incorrect 2FA verification code")
		}
		return fmt.Errorf("2FA validate error (%d): %s", ec, em)
	}
	return nil
}

func (c *Client) verifySMS2FA(p *PendingAuth, code string) error {
	bodyXML := map[string]any{
		"securityCode.code": code,
		"serverInfo": map[string]any{
			"mode":           "sms",
			"phoneNumber.id": "1",
		},
	}
	var buf bytes.Buffer
	if err := plist.NewEncoder(&buf).Encode(bodyXML); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, gsaSMSVerifyURL, &buf)
	if err != nil {
		return err
	}
	c.apply2FAHeaders(req, p.DSID, p.IDMSToken, p.Anisette)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Apple-PE-Token") == "" {
		return fmt.Errorf("incorrect or expired SMS verification code (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) fetchXcodeAuthToken(adsid, idmsToken string, sk []byte, cVal any, cpdDict map[string]any, anisette AnisetteHeaders) (string, error) {
	apps := []string{xcodeAppBundleID}
	mac := hmac.New(sha256.New, sk)
	mac.Write([]byte("apptokens"))
	mac.Write([]byte(adsid))
	for _, app := range apps {
		mac.Write([]byte(app))
	}
	checksum := mac.Sum(nil)

	reqDict := map[string]any{
		"u":        adsid,
		"app":      apps,
		"c":        cVal,
		"t":        idmsToken,
		"checksum": checksum,
		"cpd":      cpdDict,
		"o":        "apptokens",
	}

	respDict, err := c.sendGSARequest(reqDict, anisette)
	if err != nil {
		return "", err
	}

	etEnc, ok := respDict["et"].([]byte)
	if !ok || len(etEnc) == 0 {
		return "", errors.New("missing encrypted token (et) in apptokens response")
	}

	decBytes, err := decryptETGCM(sk, etEnc)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt apptoken GCM: %w", err)
	}

	var tokPlist map[string]any
	if _, err := plist.Unmarshal(decBytes, &tokPlist); err != nil {
		return "", fmt.Errorf("failed to parse decrypted apptoken plist: %w", err)
	}

	if tMap, ok := tokPlist["t"].(map[string]any); ok {
		if appMap, ok := tMap[xcodeAppBundleID].(map[string]any); ok {
			if tok, ok := appMap["token"].(string); ok && tok != "" {
				return tok, nil
			}
		}
	}
	return "", errors.New("token missing in decrypted apptoken plist")
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
			teams = append(teams, Team{
				TeamID: fmt.Sprint(m["teamId"]),
				Name:   fmt.Sprint(m["name"]),
				Type:   fmt.Sprint(m["type"]),
				Status: fmt.Sprint(m["status"]),
			})
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

// ListDevCerts lists development certificates via v1 JSON services API, falling back to QH65B2 listAllDevelopmentCerts.action.
func (c *Client) ListDevCerts(teamID, dsid, gsToken string, anisette AnisetteHeaders) ([]DevCert, error) {
	resp, err := c.sendServicesV1Request(http.MethodGet, "certificates", teamID, map[string]string{
		"filter[certificateType]": "IOS_DEVELOPMENT",
	}, dsid, gsToken, anisette)
	var out []DevCert
	if err == nil {
		raw, _ := resp["data"].([]any)
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			id := fmt.Sprint(m["id"])
			attrs, _ := m["attributes"].(map[string]any)
			if attrs == nil {
				attrs = m
			}
			var certDER []byte
			if b, ok := attrs["certContent"].([]byte); ok {
				certDER = b
			} else if s, ok := attrs["certificateContent"].(string); ok && s != "" {
				certDER, _ = base64.StdEncoding.DecodeString(s)
			}
			serial := fmt.Sprint(attrs["serialNumber"])
			if serial == "" || serial == "<nil>" {
				serial = fmt.Sprint(attrs["serialNum"])
			}
			out = append(out, DevCert{
				CertID:       id,
				Name:         fmt.Sprint(attrs["name"]),
				SerialNumber: serial,
				MachineName:  fmt.Sprint(attrs["machineName"]),
				CertContent:  certDER,
			})
		}
	} else {
		log.Printf("ListDevCerts v1 failed (%v), falling back to QH65B2", err)
	}

	if len(out) == 0 {
		resp2, err2 := c.postDevService("ios/listAllDevelopmentCerts.action", map[string]any{
			"teamId": teamID,
		}, dsid, gsToken, anisette)
		if err2 != nil {
			if err != nil {
				return nil, fmt.Errorf("v1: %v; qh65b2: %w", err, err2)
			}
			return nil, err2
		}
		raw2, _ := resp2["certificates"].([]any)
		for _, item := range raw2 {
			if m, ok := item.(map[string]any); ok {
				certBytes, _ := m["certContent"].([]byte)
				out = append(out, DevCert{
					CertID:       fmt.Sprint(m["certificateId"]),
					Name:         fmt.Sprint(m["name"]),
					SerialNumber: fmt.Sprint(m["serialNumber"]),
					MachineName:  fmt.Sprint(m["machineName"]),
					CertContent:  certBytes,
				})
			}
		}
	}
	return out, nil
}

// RevokeDevCert revokes a development certificate by v1 cert ID and/or QH65B2 serialNumber.
func (c *Client) RevokeDevCert(teamID, certID, serial, dsid, gsToken string, anisette AnisetteHeaders) error {
	var err1, err2 error
	if certID != "" && certID != "<nil>" {
		_, err1 = c.sendServicesV1Request(http.MethodDelete, "certificates/"+certID, teamID, nil, dsid, gsToken, anisette)
		if err1 == nil {
			return nil
		}
	}
	if serial != "" && serial != "<nil>" {
		_, err2 = c.postDevService("ios/revokeDevelopmentCert.action", map[string]any{
			"teamId":       teamID,
			"serialNumber": serial,
		}, dsid, gsToken, anisette)
		if err2 == nil {
			return nil
		}
	}
	if err2 != nil {
		return err2
	}
	return err1
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
	if err != nil && (strings.Contains(strings.ToLower(err.Error()), "already exists") || strings.Contains(err.Error(), "35")) {
		return nil
	}
	return err
}

// SubmitDevelopmentCSR submits a CSR to Apple and returns the certificate ID.
func (c *Client) SubmitDevelopmentCSR(teamID string, csrPEM []byte, dsid, gsToken string, anisette AnisetteHeaders) (string, error) {
	resp, err := c.postDevService("ios/submitDevelopmentCSR.action", map[string]any{
		"teamId":      teamID,
		"csrContent":  string(csrPEM),
		"machineId":   strings.ToUpper(uuid.NewString()),
		"machineName": "SignedServer",
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

func (c *Client) sendGSARequest(requestDict map[string]any, anisette AnisetteHeaders) (map[string]any, error) {
	payload := map[string]any{
		"Header":  map[string]any{"Version": "1.0.1"},
		"Request": requestDict,
	}
	var buf bytes.Buffer
	if err := plist.NewEncoder(&buf).Encode(payload); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, gsaURL, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("X-MMe-Client-Info", anisette.ClientInfo)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0")

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
		return nil, fmt.Errorf("GSA plist decode error: %w", err)
	}
	respDict, ok := out["Response"].(map[string]any)
	if !ok {
		return nil, errors.New("missing Response dict in GSA reply")
	}
	if status, ok := respDict["Status"].(map[string]any); ok {
		if ec, _ := toInt(status["ec"]); ec != 0 {
			em, _ := status["em"].(string)
			return nil, fmt.Errorf("Apple GSA error (%d): %s", ec, em)
		}
	}
	return respDict, nil
}

func (c *Client) postDevService(action string, extra map[string]any, dsid, gsToken string, anisette AnisetteHeaders) (map[string]any, error) {
	normalizeAnisette(&anisette)
	payload := map[string]any{
		"clientId":        xcodeClientID,
		"protocolVersion": "QH65B2",
		"requestId":       strings.ToUpper(uuid.NewString()),
	}
	for k, v := range extra {
		payload[k] = v
	}
	var buf bytes.Buffer
	if err := plist.NewEncoder(&buf).Encode(payload); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/%s?clientId=%s", devServicesBaseURL, strings.TrimLeft(action, "/"), xcodeClientID)
	req, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("User-Agent", xcodeUserAgent)
	req.Header.Set("Accept", "text/x-xml-plist")
	req.Header.Set("Accept-Language", "en-us")
	req.Header.Set("X-Apple-App-Info", xcodeAppBundleID)
	req.Header.Set("X-Xcode-Version", xcodeVersion)
	req.Header.Set("X-Apple-I-Identity-Id", dsid)
	req.Header.Set("X-Apple-GS-Token", gsToken)
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
		msg, _ := out["userString"].(string)
		if msg == "" {
			msg, _ = out["resultString"].(string)
		}
		return nil, fmt.Errorf("Apple DevServices error (%d): %s", rc, msg)
	}
	return out, nil
}

func (c *Client) sendServicesV1Request(methodOverride, path, teamID string, extraParams map[string]string, dsid, gsToken string, anisette AnisetteHeaders) (map[string]any, error) {
	normalizeAnisette(&anisette)
	q := url.Values{}
	if teamID != "" {
		q.Set("teamId", teamID)
	}
	for k, v := range extraParams {
		q.Set(k, v)
	}
	bodyBytes, _ := json.Marshal(map[string]string{
		"urlEncodedQueryParams": q.Encode(),
	})

	endpoint := fmt.Sprintf("%s/%s", servicesV1BaseURL, strings.TrimLeft(path, "/"))
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("User-Agent", xcodeUserAgent)
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Accept-Language", "en-us")
	req.Header.Set("X-Apple-App-Info", xcodeAppBundleID)
	req.Header.Set("X-Xcode-Version", xcodeVersion)
	req.Header.Set("X-HTTP-Method-Override", methodOverride)
	req.Header.Set("X-Apple-I-Identity-Id", dsid)
	req.Header.Set("X-Apple-GS-Token", gsToken)
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
	if len(body) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("services v1 json error: %w", err)
	}
	if rc, ok := toInt(out["resultCode"]); ok && rc != 0 {
		msg, _ := out["userString"].(string)
		if msg == "" {
			msg, _ = out["resultString"].(string)
		}
		return nil, fmt.Errorf("Apple Services v1 error (%d): %s", rc, msg)
	}
	return out, nil
}

func (c *Client) applyAnisetteHeaders(req *http.Request, a AnisetteHeaders) {
	if a.OneTimePassword != "" {
		req.Header.Set("X-Apple-I-MD", a.OneTimePassword)
	}
	if a.MachineID != "" {
		req.Header.Set("X-Apple-I-MD-M", a.MachineID)
	}
	if a.LocalUserID != "" {
		req.Header.Set("X-Apple-I-MD-LU", a.LocalUserID)
	}
	if a.RoutingInfo != "" {
		req.Header.Set("X-Apple-I-MD-RINFO", a.RoutingInfo)
	}
	if a.DeviceID != "" {
		req.Header.Set("X-Mme-Device-Id", a.DeviceID)
	}
	if a.ClientInfo != "" {
		req.Header.Set("X-MMe-Client-Info", a.ClientInfo)
	}
	if a.ClientTime != "" {
		req.Header.Set("X-Apple-I-Client-Time", a.ClientTime)
	}
	if a.Locale != "" {
		req.Header.Set("X-Apple-Locale", a.Locale)
		req.Header.Set("X-Apple-I-Locale", a.Locale)
	}
	if a.TimeZone != "" {
		req.Header.Set("X-Apple-I-TimeZone", a.TimeZone)
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

// decryptETGCM decrypts GSA apptokens "et" data using AES-256-GCM with 16-byte IV and "XYZ" header AAD (matching AltSign ALTDecryptDataGCM).
func decryptETGCM(sk, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 35 {
		return nil, errors.New("encrypted token too short")
	}
	if string(encryptedData[:3]) != "XYZ" {
		return nil, errors.New("encrypted token wrong version header")
	}
	block, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	aad := encryptedData[:3]
	iv := encryptedData[3:19]
	ciphertextAndTag := encryptedData[19:]
	return gcm.Open(nil, iv, ciphertextAndTag, aad)
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
	case float64:
		return int(t), true
	case string:
		if n, err := strconv.Atoi(t); err == nil {
			return n, true
		}
		return 0, false
	default:
		return 0, false
	}
}
