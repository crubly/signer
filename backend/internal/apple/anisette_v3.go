package apple

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"howett.net/plist"
)

const gsaLookupURL = "https://gsa.apple.com/grandslam/GsService2/lookup"

type anisetteV3State struct {
	IdentifierB64 string `json:"identifier_b64"`
	ADIPB         string `json:"adi_pb"`
	DeviceID      string `json:"device_id"`
	LocalUserID   string `json:"local_user_id"`
	ClientInfo    string `json:"client_info"`
	UserAgent     string `json:"user_agent"`
}

type anisetteV3Client struct {
	mu        sync.Mutex
	statePath string
	state     *anisetteV3State
}

func newAnisetteV3Client(dataDir string) *anisetteV3Client {
	if dataDir == "" {
		dataDir = "/data"
	}
	v3 := &anisetteV3Client{
		statePath: filepath.Join(dataDir, "anisette_v3.json"),
	}
	if raw, err := os.ReadFile(v3.statePath); err == nil {
		var st anisetteV3State
		if json.Unmarshal(raw, &st) == nil && st.IdentifierB64 != "" && st.ADIPB != "" {
			v3.state = &st
		}
	}
	return v3
}

func (c *Client) fetchAnisetteV3(baseURL string) (AnisetteHeaders, error) {
	var h AnisetteHeaders
	c.v3.mu.Lock()
	defer c.v3.mu.Unlock()

	if c.v3.state == nil {
		st, err := c.provisionAnisetteV3(baseURL)
		if err != nil {
			return h, err
		}
		c.v3.state = st
		_ = os.MkdirAll(filepath.Dir(c.v3.statePath), 0o755)
		if raw, err := json.MarshalIndent(st, "", "  "); err == nil {
			_ = os.WriteFile(c.v3.statePath, raw, 0o600)
		}
	}

	reqBody, _ := json.Marshal(map[string]string{
		"identifier": c.v3.state.IdentifierB64,
		"adi_pb":     c.v3.state.ADIPB,
	})
	resp, err := c.httpClient.Post(baseURL+"/v3/get_headers", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return h, fmt.Errorf("anisette v3 get_headers failed: %w", err)
	}
	defer resp.Body.Close()
	var res struct {
		Result  string `json:"result"`
		Message string `json:"message"`
		MD      string `json:"X-Apple-I-MD"`
		MDM     string `json:"X-Apple-I-MD-M"`
		RInfo   string `json:"X-Apple-I-MD-RINFO"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return h, err
	}
	if res.Result != "Headers" {
		// Provisioning may have expired; clear state and retry once
		log.Printf("anisette v3 get_headers returned %s (%s), re-provisioning", res.Result, res.Message)
		c.v3.state = nil
		_ = os.Remove(c.v3.statePath)
		st, err := c.provisionAnisetteV3(baseURL)
		if err != nil {
			return h, err
		}
		c.v3.state = st
		if raw, err := json.MarshalIndent(st, "", "  "); err == nil {
			_ = os.WriteFile(c.v3.statePath, raw, 0o600)
		}
		reqBody, _ = json.Marshal(map[string]string{
			"identifier": st.IdentifierB64,
			"adi_pb":     st.ADIPB,
		})
		resp2, err := c.httpClient.Post(baseURL+"/v3/get_headers", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			return h, err
		}
		defer resp2.Body.Close()
		if err := json.NewDecoder(resp2.Body).Decode(&res); err != nil {
			return h, err
		}
		if res.Result != "Headers" {
			return h, fmt.Errorf("anisette v3 error: %s: %s", res.Result, res.Message)
		}
	}

	h = AnisetteHeaders{
		OneTimePassword: res.MD,
		MachineID:       res.MDM,
		RoutingInfo:     res.RInfo,
		LocalUserID:     c.v3.state.LocalUserID,
		DeviceID:        c.v3.state.DeviceID,
		ClientInfo:      c.v3.state.ClientInfo,
		Serial:          "0",
		ClientTime:      time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Locale:          "en_US",
		TimeZone:        "UTC",
	}
	normalizeAnisette(&h)
	return h, nil
}

func (c *Client) provisionAnisetteV3(baseURL string) (*anisetteV3State, error) {
	// 1. Fetch client_info from local anisette-v3-server
	ciResp, err := c.httpClient.Get(baseURL + "/v3/client_info")
	if err != nil {
		return nil, fmt.Errorf("anisette v3 client_info failed: %w", err)
	}
	defer ciResp.Body.Close()
	var ci struct {
		ClientInfo string `json:"client_info"`
		UserAgent  string `json:"user_agent"`
	}
	if err := json.NewDecoder(ciResp.Body).Decode(&ci); err != nil {
		return nil, err
	}
	if ci.ClientInfo == "" {
		return nil, errors.New("empty client_info from anisette v3 server")
	}

	// 2. Fetch Apple provisioning URLs from gsa.apple.com/grandslam/GsService2/lookup
	startURL, finishURL, err := c.fetchAppleProvisioningURLs(ci.ClientInfo, ci.UserAgent)
	if err != nil {
		return nil, err
	}

	// 3. Connect WebSocket to local anisette-v3-server /v3/provisioning_session
	wsURL := strings.Replace(baseURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL = strings.TrimRight(wsURL, "/") + "/v3/provisioning_session"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("anisette v3 ws dial failed: %w", err)
	}
	defer conn.Close()

	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	idB64 := base64.StdEncoding.EncodeToString(idBytes)
	u, _ := uuid.FromBytes(idBytes)
	deviceID := strings.ToUpper(u.String())
	luSum := sha256.Sum256(idBytes)
	localUserID := strings.ToUpper(hex.EncodeToString(luSum[:]))

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			return nil, fmt.Errorf("anisette v3 ws read error: %w", err)
		}
		var msg map[string]any
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			return nil, err
		}
		result, _ := msg["result"].(string)
		switch result {
		case "GiveIdentifier":
			if err := conn.WriteJSON(map[string]string{"identifier": idB64}); err != nil {
				return nil, err
			}
		case "GiveStartProvisioningData":
			spim, err := c.appleStartProvisioning(startURL, ci.ClientInfo, ci.UserAgent, deviceID)
			if err != nil {
				return nil, err
			}
			if err := conn.WriteJSON(map[string]string{"spim": spim}); err != nil {
				return nil, err
			}
		case "GiveEndProvisioningData":
			cpim, _ := msg["cpim"].(string)
			ptm, tk, err := c.appleFinishProvisioning(finishURL, cpim, ci.ClientInfo, ci.UserAgent, deviceID)
			if err != nil {
				return nil, err
			}
			if err := conn.WriteJSON(map[string]string{"ptm": ptm, "tk": tk}); err != nil {
				return nil, err
			}
		case "ProvisioningSuccess":
			adiPB, _ := msg["adi_pb"].(string)
			if adiPB == "" {
				return nil, errors.New("empty adi_pb in ProvisioningSuccess")
			}
			log.Printf("Self-hosted Anisette v3 provisioned successfully (device=%s)", deviceID)
			return &anisetteV3State{
				IdentifierB64: idB64,
				ADIPB:         adiPB,
				DeviceID:      deviceID,
				LocalUserID:   localUserID,
				ClientInfo:    ci.ClientInfo,
				UserAgent:     ci.UserAgent,
			}, nil
		default:
			errMsg, _ := msg["message"].(string)
			return nil, fmt.Errorf("anisette v3 provisioning failed (%s): %s", result, errMsg)
		}
	}
}

func (c *Client) fetchAppleProvisioningURLs(clientInfo, userAgent string) (string, string, error) {
	req, err := http.NewRequest(http.MethodGet, gsaLookupURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("X-MMe-Client-Info", clientInfo)
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("apple lookup failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	var out map[string]any
	if _, err := plist.Unmarshal(body, &out); err != nil {
		return "", "", fmt.Errorf("apple lookup plist error: %w", err)
	}
	urls, _ := out["urls"].(map[string]any)
	startURL, _ := urls["midStartProvisioning"].(string)
	finishURL, _ := urls["midFinishProvisioning"].(string)
	if startURL == "" || finishURL == "" {
		return "", "", errors.New("missing provisioning URLs in Apple lookup")
	}
	return startURL, finishURL, nil
}

func (c *Client) appleStartProvisioning(startURL, clientInfo, userAgent, deviceID string) (string, error) {
	respDict, err := c.postProvisioningPlist(startURL, map[string]any{}, clientInfo, userAgent, deviceID)
	if err != nil {
		return "", err
	}
	spim, _ := respDict["spim"].(string)
	if spim == "" {
		return "", errors.New("missing spim in Apple startProvisioning")
	}
	return spim, nil
}

func (c *Client) appleFinishProvisioning(finishURL, cpim, clientInfo, userAgent, deviceID string) (string, string, error) {
	respDict, err := c.postProvisioningPlist(finishURL, map[string]any{"cpim": cpim}, clientInfo, userAgent, deviceID)
	if err != nil {
		return "", "", err
	}
	ptm, _ := respDict["ptm"].(string)
	tk, _ := respDict["tk"].(string)
	if ptm == "" || tk == "" {
		return "", "", errors.New("missing ptm or tk in Apple finishProvisioning")
	}
	return ptm, tk, nil
}

func (c *Client) postProvisioningPlist(endpoint string, reqBody map[string]any, clientInfo, userAgent, deviceID string) (map[string]any, error) {
	payload := map[string]any{
		"Header":  map[string]any{},
		"Request": reqBody,
	}
	var buf bytes.Buffer
	if err := plist.NewEncoder(&buf).Encode(payload); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("X-MMe-Client-Info", clientInfo)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Mme-Device-Id", deviceID)
	req.Header.Set("X-Apple-I-Client-Time", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	req.Header.Set("X-Apple-I-TimeZone", "UTC")
	req.Header.Set("X-Apple-Locale", "en_US")

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
		return nil, fmt.Errorf("apple provisioning plist decode error (HTTP %d): %w", resp.StatusCode, err)
	}
	respDict, _ := out["Response"].(map[string]any)
	if respDict == nil {
		return nil, errors.New("missing Response in Apple provisioning reply")
	}
	return respDict, nil
}
