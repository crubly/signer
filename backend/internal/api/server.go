package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/crubly/signer-backend/internal/apple"
	"github.com/crubly/signer-backend/internal/notify"
	"github.com/crubly/signer-backend/internal/signer"
	"github.com/crubly/signer-backend/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Config struct {
	DataDir     string
	ZsignBin    string
	JWTSecret   string
	PublicURL   string
	AnisetteURL string
}

type Server struct {
	cfg         Config
	store       *store.Store
	apple       *apple.Client
	notifier    *notify.Dispatcher
	pendingMu   sync.Mutex
	pendingAuth map[string]*apple.PendingAuth
}

func NewServer(cfg Config, st *store.Store, ap *apple.Client, disp *notify.Dispatcher) *Server {
	return &Server{
		cfg:         cfg,
		store:       st,
		apple:       ap,
		notifier:    disp,
		pendingAuth: map[string]*apple.PendingAuth{},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)

	// Apple ID Primary Auth (no JWT required)
	mux.HandleFunc("POST /api/apple/login", s.handleAppleLogin)
	mux.HandleFunc("POST /api/apple/2fa", s.handleApple2FA)
	mux.Handle("GET /api/auth/me", s.requireAuth(http.HandlerFunc(s.handleMe)))

	// Apple Developer Account & App IDs
	mux.Handle("GET /api/apple/account", s.requireAuth(http.HandlerFunc(s.handleGetAppleAccount)))
	mux.Handle("GET /api/apple/app-ids", s.requireAuth(http.HandlerFunc(s.handleListAppIDs)))
	mux.Handle("DELETE /api/apple/app-ids/{id}", s.requireAuth(http.HandlerFunc(s.handleDeleteAppID)))

	// Certificates
	mux.Handle("GET /api/certs", s.requireAuth(http.HandlerFunc(s.handleListCerts)))
	mux.Handle("POST /api/certs/upload", s.requireAuth(http.HandlerFunc(s.handleUploadCert)))

	// Apps & Signing
	mux.Handle("GET /api/apps", s.requireAuth(http.HandlerFunc(s.handleListApps)))
	mux.Handle("POST /api/apps/upload", s.requireAuth(http.HandlerFunc(s.handleUploadIPA)))
	mux.Handle("POST /api/apps/from-url", s.requireAuth(http.HandlerFunc(s.handleIPAFromURL)))
	mux.Handle("POST /api/apps/{id}/sign", s.requireAuth(http.HandlerFunc(s.handleSignApp)))
	mux.Handle("POST /api/apps/{id}/renew", s.requireAuth(http.HandlerFunc(s.handleRenewApp)))
	mux.Handle("POST /api/apps/{id}/deactivate", s.requireAuth(http.HandlerFunc(s.handleDeactivateApp)))
	mux.Handle("POST /api/apps/{id}/activate", s.requireAuth(http.HandlerFunc(s.handleActivateApp)))
	mux.Handle("DELETE /api/apps/{id}", s.requireAuth(http.HandlerFunc(s.handleDeleteApp)))

	// Public OTA manifest & IPA download (for iOS itms-services://)
	mux.HandleFunc("GET /ota/{id}/manifest.plist", s.handleOTAManifest)
	mux.HandleFunc("GET /ota/{id}/app.ipa", s.handleOTAIPA)

	// Notifications & Settings
	mux.Handle("GET /api/notifications", s.requireAuth(http.HandlerFunc(s.handleListNotifications)))
	mux.Handle("POST /api/notifications/read", s.requireAuth(http.HandlerFunc(s.handleMarkNotificationsRead)))
	mux.Handle("POST /api/notifications/test", s.requireAuth(http.HandlerFunc(s.handleTestNotification)))
	mux.Handle("GET /api/settings", s.requireAuth(http.HandlerFunc(s.handleGetSettings)))
	mux.Handle("PUT /api/settings", s.requireAuth(http.HandlerFunc(s.handleUpdateSettings)))

	return corsMiddleware(mux)
}

type ctxKey string

const userIDKey ctxKey = "user_id"

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tokStr := strings.TrimPrefix(auth, "Bearer ")
		tok, err := jwt.Parse(tokStr, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(s.cfg.JWTSecret), nil
		})
		if err != nil || !tok.Valid {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "invalid claims")
			return
		}
		uid, _ := claims["sub"].(string)
		if uid == "" {
			writeErr(w, http.StatusUnauthorized, "missing subject")
			return
		}
		ctx := context.WithValue(r.Context(), userIDKey, uid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func currentUserID(r *http.Request) string {
	v, _ := r.Context().Value(userIDKey).(string)
	return v
}

func (s *Server) issueJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.cfg.JWTSecret))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"time": time.Now().UTC(),
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	u, err := s.store.GetUserByID(uid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	acc, _ := s.store.GetAppleAccount(uid)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          u,
		"apple_account": acc,
	})
}

func (s *Server) handleGetAppleAccount(w http.ResponseWriter, r *http.Request) {
	acc, err := s.store.GetAppleAccount(currentUserID(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if acc == nil {
		writeJSON(w, http.StatusOK, map[string]any{"logged_in": false})
		return
	}
	writeJSON(w, http.StatusOK, acc)
}

func (s *Server) handleAppleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AppleID    string `json:"apple_id"`
		Password   string `json:"password"`
		DeviceUDID string `json:"device_udid"`
		DeviceName string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	appleID := strings.TrimSpace(strings.ToLower(body.AppleID))
	if appleID == "" || body.Password == "" {
		writeErr(w, http.StatusBadRequest, "apple_id and password required")
		return
	}

	s.apple.SetAnisetteURL(s.cfg.AnisetteURL)
	res, pending, err := s.apple.StartLogin(appleID, body.Password)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}

	user, err := s.store.UpsertAppleUser(uuid.NewString(), appleID, res.DSID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	acc := store.Account{
		UserID:     user.ID,
		AppleID:    appleID,
		DSID:       res.DSID,
		GSToken:    res.GSToken,
		DeviceUDID: body.DeviceUDID,
		DeviceName: body.DeviceName,
		Needs2FA:   res.Needs2FA,
		LoggedIn:   !res.Needs2FA,
	}

	if res.Needs2FA {
		sessionID := uuid.NewString()
		s.pendingMu.Lock()
		s.pendingAuth[sessionID] = pending
		s.pendingMu.Unlock()
		_ = s.store.SaveAppleAccount(acc)
		writeJSON(w, http.StatusOK, map[string]any{
			"needs_2fa":  true,
			"session_id": sessionID,
			"account":    acc,
		})
		return
	}

	s.syncTeamsAndSave(user.ID, &acc, res.Anisette)
	tok, err := s.issueJWT(user.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"needs_2fa": false,
		"token":     tok,
		"user":      user,
		"account":   acc,
	})
}

func (s *Server) handleApple2FA(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionID string `json:"session_id"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Code) != 6 || body.SessionID == "" {
		writeErr(w, http.StatusBadRequest, "session_id and 6-digit code required")
		return
	}

	s.pendingMu.Lock()
	pending := s.pendingAuth[body.SessionID]
	s.pendingMu.Unlock()
	if pending == nil {
		writeErr(w, http.StatusBadRequest, "no pending 2FA session")
		return
	}

	res, err := s.apple.Submit2FA(pending, body.Code)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}

	s.pendingMu.Lock()
	delete(s.pendingAuth, body.SessionID)
	s.pendingMu.Unlock()

	user, err := s.store.UpsertAppleUser(uuid.NewString(), strings.ToLower(pending.AppleID), res.DSID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	acc, _ := s.store.GetAppleAccount(user.ID)
	if acc == nil {
		acc = &store.Account{UserID: user.ID, AppleID: strings.ToLower(pending.AppleID)}
	}
	acc.DSID = res.DSID
	acc.GSToken = res.GSToken
	acc.Needs2FA = false
	acc.LoggedIn = true
	s.syncTeamsAndSave(user.ID, acc, res.Anisette)

	tok, err := s.issueJWT(user.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"needs_2fa": false,
		"token":     tok,
		"user":      user,
		"account":   acc,
	})
}

func (s *Server) syncTeamsAndSave(uid string, acc *store.Account, anisette apple.AnisetteHeaders) {
	if acc.SessionData == nil {
		acc.SessionData = map[string]string{}
	}
	if aniBytes, err := json.Marshal(anisette); err == nil {
		acc.SessionData["anisette"] = string(aniBytes)
	}
	teams, err := s.apple.ListTeams(acc.DSID, acc.GSToken, anisette)
	if err != nil {
		log.Printf("apple ListTeams error for %s: %v", acc.AppleID, err)
	} else if len(teams) > 0 {
		acc.TeamID = teams[0].TeamID
		acc.TeamName = teams[0].Name
		if strings.Contains(strings.ToLower(teams[0].Type), "individual") {
			acc.TeamType = "free"
		} else {
			acc.TeamType = "paid"
		}
	}
	_ = s.store.SaveAppleAccount(*acc)
}

func (s *Server) accountAnisette(acc *store.Account) (apple.AnisetteHeaders, error) {
	if acc != nil && acc.SessionData != nil {
		if raw := acc.SessionData["anisette"]; raw != "" {
			var h apple.AnisetteHeaders
			if err := json.Unmarshal([]byte(raw), &h); err == nil && h.MachineID != "" {
				return h, nil
			}
		}
	}
	return s.apple.FetchAnisette()
}

func (s *Server) handleListAppIDs(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	acc, _ := s.store.GetAppleAccount(uid)
	if acc != nil && acc.LoggedIn && acc.TeamID != "" {
		if anisette, err := s.accountAnisette(acc); err == nil {
			if ids, err := s.apple.ListAppIDs(acc.TeamID, acc.DSID, acc.GSToken, anisette); err == nil {
				records := make([]store.AppIDRecord, 0, len(ids))
				for _, id := range ids {
					isExt := strings.Count(id.Identifier, ".") >= 3 || strings.Contains(strings.ToLower(id.Name), "ext") || strings.Contains(strings.ToLower(id.Name), "widget")
					records = append(records, store.AppIDRecord{
						AppIDID:    id.AppIDID,
						UserID:     uid,
						Name:       id.Name,
						Identifier: id.Identifier,
						IsExt:      isExt,
					})
				}
				_ = s.store.ReplaceAppIDs(uid, records)
			}
		}
	}
	list, err := s.store.ListAppIDs(uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app_ids": list})
}

func (s *Server) handleDeleteAppID(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	appIDID := r.PathValue("id")
	acc, _ := s.store.GetAppleAccount(uid)
	if acc != nil && acc.LoggedIn && acc.TeamID != "" {
		if anisette, err := s.accountAnisette(acc); err == nil {
			_ = s.apple.DeleteAppID(acc.TeamID, appIDID, acc.DSID, acc.GSToken, anisette)
		}
	}
	if err := s.store.DeleteAppID(uid, appIDID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": appIDID})
}

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.store.ListCertificates(currentUserID(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": certs})
}

func (s *Server) handleUploadCert(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	p12File, _, err := r.FormFile("p12")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "p12 file required")
		return
	}
	defer p12File.Close()
	provFile, _, err := r.FormFile("mobileprovision")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "mobileprovision file required")
		return
	}
	defer provFile.Close()

	certID := uuid.NewString()
	certDir := filepath.Join(s.cfg.DataDir, "certs", uid, certID)
	_ = os.MkdirAll(certDir, 0o755)
	p12Path := filepath.Join(certDir, "cert.p12")
	provPath := filepath.Join(certDir, "profile.mobileprovision")

	if err := saveUploadedFile(p12File, p12Path); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := saveUploadedFile(provFile, provPath); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	name := r.FormValue("name")
	if name == "" {
		name = "Uploaded Certificate"
	}
	cert := store.Certificate{
		ID:                  certID,
		UserID:              uid,
		Name:                name,
		CertType:            "development",
		P12Path:             p12Path,
		Password:            r.FormValue("password"),
		MobileprovisionPath: provPath,
		ExpiresAt:           time.Now().Add(365 * 24 * time.Hour),
		Source:              "uploaded",
		CreatedAt:           time.Now(),
	}
	if err := s.store.SaveCertificate(cert); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApps(currentUserID(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
}

func (s *Server) handleUploadIPA(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	file, _, err := r.FormFile("ipa")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ipa file required")
		return
	}
	defer file.Close()

	appID := uuid.NewString()
	appDir := filepath.Join(s.cfg.DataDir, "apps", uid, appID)
	_ = os.MkdirAll(appDir, 0o755)
	rawPath := filepath.Join(appDir, "raw.ipa")
	if err := saveUploadedFile(file, rawPath); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.registerUploadedIPA(w, uid, appID, rawPath)
}

func (s *Server) handleIPAFromURL(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		writeErr(w, http.StatusBadRequest, "url required")
		return
	}

	resp, err := http.Get(body.URL)
	if err != nil || resp.StatusCode >= 300 {
		writeErr(w, http.StatusBadGateway, "failed to download ipa")
		return
	}
	defer resp.Body.Close()

	appID := uuid.NewString()
	appDir := filepath.Join(s.cfg.DataDir, "apps", uid, appID)
	_ = os.MkdirAll(appDir, 0o755)
	rawPath := filepath.Join(appDir, "raw.ipa")
	if err := saveUploadedFile(resp.Body, rawPath); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.registerUploadedIPA(w, uid, appID, rawPath)
}

func (s *Server) registerUploadedIPA(w http.ResponseWriter, uid, appID, rawPath string) {
	meta, err := signer.InspectIPA(rawPath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	app := store.SignedApp{
		ID:                  appID,
		UserID:              uid,
		Name:                meta.Name,
		BundleID:            meta.BundleID,
		OriginalBundleID:    meta.BundleID,
		Version:             meta.Version,
		RawIPAPath:          rawPath,
		AvailableExtensions: meta.Extensions,
		StrippedExtensions:  []string{},
		SignedAt:            time.Now(),
		ExpiresAt:           time.Now(),
		Status:              "unsigned",
	}
	if err := s.store.SaveApp(app); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) handleSignApp(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	appID := r.PathValue("id")
	app, err := s.store.GetApp(appID)
	if err != nil || app == nil || app.UserID != uid {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}

	var body struct {
		CertID          string   `json:"cert_id"`
		BundleID        string   `json:"bundle_id"`
		StripExtensions []string `json:"strip_extensions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	targetBundleID := body.BundleID
	if targetBundleID == "" {
		targetBundleID = app.BundleID
	}

	cert, err := s.store.GetCertificate(uid, body.CertID)
	if err != nil || cert == nil || body.CertID == "" {
		autoCert, autoBundleID, provErr := s.ensureAppleProvisioning(uid, targetBundleID, app.Name)
		if provErr == nil && autoCert != nil {
			cert = autoCert
			targetBundleID = autoBundleID
		} else if cert == nil {
			msg := "no signing certificate available"
			if provErr != nil {
				msg = "Apple ID auto-provisioning failed: " + provErr.Error()
			}
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
	}

	outPath := filepath.Join(filepath.Dir(app.RawIPAPath), "signed.ipa")

	err = signer.SignIPA(signer.SignOptions{
		ZsignBin:        s.cfg.ZsignBin,
		InputIPA:        app.RawIPAPath,
		OutputIPA:       outPath,
		P12Path:         cert.P12Path,
		P12Password:     cert.Password,
		Mobileprovision: cert.MobileprovisionPath,
		BundleID:        targetBundleID,
		StripExts:       body.StripExtensions,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	now := time.Now()
	app.BundleID = targetBundleID
	app.CertID = cert.ID
	app.SignedIPAPath = outPath
	app.StrippedExtensions = body.StripExtensions
	app.SignedAt = now
	app.ExpiresAt = now.Add(7 * 24 * time.Hour)
	app.Status = "signed"

	if err := s.store.SaveApp(*app); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	baseURL := strings.TrimRight(s.effectivePublicURL(r), "/")
	manifestURL := fmt.Sprintf("%s/ota/%s/manifest.plist", baseURL, app.ID)
	otaURL := "itms-services://?action=download-manifest&url=" + url.QueryEscape(manifestURL)

	writeJSON(w, http.StatusOK, map[string]any{
		"app":          app,
		"ota_url":      otaURL,
		"manifest_url": manifestURL,
	})
}

func (s *Server) handleRenewApp(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	appID := r.PathValue("id")
	app, err := s.store.GetApp(appID)
	if err != nil || app == nil || app.UserID != uid {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	targetBundleID := app.BundleID
	cert, err := s.store.GetCertificate(uid, app.CertID)
	if err != nil || cert == nil {
		autoCert, autoBundleID, provErr := s.ensureAppleProvisioning(uid, targetBundleID, app.Name)
		if provErr == nil && autoCert != nil {
			cert = autoCert
			targetBundleID = autoBundleID
		} else {
			msg := "signing certificate not found"
			if provErr != nil {
				msg = "Apple ID auto-provisioning failed: " + provErr.Error()
			}
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
	}

	outPath := filepath.Join(filepath.Dir(app.RawIPAPath), "signed.ipa")
	if err := signer.SignIPA(signer.SignOptions{
		ZsignBin:        s.cfg.ZsignBin,
		InputIPA:        app.RawIPAPath,
		OutputIPA:       outPath,
		P12Path:         cert.P12Path,
		P12Password:     cert.Password,
		Mobileprovision: cert.MobileprovisionPath,
		BundleID:        targetBundleID,
		StripExts:       app.StrippedExtensions,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	now := time.Now()
	app.BundleID = targetBundleID
	app.CertID = cert.ID
	app.SignedIPAPath = outPath
	app.SignedAt = now
	app.ExpiresAt = now.Add(7 * 24 * time.Hour)
	app.Status = "signed"
	_ = s.store.SaveApp(*app)

	baseURL := strings.TrimRight(s.effectivePublicURL(r), "/")
	manifestURL := fmt.Sprintf("%s/ota/%s/manifest.plist", baseURL, app.ID)
	otaURL := "itms-services://?action=download-manifest&url=" + url.QueryEscape(manifestURL)
	writeJSON(w, http.StatusOK, map[string]any{
		"app":     app,
		"ota_url": otaURL,
	})
}

func (s *Server) ensureAppleProvisioning(uid, bundleID, appName string) (*store.Certificate, string, error) {
	acc, err := s.store.GetAppleAccount(uid)
	if err != nil || acc == nil || !acc.LoggedIn {
		return nil, bundleID, errors.New("Apple ID session missing; sign in with Apple ID")
	}

	anisette, err := s.accountAnisette(acc)
	if err != nil {
		return nil, bundleID, err
	}

	if acc.TeamID == "" {
		teams, terr := s.apple.ListTeams(acc.DSID, acc.GSToken, anisette)
		if terr != nil || len(teams) == 0 {
			return nil, bundleID, fmt.Errorf("failed to fetch Apple Developer Team: %v", terr)
		}
		acc.TeamID = teams[0].TeamID
		acc.TeamName = teams[0].Name
		if strings.Contains(strings.ToLower(teams[0].Type), "individual") {
			acc.TeamType = "free"
		} else {
			acc.TeamType = "paid"
		}
		_ = s.store.SaveAppleAccount(*acc)
	}

	_ = s.apple.AddDevice(acc.TeamID, acc.DeviceName, acc.DeviceUDID, acc.DSID, acc.GSToken, anisette)

	// Generate RSA key + CSR and submit to Apple
	privPEM, csrPEM, err := apple.GenerateCSR("Signed")
	if err != nil {
		return nil, bundleID, err
	}

	certIDFromApple, err := s.apple.SubmitDevelopmentCSR(acc.TeamID, csrPEM, acc.DSID, acc.GSToken, anisette)
	if err != nil {
		// If max certificates reached, revoke oldest dev cert and retry
		if certs, lerr := s.apple.ListDevCerts(acc.TeamID, acc.DSID, acc.GSToken, anisette); lerr == nil && len(certs) > 0 {
			revTarget := certs[0].CertID
			if revTarget == "" {
				revTarget = certs[0].SerialNumber
			}
			_ = s.apple.RevokeDevCert(acc.TeamID, revTarget, acc.DSID, acc.GSToken, anisette)
			certIDFromApple, err = s.apple.SubmitDevelopmentCSR(acc.TeamID, csrPEM, acc.DSID, acc.GSToken, anisette)
		}
		if err != nil {
			return nil, bundleID, err
		}
	}

	devCerts, err := s.apple.ListDevCerts(acc.TeamID, acc.DSID, acc.GSToken, anisette)
	if err != nil || len(devCerts) == 0 {
		return nil, bundleID, errors.New("failed to fetch development certificate from Apple")
	}
	var chosen *apple.DevCert
	for i := range devCerts {
		if devCerts[i].CertID == certIDFromApple || len(devCerts[i].CertContent) > 0 {
			chosen = &devCerts[i]
			if devCerts[i].CertID == certIDFromApple {
				break
			}
		}
	}
	if chosen == nil || len(chosen.CertContent) == 0 {
		return nil, bundleID, errors.New("Apple returned empty certificate content")
	}

	// Ensure unique App ID for free account (append team suffix if not already)
	uniqueBundleID := bundleID
	if !strings.HasSuffix(uniqueBundleID, "."+acc.TeamID) {
		uniqueBundleID = bundleID + "." + acc.TeamID
	}

	var targetAppID apple.AppID
	existingIDs, _ := s.apple.ListAppIDs(acc.TeamID, acc.DSID, acc.GSToken, anisette)
	for _, id := range existingIDs {
		if id.Identifier == uniqueBundleID || id.Identifier == bundleID {
			targetAppID = id
			uniqueBundleID = id.Identifier
			break
		}
	}
	if targetAppID.AppIDID == "" {
		cleanName := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' {
				return r
			}
			return ' '
		}, appName)
		if strings.TrimSpace(cleanName) == "" {
			cleanName = "SignedApp"
		}
		targetAppID, err = s.apple.AddAppID(acc.TeamID, strings.TrimSpace(cleanName), uniqueBundleID, acc.DSID, acc.GSToken, anisette)
		if err != nil {
			return nil, bundleID, err
		}
	}

	provBytes, err := s.apple.DownloadProvisioningProfile(acc.TeamID, targetAppID.AppIDID, acc.DSID, acc.GSToken, anisette)
	if err != nil {
		return nil, bundleID, err
	}

	certUUID := uuid.NewString()
	certDir := filepath.Join(s.cfg.DataDir, "certs", uid, certUUID)
	_ = os.MkdirAll(certDir, 0o755)
	keyPath := filepath.Join(certDir, "key.pem")
	certPEMPath := filepath.Join(certDir, "cert.pem")
	p12Path := filepath.Join(certDir, "cert.p12")
	provPath := filepath.Join(certDir, "profile.mobileprovision")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chosen.CertContent})
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return nil, bundleID, err
	}
	if err := os.WriteFile(certPEMPath, certPEM, 0o644); err != nil {
		return nil, bundleID, err
	}
	if err := os.WriteFile(provPath, provBytes, 0o644); err != nil {
		return nil, bundleID, err
	}

	var outBuf bytes.Buffer
	cmd := exec.Command("openssl", "pkcs12", "-export", "-inkey", keyPath, "-in", certPEMPath, "-out", p12Path, "-passout", "pass:")
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	if err := cmd.Run(); err != nil {
		return nil, bundleID, fmt.Errorf("openssl pkcs12 failed (%w): %s", err, outBuf.String())
	}

	cert := store.Certificate{
		ID:                  certUUID,
		UserID:              uid,
		Name:                "Apple Free (" + acc.AppleID + ")",
		SerialNumber:        chosen.SerialNumber,
		CertType:            "development",
		P12Path:             p12Path,
		Password:            "",
		MobileprovisionPath: provPath,
		ExpiresAt:           time.Now().Add(7 * 24 * time.Hour),
		Source:              "apple",
		CreatedAt:           time.Now(),
	}
	if err := s.store.SaveCertificate(cert); err != nil {
		return nil, bundleID, err
	}
	return &cert, uniqueBundleID, nil
}

func (s *Server) handleDeactivateApp(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	appID := r.PathValue("id")
	app, err := s.store.GetApp(appID)
	if err != nil || app == nil || app.UserID != uid {
		writeErr(w, http.StatusNotFound, "app not found")
		return
	}
	app.Status = "deactivated"
	if err := s.store.SaveApp(*app); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) handleActivateApp(w http.ResponseWriter, r *http.Request) {
	s.handleRenewApp(w, r)
}

func (s *Server) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	appID := r.PathValue("id")
	app, _ := s.store.GetApp(appID)
	if app != nil && app.UserID == uid {
		_ = os.RemoveAll(filepath.Dir(app.RawIPAPath))
	}
	if err := s.store.DeleteApp(uid, appID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": appID})
}

func (s *Server) handleOTAManifest(w http.ResponseWriter, r *http.Request) {
	appID := r.PathValue("id")
	app, err := s.store.GetApp(appID)
	if err != nil || app == nil || app.SignedIPAPath == "" {
		writeErr(w, http.StatusNotFound, "signed app not found")
		return
	}
	baseURL := strings.TrimRight(s.effectivePublicURL(r), "/")
	ipaURL := fmt.Sprintf("%s/ota/%s/app.ipa", baseURL, app.ID)
	plistBytes := signer.BuildOTAManifest(ipaURL, app.BundleID, app.Version, app.Name)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(plistBytes)
}

func (s *Server) handleOTAIPA(w http.ResponseWriter, r *http.Request) {
	appID := r.PathValue("id")
	app, err := s.store.GetApp(appID)
	if err != nil || app == nil || app.SignedIPAPath == "" {
		writeErr(w, http.StatusNotFound, "signed ipa not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.ipa"`, app.Name))
	http.ServeFile(w, r, app.SignedIPAPath)
}

func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListNotifications(currentUserID(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notifications": list})
}

func (s *Server) handleMarkNotificationsRead(w http.ResponseWriter, r *http.Request) {
	if err := s.store.MarkNotificationsRead(currentUserID(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	settings, _ := s.store.GetSettings(uid)
	ev := store.NotificationEvent{
		ID:        uuid.NewString(),
		UserID:    uid,
		AppName:   "Signer",
		Title:     "Test Renewal Alert",
		Body:      "Push & expiration alerts are working. Tap to renew apps.",
		Level:     "warning",
		CreatedAt: time.Now(),
	}
	_ = s.store.AddNotification(ev)
	s.notifier.DispatchPush(settings, ev.Title, ev.Body, ev.Level)
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.GetSettings(currentUserID(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	uid := currentUserID(r)
	var st store.PushSettings
	if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	st.UserID = uid
	if err := s.store.SaveSettings(st); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) effectivePublicURL(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return s.cfg.PublicURL
	}
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func saveUploadedFile(src io.Reader, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
