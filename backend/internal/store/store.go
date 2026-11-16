package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/crubly/signer-backend/internal/crypto"
	_ "github.com/lib/pq"
)

type User struct {
	ID        string    `json:"id"`
	GoogleSub string    `json:"google_sub"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	AvatarURL string    `json:"avatar_url"`
	CreatedAt time.Time `json:"created_at"`
}

type Account struct {
	UserID      string            `json:"user_id"`
	AppleID     string            `json:"apple_id"`
	TeamID      string            `json:"team_id"`
	TeamName    string            `json:"team_name"`
	TeamType    string            `json:"team_type"`
	DSID        string            `json:"dsid"`
	GSToken     string            `json:"-"`
	SessionData map[string]string `json:"-"`
	DeviceUDID  string            `json:"device_udid"`
	DeviceName  string            `json:"device_name"`
	LoggedIn    bool              `json:"logged_in"`
	Needs2FA    bool              `json:"needs_2fa"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type Certificate struct {
	ID                  string    `json:"id"`
	UserID              string    `json:"user_id"`
	Name                string    `json:"name"`
	SerialNumber        string    `json:"serial_number"`
	CertType            string    `json:"cert_type"`
	P12Path             string    `json:"p12_path"`
	Password            string    `json:"-"`
	MobileprovisionPath string    `json:"mobileprovision_path"`
	ExpiresAt           time.Time `json:"expires_at"`
	Source              string    `json:"source"`
	CreatedAt           time.Time `json:"created_at"`
}

type AppIDRecord struct {
	AppIDID    string `json:"app_id_id"`
	UserID     string `json:"user_id"`
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
	IsExt      bool   `json:"is_extension"`
}

type SignedApp struct {
	ID                  string    `json:"id"`
	UserID              string    `json:"user_id"`
	Name                string    `json:"name"`
	BundleID            string    `json:"bundle_id"`
	OriginalBundleID    string    `json:"original_bundle_id"`
	Version             string    `json:"version"`
	RawIPAPath          string    `json:"raw_ipa_path"`
	SignedIPAPath       string    `json:"signed_ipa_path"`
	CertID              string    `json:"cert_id"`
	AvailableExtensions []string  `json:"available_extensions"`
	StrippedExtensions  []string  `json:"stripped_extensions"`
	SignedAt            time.Time `json:"signed_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Status              string    `json:"status"`
}

type NotificationEvent struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	AppID     string    `json:"app_id"`
	AppName   string    `json:"app_name"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Level     string    `json:"level"`
	CreatedAt time.Time `json:"created_at"`
	Read      bool      `json:"read"`
}

type PushSettings struct {
	UserID             string `json:"user_id"`
	PublicURL          string `json:"public_url"`
	AnisetteURL        string `json:"anisette_url"`
	NtfyURL            string `json:"ntfy_url"`
	WebhookURL         string `json:"webhook_url"`
	APNsDeviceToken    string `json:"apns_device_token"`
	ExpiryWarningHours int    `json:"expiry_warning_hours"`
}

type Store struct {
	db                *sql.DB
	cipher            *crypto.Cipher
	defaultPublicURL  string
	defaultAnisette   string
}

func NewPostgres(dsn string, cipher *crypto.Cipher, defaultPublicURL, defaultAnisetteURL string) (*Store, error) {
	var db *sql.DB
	var err error
	for i := 0; i < 20; i++ {
		db, err = sql.Open("postgres", dsn)
		if err == nil {
			err = db.Ping()
		}
		if err == nil {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	s := &Store{
		db:               db,
		cipher:           cipher,
		defaultPublicURL: defaultPublicURL,
		defaultAnisette:  defaultAnisetteURL,
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		google_sub TEXT UNIQUE NOT NULL,
		email TEXT NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		avatar_url TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS apple_accounts (
		user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		apple_id TEXT NOT NULL,
		team_id TEXT NOT NULL DEFAULT '',
		team_name TEXT NOT NULL DEFAULT '',
		team_type TEXT NOT NULL DEFAULT 'free',
		dsid TEXT NOT NULL DEFAULT '',
		gs_token_enc TEXT NOT NULL DEFAULT '',
		session_json_enc TEXT NOT NULL DEFAULT '',
		device_udid TEXT NOT NULL DEFAULT '',
		device_name TEXT NOT NULL DEFAULT '',
		logged_in BOOLEAN NOT NULL DEFAULT FALSE,
		needs_2fa BOOLEAN NOT NULL DEFAULT FALSE,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		serial_number TEXT NOT NULL DEFAULT '',
		cert_type TEXT NOT NULL DEFAULT 'development',
		p12_path TEXT NOT NULL,
		password_enc TEXT NOT NULL DEFAULT '',
		mobileprovision_path TEXT NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		source TEXT NOT NULL DEFAULT 'uploaded',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS app_ids (
		app_id_id TEXT NOT NULL,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		identifier TEXT NOT NULL,
		is_extension BOOLEAN NOT NULL DEFAULT FALSE,
		PRIMARY KEY (user_id, app_id_id)
	);

	CREATE TABLE IF NOT EXISTS signed_apps (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		bundle_id TEXT NOT NULL,
		original_bundle_id TEXT NOT NULL,
		version TEXT NOT NULL DEFAULT '',
		raw_ipa_path TEXT NOT NULL,
		signed_ipa_path TEXT NOT NULL DEFAULT '',
		cert_id TEXT NOT NULL DEFAULT '',
		available_extensions JSONB NOT NULL DEFAULT '[]'::jsonb,
		stripped_extensions JSONB NOT NULL DEFAULT '[]'::jsonb,
		signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		status TEXT NOT NULL DEFAULT 'unsigned'
	);

	CREATE TABLE IF NOT EXISTS notifications (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		app_id TEXT NOT NULL DEFAULT '',
		app_name TEXT NOT NULL DEFAULT '',
		title TEXT NOT NULL,
		body TEXT NOT NULL,
		level TEXT NOT NULL DEFAULT 'info',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		is_read BOOLEAN NOT NULL DEFAULT FALSE
	);

	CREATE TABLE IF NOT EXISTS user_settings (
		user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		public_url TEXT NOT NULL DEFAULT '',
		anisette_url TEXT NOT NULL DEFAULT '',
		ntfy_url TEXT NOT NULL DEFAULT '',
		webhook_url TEXT NOT NULL DEFAULT '',
		apns_device_token TEXT NOT NULL DEFAULT '',
		expiry_warning_hours INT NOT NULL DEFAULT 24
	);

	CREATE TABLE IF NOT EXISTS sent_alerts (
		alert_key TEXT PRIMARY KEY,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) UpsertGoogleUser(id, googleSub, email, name, avatar string) (User, error) {
	var u User
	err := s.db.QueryRow(`
		INSERT INTO users (id, google_sub, email, name, avatar_url)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (google_sub) DO UPDATE
		SET email = EXCLUDED.email, name = EXCLUDED.name, avatar_url = EXCLUDED.avatar_url
		RETURNING id, google_sub, email, name, avatar_url, created_at
	`, id, googleSub, email, name, avatar).Scan(&u.ID, &u.GoogleSub, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt)
	if err != nil {
		return u, err
	}
	_, _ = s.db.Exec(`
		INSERT INTO user_settings (user_id, public_url, anisette_url, expiry_warning_hours)
		VALUES ($1, $2, $3, 24)
		ON CONFLICT (user_id) DO NOTHING
	`, u.ID, s.defaultPublicURL, s.defaultAnisette)
	return u, nil
}

func (s *Store) GetUserByID(id string) (User, error) {
	var u User
	err := s.db.QueryRow(`SELECT id, google_sub, email, name, avatar_url, created_at FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.GoogleSub, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt)
	return u, err
}

func (s *Store) SaveAppleAccount(a Account) error {
	gsEnc, err := s.cipher.Encrypt(a.GSToken)
	if err != nil {
		return err
	}
	sessBytes, _ := json.Marshal(a.SessionData)
	sessEnc, err := s.cipher.Encrypt(string(sessBytes))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO apple_accounts (user_id, apple_id, team_id, team_name, team_type, dsid, gs_token_enc, session_json_enc, device_udid, device_name, logged_in, needs_2fa, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
		ON CONFLICT (user_id) DO UPDATE SET
			apple_id = EXCLUDED.apple_id,
			team_id = EXCLUDED.team_id,
			team_name = EXCLUDED.team_name,
			team_type = EXCLUDED.team_type,
			dsid = EXCLUDED.dsid,
			gs_token_enc = EXCLUDED.gs_token_enc,
			session_json_enc = EXCLUDED.session_json_enc,
			device_udid = EXCLUDED.device_udid,
			device_name = EXCLUDED.device_name,
			logged_in = EXCLUDED.logged_in,
			needs_2fa = EXCLUDED.needs_2fa,
			updated_at = NOW()
	`, a.UserID, a.AppleID, a.TeamID, a.TeamName, a.TeamType, a.DSID, gsEnc, sessEnc, a.DeviceUDID, a.DeviceName, a.LoggedIn, a.Needs2FA)
	return err
}

func (s *Store) GetAppleAccount(userID string) (*Account, error) {
	var a Account
	var gsEnc, sessEnc string
	err := s.db.QueryRow(`
		SELECT user_id, apple_id, team_id, team_name, team_type, dsid, gs_token_enc, session_json_enc, device_udid, device_name, logged_in, needs_2fa, updated_at
		FROM apple_accounts WHERE user_id = $1
	`, userID).Scan(&a.UserID, &a.AppleID, &a.TeamID, &a.TeamName, &a.TeamType, &a.DSID, &gsEnc, &sessEnc, &a.DeviceUDID, &a.DeviceName, &a.LoggedIn, &a.Needs2FA, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.GSToken, _ = s.cipher.Decrypt(gsEnc)
	if plainSess, err := s.cipher.Decrypt(sessEnc); err == nil && plainSess != "" {
		_ = json.Unmarshal([]byte(plainSess), &a.SessionData)
	}
	return &a, nil
}

func (s *Store) SaveCertificate(c Certificate) error {
	pwEnc, err := s.cipher.Encrypt(c.Password)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO certificates (id, user_id, name, serial_number, cert_type, p12_path, password_enc, mobileprovision_path, expires_at, source, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, c.ID, c.UserID, c.Name, c.SerialNumber, c.CertType, c.P12Path, pwEnc, c.MobileprovisionPath, c.ExpiresAt, c.Source, c.CreatedAt)
	return err
}

func (s *Store) ListCertificates(userID string) ([]Certificate, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, name, serial_number, cert_type, p12_path, password_enc, mobileprovision_path, expires_at, source, created_at
		FROM certificates WHERE user_id = $1 ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Certificate{}
	for rows.Next() {
		var c Certificate
		var pwEnc string
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &c.SerialNumber, &c.CertType, &c.P12Path, &pwEnc, &c.MobileprovisionPath, &c.ExpiresAt, &c.Source, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.Password, _ = s.cipher.Decrypt(pwEnc)
		out = append(out, c)
	}
	return out, nil
}

func (s *Store) GetCertificate(userID, certID string) (*Certificate, error) {
	certs, err := s.ListCertificates(userID)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if c.ID == certID || certID == "" {
			cp := c
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *Store) ReplaceAppIDs(userID string, records []AppIDRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM app_ids WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, r := range records {
		if _, err := tx.Exec(`INSERT INTO app_ids (app_id_id, user_id, name, identifier, is_extension) VALUES ($1,$2,$3,$4,$5)`,
			r.AppIDID, userID, r.Name, r.Identifier, r.IsExt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListAppIDs(userID string) ([]AppIDRecord, error) {
	rows, err := s.db.Query(`SELECT app_id_id, user_id, name, identifier, is_extension FROM app_ids WHERE user_id = $1 ORDER BY is_extension DESC, identifier ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppIDRecord{}
	for rows.Next() {
		var r AppIDRecord
		if err := rows.Scan(&r.AppIDID, &r.UserID, &r.Name, &r.Identifier, &r.IsExt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *Store) DeleteAppID(userID, appIDID string) error {
	_, err := s.db.Exec(`DELETE FROM app_ids WHERE user_id = $1 AND app_id_id = $2`, userID, appIDID)
	return err
}

func (s *Store) SaveApp(a SignedApp) error {
	avail, _ := json.Marshal(a.AvailableExtensions)
	stripped, _ := json.Marshal(a.StrippedExtensions)
	_, err := s.db.Exec(`
		INSERT INTO signed_apps (id, user_id, name, bundle_id, original_bundle_id, version, raw_ipa_path, signed_ipa_path, cert_id, available_extensions, stripped_extensions, signed_at, expires_at, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)
		ON CONFLICT (id) DO UPDATE SET
			bundle_id = EXCLUDED.bundle_id,
			signed_ipa_path = EXCLUDED.signed_ipa_path,
			cert_id = EXCLUDED.cert_id,
			available_extensions = EXCLUDED.available_extensions,
			stripped_extensions = EXCLUDED.stripped_extensions,
			signed_at = EXCLUDED.signed_at,
			expires_at = EXCLUDED.expires_at,
			status = EXCLUDED.status
	`, a.ID, a.UserID, a.Name, a.BundleID, a.OriginalBundleID, a.Version, a.RawIPAPath, a.SignedIPAPath, a.CertID, string(avail), string(stripped), a.SignedAt, a.ExpiresAt, a.Status)
	return err
}

func (s *Store) ListApps(userID string) ([]SignedApp, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, name, bundle_id, original_bundle_id, version, raw_ipa_path, signed_ipa_path, cert_id, available_extensions, stripped_extensions, signed_at, expires_at, status
		FROM signed_apps WHERE user_id = $1 ORDER BY signed_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanApps(rows)
}

func (s *Store) ListAllSignedApps() ([]SignedApp, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, name, bundle_id, original_bundle_id, version, raw_ipa_path, signed_ipa_path, cert_id, available_extensions, stripped_extensions, signed_at, expires_at, status
		FROM signed_apps WHERE status = 'signed'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanApps(rows)
}

func (s *Store) GetApp(appID string) (*SignedApp, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, name, bundle_id, original_bundle_id, version, raw_ipa_path, signed_ipa_path, cert_id, available_extensions, stripped_extensions, signed_at, expires_at, status
		FROM signed_apps WHERE id = $1
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	apps, err := scanApps(rows)
	if err != nil || len(apps) == 0 {
		return nil, err
	}
	return &apps[0], nil
}

func (s *Store) DeleteApp(userID, appID string) error {
	_, err := s.db.Exec(`DELETE FROM signed_apps WHERE user_id = $1 AND id = $2`, userID, appID)
	return err
}

func scanApps(rows *sql.Rows) ([]SignedApp, error) {
	out := []SignedApp{}
	for rows.Next() {
		var a SignedApp
		var availJSON, strippedJSON []byte
		if err := rows.Scan(&a.ID, &a.UserID, &a.Name, &a.BundleID, &a.OriginalBundleID, &a.Version, &a.RawIPAPath, &a.SignedIPAPath, &a.CertID, &availJSON, &strippedJSON, &a.SignedAt, &a.ExpiresAt, &a.Status); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(availJSON, &a.AvailableExtensions)
		_ = json.Unmarshal(strippedJSON, &a.StrippedExtensions)
		if a.AvailableExtensions == nil {
			a.AvailableExtensions = []string{}
		}
		if a.StrippedExtensions == nil {
			a.StrippedExtensions = []string{}
		}
		out = append(out, a)
	}
	return out, nil
}

func (s *Store) AddNotification(n NotificationEvent) error {
	_, err := s.db.Exec(`
		INSERT INTO notifications (id, user_id, app_id, app_name, title, body, level, created_at, is_read)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, n.ID, n.UserID, n.AppID, n.AppName, n.Title, n.Body, n.Level, n.CreatedAt, n.Read)
	return err
}

func (s *Store) ListNotifications(userID string) ([]NotificationEvent, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, app_id, app_name, title, body, level, created_at, is_read
		FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationEvent{}
	for rows.Next() {
		var n NotificationEvent
		if err := rows.Scan(&n.ID, &n.UserID, &n.AppID, &n.AppName, &n.Title, &n.Body, &n.Level, &n.CreatedAt, &n.Read); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (s *Store) MarkNotificationsRead(userID string) error {
	_, err := s.db.Exec(`UPDATE notifications SET is_read = TRUE WHERE user_id = $1`, userID)
	return err
}

func (s *Store) GetSettings(userID string) (PushSettings, error) {
	st := PushSettings{
		UserID:             userID,
		PublicURL:          s.defaultPublicURL,
		AnisetteURL:        s.defaultAnisette,
		ExpiryWarningHours: 24,
	}
	err := s.db.QueryRow(`
		SELECT public_url, anisette_url, ntfy_url, webhook_url, apns_device_token, expiry_warning_hours
		FROM user_settings WHERE user_id = $1
	`, userID).Scan(&st.PublicURL, &st.AnisetteURL, &st.NtfyURL, &st.WebhookURL, &st.APNsDeviceToken, &st.ExpiryWarningHours)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if st.PublicURL == "" {
		st.PublicURL = s.defaultPublicURL
	}
	if st.AnisetteURL == "" {
		st.AnisetteURL = s.defaultAnisette
	}
	if st.ExpiryWarningHours == 0 {
		st.ExpiryWarningHours = 24
	}
	return st, err
}

func (s *Store) SaveSettings(st PushSettings) error {
	_, err := s.db.Exec(`
		INSERT INTO user_settings (user_id, public_url, anisette_url, ntfy_url, webhook_url, apns_device_token, expiry_warning_hours)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (user_id) DO UPDATE SET
			public_url = EXCLUDED.public_url,
			anisette_url = EXCLUDED.anisette_url,
			ntfy_url = EXCLUDED.ntfy_url,
			webhook_url = EXCLUDED.webhook_url,
			apns_device_token = EXCLUDED.apns_device_token,
			expiry_warning_hours = EXCLUDED.expiry_warning_hours
	`, st.UserID, st.PublicURL, st.AnisetteURL, st.NtfyURL, st.WebhookURL, st.APNsDeviceToken, st.ExpiryWarningHours)
	return err
}

func (s *Store) HasSentAlert(key string) bool {
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM sent_alerts WHERE alert_key = $1`, key).Scan(&exists)
	return err == nil
}

func (s *Store) MarkAlertSent(key string) {
	_, _ = s.db.Exec(`INSERT INTO sent_alerts (alert_key) VALUES ($1) ON CONFLICT DO NOTHING`, key)
}
