package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/crubly/signer-backend/internal/store"
	"github.com/google/uuid"
)

type Dispatcher struct {
	store      *store.Store
	httpClient *http.Client
}

func NewDispatcher(st *store.Store) *Dispatcher {
	return &Dispatcher{
		store:      st,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *Dispatcher) Start(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	d.CheckExpirations()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.CheckExpirations()
		}
	}
}

func (d *Dispatcher) CheckExpirations() {
	apps, err := d.store.ListAllSignedApps()
	if err != nil {
		log.Printf("notify: list signed apps error: %v", err)
		return
	}
	now := time.Now()
	for _, app := range apps {
		rem := app.ExpiresAt.Sub(now)
		settings, _ := d.store.GetSettings(app.UserID)
		warnHours := settings.ExpiryWarningHours
		if warnHours <= 0 {
			warnHours = 24
		}

		var stage, level, title, body string
		switch {
		case rem <= 0:
			stage = "expired"
			level = "urgent"
			title = fmt.Sprintf("%s expired", app.Name)
			body = fmt.Sprintf("%s signature expired. Open Signer to re-sign and renew it.", app.Name)
		case rem <= 6*time.Hour:
			stage = "6h"
			level = "urgent"
			title = fmt.Sprintf("%s expires in <6h", app.Name)
			body = fmt.Sprintf("Open Signer now to renew %s before iOS revokes launch.", app.Name)
		case rem <= time.Duration(warnHours)*time.Hour:
			stage = fmt.Sprintf("%dh", warnHours)
			level = "warning"
			hoursLeft := int(rem.Hours())
			title = fmt.Sprintf("%s expires in %dh", app.Name, hoursLeft)
			body = fmt.Sprintf("Tap to open Signer and renew %s (%s).", app.Name, app.Version)
		default:
			continue
		}

		alertKey := fmt.Sprintf("%s:%d:%s", app.ID, app.SignedAt.Unix(), stage)
		if d.store.HasSentAlert(alertKey) {
			continue
		}

		ev := store.NotificationEvent{
			ID:        uuid.NewString(),
			UserID:    app.UserID,
			AppID:     app.ID,
			AppName:   app.Name,
			Title:     title,
			Body:      body,
			Level:     level,
			CreatedAt: now,
			Read:      false,
		}
		if err := d.store.AddNotification(ev); err != nil {
			log.Printf("notify: save notification error: %v", err)
			continue
		}
		d.store.MarkAlertSent(alertKey)
		d.DispatchPush(settings, title, body, level)
	}
}

func (d *Dispatcher) DispatchPush(settings store.PushSettings, title, body, level string) {
	if settings.NtfyURL != "" {
		req, err := http.NewRequest(http.MethodPost, strings.TrimSpace(settings.NtfyURL), strings.NewReader(body))
		if err == nil {
			req.Header.Set("Title", title)
			if level == "urgent" {
				req.Header.Set("Priority", "high")
			}
			resp, err := d.httpClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
	}

	if settings.WebhookURL != "" {
		payload, _ := json.Marshal(map[string]string{
			"title": title,
			"body":  body,
			"level": level,
		})
		req, err := http.NewRequest(http.MethodPost, strings.TrimSpace(settings.WebhookURL), bytes.NewReader(payload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := d.httpClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
	}
}
