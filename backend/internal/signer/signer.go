package signer

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

type IPAMetadata struct {
	Name       string   `json:"name"`
	BundleID   string   `json:"bundle_id"`
	Version    string   `json:"version"`
	Extensions []string `json:"extensions"`
	AppDirName string   `json:"-"`
}

func InspectIPA(ipaPath string) (*IPAMetadata, error) {
	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return nil, fmt.Errorf("invalid ipa zip: %w", err)
	}
	defer r.Close()

	var appDir string
	var infoFile *zip.File
	extSet := map[string]bool{}

	for _, f := range r.File {
		parts := strings.Split(f.Name, "/")
		if len(parts) >= 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") {
			if appDir == "" {
				appDir = parts[1]
			}
			if parts[1] == appDir && parts[2] == "Info.plist" && len(parts) == 3 {
				infoFile = f
			}
			if parts[1] == appDir && len(parts) >= 4 && parts[2] == "PlugIns" && strings.HasSuffix(parts[3], ".appex") {
				extSet[parts[3]] = true
			}
		}
	}

	if infoFile == nil {
		return nil, errors.New("Payload/*.app/Info.plist not found in IPA")
	}

	rc, err := infoFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	var info map[string]any
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse Info.plist: %w", err)
	}

	name, _ := info["CFBundleDisplayName"].(string)
	if name == "" {
		name, _ = info["CFBundleName"].(string)
	}
	if name == "" {
		name = strings.TrimSuffix(appDir, ".app")
	}
	bundleID, _ := info["CFBundleIdentifier"].(string)
	version, _ := info["CFBundleShortVersionString"].(string)
	if version == "" {
		version, _ = info["CFBundleVersion"].(string)
	}

	exts := make([]string, 0, len(extSet))
	for k := range extSet {
		exts = append(exts, k)
	}

	return &IPAMetadata{
		Name:       name,
		BundleID:   bundleID,
		Version:    version,
		Extensions: exts,
		AppDirName: appDir,
	}, nil
}

// StripExtensions creates a copy of inputIPA excluding the specified PlugIns/*.appex directories.
func StripExtensions(inputIPA, outputIPA string, stripExts []string) error {
	if len(stripExts) == 0 {
		return copyFile(inputIPA, outputIPA)
	}
	stripMap := map[string]bool{}
	for _, e := range stripExts {
		stripMap[e] = true
	}

	r, err := zip.OpenReader(inputIPA)
	if err != nil {
		return err
	}
	defer r.Close()

	out, err := os.Create(outputIPA)
	if err != nil {
		return err
	}
	defer out.Close()

	w := zip.NewWriter(out)
	defer w.Close()

	for _, f := range r.File {
		parts := strings.Split(f.Name, "/")
		if len(parts) >= 4 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") && parts[2] == "PlugIns" {
			if stripMap[parts[3]] {
				continue
			}
		}
		header := f.FileHeader
		header.Method = zip.Deflate
		fw, err := w.CreateHeader(&header)
		if err != nil {
			return err
		}
		if !f.FileInfo().IsDir() {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			if _, err := io.Copy(fw, rc); err != nil {
				rc.Close()
				return err
			}
			rc.Close()
		}
	}
	return nil
}

type SignOptions struct {
	ZsignBin        string
	InputIPA        string
	OutputIPA       string
	P12Path         string
	P12Password     string
	Mobileprovision string
	BundleID        string
	BundleName      string
	StripExts       []string
}

func SignIPA(opts SignOptions) error {
	zsign := opts.ZsignBin
	if zsign == "" {
		zsign = "zsign"
	}

	workIPA := opts.InputIPA
	if len(opts.StripExts) > 0 {
		tmpIPA := opts.OutputIPA + ".stripped.ipa"
		if err := StripExtensions(opts.InputIPA, tmpIPA, opts.StripExts); err != nil {
			return fmt.Errorf("strip extensions failed: %w", err)
		}
		defer os.Remove(tmpIPA)
		workIPA = tmpIPA
	}

	if err := os.MkdirAll(filepath.Dir(opts.OutputIPA), 0o755); err != nil {
		return err
	}

	args := []string{
		"-k", opts.P12Path,
		"-m", opts.Mobileprovision,
		"-o", opts.OutputIPA,
		"-z", "6",
	}
	if opts.P12Password != "" {
		args = append(args, "-p", opts.P12Password)
	}
	if opts.BundleID != "" {
		args = append(args, "-b", opts.BundleID)
	}
	if opts.BundleName != "" {
		args = append(args, "-n", opts.BundleName)
	}
	args = append(args, workIPA)

	cmd := exec.Command(zsign, args...)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("zsign error (%w): %s", err, outBuf.String())
	}
	return nil
}

func BuildOTAManifest(ipaURL, bundleID, version, title string) []byte {
	manifest := map[string]any{
		"items": []any{
			map[string]any{
				"assets": []any{
					map[string]any{
						"kind": "software-package",
						"url":  ipaURL,
					},
				},
				"metadata": map[string]any{
					"bundle-identifier": bundleID,
					"bundle-version":    version,
					"kind":              "software",
					"title":             title,
				},
			},
		},
	}
	var buf bytes.Buffer
	enc := plist.NewEncoder(&buf)
	enc.Indent("\t")
	_ = enc.Encode(manifest)
	return buf.Bytes()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
