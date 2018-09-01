package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"text/template"

	"github.com/gobuffalo/packr"
)

// PivotConfig - Parameters when generating a pivot
type PivotConfig struct {
	Name               string
	CACert             string
	Cert               string
	Key                string
	DefaultServer      string
	DefaultServerLport uint16
}

// GeneratePivotBinary - Generates a pivot binary
func GeneratePivotBinary(goos string, goarch string) (string, error) {

	goos = path.Base(goos)
	goarch = path.Base(goarch)
	target := fmt.Sprintf("%s/%s", goos, goarch)
	if _, ok := validCompilerTargets[target]; !ok {
		return "", fmt.Errorf("Invalid compiler target: %s", target)
	}

	config := PivotConfig{
		DefaultServer:      "localhost",
		DefaultServerLport: 8444,
	}

	config.Name = GetCodename()
	log.Printf("Generating new pivot binary '%s'", config.Name)

	// Cert PEM encoded certificates
	caCert, _, _ := GetCertificateAuthorityPEM(PivotsDir)
	pivotCert, pivotKey := GeneratePivotCertificate(config.Name, true)
	config.CACert = string(caCert)
	config.Cert = string(pivotCert)
	config.Key = string(pivotKey)

	// Load code template
	pivotBox := packr.NewBox("../pivot")
	pivotCode, _ := pivotBox.MustString("pivot.go")
	pivotCodeTmpl, _ := template.New("pivot").Parse(pivotCode)

	binDir := GetBinDir()
	workingDir := path.Join(binDir, PivotsDir, goos, goarch, config.Name)
	os.MkdirAll(workingDir, os.ModePerm)
	pivotCodePath := path.Join(workingDir, "pivot.go")
	fPivot, _ := os.Create(pivotCodePath)

	log.Printf("Rendering pivot code to: %s", pivotCodePath)
	err := pivotCodeTmpl.Execute(fPivot, config)
	if err != nil {
		log.Printf("Failed to render go code: %v", err)
		return "", err
	}

	// Compile go code
	goConfig := GoConfig{
		GOOS:   goos,
		GOARCH: goarch,
		GOROOT: GetGoRootDir(),
		GOPATH: GetGoPathDir(),
	}

	dst := path.Join(workingDir, config.Name)
	tags := []string{"netgo"}
	ldflags := []string{"-s -w"}
	_, err = GoBuild(goConfig, workingDir, dst, tags, ldflags)
	return dst, err
}
