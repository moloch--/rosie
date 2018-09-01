package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"text/template"

	"github.com/gobuffalo/packr"
)

const (
	binDirName = "bin"
)

// ClientConfig - Parameters when generating a pivot
type ClientConfig struct {
	Name               string
	CACert             string
	Cert               string
	Key                string
	DefaultServer      string
	DefaultServerLport uint16
}

// GetBinDir - Get the binary directory
func GetBinDir() string {
	rosieDir := GetRosieDir()
	binDir := path.Join(rosieDir, binDirName)
	if _, err := os.Stat(binDir); os.IsNotExist(err) {
		log.Printf("Creating rosie bin directory: %s", binDir)
		err = os.MkdirAll(binDir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}
	return binDir
}

// GenerateClientBinary - Generate and compile a new client binary
func GenerateClientBinary(goos string, goarch string) (string, error) {

	goos = path.Base(goos)
	goarch = path.Base(goarch)
	target := fmt.Sprintf("%s/%s", goos, goarch)
	if _, ok := validCompilerTargets[target]; !ok {
		return "", fmt.Errorf("Invalid compiler target: %s", target)
	}

	config := ClientConfig{
		DefaultServer:      "localhost",
		DefaultServerLport: 8443,
	}

	config.Name = GetCodename()
	log.Printf("Generating new client binary '%s'", config.Name)

	// Cert PEM encoded certificates
	caCert, _, _ := GetCertificateAuthorityPEM(ClientsDir)
	clientCert, clientKey := GenerateClientCertificate(config.Name, true)
	config.CACert = string(caCert)
	config.Cert = string(clientCert)
	config.Key = string(clientKey)

	// Render the Go source code
	clientBox := packr.NewBox("../client")
	clientCode, _ := clientBox.MustString("client.go")
	clientCodeTmpl, _ := template.New("pivot").Parse(clientCode)

	// Render code to file
	binDir := GetBinDir()
	workingDir := path.Join(binDir, ClientsDir, goos, goarch, config.Name)
	os.MkdirAll(workingDir, os.ModePerm)
	clientCodePath := path.Join(workingDir, "client.go")
	log.Printf("Rendering client go code to: %s", clientCodePath)

	fClientCode, _ := os.Create(clientCodePath)
	err := clientCodeTmpl.Execute(fClientCode, config)
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
