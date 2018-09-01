package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
)

const (
	goDirName     = "go"
	goPathDirName = "gopath"
)

var (
	validCompilerTargets = map[string]bool{
		"darwin/386":      true,
		"darwin/amd64":    true,
		"dragonfly/amd64": true,
		"freebsd/386":     true,
		"freebsd/amd64":   true,
		"freebsd/arm":     true,
		"linux/386":       true,
		"linux/amd64":     true,
		"linux/arm":       true,
		"linux/arm64":     true,
		"linux/ppc64":     true,
		"linux/ppc64le":   true,
		"linux/mips":      true,
		"linux/mipsle":    true,
		"linux/mips64":    true,
		"linux/mips64le":  true,
		"linux/s390x":     true,
		"netbsd/386":      true,
		"netbsd/amd64":    true,
		"netbsd/arm":      true,
		"openbsd/386":     true,
		"openbsd/amd64":   true,
		"openbsd/arm":     true,
		"plan9/386":       true,
		"plan9/amd64":     true,
		"plan9/arm":       true,
		"solaris/amd64":   true,
		"windows/386":     true,
		"windows/amd64":   true,
	}
)

// GoConfig - Env variables for Go compiler
type GoConfig struct {
	GOOS   string
	GOARCH string
	GOROOT string
	GOPATH string
}

// GetGoRootDir - Get the path to GOROOT
func GetGoRootDir() string {
	roseDir := GetRosieDir()
	return path.Join(roseDir, goDirName)
}

// GetGoPathDir - Get the path to GOPATH
func GetGoPathDir() string {
	roseDir := GetRosieDir()
	return path.Join(roseDir, goPathDirName)
}

// GoCmd - Execute a go command
func GoCmd(config GoConfig, cwd string, command []string) ([]byte, error) {
	target := fmt.Sprintf("%s/%s", config.GOOS, config.GOARCH)
	if _, ok := validCompilerTargets[target]; !ok {
		return nil, fmt.Errorf(fmt.Sprintf("Invalid compiler target: %s", target))
	}
	goBinPath := path.Join(config.GOROOT, "bin", "go")
	cmd := exec.Command(goBinPath, command...)
	cmd.Dir = cwd
	cmd.Env = []string{
		"CGO_ENABLED=0",
		fmt.Sprintf("GOOS=%s", config.GOOS),
		fmt.Sprintf("GOARCH=%s", config.GOARCH),
		fmt.Sprintf("GOROOT=%s", config.GOROOT),
		fmt.Sprintf("GOPATH=%s", config.GOPATH),
		fmt.Sprintf("PATH=%s/bin", config.GOROOT),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("go cmd: '%v'", cmd)
	err := cmd.Run()
	if err != nil {
		log.Printf("--- stdout ---\n%s\n", stdout.String())
		log.Printf("--- stderr ---\n%s\n", stderr.String())
		log.Print(err)
	}

	return stdout.Bytes(), err
}

// GoBuild - Execute a go build command, returns stdout/error
func GoBuild(config GoConfig, src string, dest string, tags []string, ldflags []string) ([]byte, error) {
	var goCommand = []string{"build"}
	if 0 < len(tags) {
		goCommand = append(goCommand, "-tags")
		goCommand = append(goCommand, tags...)
	}
	if 0 < len(ldflags) {
		goCommand = append(goCommand, "-ldflags")
		goCommand = append(goCommand, ldflags...)
	}
	goCommand = append(goCommand, []string{"-o", dest, "."}...)
	return GoCmd(config, src, goCommand)
}

// GoVersion - Execute a go version command, returns stdout/error
func GoVersion(config GoConfig) ([]byte, error) {
	var goCommand = []string{"version"}
	wd, _ := os.Getwd()
	return GoCmd(config, wd, goCommand)
}
