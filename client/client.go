package main

/*
 * Rosie client code, since we dynamically render and compile this file
 * I've tried to keep the code in as few files as possible, same w/Pivot.
 */

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/golang/protobuf/proto"

	mathrand "math/rand"
	pb "rosie/protobuf"
)

const (
	clientName    = `{{.Name}}`
	clientKeyPEM  = `{{.Key}}`
	clientCertPEM = `{{.Cert}}`
	caCertPEM     = `{{.CACert}}`

	defaultServerIP    = `{{.DefaultServer}}`
	defaultServerLPort = 8443

	// ANSI escapes for terminal colors
	normal  = "\033[0m"
	black   = "\033[30m"
	red     = "\033[31m"
	green   = "\033[32m"
	orange  = "\033[33m"
	blue    = "\033[34m"
	purple  = "\033[35m"
	cyan    = "\033[36m"
	gray    = "\033[37m"
	bold    = "\033[1m"
	clearLn = "\r\x1b[2K"
	upN     = "\033[%dA"
	downN   = "\033[%dB"

	// Info - Display colorful information
	Info = bold + cyan + "[*] " + normal
	// Warn - Warn a user
	Warn = bold + red + "[!] " + normal
	// Debug - Display debug information
	Debug = bold + purple + "[-] " + normal
	// Woot - Display success
	Woot = bold + green + "[$] " + normal

	timeout     = 10 * time.Second
	readBufSize = 256 * 1024

	// RandomIDSize - Size of the TunnelID in bytes
	RandomIDSize = 16

	// ----------------
	// Client Messages
	// ----------------
	// These are used when talking to the server

	// DataMsg - Connection data
	DataMsg = "d"
	// ListPivotsMsg - List connected pivots
	ListPivotsMsg = "list-pivots"
	// GenPivotMsg - Generates a pivot binary
	GenPivotMsg = "generate-pivot"
	// GenClientMsg - Generates a client binary
	GenClientMsg = "generate-client"
	// TCPTunnelMsg - Holds data related to setting up a TCP tunnel
	TCPTunnelMsg = "tcp-tunnel"
	// ExeFileMsg - Serialized executable file (client/pivot)
	ExeFileMsg = "exe-file"

	// ----------------
	// Subcommand Strs
	// ----------------
	// These are used to parse the CLI subcommands
	lsCmdStr        = "ls"
	pivotCmdStr     = "pivot"
	clientCmdStr    = "client"
	tcpTunnelCmdStr = "tcp-tunnel"
)

var (
	server  *string
	lport   *int
	verbose *bool

	lsPivotsCmd *flag.FlagSet
	lsActive    *bool

	genClientCmd *flag.FlagSet
	clientOS     *string
	clientArch   *string
	clientOutput *string

	genPivotCmd *flag.FlagSet
	pivotOS     *string
	pivotArch   *string
	pivotOutput *string

	tunnelCmd        *flag.FlagSet
	tunnelPivot      *string
	tunnelRemoteAddr *string
	tunnelBind       *int
)

type c2Connection struct {
	Send chan pb.Envelope
	Recv chan pb.Envelope
}

func main() {
	flag.Usage = usage
	if len(os.Args) == 1 {
		usage()
		os.Exit(0)
	}

	server = flag.String("server", defaultServerIP, "server address")
	lport = flag.Int("lport", defaultServerLPort, "server listen port")
	verbose = flag.Bool("verbose", false, "verbose output")

	lsPivotsCmd = flag.NewFlagSet(lsCmdStr, flag.ExitOnError)
	lsActive = lsPivotsCmd.Bool("active", false, "only list pivots with active connections")

	genClientCmd = flag.NewFlagSet(GenClientMsg, flag.ExitOnError)
	clientOS = genClientCmd.String("os", runtime.GOOS, "target cpu architecture")
	clientArch = genClientCmd.String("arch", runtime.GOARCH, "target cpu architecture")
	clientOutput = genClientCmd.String("output", "rosie", "output file path")

	genPivotCmd = flag.NewFlagSet(GenPivotMsg, flag.ExitOnError)
	pivotOS = genPivotCmd.String("os", runtime.GOOS, "target cpu architecture")
	pivotArch = genPivotCmd.String("arch", runtime.GOARCH, "target cpu architecture")
	pivotOutput = genPivotCmd.String("output", "rosie", "output file path")

	tunnelCmd = flag.NewFlagSet(TCPTunnelMsg, flag.ExitOnError)
	tunnelPivot = tunnelCmd.String("pivot", "", "name of pivot to tunnel thru")
	tunnelRemoteAddr = tunnelCmd.String("to", "", "remote address")
	tunnelBind = tunnelCmd.Int("bind", 0, "bind tunnel to local port")
	flag.Parse()
	verbosity()

	broker := NewBroker()
	go broker.Start()

	// [!] Go's sub-command arg parser is super shitty, you have to slice
	//     it just right or it won't parse any of the arguments.
	if contains(lsCmdStr, os.Args) {
		lsPivotsCmd.Parse(subArgs(lsCmdStr))
		execLsPivots(broker)
	} else if contains(clientCmdStr, os.Args) {
		genClientCmd.Parse(subArgs(clientCmdStr))
		execGenerateClient(broker)
	} else if contains(pivotCmdStr, os.Args) {
		genPivotCmd.Parse(subArgs(pivotCmdStr))
		execGeneratePivot(broker)
	} else if contains(tcpTunnelCmdStr, os.Args) {
		tunnelCmd.Parse(subArgs(tcpTunnelCmdStr))
		execTCPTunnel(broker)
	}

	if *verbose {
		panic("Stacks on Exit") // Print stacks on exit
	}
}

// subArgs - Get arguments after a subcommand
func subArgs(subcmd string) []string {
	index := indexOf(subcmd, os.Args) + 1
	if index < len(os.Args) {
		return os.Args[index:]
	}
	return []string{}
}

// verbosity - Log calls if -verbose, otherwise pipe to /dev/null
func verbosity() {
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.SetOutput(os.Stdout)
	} else {
		null, _ := os.OpenFile(os.DevNull, os.O_RDWR|os.O_APPEND, 0666)
		log.SetOutput(null)
	}
}

// Keep in mind this file gets rendered as a template too
// so we swap out the default delimeters '{' for '['
func usage() {
	tmpl, _ := template.New("usage").Delims("[[", "]]").Parse(`
roise <server options> [subcommand] <options>

Server options

    -server <server address>
    -lport <server listen port>
    -verbose (default: false)

Sub-commands

    [[.Bold]][[.Ls]][[.Normal]]: List active pivot connections
        -active (default: false)

    [[.Bold]][[.Pivot]][[.Normal]]: Generate a new pivot binary
        -os <target os> (default: [[.GOOS]])
        -arch <target arch> (default: [[.GOARCH]])

    [[.Bold]][[.Client]][[.Normal]]: Generate a new client binary
        -os <target os> (default: [[.GOOS]])
        -arch <target arch> (default: [[.GOARCH]])

    [[.Bold]][[.TCPTunnel]][[.Normal]]: Create a new tunnel via a pivot
        -pivot <name>
        -bind <bind to local port> (default: random ephermal)
        -to <remote bind> (e.g. 1.1.1.1:22)
`)
	// Render template to stdout
	tmpl.Execute(os.Stdout, struct {
		Normal    string
		Bold      string
		Ls        string
		Pivot     string
		Client    string
		TCPTunnel string
		GOOS      string
		GOARCH    string
	}{
		Normal:    normal,
		Bold:      bold,
		Ls:        lsCmdStr,
		Pivot:     pivotCmdStr,
		Client:    clientCmdStr,
		TCPTunnel: tcpTunnelCmdStr,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
	})
}

// ----------------------
// Broker Implementations
// ----------------------
// Adapted from: https://stackoverflow.com/questions/36417199/how-to-broadcast-message-using-channel

// Broker - Holds all the channels
type Broker struct {
	stopCh    chan struct{}
	publishCh chan pb.Envelope
	subCh     chan chan pb.Envelope
	unsubCh   chan chan pb.Envelope
	sendCh    chan pb.Envelope
}

// NewBroker - Instanciate new broker
func NewBroker() *Broker {
	return &Broker{
		stopCh:    make(chan struct{}),
		publishCh: make(chan pb.Envelope, 1),
		subCh:     make(chan chan pb.Envelope, 1),
		unsubCh:   make(chan chan pb.Envelope, 1),
		sendCh:    make(chan pb.Envelope, 1),
	}
}

// Start a broker instance
func (broker *Broker) Start() {
	c2Connect(broker)
	subscribers := map[chan pb.Envelope]struct{}{}
	for {
		select {
		case <-broker.stopCh:
			log.Printf("Closing all subscriber channels ...")
			for msgCh := range subscribers {
				close(msgCh)
			}
			return
		case msgCh := <-broker.subCh:
			subscribers[msgCh] = struct{}{}
		case msgCh := <-broker.unsubCh:
			delete(subscribers, msgCh)
		case msg := <-broker.publishCh:
			for msgCh := range subscribers {
				msgCh <- msg
			}
		}
	}
}

// Stop - Close down all channels
func (broker *Broker) Stop() {
	close(broker.stopCh)
}

// Subscribe - Generate a new subscription channel
func (broker *Broker) Subscribe() chan pb.Envelope {
	msgCh := make(chan pb.Envelope, 5)
	broker.subCh <- msgCh
	return msgCh
}

// Unsubscribe - Remove a subscription channel
func (broker *Broker) Unsubscribe(msgCh chan pb.Envelope) {
	broker.unsubCh <- msgCh
	close(msgCh)
}

// Publish - Push a message to all subscribers
func (broker *Broker) Publish(msg pb.Envelope) {
	broker.publishCh <- msg
}

// SendMessage - Send a message to the remote connection
func (broker *Broker) SendMessage(msgType string, msg []byte) {
	envelope := pb.Envelope{
		Type: msgType,
		Data: msg,
	}
	broker.sendCh <- envelope
}

// ------------------------
// Command Implementations
// ------------------------

func execLsPivots(broker *Broker) {
	recv := broker.Subscribe()
	defer broker.Unsubscribe(recv)
	broker.SendMessage(ListPivotsMsg, []byte{})
	envelope := <-recv
	if envelope.Type == ListPivotsMsg {
		pivots := &pb.Pivots{}
		proto.Unmarshal(envelope.Data, pivots)
		if 0 < len(pivots.List) {
			for index, pivot := range pivots.List {
				fmt.Printf("% 2d. %s\n", index+1, pivot.Name)
			}
		} else {
			fmt.Println(Info + "No povits found")
		}
	}
}

func execGeneratePivot(broker *Broker) {
	fmt.Println(Info + "Generating new pivot binary ...")
	fmt.Printf(Info+"Compiler target %s/%s\n", *pivotOS, *pivotArch)

	exeFormat, exe, err := generatePivot(broker, *pivotOS, *pivotArch, *pivotOutput)
	if err != nil {
		fmt.Printf(Warn+"Failed to generate pivot binary: %s\n", err)
	} else {
		err = ioutil.WriteFile(*pivotOutput, exe, 0755)
		if err != nil {
			fmt.Printf(Warn+"Failed to write exe: %s\n", *pivotOutput)
		}
	}
	fmt.Printf(Info+"New pivot (%s): %s\n", exeFormat, *pivotOutput)
}

func generatePivot(broker *Broker, targetOS string, targetArch string, output string) (string, []byte, error) {
	recv := broker.Subscribe()
	defer broker.Unsubscribe(recv)
	genPivotReq := &pb.GeneratePivotRequest{
		OperatingSystem: targetOS,
		Arch:            targetArch,
	}
	data, _ := proto.Marshal(genPivotReq)
	broker.SendMessage(GenPivotMsg, data)
	envelope := <-recv
	if envelope.Type == ExeFileMsg {
		pivotExe := &pb.ExeFile{}
		proto.Unmarshal(envelope.Data, pivotExe)
		if pivotExe.Errors != "" {
			return "", nil, fmt.Errorf("%s", pivotExe.Errors)
		}
		return pivotExe.Format, pivotExe.Data, nil
	}
	return "", nil, fmt.Errorf("invalid server response (%s)", envelope.Type)
}

func execGenerateClient(broker *Broker) {
	fmt.Println(Info + "Generating new client binary ...")
	fmt.Printf(Info+"Compiler target %s/%s\n", *clientOS, *clientArch)

	exeFormat, exe, err := generateClient(broker, *clientOS, *clientArch, *clientOutput)
	if err != nil {
		fmt.Printf(Warn+"Failed to generate client binary: %s\n", err)
	} else {
		err = ioutil.WriteFile(*clientOutput, exe, 0755)
		if err != nil {
			fmt.Printf(Warn+"Failed to write exe: %s\n", *clientOutput)
		}
		fmt.Printf(Info+"New client (%s): %s\n", exeFormat, *clientOutput)
	}
}

func generateClient(broker *Broker, targetOS string, targetArch string, output string) (string, []byte, error) {
	recv := broker.Subscribe()
	genClientReq := &pb.GenerateClientRequest{
		OperatingSystem: targetOS,
		Arch:            targetArch,
	}
	data, _ := proto.Marshal(genClientReq)
	broker.SendMessage(GenClientMsg, data)
	envelope := <-recv
	if envelope.Type == ExeFileMsg {
		clientExe := &pb.ExeFile{}
		proto.Unmarshal(envelope.Data, clientExe)
		if clientExe.Errors != "" {
			return "", nil, fmt.Errorf("%s", clientExe.Errors)
		}
		return clientExe.Format, clientExe.Data, nil
	}
	return "", nil, fmt.Errorf("invalid server response (%s)", envelope.Type)
}

func execTCPTunnel(broker *Broker) {
	address := strings.Split(*tunnelRemoteAddr, ":")
	if len(address) != 2 {
		fmt.Printf(Warn+"Invalid remote address '%s'\n", *tunnelRemoteAddr)
		return
	}
	rAddressPort, err := strconv.Atoi(address[1])
	rPort := uint16(rAddressPort)
	if err != nil {
		fmt.Printf(Warn+"Invalid remote port number '%s'\n", address[1])
		return
	}
	lPort := uint16(*tunnelBind)
	if lPort == 0 {
		lPort = RandomTCPPortNumber()
	}
	startTCPTunnelListener(broker, *tunnelPivot, address[0], rPort, lPort)
}

func startTCPTunnelListener(broker *Broker, pivotName string, rAddress string, rPort uint16, lPort uint16) {

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", lPort))
	defer ln.Close()
	if err != nil {
		fmt.Printf(Warn+"Failed to start listener %s\n", err)
		os.Exit(-1)
	}
	fmt.Printf(Info+"Listener started successfully on port %d\n", lPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go tcpTunnelTo(conn, broker, pivotName, rAddress, rPort)
	}

}

func tcpTunnelTo(conn net.Conn, broker *Broker, pivotName string, rAddress string, rPort uint16) {

	fmt.Printf(Info+"Tunneling %s -> %s:%d ...\n", pivotName, rAddress, rPort)

	recv := broker.Subscribe()
	defer broker.Unsubscribe(recv)

	tunnelID := RandomID()
	tcpTunnelInit := &pb.TCPTunnelInit{
		ID:            tunnelID,
		PivotName:     pivotName,
		RemoteAddress: rAddress,
		RemotePort:    int32(rPort),
	}

	tunInitData, _ := proto.Marshal(tcpTunnelInit)
	broker.SendMessage(TCPTunnelMsg, tunInitData)

	// The first packet is always empty just to tell us if
	// there's an EOF from the other side before we .Read()
	init0 := <-recv
	data0 := &pb.Data{}
	proto.Unmarshal(init0.Data, data0)
	if data0.EOF {
		fmt.Printf(Warn + "Remote connection failed\n")
		return
	}

	go func() {
		defer func() {
			log.Printf("Closing connection to %s\n", conn.RemoteAddr())
			conn.Close() // This will terminate the lower .Read() loop
		}()
		for envelope := range recv {
			if envelope.Type == DataMsg {
				dataPkt := &pb.Data{}
				proto.Unmarshal(envelope.Data, dataPkt)
				if dataPkt.TunnelID == tunnelID {
					fmt.Printf(Info+"[Client] Write %d bytes (%s)\n", len(dataPkt.Payload), dataPkt.TunnelID)
					if 0 < len(dataPkt.Payload) {
						conn.Write(dataPkt.Payload)
					}
					if dataPkt.EOF {
						log.Printf("[Client] Remote connection returned EOF (%s)\n", dataPkt.TunnelID)
						return
					}
				}
			}
		}
	}()

	zeroReads := 0
	readBuf := make([]byte, readBufSize)
	for {
		n, err := conn.Read(readBuf)
		dataPkt, _ := proto.Marshal(&pb.Data{
			TunnelID: tunnelID,
			Payload:  readBuf[:n],
			EOF:      err == io.EOF,
		})
		fmt.Printf(Info+"[Client] Read %d bytes (%s)\n", len(readBuf[:n]), tunnelID)
		broker.SendMessage(DataMsg, dataPkt)
		if err == io.EOF {
			log.Printf("[Client] Read EOF (%s)\n", tunnelID)
			break
		}
		if n == 0 {
			zeroReads++
			if zeroReads > 10 {
				break
			}
		} else {
			zeroReads = 0
		}
	}
	log.Printf("[Client] Read loop exit (%s)", tunnelID)
}

// ----------------------
// Network Communication
// ----------------------
// c2Connect - Connect to server and get channels for send/recv
func c2Connect(broker *Broker) {
	log.Printf("Connecting to %s:%d ...\n", *server, *lport)
	conn := tlsConnect(*server, uint16(*lport))

	go func() {
		defer func() {
			log.Printf("Clean up channels/connections ...")
			conn.Close()
			close(broker.publishCh)
		}()
		for {
			envelope, err := socketReadMessage(conn)
			if err != nil {
				return
			}
			broker.Publish(envelope)
		}
	}()

	// Convert channel back to socket writes
	go func() {
		for envelope := range broker.sendCh {
			socketWriteMessage(conn, envelope)
		}
	}()
}

// socketWriteMessage - Writes a message to the TLS socket using length prefix framing
// which is a fancy way of saying we write the length of the message then the message
// e.g. [uint32 length|message] so the reciever can delimit messages properly
func socketWriteMessage(connection *tls.Conn, envelope pb.Envelope) error {
	log.Printf("Send: %s", envelope.Type)
	data, err := proto.Marshal(&envelope)
	if err != nil {
		log.Print("Envelope marshaling error: ", err)
		return err
	}
	dataLengthBuf := new(bytes.Buffer)
	binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))
	connection.Write(dataLengthBuf.Bytes())
	connection.Write(data)
	return nil
}

// socketReadMessage - Reads a message from the TLS connection using length prefix framing
func socketReadMessage(connection *tls.Conn) (pb.Envelope, error) {
	log.Println("Reading length ...")
	dataLengthBuf := make([]byte, 4) // Size of uint32
	_, err := connection.Read(dataLengthBuf)
	if err != nil {
		fmt.Printf(Warn+"Socket error (read msg-length): %v\n", err)
		return pb.Envelope{}, err
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))
	log.Printf("Data length: %d", dataLength)

	// Read the length of the data
	log.Println("Reading data ...")
	readBuf := make([]byte, readBufSize)
	dataBuf := make([]byte, 0)
	totalRead := 0
	for {
		n, err := connection.Read(readBuf)
		dataBuf = append(dataBuf, readBuf[:n]...)
		totalRead += n
		if totalRead == dataLength {
			break
		}
		if err != nil {
			log.Printf(Warn+"Read error: %s\n", err)
			break
		}
	}
	log.Printf("Read %d bytes", totalRead)

	// Unmarshal the protobuf envelope
	envelope := &pb.Envelope{}
	err = proto.Unmarshal(dataBuf, envelope)
	if err != nil {
		fmt.Printf(Warn+"Unmarshaling envelope error: %v", err)
		return pb.Envelope{}, err
	}

	return *envelope, nil
}

// tlsConnect - Get a TLS connection or die trying
func tlsConnect(address string, port uint16) *tls.Conn {
	tlsConfig := getTLSConfig()
	connection, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", address, port), tlsConfig)
	if err != nil {
		fmt.Printf(Warn+"Unable to connect: %v", err)
		os.Exit(4)
	}
	return connection
}

func getTLSConfig() *tls.Config {

	// Load client certs
	clientCert, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))
	if err != nil {
		fmt.Printf(Warn+"Cannot load client certificate: %v", err)
		os.Exit(5)
	}

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(caCertPEM))

	// Setup config with custom certificate validation routine
	tlsConfig := &tls.Config{
		Certificates:          []tls.Certificate{clientCert},
		RootCAs:               caCertPool,
		InsecureSkipVerify:    true, // Don't worry I sorta know what I'm doing
		VerifyPeerCertificate: rootOnlyVerifyCertificate,
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig
}

// rootOnlyVerifyCertificate - Go doesn't provide a method for only skipping hostname validation so
// we have to disable all of the fucking certificate validation and re-implement everything.
// https://github.com/golang/go/issues/21971
func rootOnlyVerifyCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(caCertPEM))
	if !ok {
		fmt.Printf(Warn + "Failed to parse root certificate")
		os.Exit(3)
	}

	cert, err := x509.ParseCertificate(rawCerts[0]) // We should only get one cert
	if err != nil {
		fmt.Printf(Warn + "Failed to parse certificate: " + err.Error())
		return err
	}

	// Basically we only care if the certificate was signed by our authority
	// Go selects sensible defaults for time and EKU, basically we're only
	// skipping the hostname check, I think?
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		fmt.Printf(Warn + "Failed to verify certificate: " + err.Error())
		return err
	}

	return nil
}

// ---------------------------------------------------
// Random helper functions to deal with Go's bullshit
// ---------------------------------------------------
// There's cearly no need for standard library functions
// that do obscure operations like determining if a value
// is in a slice, or getting the index of a value

const (
	tcpMin = 1024
	tcpMax = 65534
)

// RandomTCPPortNumber - Get a random TCP port number 1024 - 65535
func RandomTCPPortNumber() uint16 {
	seed := mathrand.NewSource(time.Now().UnixNano())
	rng := mathrand.New(seed)
	number := rng.Intn(tcpMax-tcpMin) + tcpMin
	return uint16(number)
}

// RandomID - Generate random ID of RandomIDSize bytes
func RandomID() string {
	randBuf := make([]byte, 64) // 64 bytes of randomness
	rand.Read(randBuf)
	digest := sha256.Sum256(randBuf)
	return fmt.Sprintf("%x", digest[:RandomIDSize])
}

// Because Go is annoying as fuck some of the time
func contains(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// Fuck you Go
func indexOf(needle string, haystack []string) int {
	for index, value := range haystack {
		if needle == value {
			return index
		}
	}
	return -1
}
