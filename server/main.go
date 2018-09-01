package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path"
	"runtime"
	"time"

	"github.com/golang/protobuf/proto"

	pb "rosie/protobuf"
)

const (
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
	clearln = "\r\x1b[2K"
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

	clientBinFileName = "rosie" // TODO: Dynamically add .exe for Windows
	logFileName       = "rosie.log"
	timeout           = 10 * time.Second
	readBufSize       = 1024
)

var (
	genClient       *bool
	genClientOutput *string

	clientServer *string
	clientLport  *int

	pivotServer *string
	pivotLport  *int
)

type c2Connection struct {
	Send chan pb.Envelope
	Recv chan pb.Envelope
}

func main() {

	clientServer = flag.String("client-iface", "", "client bind server address")
	clientLport = flag.Int("client-lport", 8443, "client bind listen port")

	pivotServer = flag.String("pivot-iface", "", "pivot bind server address")
	pivotLport = flag.Int("pivot-lport", 8444, "pivot bind listen port")

	genClient = flag.Bool("generate-client", false, "generate a new client binary")
	genClientOutput = flag.String("client-outfile", "", "output file (use with -generate-client)")
	flag.Parse()

	// Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	rosieDir := GetRosieDir()
	f, err := os.OpenFile(path.Join(rosieDir, logFileName), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	defer f.Close()
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	log.SetOutput(f)

	if _, err := os.Stat(path.Join(rosieDir, goDirName)); os.IsNotExist(err) {
		fmt.Println(Info + "First time setup, unpacking assets please wait ... ")
		SetupAssets()
		*genClient = true
	}

	if *genClient {
		generateNewClinetBinary(*genClientOutput)
	}

	// Start server listeners
	fmt.Println(Info + "Starting listeners ...")
	go startClientListener(*clientServer, uint16(*clientLport))
	startPivotListener(*pivotServer, uint16(*pivotLport))
}

func generateNewClinetBinary(output string) {
	exePath, err := GenerateClientBinary(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		log.Printf(Warn+"Failed to generate client binary: %v", err)
	}
	cwd, _ := os.Getwd()
	var outfile string
	if output == "" {
		outfile = path.Join(cwd, clientBinFileName)
	}
	log.Printf("Copy file %s -> %s", exePath, outfile)
	copyFileContents(exePath, outfile)
	os.Chmod(outfile, 0755)
	fmt.Printf(Info+"Client binary written to: %s\n", outfile)
}

func startPivotListener(bindIface string, port uint16) {
	log.Printf("Starting pivot listener on %s:%d", bindIface, port)

	tlsConfig := getServerTLSConfig(PivotsDir, bindIface)
	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", bindIface, port), tlsConfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handlePivotConnection(conn)
	}
}

// --------------------
// Connection Handlers
// --------------------

func handlePivotConnection(connection net.Conn) {
	defer connection.Close()

	log.Printf("Pivot connection from %s", connection.RemoteAddr())
	pivotConn := c2Connection{
		Send: make(chan pb.Envelope),
		Recv: make(chan pb.Envelope),
	}

	// Convert reads from socket into channel messages
	go func() {
		defer func() {
			close(pivotConn.Recv)
			close(pivotConn.Send)
		}()
		for {
			envelope, err := socketReadMessage(connection)
			if err != nil {
				log.Printf("Read message error: %s", err)
				return
			}
			pivotConn.Recv <- envelope
		}
	}()

	// Convert channel back to socket writes
	go func() {
		for envelope := range pivotConn.Send {
			err := socketWriteMessage(connection, envelope)
			if err != nil {
				return
			}
		}
	}()

	// Distribute messages
	for envelope := range pivotConn.Recv {
		log.Printf("Message type: %s", envelope.Type)

		handler, ok := pivotMessageHandlers[envelope.Type]
		if ok {
			// Calls the handler based on msgType
			go handler.(func(c2Connection, []byte))(pivotConn, envelope.Data)
		} else {
			log.Printf("No message handler for message type: %s", envelope.Type)
		}
	}
}

// startClientListener - Creates the client listener port
func startClientListener(bindIface string, port uint16) {

	log.Printf("Starting client listener on %s:%d", bindIface, port)

	tlsConfig := getServerTLSConfig(ClientsDir, bindIface)
	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", bindIface, port), tlsConfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleClientConnection(conn)
	}

}

// handleClientConnection - Go routine for each TCP connection
func handleClientConnection(connection net.Conn) {
	defer connection.Close()

	clientConn := c2Connection{
		Send: make(chan pb.Envelope),
		Recv: make(chan pb.Envelope),
	}

	// Convert reads from socket into channel messages
	go func() {
		defer func() {
			close(clientConn.Recv)
			close(clientConn.Send)
		}()
		for {
			envelope, err := socketReadMessage(connection)
			if err != nil {
				log.Printf("Read message error: %s", err)
				return
			}
			clientConn.Recv <- envelope
		}
	}()

	// Convert channel back to socket writes
	go func() {
		for envelope := range clientConn.Send {
			err := socketWriteMessage(connection, envelope)
			if err != nil {
				return
			}
		}
	}()

	// Distribute messages
	for envelope := range clientConn.Recv {
		log.Printf("Message type: %s", envelope.Type)
		handler := clientMessageHandlers[envelope.Type]
		go handler.(func(c2Connection, []byte))(clientConn, envelope.Data)
	}
}

// socketWriteMessage - Writes a message to the TLS socket using length prefix framing
// which is a fancy way of saying we write the length of the message then the message
// e.g. [uint32 length|message] so the reciever can delimit messages properly
func socketWriteMessage(connection net.Conn, envelope pb.Envelope) error {
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
// returns messageType, message, and error
func socketReadMessage(connection net.Conn) (pb.Envelope, error) {

	log.Print("Reading ... ")

	// Read the first four bytes to determine data length
	dataLengthBuf := make([]byte, 4) // Size of uint32
	_, err := connection.Read(dataLengthBuf)
	if err != nil {
		log.Printf("Socket error (read msg-length): %v", err)
		return pb.Envelope{}, err
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))

	// Read the length of the data, keep in mind each call to .Read() may not
	// fill the entire buffer length that we specify, so instead we use two buffers
	// readBuf is the result of each .Read() operation, which is then concatinated
	// onto dataBuf which contains all of data read so far and we keep calling
	// .Read() until the running total is equal to the length of the message that
	// we're expecting or we get an error.
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
			log.Printf("Read error: %s", err)
			break
		}
	}

	if err != nil {
		log.Printf("Socket error (read data): %v", err)
		return pb.Envelope{}, err
	}
	// Unmarshal the protobuf envelope
	envelope := &pb.Envelope{}
	err = proto.Unmarshal(dataBuf, envelope)
	if err != nil {
		log.Printf("unmarshaling envelope error: %v", err)
		return pb.Envelope{}, err
	}
	return *envelope, nil
}

// getServerTLSConfig - Generate the TLS configuration, we do now allow the end user
// to specify any TLS paramters, we choose sensible defaults instead
func getServerTLSConfig(caType string, host string) *tls.Config {
	caCertPtr, _, err := GetCertificateAuthority(caType)
	if err != nil {
		log.Fatalf("Invalid ca type (%s): %v", caType, host)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCertPtr)

	certPEM, keyPEM, _ := GetServerCertificatePEM(caType, host)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Error loading server certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:                  caCertPool,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                caCertPool,
		Certificates:             []tls.Certificate{cert},
		CipherSuites:             []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig
}

// GetRosieDir - Get the Rosie working dir ~/.rosie/
func GetRosieDir() string {
	user, _ := user.Current()
	rosieDir := path.Join(user.HomeDir, ".rosie")
	if _, err := os.Stat(rosieDir); os.IsNotExist(err) {
		log.Printf("Creating rosie working directory: %s", rosieDir)
		err = os.MkdirAll(rosieDir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}
	return rosieDir
}
