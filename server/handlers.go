package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"sync"

	pb "rosie/protobuf"

	"github.com/golang/protobuf/proto"
)

const (
	// RandomIDSize - Size of the TunnelID in bytes
	RandomIDSize = 16

	// ---------------
	// Pivot Messages
	// ---------------

	// PivotInitMsg - Sends pivot metadata to server
	PivotInitMsg = "pivot-init"
	// DataMsg - Connection data
	DataMsg = "d"

	// ---------------
	// Client Messages
	// ---------------

	// TCPTunnelMsg - Holds data related to setting up a TCP tunnel
	TCPTunnelMsg = "tcp-tunnel"
	// ListPivotsMsg - List connected pivots
	ListPivotsMsg = "list-pivots"
	// GenPivotMsg - Generates a pivot binary
	GenPivotMsg = "generate-pivot"
	// GenClientMsg - Generates a client binary
	GenClientMsg = "generate-client"
	// ExeFileMsg - Serialized executable file (client/pivot)
	ExeFileMsg = "exe-file"
)

// TunnelConnection - Maps clients to pivots
type TunnelConnection struct {
	ID     string
	Client c2Connection
	Pivot  c2Connection
}

var (
	pivotConnections      = make(map[string]c2Connection)
	pivotConnectionsMutex = &sync.RWMutex{}

	tunnels      = make(map[string]TunnelConnection)
	tunnelsMutex = &sync.RWMutex{}

	pivotMessageHandlers = map[string]interface{}{
		PivotInitMsg: pivotInitHandler,
		DataMsg:      pivotDataHandler,
	}

	clientMessageHandlers = map[string]interface{}{
		DataMsg:       clientDataHandler,
		TCPTunnelMsg:  tcpTunnelHandler,
		ListPivotsMsg: listPivotsHandler,
		GenPivotMsg:   generatePivotHandler,
		GenClientMsg:  generateClientHandler,
	}
)

// Send a message to channel wrapped in an Envelope
func sendMessage(sendTo chan<- pb.Envelope, msgType string, msg []byte) {
	envelope := pb.Envelope{
		Type: msgType,
		Data: msg,
	}
	sendTo <- envelope
}

// ---------------
// Pivot Handlers
// ---------------
func pivotInitHandler(conn c2Connection, msg []byte) {
	pivotInit := &pb.PivotInit{}
	err := proto.Unmarshal(msg, pivotInit)
	if err != nil {
		log.Printf("unmarshaling init-pivot error: %v", err)
	}
	pivotConnections[pivotInit.Name] = conn
}

func pivotDataHandler(conn c2Connection, msg []byte) {
	data := &pb.Data{}
	proto.Unmarshal(msg, data)
	tunnelsMutex.Lock()
	tun, ok := tunnels[data.TunnelID]
	if data.EOF {
		delete(tunnels, data.TunnelID)
	}
	tunnelsMutex.Unlock()
	if ok {
		go sendMessage(tun.Client.Send, DataMsg, msg)
	} else {
		log.Printf("Tunnel (%s) no longer exists", data.TunnelID)
	}
}

// ----------------
// Client Handlers
// ----------------
func clientDataHandler(conn c2Connection, msg []byte) {
	data := &pb.Data{}
	proto.Unmarshal(msg, data)
	tunnelsMutex.Lock()
	tun, ok := tunnels[data.TunnelID]
	if data.EOF {
		delete(tunnels, data.TunnelID)
	}
	tunnelsMutex.Unlock()
	if ok {
		go sendMessage(tun.Pivot.Send, DataMsg, msg)
	} else {
		log.Printf("Tunnel ID '%s' does not exist", data.TunnelID)
	}
}

func tcpTunnelHandler(conn c2Connection, msg []byte) {

	tunInit := &pb.TCPTunnelInit{}
	err := proto.Unmarshal(msg, tunInit)
	if err != nil {
		log.Printf("unmarshaling tunnel error: %v", err)
		return
	}
	log.Printf("Tunnel %s (%s) -> %s", tunInit.PivotName, tunInit.ID, tunInit.RemoteAddress)
	pivotConnectionsMutex.RLock()
	pivotC2, ok := pivotConnections[tunInit.PivotName]
	pivotConnectionsMutex.RUnlock()
	if ok {
		log.Printf("Connection to pivot is active")
		tunnelsMutex.Lock()
		tunnels[tunInit.ID] = TunnelConnection{
			ID:     tunInit.ID,
			Client: conn,
			Pivot:  pivotC2,
		}
		tunnelsMutex.Unlock()
		sendMessage(pivotC2.Send, TCPTunnelMsg, msg)
	} else {
		log.Printf("No connection to pivot: %s", tunInit.PivotName)
		data, _ := proto.Marshal(&pb.Data{
			TunnelID: tunInit.ID,
			EOF:      true,
			Errors:   "Invalid pivot name",
		})
		sendMessage(conn.Send, TCPTunnelMsg, data)
	}
}

func listPivotsHandler(conn c2Connection, _ []byte) {
	log.Printf("List pivots handler invoked")
	pivots := &pb.Pivots{}
	for name := range pivotConnections {
		pivot := &pb.Pivot{
			Name: name,
		}
		pivots.List = append(pivots.List, pivot)
	}
	data, err := proto.Marshal(pivots)
	if err != nil {
		log.Printf("Failed to marshal pivots: %s", err)
	}
	sendMessage(conn.Send, ListPivotsMsg, data)
}

func generatePivotHandler(conn c2Connection, msg []byte) {
	pivotReq := &pb.GeneratePivotRequest{}
	err := proto.Unmarshal(msg, pivotReq)
	if err != nil {
		log.Printf("unmarshaling generate-pivot error: %v", err)
	}

	pivotExe := &pb.ExeFile{}
	pivotExe.Format = fmt.Sprintf("%s/%s", pivotReq.OperatingSystem, pivotReq.Arch)
	exePath, err := GeneratePivotBinary(pivotReq.OperatingSystem, pivotReq.Arch)
	if err != nil {
		log.Printf("Failed to generate requested pivot binary")
		log.Printf("%s", err)
		pivotExe.Data = nil
		pivotExe.Errors = fmt.Sprintf("%s", err)
	} else {
		exe, _ := ioutil.ReadFile(exePath)
		pivotExe.Data = exe
		pivotExe.Errors = ""
	}
	data, err := proto.Marshal(pivotExe)
	if err != nil {
		log.Printf("Failed to marshal pivot-exe: %s", err)
	}
	go sendMessage(conn.Send, ExeFileMsg, data)
}

func generateClientHandler(conn c2Connection, msg []byte) {
	clientReq := &pb.GenerateClientRequest{}
	err := proto.Unmarshal(msg, clientReq)
	if err != nil {
		log.Printf("unmarshaling generate-client error: %v", err)
	}

	clientExe := &pb.ExeFile{}
	clientExe.Format = fmt.Sprintf("%s/%s", clientReq.OperatingSystem, clientReq.Arch)
	exePath, err := GenerateClientBinary(clientReq.OperatingSystem, clientReq.Arch)
	if err != nil {
		log.Printf("Failed to generate requested client binary")
		log.Printf("%s", err)
		clientExe.Data = nil
		clientExe.Errors = fmt.Sprintf("%s", err)
	} else {
		exe, _ := ioutil.ReadFile(exePath)
		clientExe.Data = exe
		clientExe.Errors = ""
	}
	data, err := proto.Marshal(clientExe)
	if err != nil {
		log.Printf("Failed to marshal client-exe: %s", err)
	}
	go sendMessage(conn.Send, ExeFileMsg, data)
}

// --------
// Helpers
// --------

// RandomID - Generate random ID of RandomIDSize bytes
func RandomID() string {
	randBuf := make([]byte, 64) // 64 bytes of randomness
	rand.Read(randBuf)
	digest := sha256.Sum256(randBuf)
	return fmt.Sprintf("%x", digest[:RandomIDSize])
}
