// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"github.com/fiorix/go-diameter/v4/diam/sm/smpeer"
)

// SupportedApp holds properties of each locally supported App
type SupportedApp struct {
	ID      uint32
	AppType string
	Vendor  uint32
}

// PrepareSupportedApps prepares a list of locally supported apps
func PrepareSupportedApps(d *dict.Parser, supportedApps []string) []*SupportedApp {
	locallySupportedApps := make([]*SupportedApp, 0)
	dictApps := d.Apps()      // dictionary applications
	if supportedApps != nil { // use only selected apps from dictionaries
		for _, appStr := range supportedApps {
			parts := strings.Split(appStr, ".")
			var vendor, appPart string
			if len(parts) > 1 {
				vendor, appPart = parts[0], parts[1]
			} else {
				appPart = parts[0]
			}
			foundAppIdx := -1 // application index that matches in the dictionary
			for i, dictApp := range dictApps {
				// if app ID or Name is found in dictionary, store the index of that app
				if appID, err := strconv.Atoi(appPart); err != nil && appPart == dictApp.Name || appID != 0 && appID == int(dictApp.ID) {
					if foundAppIdx == -1 {
						foundAppIdx = i // if no vendors found, pick first app that matched
					}
					if vendor == "" {
						break
					}
					foundVendor := false
					for _, dictVendor := range dictApp.Vendor {
						if dictVendor.Name == vendor {
							foundAppIdx = i
							foundVendor = true
							break
						}
					}
					if foundVendor {
						break
					}
				}
			}
			if foundAppIdx != -1 { // continue to next iteration if app not found in dictionary
				locallySupportedApps = append(locallySupportedApps, createSupportedApp(dictApps[foundAppIdx]))
			}
		}
		return locallySupportedApps
	}
	// If no supportedApps provided, include all apps
	for _, app := range dictApps {
		if app.ID == 0 {
			continue
		}
		locallySupportedApps = append(locallySupportedApps, createSupportedApp(app))
	}
	return locallySupportedApps
}

// createSupportedApp creates SupportedApp out of dict.App
func createSupportedApp(app *dict.App) *SupportedApp {
	supportedApp := &SupportedApp{
		ID:      app.ID,
		AppType: app.Type,
	}
	if len(app.Vendor) > 0 {
		supportedApp.Vendor = app.Vendor[0].ID
	}
	return supportedApp
}

// Settings used to configure the state machine with AVPs to be added
// to CER on clients or CEA on servers.
type Settings struct {
	SupportedApps []string
	OriginHost    datatype.DiameterIdentity
	OriginRealm   datatype.DiameterIdentity
	VendorID      datatype.Unsigned32
	ProductName   datatype.UTF8String

	// OriginStateID is optional for clients, and not added if unset.
	//
	// On servers it has no effect because CEA will contain the
	// same value from CER, if present.
	//
	// May be set to datatype.Unsigned32(time.Now().Unix()).
	OriginStateID datatype.Unsigned32

	// FirmwareRevision is optional, and not added if unset.
	FirmwareRevision datatype.Unsigned32

	// HostIPAddress is optional for both clients and servers, when not set local
	// host IP address is used.
	//
	// This property may be set when the IP address of the host sending/receiving
	// the request is different from the configured allowed IPs in the other end,
	// for example when using a VPN or a gateway.
	//
	HostIPAddresses []datatype.Address
	//
	// Deprecated: HostIPAddress is depreciated, use HostIPAddresses instead
	HostIPAddress datatype.Address
}

var (
	baseCERIdx = diam.CommandIndex{AppID: 0, Code: diam.CapabilitiesExchange, Request: true}
	baseCEAIdx = diam.CommandIndex{AppID: 0, Code: diam.CapabilitiesExchange, Request: false}
	baseDWRIdx = diam.CommandIndex{AppID: 0, Code: diam.DeviceWatchdog, Request: true}
)

// StateMachine is a specialized type of diam.ServeMux that handles
// the CER/CEA handshake and DWR/DWA messages for clients or servers.
//
// Other handlers registered in the state machine are only executed
// after the peer has passed the initial CER/CEA handshake.
type StateMachine struct {
	cfg           *Settings
	mux           *diam.ServeMux
	hsNotifyc     chan diam.Conn // handshake notifier
	supportedApps []*SupportedApp
}

// New creates and initializes a new StateMachine for clients or servers.
func New(settings *Settings) *StateMachine {
	if len(settings.HostIPAddresses) == 0 && len(settings.HostIPAddress) > 0 {
		settings.HostIPAddresses = []datatype.Address{settings.HostIPAddress}
	}
	sm := &StateMachine{
		cfg:           settings,
		mux:           diam.NewServeMux(),
		hsNotifyc:     make(chan diam.Conn),
		supportedApps: PrepareSupportedApps(dict.Default, settings.SupportedApps),
	}
	sm.mux.Handle("CER", handleCER(sm))
	sm.mux.Handle("DWR", handshakeOK(handleDWR(sm)))
	sm.mux.HandleIdx(baseCERIdx, handleCER(sm))
	sm.mux.HandleIdx(baseDWRIdx, handleDWR(sm))
	return sm
}

// Settings return the Settings object used by this StateMachine.
func (sm *StateMachine) Settings() *Settings {
	return sm.cfg
}

// ServeDIAM implements the diam.Handler interface.
func (sm *StateMachine) ServeDIAM(c diam.Conn, m *diam.Message) {
	sm.mux.ServeDIAM(c, m)
}

// Handle implements the diam.Handler interface.
func (sm *StateMachine) Handle(cmd string, handler diam.Handler) {
	sm.HandleFunc(cmd, handler.ServeDIAM)
}

func (sm *StateMachine) HandleIdx(cmd diam.CommandIndex, handler diam.Handler) {
	switch cmd {
	case baseCERIdx, baseCEAIdx, baseDWRIdx:
		sm.Error(&diam.ErrorReport{
			Error: fmt.Errorf("cannot overwrite %v command in the state machine", cmd),
		})
	default:
		sm.mux.HandleIdx(cmd, handshakeOK(handler.ServeDIAM))
	}
}

// HandleFunc implements the diam.Handler interface.
func (sm *StateMachine) HandleFunc(cmd string, handler diam.HandlerFunc) {
	switch cmd {
	case "CER", "CEA", "DWR":
		sm.Error(&diam.ErrorReport{
			Error: fmt.Errorf("cannot overwrite %s command in the state machine", cmd),
		})
	default:
		sm.mux.Handle(cmd, handshakeOK(handler))
	}
}

// Error implements the diam.ErrorReporter interface.
func (sm *StateMachine) Error(err *diam.ErrorReport) {
	sm.mux.Error(err)
}

// ErrorReports implement the diam.ErrorReporter interface.
func (sm *StateMachine) ErrorReports() <-chan *diam.ErrorReport {
	return sm.mux.ErrorReports()
}

// HandshakeNotify implements the HandshakeNotifier interface.
func (sm *StateMachine) HandshakeNotify() <-chan diam.Conn {
	return sm.hsNotifyc
}

// The HandshakeNotifier interface is implemented by Handlers
// that allow detecting peers that have passed the CER/CEA
// handshake.
type HandshakeNotifier interface {
	// HandshakeNotify returns a channel that receives
	// a peer's diam.Conn after it passes the handshake.
	HandshakeNotify() <-chan diam.Conn
}

// handshakeOK is a wrapper for state machine handlers that only
// calls the designated handler function if the peer has passed the
// CER/CEA handshake.
type handshakeOK diam.HandlerFunc

// ServeDIAM implements the diam.Handler interface.
func (f handshakeOK) ServeDIAM(c diam.Conn, m *diam.Message) {
	if _, ok := smpeer.FromContext(c.Context()); ok {
		f(c, m)
	}
}
