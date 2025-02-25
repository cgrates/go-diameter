// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"reflect"
	"testing"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/diamtest"
	"github.com/fiorix/go-diameter/v4/diam/dict"
)

func testResultCode(m *diam.Message, want uint32) bool {
	rc, err := m.FindAVP("Result-Code", 0)
	if err != nil {
		return false
	}
	if code, ok := rc.Data.(datatype.Unsigned32); ok {
		return uint32(code) == want
	}
	return false
}

// TestStateMachineTCP establishes a connection with a test TCP server and
// sends a Re-Auth-Request message to ensure the handshake was
// completed and that the RAR handler has context from the peer.
func TestStateMachineTCP(t *testing.T) {
	testStateMachine(t, "tcp")
}

// TestStateMachine establishes a connection with a test server and
// sends a Re-Auth-Request message to ensure the handshake was
// completed and that the RAR handler has context from the peer.
func testStateMachine(t *testing.T, network string) {
	sm := New(serverSettings)
	if sm.Settings() != serverSettings {
		t.Fatal("Invalid settings")
	}
	srv := diamtest.NewServerNetwork(network, sm, dict.Default)
	defer srv.Close()
	// CER handlers are ignored by the state machine.
	// Using Handle instead of HandleFunc to exercise that code.
	sm.Handle("CER", func() diam.HandlerFunc {
		return func(c diam.Conn, m *diam.Message) {}
	}())
	select {
	case err := <-sm.ErrorReports():
		if err == nil {
			t.Fatal("Expecting error that didn't occur")
		}
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for error")
	}
	// RAR for our test.
	mc := make(chan *diam.Message, 1)
	sm.HandleFunc("RAR", func(c diam.Conn, m *diam.Message) {
		mc <- m
	})
	mux := diam.NewServeMux()
	mux.HandleFunc("CEA", func(c diam.Conn, m *diam.Message) {
		mc <- m
	})
	mux.HandleFunc("DWA", func(c diam.Conn, m *diam.Message) {
		mc <- m
	})
	cli, err := diam.DialNetwork(network, srv.Addr, mux, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	// Send CER first, wait for CEA.
	m := diam.NewRequest(diam.CapabilitiesExchange, 1001, dict.Default)
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	m.NewAVP(avp.HostIPAddress, avp.Mbit, 0, localhostAddress)
	m.NewAVP(avp.VendorID, avp.Mbit, 0, clientSettings.VendorID)
	m.NewAVP(avp.ProductName, 0, 0, clientSettings.ProductName)
	m.NewAVP(avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	m.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
	m.NewAVP(avp.FirmwareRevision, 0, 0, clientSettings.FirmwareRevision)
	_, err = m.WriteTo(cli)
	if err != nil {
		t.Fatal(err)
	}
	// Retransmit CER.
	_, err = m.WriteTo(cli)
	if err != nil {
		t.Fatal(err)
	}
	// Test CEA Result-Code.
	select {
	case resp := <-mc:
		if !testResultCode(resp, diam.Success) {
			t.Fatalf("Unexpected result code.\n%s", resp)
		}
	case err := <-sm.ErrorReports():
		t.Fatal(err)
	case err := <-mux.ErrorReports():
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("No CEA message received")
	}
	// Send RAR.
	m = diam.NewRequest(diam.ReAuth, 0, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.OctetString("foobar"))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	m.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(1002))
	m.NewAVP(avp.ReAuthRequestType, avp.Mbit, 0, datatype.Unsigned32(0))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.OctetString("test"))
	m.NewAVP(avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	_, err = m.WriteTo(cli)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure the RAR was handled by the state machine.
	select {
	case <-mc:
		// All good.
	case err := <-sm.ErrorReports():
		t.Fatal(err)
	case err := <-mux.ErrorReports():
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("No RAR message received")
	}
	// Send DWR.
	m = diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, clientSettings.OriginHost)
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, clientSettings.OriginRealm)
	_, err = m.WriteTo(cli)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure the DWR was handled by the state machine.
	select {
	case <-mc:
	// All good.
	case err := <-sm.ErrorReports():
		t.Fatal(err)
	case err := <-mux.ErrorReports():
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("No DWR message received")
	}
}

func TestPrepareSupportedAppsWithSuppApps1(t *testing.T) {
	expLst := []*SupportedApp{
		{ID: 4, AppType: "auth", Vendor: 0},
		{ID: 1, AppType: "auth", Vendor: 0},
		{ID: 16777251, AppType: "auth", Vendor: 10415},
	}
	rcvLst := PrepareSupportedApps(dict.Default, []string{"Charging Control", "1",
		"TGPP.TGPP S6A"})
	if len(expLst) != len(rcvLst) {
		t.Errorf("expected length <%v>, received <%v>", len(expLst), len(rcvLst))
	}
	for i := range rcvLst {
		if !reflect.DeepEqual(expLst[i], rcvLst[i]) {
			t.Errorf("Expected <%v>\nReceived <%v>", expLst[i], rcvLst[i])
		}
	}
}

func TestPrepareSupportedAppsNil(t *testing.T) {
	var testDicts = []string{
		"../dict/testdata/base.xml",
		"../dict/testdata/credit_control.xml",
		"../dict/testdata/network_access_server.xml",
		"../dict/testdata/tgpp_ro_rf.xml",
		"../dict/testdata/tgpp_s6a.xml",
		"../dict/testdata/tgpp_swx.xml"}
	parser, err := dict.NewParser(testDicts...)
	if err != nil {
		t.Fatal(err)
	}
	expLst := []*SupportedApp{
		{ID: 3, AppType: "acct", Vendor: 0},
		{ID: 4, AppType: "auth", Vendor: 0},
		{ID: 1, AppType: "auth", Vendor: 0},
		{ID: 4, AppType: "auth", Vendor: 10415},
		{ID: 16777251, AppType: "auth", Vendor: 10415},
		{ID: 16777265, AppType: "auth", Vendor: 10415},
	}
	rcvLst := PrepareSupportedApps(parser, nil)
	if len(expLst) != len(rcvLst) {
		t.Errorf("expected length <%v>, received <%v>", len(expLst), len(rcvLst))
	}
	for i := range rcvLst {
		if !reflect.DeepEqual(expLst[i], rcvLst[i]) {
			t.Errorf("Expected <%v>\nReceived <%v>", expLst[i], rcvLst[i])
		}
	}
}

func TestPrepareSupportedAppsWithSuppAppsNoVendorFound(t *testing.T) {
	expLst := []*SupportedApp{
		{ID: 1, AppType: "auth", Vendor: 0},
		{ID: 4, AppType: "auth", Vendor: 10415},
	}
	rcvLst := PrepareSupportedApps(dict.Default, []string{"TGPP.TGPP", "1",
		"NonExistentVendor.4"})
	if len(expLst) != len(rcvLst) {
		t.Errorf("expected length <%v>, received <%v>", len(expLst), len(rcvLst))
	}
	for i := range rcvLst {
		if !reflect.DeepEqual(expLst[i], rcvLst[i]) {
			t.Errorf("Expected <%v>\nReceived <%v>", expLst[i], rcvLst[i])
		}
	}
}

func TestPrepareSupportedAppsWithSuppAppsEmptySuppApps(t *testing.T) {
	rcvLst := PrepareSupportedApps(dict.Default, []string{})
	if len(rcvLst) != 0 {
		t.Errorf("expected length <%v>, received <%v>", 0, len(rcvLst))
	}
}
