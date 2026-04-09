package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// mustGetenv
// ---------------------------------------------------------------------------

func TestMustGetenv_ReturnsEnvValue(t *testing.T) {
	const key = "TEST_NETPULSE_KEY_SET"
	os.Setenv(key, "expected_value")
	defer os.Unsetenv(key)

	got := mustGetenv(key, "fallback")
	if got != "expected_value" {
		t.Errorf("mustGetenv: expected %q, got %q", "expected_value", got)
	}
}

func TestMustGetenv_FallsBackWhenUnset(t *testing.T) {
	const key = "TEST_NETPULSE_KEY_UNSET"
	os.Unsetenv(key)

	got := mustGetenv(key, "fallback_value")
	if got != "fallback_value" {
		t.Errorf("mustGetenv: expected fallback %q, got %q", "fallback_value", got)
	}
}

func TestMustGetenv_FallsBackOnEmptyString(t *testing.T) {
	const key = "TEST_NETPULSE_KEY_EMPTY"
	os.Setenv(key, "")
	defer os.Unsetenv(key)

	got := mustGetenv(key, "fallback_value")
	if got != "fallback_value" {
		t.Errorf("mustGetenv: expected fallback for empty string, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// BPF filter correctness
// ---------------------------------------------------------------------------

func TestBPFFilter_ExcludesMedicalPorts(t *testing.T) {
	// The filter must explicitly reference every medical port so that
	// traffic on those ports is dropped at the kernel level.
	requiredPorts := []string{"2575", "104", "2762"}
	for _, port := range requiredPorts {
		if !strings.Contains(bpfFilter, port) {
			t.Errorf("BPF filter must reference medical/DICOM port %s, but it does not", port)
		}
	}
}

func TestBPFFilter_IsNegating(t *testing.T) {
	// The filter is a deny-list, so it must start with or contain "not".
	if !strings.Contains(bpfFilter, "not") {
		t.Error("BPF filter must contain 'not' to exclude medical ports")
	}
}

// ---------------------------------------------------------------------------
// PacketEvent JSON marshaling
// ---------------------------------------------------------------------------

func TestPacketEvent_JSONFieldNames(t *testing.T) {
	evt := PacketEvent{
		Timestamp:  "2024-01-01T00:00:00Z",
		SrcMAC:     "aa:bb:cc:dd:ee:ff",
		DstMAC:     "11:22:33:44:55:66",
		SrcIP:      "10.0.0.1",
		DstIP:      "10.0.0.2",
		Protocol:   "TCP",
		SrcPort:    1234,
		DstPort:    80,
		PayloadLen: 512,
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("json.Marshal(PacketEvent) failed: %v", err)
	}

	s := string(data)
	expectations := map[string]string{
		"ts":          `"ts"`,
		"src_mac":     `"src_mac"`,
		"dst_mac":     `"dst_mac"`,
		"src_ip":      `"src_ip"`,
		"dst_ip":      `"dst_ip"`,
		"proto":       `"proto"`,
		"src_port":    `"src_port"`,
		"dst_port":    `"dst_port"`,
		"payload_len": `"payload_len"`,
	}
	for field, jsonKey := range expectations {
		if !strings.Contains(s, jsonKey) {
			t.Errorf("PacketEvent JSON: expected field %q (%s) to be present in %s", field, jsonKey, s)
		}
	}
}

func TestPacketEvent_OmitsEmptyOptionalFields(t *testing.T) {
	// Fields tagged omitempty must be absent when zero/empty.
	evt := PacketEvent{
		PayloadLen: 0,
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("json.Marshal(PacketEvent) failed: %v", err)
	}

	s := string(data)
	omitFields := []string{"src_mac", "dst_mac", "src_ip", "dst_ip", "proto", "src_port", "dst_port"}
	for _, field := range omitFields {
		if strings.Contains(s, `"`+field+`"`) {
			t.Errorf("Expected field %q to be omitted when empty, but it appeared in: %s", field, s)
		}
	}
}

func TestPacketEvent_PayloadLenAlwaysPresent(t *testing.T) {
	// payload_len has no omitempty, so it must appear even when zero.
	evt := PacketEvent{}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"payload_len"`) {
		t.Errorf("payload_len must always be present in JSON, got: %s", string(data))
	}
}

func TestPacketEvent_RoundTrip(t *testing.T) {
	original := PacketEvent{
		Timestamp:  "2024-06-15T12:00:00Z",
		SrcIP:      "192.168.1.1",
		DstIP:      "8.8.8.8",
		Protocol:   "UDP",
		SrcPort:    53000,
		DstPort:    53,
		PayloadLen: 64,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded PacketEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Timestamp != original.Timestamp {
		t.Errorf("Timestamp mismatch: got %q, want %q", decoded.Timestamp, original.Timestamp)
	}
	if decoded.SrcIP != original.SrcIP {
		t.Errorf("SrcIP mismatch: got %q, want %q", decoded.SrcIP, original.SrcIP)
	}
	if decoded.DstPort != original.DstPort {
		t.Errorf("DstPort mismatch: got %d, want %d", decoded.DstPort, original.DstPort)
	}
	if decoded.PayloadLen != original.PayloadLen {
		t.Errorf("PayloadLen mismatch: got %d, want %d", decoded.PayloadLen, original.PayloadLen)
	}
}
