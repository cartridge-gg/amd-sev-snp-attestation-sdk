package registry

import (
	"testing"
)

func TestParseSevDeployment_ValidAddress(t *testing.T) {
	data := []byte(`{"VERIFIER":"0x84d19f7F2e07766ea16D1c24f7e0828FA11273A2","remark":"test"}`)
	contracts, err := parseSevDeployment(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "0x84d19f7F2e07766ea16D1c24f7e0828FA11273A2"
	if contracts.Verifier.Hex() != expected {
		t.Errorf("expected %s, got %s", expected, contracts.Verifier.Hex())
	}
}

func TestParseSevDeployment_EmptyVerifier(t *testing.T) {
	_, err := parseSevDeployment([]byte(`{"VERIFIER":"","remark":"test"}`))
	if err == nil {
		t.Fatal("expected error for empty verifier")
	}
}

func TestParseSevDeployment_InvalidAddress(t *testing.T) {
	_, err := parseSevDeployment([]byte(`{"VERIFIER":"not-a-valid-address"}`))
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestParseSevDeployment_InvalidJSON(t *testing.T) {
	_, err := parseSevDeployment([]byte(`{invalid}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
