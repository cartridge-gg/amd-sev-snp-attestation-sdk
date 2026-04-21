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

func TestParseMetadata_Found(t *testing.T) {
	data := []byte(`{
		"eth_sepolia": {
			"name": "Ethereum Sepolia",
			"chain_id": 11155111,
			"testnet": true,
			"rpc_endpoints": ["https://1rpc.io/sepolia"]
		},
		"automata_testnet": {
			"name": "Automata Testnet",
			"chain_id": 1398243,
			"testnet": true,
			"rpc_endpoints": ["https://rpc-testnet.ata.network"]
		},
		"default": {
			"network_key": "automata_testnet"
		}
	}`)

	key, meta, err := parseMetadata(data, 11155111)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "eth_sepolia" {
		t.Errorf("key = %q, want %q", key, "eth_sepolia")
	}
	if meta.ChainID != 11155111 {
		t.Errorf("ChainID = %d, want 11155111", meta.ChainID)
	}
	if meta.Name != "Ethereum Sepolia" {
		t.Errorf("Name = %q, want %q", meta.Name, "Ethereum Sepolia")
	}
}

func TestParseMetadata_NotFound(t *testing.T) {
	data := []byte(`{
		"eth_sepolia": {
			"name": "Ethereum Sepolia",
			"chain_id": 11155111,
			"testnet": true,
			"rpc_endpoints": ["https://1rpc.io/sepolia"]
		}
	}`)

	_, _, err := parseMetadata(data, 999999999)
	if err == nil {
		t.Fatal("expected error for unknown chain ID")
	}
}

func TestParseMetadata_InvalidJSON(t *testing.T) {
	_, _, err := parseMetadata([]byte(`{invalid}`), 11155111)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseMetadata_InvalidNetworkEntry(t *testing.T) {
	data := []byte(`{
		"eth_sepolia": "not-a-valid-network"
	}`)

	_, _, err := parseMetadata(data, 11155111)
	if err == nil {
		t.Fatal("expected error for invalid network entry")
	}
}

func TestParseMetadata_IgnoresDefaultKey(t *testing.T) {
	data := []byte(`{
		"eth_sepolia": {
			"name": "Ethereum Sepolia",
			"chain_id": 11155111,
			"testnet": true,
			"rpc_endpoints": ["https://1rpc.io/sepolia"]
		},
		"default": {
			"network_key": "eth_sepolia"
		}
	}`)

	_, _, err := parseMetadata(data, 11155111)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
