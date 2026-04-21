package registry

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestNew_EthereumSepolia(t *testing.T) {
	net, err := New(11155111)
	if err != nil {
		t.Fatalf("New(11155111) error: %v", err)
	}
	if net.Key != "eth_sepolia" {
		t.Errorf("Key = %q, want %q", net.Key, "eth_sepolia")
	}
	if net.ChainID != 11155111 {
		t.Errorf("ChainID = %d, want 11155111", net.ChainID)
	}
	if net.DisplayName != "Ethereum Sepolia" {
		t.Errorf("DisplayName = %q, want %q", net.DisplayName, "Ethereum Sepolia")
	}
	if !net.Testnet {
		t.Error("Testnet = false, want true")
	}
	if net.DefaultRpcUrl() == "" {
		t.Error("DefaultRpcUrl() returned empty string")
	}
	if net.DefaultExplorer() == "" {
		t.Error("DefaultExplorer() returned empty string")
	}
	if net.VerifierAddress() == (common.Address{}) {
		t.Error("VerifierAddress() returned zero address")
	}
}

func TestNew_AutomataTestnet(t *testing.T) {
	net, err := New(1398243)
	if err != nil {
		t.Fatalf("New(1398243) error: %v", err)
	}
	if net.Key != "automata_testnet" {
		t.Errorf("Key = %q, want %q", net.Key, "automata_testnet")
	}
}

func TestNew_EthereumHoodi(t *testing.T) {
	net, err := New(560048)
	if err != nil {
		t.Fatalf("New(560048) error: %v", err)
	}
	if net.Key != "eth_hoodi" {
		t.Errorf("Key = %q, want %q", net.Key, "eth_hoodi")
	}
}

func TestNew_NotFound(t *testing.T) {
	_, err := New(999999999)
	if err == nil {
		t.Fatal("expected error for unknown chain ID")
	}
}

func TestNew_NoDeployment(t *testing.T) {
	_, err := New(17000)
	if err == nil {
		t.Fatal("expected error for chain ID not in metadata")
	}
}

func TestNew_AllDeployedChainsHaveVerifier(t *testing.T) {
	chainIDs := []uint64{11155111, 560048, 1398243}
	for _, id := range chainIDs {
		t.Run(fmt.Sprintf("chain_%d", id), func(t *testing.T) {
			net, err := New(id)
			if err != nil {
				t.Fatalf("New(%d) error: %v", id, err)
			}
			if net.VerifierAddress() == (common.Address{}) {
				t.Errorf("chain %d (%s) has zero verifier address", id, net.Key)
			}
		})
	}
}
