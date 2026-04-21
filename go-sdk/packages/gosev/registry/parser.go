package registry

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// NetworkMetadata represents the metadata for a network
type NetworkMetadata struct {
	Name            string   `json:"name"`
	ChainID         uint64   `json:"chain_id"`
	Testnet         bool     `json:"testnet"`
	RpcEndpoints    []string `json:"rpc_endpoints"`
	GasPriceHintWei *uint64  `json:"gas_price_hint_wei,omitempty"`
	BlockExplorers  []string `json:"block_explorers,omitempty"`
}

// SevDeployment represents the SEV deployment JSON structure
type SevDeployment struct {
	Verifier string `json:"VERIFIER"`
	Remark   string `json:"remark,omitempty"`
}

// parseSevDeployment parses the SEV deployment JSON and extracts contract addresses
func parseSevDeployment(data []byte) (*SevContracts, error) {
	var deployment SevDeployment
	if err := json.Unmarshal(data, &deployment); err != nil {
		return nil, fmt.Errorf("failed to parse SEV deployment: %w", err)
	}

	if deployment.Verifier == "" {
		return nil, fmt.Errorf("VERIFIER address not found in deployment")
	}

	if !common.IsHexAddress(deployment.Verifier) {
		return nil, fmt.Errorf("invalid VERIFIER address: %q", deployment.Verifier)
	}

	return &SevContracts{
		Verifier: common.HexToAddress(deployment.Verifier),
	}, nil
}

// parseNetwork creates a Network from metadata and deployment data
func parseNetwork(key string, metadata *NetworkMetadata, sevData []byte) (*Network, error) {
	sev, err := parseSevDeployment(sevData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SEV for %s: %w", key, err)
	}

	var gasPriceHint *big.Int
	if metadata.GasPriceHintWei != nil {
		gasPriceHint = new(big.Int).SetUint64(*metadata.GasPriceHintWei)
	}

	return &Network{
		Key:             key,
		DisplayName:     metadata.Name,
		ChainID:         metadata.ChainID,
		Testnet:         metadata.Testnet,
		RpcEndpoints:    metadata.RpcEndpoints,
		BlockExplorers:  metadata.BlockExplorers,
		GasPriceHintWei: gasPriceHint,
		Contracts:       *sev,
	}, nil
}

// parseMetadata parses the metadata JSON and returns the entry matching chainID
func parseMetadata(data []byte, chainID uint64) (string, *NetworkMetadata, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	for key, rawMsg := range raw {
		if key == "default" {
			continue
		}

		var meta NetworkMetadata
		if err := json.Unmarshal(rawMsg, &meta); err != nil {
			return "", nil, fmt.Errorf("invalid metadata for network %q: %w", key, err)
		}

		if meta.ChainID == chainID {
			return key, &meta, nil
		}
	}

	return "", nil, fmt.Errorf("network not found for chain ID: %d", chainID)
}
