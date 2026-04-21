package registry

import (
	_ "embed"
	"fmt"
	"strconv"

	"github.com/automata-network/amd-sev-snp-attestation-sdk/contracts/deployments"
)

//go:embed metadata.json
var metadataJSON []byte

// New loads the network configuration for the given chain ID.
// Returns an error if the chain ID is not found or data is invalid.
func New(chainID uint64) (*Network, error) {
	key, meta, err := parseMetadata(metadataJSON, chainID)
	if err != nil {
		return nil, err
	}

	chainIDStr := strconv.FormatUint(chainID, 10)
	sevData, err := deployments.FS.ReadFile(chainIDStr + ".json")
	if err != nil {
		return nil, fmt.Errorf("no deployment found for chain ID %d: %w", chainID, err)
	}

	return parseNetwork(key, meta, sevData)
}
