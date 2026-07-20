use std::marker::PhantomData;

use alloy_primitives::{hex::FromHex, Bytes, B256};
use alloy_sol_types::SolValue;
use anyhow::anyhow;
use sp1_methods::{block_on, ENV_PROVER};
use sp1_sdk::{
    env::{EnvProver, EnvProvingKey},
    HashableKey, ProveRequest, Prover, ProverClient, SP1Proof, SP1Stdin, SP1VerifyingKey,
    SP1_CIRCUIT_VERSION,
};

use crate::{
    program::{Program, ProofCost, RemoteProverConfig},
    RawProof, RawProofType,
};

#[derive(Debug, Clone)]
pub struct SP1ProverConfig {
    pub private_key: Option<String>,
    pub rpc_url: Option<String>,
    /// SP1 prover mode: "network", "cpu", or "mock".
    /// When set, `AmdSevSnpProver::new()` writes this to the `SP1_PROVER` env var
    /// so callers don't need `unsafe set_var` themselves.
    pub prover_mode: Option<String>,
}

impl Default for SP1ProverConfig {
    fn default() -> Self {
        SP1ProverConfig {
            // NETWORK_PRIVATE_KEY is the standard env var used by SP1 SDK for network proving
            // Fall back to SP1_PRIVATE_KEY for backwards compatibility
            private_key: std::env::var("NETWORK_PRIVATE_KEY")
                .ok()
                .or_else(|| std::env::var("SP1_PRIVATE_KEY").ok()),
            rpc_url: std::env::var("SP1_RPC_URL").ok(),
            prover_mode: std::env::var("SP1_PROVER").ok(),
        }
    }
}

impl TryFrom<SP1ProverConfig> for RemoteProverConfig {
    type Error = anyhow::Error;
    fn try_from(value: SP1ProverConfig) -> anyhow::Result<Self> {
        Ok(RemoteProverConfig {
            api_url: value.rpc_url,
            api_key: value
                .private_key
                .ok_or_else(|| anyhow!("missing private key"))?,
        })
    }
}

#[derive(Clone)]
pub struct ProgramSP1<ZkType, Input, Output> {
    zktype: ZkType,
    vk: &'static SP1VerifyingKey,
    pk: &'static EnvProvingKey,
    elf: &'static [u8],
    _marker: PhantomData<(Input, Output)>,
}

impl<ZkType, Input, Output> ProgramSP1<ZkType, Input, Output> {
    pub fn new(
        zktype: ZkType,
        elf: &'static [u8],
        vk: &'static SP1VerifyingKey,
        pk: &'static EnvProvingKey,
    ) -> Self {
        ProgramSP1 {
            zktype,
            vk,
            pk,
            elf,
            _marker: PhantomData,
        }
    }

    fn gen_raw_proof(
        &self,
        stdin: SP1Stdin,
        raw_proof_type: RawProofType,
    ) -> anyhow::Result<RawProof> {
        // On the prover network, drive `NetworkProver` directly so we can hold onto the
        // `request_id` and look up the fulfilled request's billed cost afterwards — the
        // high-level `ENV_PROVER.prove(..).await` path discards the id. Off-network
        // (cpu/mock) there is no fee, so we keep the original path and report no cost.
        if let EnvProver::Network(network) = &*ENV_PROVER {
            let EnvProvingKey::Network { pk, .. } = self.pk else {
                return Err(anyhow!(
                    "network prover selected but proving key is not a network key"
                ));
            };

            return block_on(async {
                let req = network.prove(pk, stdin);
                let req = match raw_proof_type {
                    RawProofType::Composite => req.compressed(),
                    RawProofType::Groth16 => req.groth16(),
                };

                let request_id = req.request().await?;
                let proof = network.wait_proof(request_id, None, None).await?;

                // Best-effort: a failed details lookup must not discard an otherwise valid
                // proof, so cost degrades to `None` rather than erroring.
                let cost = network
                    .get_proof_request(request_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|r| ProofCost {
                        cycles: r.cycles,
                        gas_used: r.gas_used,
                        gas_price: r.gas_price,
                        deduction_amount: r.deduction_amount,
                    });

                Ok(RawProof::from_proof(
                    &(proof.proof, self.vk),
                    proof.public_values.to_vec().into(),
                )?
                .with_cost(cost)
                .with_request_id(Some(request_id)))
            });
        }

        let proof = block_on(async {
            let req = ENV_PROVER.prove(self.pk, stdin);
            let req = match raw_proof_type {
                RawProofType::Composite => req.compressed(),
                RawProofType::Groth16 => req.groth16(),
            };
            req.await
        })?;

        Ok(RawProof::from_proof(
            &(proof.proof, self.vk),
            proof.public_values.to_vec().into(),
        )?)
    }
}

impl<ZkType, Input, Output> Program for ProgramSP1<ZkType, Input, Output>
where
    Input: SolValue + Send + Sync,
    Output: SolValue + Send + Sync,
    ZkType: Send + Sync + Copy,
{
    type Input = Input;
    type Output = Output;
    type ZkType = ZkType;
    fn version(&self) -> &'static str {
        SP1_CIRCUIT_VERSION
    }
    fn zktype(&self) -> Self::ZkType {
        self.zktype
    }
    fn recover_proof(
        &self,
        request_id: B256,
        timeout: Option<core::time::Duration>,
    ) -> anyhow::Result<RawProof> {
        // Same NetworkProver plumbing as `gen_raw_proof`, minus the `request()` — the request
        // already exists on the network; we only wait for (or immediately fetch) its result.
        let EnvProver::Network(network) = &*ENV_PROVER else {
            return Err(anyhow!(
                "proof recovery by request id requires the network prover (SP1_PROVER=network)"
            ));
        };

        block_on(async {
            let proof = network.wait_proof(request_id, timeout, None).await?;

            // Best-effort, mirroring `gen_raw_proof`: a failed details lookup must not discard
            // an otherwise valid proof, so cost degrades to `None` rather than erroring.
            let cost = network
                .get_proof_request(request_id)
                .await
                .ok()
                .flatten()
                .map(|r| ProofCost {
                    cycles: r.cycles,
                    gas_used: r.gas_used,
                    gas_price: r.gas_price,
                    deduction_amount: r.deduction_amount,
                });

            Ok(RawProof::from_proof(
                &(proof.proof, self.vk),
                proof.public_values.to_vec().into(),
            )?
            .with_cost(cost)
            .with_request_id(Some(request_id)))
        })
    }

    fn onchain_proof(&self, proof: &RawProof) -> anyhow::Result<Bytes> {
        let (sp1_proof, _) = proof.decode_proof::<(SP1Proof, SP1VerifyingKey)>()?;
        Ok(match sp1_proof {
            SP1Proof::Groth16(groth16_proof) => {
                if groth16_proof.encoded_proof.is_empty() {
                    return Ok(Bytes::new());
                }
                let proof_bytes = Bytes::from_hex(&groth16_proof.encoded_proof)?;
                let proof: Bytes = [
                    groth16_proof.groth16_vkey_hash[..4].to_vec(),
                    proof_bytes.to_vec(),
                ]
                .concat()
                .into();
                proof
            }
            SP1Proof::Plonk(plonk_proof) => {
                if plonk_proof.encoded_proof.is_empty() {
                    return Ok(Bytes::new());
                }
                let proof_bytes = Bytes::from_hex(&plonk_proof.encoded_proof)?;
                let proof: Bytes = [
                    plonk_proof.plonk_vkey_hash[..4].to_vec(),
                    proof_bytes.to_vec(),
                ]
                .concat()
                .into();
                proof
            }
            SP1Proof::Compressed(_) | SP1Proof::Core(_) => Bytes::new(),
        })
    }

    fn upload_image(&self, cfg: &RemoteProverConfig) -> anyhow::Result<()> {
        block_on(async {
            let mut builder = ProverClient::builder().network().private_key(&cfg.api_key);
            if let Some(api_url) = &cfg.api_url {
                builder = builder.rpc_url(&api_url);
            }
            let prover = builder.build().await;
            prover.register_program(self.vk, self.elf).await?;
            Ok(())
        })
    }

    fn program_id(&self) -> B256 {
        self.vk.bytes32_raw().into()
    }

    fn verify_proof_id(&self) -> B256 {
        B256::new(unsafe { std::mem::transmute(self.vk.hash_u32()) })
    }

    fn gen_proof(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof> {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(input.abi_encode());
        if let Some(encoded_composite_proofs) = encoded_composite_proofs {
            for proof in encoded_composite_proofs {
                let (proof, vk) = bincode::deserialize::<(SP1Proof, SP1VerifyingKey)>(&proof)?;
                let SP1Proof::Compressed(proof) = proof else {
                    return Err(anyhow!("Expected a compressed SP1 proof"));
                };
                stdin.write_proof(*proof, vk.vk);
            }
        }
        Ok(self.gen_raw_proof(stdin, raw_proof_type)?)
    }
}
