use lazy_static::lazy_static;
use sp1_sdk::{
    env::{EnvProver, EnvProvingKey},
    Elf, Prover, ProverClient, ProvingKey, SP1VerifyingKey,
};
use tokio::runtime::{Handle, Runtime};
use tokio::task::block_in_place;

pub const SP1_VERIFIER_ELF: &[u8] = include_bytes!(".././elf/sp1-verifier-elf");

lazy_static! {
    /// A single persistent Tokio runtime shared by every SP1 prover operation.
    /// The v6 `EnvProver` spawns a background worker; it must live on a runtime
    /// that outlives all calls, so we never create/drop a per-call runtime
    /// (doing so closes the worker's task channel — "channel closed" on setup).
    static ref SP1_RT: Runtime = Runtime::new().expect("failed to build SP1 runtime");
    pub static ref ENV_PROVER: EnvProver = block_on(ProverClient::from_env());
    pub static ref SP1_VERIFIER_PK: EnvProvingKey =
        block_on(ENV_PROVER.setup(Elf::from(SP1_VERIFIER_ELF))).expect("SP1 setup failed");
    pub static ref SP1_VERIFIER_VK: SP1VerifyingKey = SP1_VERIFIER_PK.verifying_key().clone();
}

/// Drive an SP1 async operation to completion on the shared persistent runtime
/// [`SP1_RT`], so the `EnvProver` worker stays alive across calls. When already
/// inside another runtime (e.g. the CLI's `#[tokio::main]`), use `block_in_place`
/// to avoid the "cannot start a runtime from within a runtime" panic.
pub fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    if Handle::try_current().is_ok() {
        block_in_place(|| SP1_RT.block_on(fut))
    } else {
        SP1_RT.block_on(fut)
    }
}
