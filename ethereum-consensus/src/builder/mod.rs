use crate::{
    phase0::compute_domain,
    primitives::{BlsPublicKey, BlsSignature, Domain, DomainType, ExecutionAddress},
    ssz::prelude::*,
    state_transition::Context,
    Error,
};

use sha2::{Digest, Sha256};

fn log2(x: usize) -> u32 {
    if x == 0 {
        0
    } else if x.is_power_of_two() {
        1usize.leading_zeros() - x.leading_zeros()
    } else {
        0usize.leading_zeros() - x.leading_zeros()
    }
}

fn get_power_of_two_ceil(x: usize) -> usize {
    match x {
        x if x <= 1 => 1,
        2 => 2,
        x => 2 * get_power_of_two_ceil((x + 1) / 2),
    }
}

pub fn sha256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    let output = hasher.finalize();
    output.into()
}

#[derive(Debug, Clone, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct ValidatorRegistration {
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "crate::serde::as_str")]
    pub gas_limit: u64,
    #[serde(with = "crate::serde::as_str")]
    pub timestamp: u64,
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
}

#[derive(Debug, Clone, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SignedValidatorRegistration {
    pub message: ValidatorRegistration,
    pub signature: BlsSignature,
}

pub fn compute_builder_domain(context: &Context) -> Result<Domain, Error> {
    let domain_type = DomainType::ApplicationBuilder;
    compute_domain(domain_type, None, None, context)
}
