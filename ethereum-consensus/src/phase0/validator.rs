use crate::{
    phase0::operations::Attestation,
    primitives::{BlsPublicKey, BlsSignature, Bytes32, Epoch, Gwei, Root, ValidatorIndex},
    ssz::prelude::*,
};

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct Validator {
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "crate::serde::as_str")]
    pub effective_balance: Gwei,
    pub slashed: bool,
    // Status epochs
    #[serde(with = "crate::serde::as_str")]
    pub activation_eligibility_epoch: Epoch,
    #[serde(with = "crate::serde::as_str")]
    pub activation_epoch: Epoch,
    #[serde(with = "crate::serde::as_str")]
    pub exit_epoch: Epoch,
    #[serde(with = "crate::serde::as_str")]
    pub withdrawable_epoch: Epoch,
}

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

#[derive(Default, Debug, SimpleSerialize, Clone, serde::Serialize, serde::Deserialize)]
pub struct Eth1Block {
    pub timestamp: u64,
    pub deposit_root: Root,
    pub deposit_count: u64,
}

#[derive(Default, Debug, SimpleSerialize, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregateAndProof<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
    #[serde(with = "crate::serde::as_str")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation<MAX_VALIDATORS_PER_COMMITTEE>,
    pub selection_proof: BlsSignature,
}

#[derive(Default, Debug, SimpleSerialize, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedAggregateAndProof<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
    pub message: AggregateAndProof<MAX_VALIDATORS_PER_COMMITTEE>,
    pub signature: BlsSignature,
}
