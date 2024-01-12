use crate::{
    primitives::{BlsPublicKey, BlsSignature, ExecutionAddress, ValidatorIndex},
    ssz::prelude::*,
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

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct BlsToExecutionChange {
    #[serde(with = "crate::serde::as_str")]
    pub validator_index: ValidatorIndex,
    #[serde(rename = "from_bls_pubkey")]
    pub from_bls_public_key: BlsPublicKey,
    pub to_execution_address: ExecutionAddress,
}

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: BlsSignature,
}
