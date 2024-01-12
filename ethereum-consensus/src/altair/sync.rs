use crate::{
    primitives::{BlsPublicKey, BlsSignature},
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
pub struct SyncAggregate<const SYNC_COMMITTEE_SIZE: usize> {
    pub sync_committee_bits: Bitvector<SYNC_COMMITTEE_SIZE>,
    pub sync_committee_signature: BlsSignature,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct SyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
    #[serde(rename = "pubkeys")]
    pub public_keys: Vector<BlsPublicKey, SYNC_COMMITTEE_SIZE>,
    #[serde(rename = "aggregate_pubkey")]
    pub aggregate_public_key: BlsPublicKey,
}
