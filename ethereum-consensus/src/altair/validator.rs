use crate::{
    primitives::{BlsSignature, Root, Slot, ValidatorIndex},
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

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SyncCommitteeMessage {
    #[serde(with = "crate::serde::as_str")]
    pub slot: Slot,
    pub beacon_block_root: Root,
    #[serde(with = "crate::serde::as_str")]
    pub validator_index: ValidatorIndex,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SyncCommitteeContribution<const SYNC_SUBCOMMITTEE_SIZE: usize> {
    #[serde(with = "crate::serde::as_str")]
    pub slot: Slot,
    pub beacon_block_root: Root,
    #[serde(with = "crate::serde::as_str")]
    pub subcommittee_index: u64,
    pub aggregation_bits: Bitvector<SYNC_SUBCOMMITTEE_SIZE>,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct ContributionAndProof<const SYNC_SUBCOMMITTEE_SIZE: usize> {
    #[serde(with = "crate::serde::as_str")]
    pub aggregator_index: ValidatorIndex,
    pub contribution: SyncCommitteeContribution<SYNC_SUBCOMMITTEE_SIZE>,
    pub selection_proof: BlsSignature,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SignedContributionAndProof<const SYNC_SUBCOMMITTEE_SIZE: usize> {
    pub message: ContributionAndProof<SYNC_SUBCOMMITTEE_SIZE>,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SyncAggregatorSelectionData {
    pub slot: Slot,
    pub subcommittee_index: u64,
}
