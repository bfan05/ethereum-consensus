use crate::{
    phase0::{
        beacon_block::BeaconBlockHeader,
        constants::JUSTIFICATION_BITS_LENGTH,
        operations::{Checkpoint, Eth1Data, PendingAttestation},
        validator::Validator,
    },
    primitives::{Bytes32, Epoch, Gwei, Root, Slot, Version},
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
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct Fork {
    #[serde(with = "crate::serde::as_hex")]
    pub previous_version: Version,
    #[serde(with = "crate::serde::as_hex")]
    pub current_version: Version,
    #[serde(with = "crate::serde::as_str")]
    pub epoch: Epoch,
}

#[derive(Default, Debug, SimpleSerialize, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForkData {
    #[serde(with = "crate::serde::as_hex")]
    pub current_version: Version,
    pub genesis_validators_root: Root,
}

#[derive(Default, Debug, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct HistoricalBatch<const SLOTS_PER_HISTORICAL_ROOT: usize> {
    pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
}

// Note: `HistoricalSummary` is defined in the `capella` specs; however, this // repo used the same
// strategy to compute the `HistoricalBatch` roots so // the type already existed.
#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct HistoricalSummary {
    pub block_summary_root: Root,
    pub state_summary_root: Root,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct BeaconState<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const PENDING_ATTESTATIONS_BOUND: usize,
> {
    #[serde(with = "crate::serde::as_str")]
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
    #[serde(with = "crate::serde::as_str")]
    pub slot: Slot,
    pub fork: Fork,
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: List<Eth1Data, ETH1_DATA_VOTES_BOUND>,
    #[serde(with = "crate::serde::as_str")]
    pub eth1_deposit_index: u64,
    pub validators: List<Validator, VALIDATOR_REGISTRY_LIMIT>,
    #[serde(with = "crate::serde::seq_of_str")]
    pub balances: List<Gwei, VALIDATOR_REGISTRY_LIMIT>,
    pub randao_mixes: Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR>,
    #[serde(with = "crate::serde::seq_of_str")]
    pub slashings: Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>,
    pub previous_epoch_attestations:
        List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>,
    pub current_epoch_attestations:
        List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>,
    pub justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
}
