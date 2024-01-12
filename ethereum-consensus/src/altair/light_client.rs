use crate::{
    altair::{
        sync::{SyncAggregate, SyncCommittee},
        BeaconBlockHeader,
    },
    primitives::{Bytes32, Slot},
    ssz::prelude::*,
};

pub const FINALIZED_ROOT_INDEX: usize = 105;
pub const FINALIZED_ROOT_INDEX_FLOOR_LOG_2: usize = 6;

pub const CURRENT_SYNC_COMMITTEE_INDEX: usize = 54;
pub const CURRENT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2: usize = 5;

pub const NEXT_SYNC_COMMITTEE_INDEX: usize = 55;
pub const NEXT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2: usize = 5;

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

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientBootstrap<const SYNC_COMMITTEE_SIZE: usize> {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub current_sync_committee_branch: Vector<Bytes32, CURRENT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2>,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientUpdate<const SYNC_COMMITTEE_SIZE: usize> {
    pub attested_header: LightClientHeader,
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee_branch: Vector<Bytes32, NEXT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2>,
    pub finalized_header: LightClientHeader,
    pub finality_branch: Vector<Bytes32, FINALIZED_ROOT_INDEX_FLOOR_LOG_2>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientFinalityUpdate<const SYNC_COMMITTEE_SIZE: usize> {
    pub attested_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    pub finality_branch: Vector<Bytes32, FINALIZED_ROOT_INDEX_FLOOR_LOG_2>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientOptimisticUpdate<const SYNC_COMMITTEE_SIZE: usize> {
    pub attested_header: LightClientHeader,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}

#[derive(Default, Debug, Clone)]
pub struct LightClientStore<const SYNC_COMMITTEE_SIZE: usize> {
    pub finalized_header: LightClientHeader,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub best_valid_update: Option<LightClientUpdate<SYNC_COMMITTEE_SIZE>>,
    pub optimistic_header: LightClientHeader,
    pub previous_max_active_participants: u64,
    pub current_max_active_participants: u64,
}
