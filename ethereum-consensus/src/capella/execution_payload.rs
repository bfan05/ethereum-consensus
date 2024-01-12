use crate::{
    bellatrix::Transaction,
    capella::withdrawal::Withdrawal,
    primitives::{Bytes32, ExecutionAddress, Hash32, Root, U256},
    ssz::prelude::*,
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

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct ExecutionPayload<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
> {
    pub parent_hash: Hash32,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
    pub prev_randao: Bytes32,
    #[serde(with = "crate::serde::as_str")]
    pub block_number: u64,
    #[serde(with = "crate::serde::as_str")]
    pub gas_limit: u64,
    #[serde(with = "crate::serde::as_str")]
    pub gas_used: u64,
    #[serde(with = "crate::serde::as_str")]
    pub timestamp: u64,
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    #[serde(with = "crate::serde::as_str")]
    pub base_fee_per_gas: U256,
    pub block_hash: Hash32,
    pub transactions: List<Transaction<MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
    pub withdrawals: List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
}

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct ExecutionPayloadHeader<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub parent_hash: Hash32,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
    pub prev_randao: Bytes32,
    #[serde(with = "crate::serde::as_str")]
    pub block_number: u64,
    #[serde(with = "crate::serde::as_str")]
    pub gas_limit: u64,
    #[serde(with = "crate::serde::as_str")]
    pub gas_used: u64,
    #[serde(with = "crate::serde::as_str")]
    pub timestamp: u64,
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    #[serde(with = "crate::serde::as_str")]
    pub base_fee_per_gas: U256,
    pub block_hash: Hash32,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
}

impl<
        'a,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const MAX_BYTES_PER_TRANSACTION: usize,
        const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    >
    TryFrom<
        &'a mut ExecutionPayload<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
    > for ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    type Error = Error;

    fn try_from(
        payload: &'a mut ExecutionPayload<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
    ) -> Result<ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>, Self::Error>
    {
        let transactions_root = payload.transactions.hash_tree_root()?;
        let withdrawals_root = payload.withdrawals.hash_tree_root()?;

        Ok(ExecutionPayloadHeader {
            parent_hash: payload.parent_hash.clone(),
            fee_recipient: payload.fee_recipient.clone(),
            state_root: payload.state_root.clone(),
            receipts_root: payload.receipts_root.clone(),
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao.clone(),
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash.clone(),
            transactions_root,
            withdrawals_root,
        })
    }
}
