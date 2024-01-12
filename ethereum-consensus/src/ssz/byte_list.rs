use crate::ssz::prelude::*;
use ssz_rs::utils::{write_bytes_to_lower_hex, write_bytes_to_lower_hex_display};
use std::{
    fmt,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
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

#[derive(Default, Clone, PartialEq, Eq, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct ByteList<const N: usize>(#[serde(with = "crate::serde::as_hex")] List<u8, N>);

impl<const N: usize> TryFrom<&[u8]> for ByteList<N> {
    type Error = DeserializeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ByteList::<N>::deserialize(bytes)
    }
}

impl<const N: usize> Hash for ByteList<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl<const N: usize> fmt::Debug for ByteList<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_bytes_to_lower_hex(f, &self.0)
    }
}

impl<const N: usize> fmt::Display for ByteList<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_bytes_to_lower_hex_display(f, self.0.iter())
    }
}

impl<const N: usize> AsRef<[u8]> for ByteList<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize> Deref for ByteList<N> {
    type Target = List<u8, N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ByteList<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_list_serde() {
        let list = ByteList::<32>::try_from([255u8, 255u8].as_ref()).unwrap();
        let encoding = serialize(&list).unwrap();
        assert_eq!(encoding, [255, 255]);

        let recovered_list = ByteList::<32>::deserialize(&encoding).unwrap();
        assert_eq!(list, recovered_list);
    }
}
