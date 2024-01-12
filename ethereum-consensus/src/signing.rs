use crate::{
    crypto::{self, SecretKey},
    primitives::{BlsPublicKey, BlsSignature, Domain, Root},
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

#[derive(Default, Debug, SimpleSerialize)]
pub struct SigningData {
    pub object_root: Root,
    pub domain: Domain,
}

pub fn compute_signing_root<T: Merkleized>(
    ssz_object: &mut T,
    domain: Domain,
) -> Result<Root, Error> {
    let object_root = ssz_object.hash_tree_root()?;

    let mut s = SigningData { object_root, domain };
    s.hash_tree_root().map_err(Error::Merkleization)
}

pub fn sign_with_domain<T: Merkleized>(
    data: &mut T,
    signing_key: &SecretKey,
    domain: Domain,
) -> Result<BlsSignature, Error> {
    let signing_root = compute_signing_root(data, domain)?;
    Ok(signing_key.sign(signing_root.as_ref()))
}

pub fn verify_signed_data<T: Merkleized>(
    data: &mut T,
    signature: &BlsSignature,
    public_key: &BlsPublicKey,
    domain: Domain,
) -> Result<(), Error> {
    let signing_root = compute_signing_root(data, domain)?;
    crypto::verify_signature(public_key, signing_root.as_ref(), signature).map_err(Into::into)
}

// This function wraps the inner implementation defined in `crate::crypto` but presents a bit nicer
// interface to users external to this crate.
// NOTE: `verify_signed_data` serves a similar purpose but asking for a `&mut T` there
// means that any message containing its public key (a common pattern in ethereum types)
// needs to pass in a (ref to a) `clone` of the public key inside the message type.
pub fn verify_signature(
    public_key: &BlsPublicKey,
    signing_root: &[u8],
    signature: &BlsSignature,
) -> Result<(), Error> {
    crypto::verify_signature(public_key, signing_root, signature).map_err(Into::into)
}
