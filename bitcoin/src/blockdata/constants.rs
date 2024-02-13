// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use core::default::Default;

use bitcoin_internals::impl_array_newtype;
use hex_lit::hex;

use crate::hashes::{Hash, sha256d};
use crate::blockdata::script;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::locktime::absolute;
use crate::blockdata::transaction::{OutPoint, Transaction, TxOut, TxIn, Sequence};
use crate::blockdata::block::{self, Block};
use crate::blockdata::witness::Witness;
use crate::network::constants::Network;
use crate::pow::CompactTarget;
use crate::internal_macros::impl_bytes_newtype;

/// How many satoshis are in "one peercoin".
pub const COIN_VALUE: u64 = 1_000_000;
/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 600;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
/// The maximum allowed weight for a block, see BIP 141 (network rule).
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction.
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (peercoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 55; // 0x37
/// Mainnet (peercoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 117; // 0x75
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub const MAX_MONEY: u64 = 21_000_000 * COIN_VALUE;

/// Constructs and returns the coinbase (and only) transaction of the Peercoin genesis block.
fn peercoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        timestamp: 1345083810,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().push_int(486604799)
                                          .push_int_non_minimal(9999)
                                          .push_slice(b"Matonis 07-AUG-2012 Parallel Currencies And The Roadmap To Monetary Freedom")
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");
    let out_script = script::Builder::new()
        .into_script();
    ret.output.push(TxOut {
        value: 0,
        script_pubkey: out_script
    });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![peercoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Peercoin => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1345084287,
                    bits: CompactTarget::from_consensus(0x1d00ffff),
                    nonce: 2179302059
                },
                txdata,
                signature: Vec::new(),
            }
        }
        Network::Testnet => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1345090000,
                    bits: CompactTarget::from_consensus(0x1d0fffff),
                    nonce: 122894938
                },
                txdata,
                signature: Vec::new(),
            }
        }
        Network::Signet => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1345090000,
                    bits: CompactTarget::from_consensus(0x1d0fffff),
                    nonce: 122894938
                },
                txdata,
                signature: Vec::new(),
            }
        }
        Network::Regtest => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1345090000,
                    bits: CompactTarget::from_consensus(0x1d0fffff),
                    nonce: 122894938
                },
                txdata,
                signature: Vec::new(),
            }
        }
    }
}

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    // Mainnet value can be verified at https://github.com/lightning/bolts/blob/master/00-introduction.md
    /// `ChainHash` for mainnet peercoin.
    pub const PEERCOIN: Self = Self([227, 39, 205, 128, 200, 177, 126, 253, 164, 234, 8, 197, 135, 126, 149, 216, 119, 70, 42, 182, 99, 73, 213, 102, 113, 103, 254, 50, 0, 0, 0, 0]);
    /// `ChainHash` for testnet peercoin.
    pub const TESTNET: Self = Self([6, 159, 124, 196, 174, 129, 202, 12, 124, 114, 204, 48, 230, 140, 101, 176, 23, 205, 23, 62, 80, 150, 101, 127, 115, 187, 87, 247, 1, 0, 0, 0]);
    /// `ChainHash` for signet peercoin.
    pub const SIGNET: Self = Self([6, 159, 124, 196, 174, 129, 202, 12, 124, 114, 204, 48, 230, 140, 101, 176, 23, 205, 23, 62, 80, 150, 101, 127, 115, 187, 87, 247, 1, 0, 0, 0]);
    /// `ChainHash` for regtest peercoin.
    pub const REGTEST: Self = Self([6, 159, 124, 196, 174, 129, 202, 12, 124, 114, 204, 48, 230, 140, 101, 176, 23, 205, 23, 62, 80, 150, 101, 127, 115, 187, 87, 247, 1, 0, 0, 0]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block(network: Network) -> Self {
        let hashes = [Self::PEERCOIN, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::network::constants::Network;
    use crate::consensus::encode::serialize;
    use crate::blockdata::locktime::absolute;
    use crate::internal_macros::hex;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = peercoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("5404ffff001d020f274b4d61746f6e69732030372d4155472d3230313220506172616c6c656c2043757272656e6369657320416e642054686520526f61646d617020546f204d6f6e65746172792046726565646f6d"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("00"));
        assert_eq!(gen.output[0].value, 0);
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(gen.wtxid().to_string(), "3c2d8f85fab4d17aac558cc648a1a58acff0de6deb890c29985690052c5993c2");
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Peercoin);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "3c2d8f85fab4d17aac558cc648a1a58acff0de6deb890c29985690052c5993c2");

        assert_eq!(gen.header.time, 1345084287);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(gen.header.nonce, 2179302059);
        assert_eq!(gen.header.block_hash().to_string(), "0000000032fe677166d54963b62a4677d8957e87c508eaa4fd7eb1c880cd27e3");
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "3c2d8f85fab4d17aac558cc648a1a58acff0de6deb890c29985690052c5993c2");
        assert_eq!(gen.header.time, 1345090000);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1d0fffff));
        assert_eq!(gen.header.nonce, 122894938);
        assert_eq!(gen.header.block_hash().to_string(), "00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06");
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(Network::Signet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "3c2d8f85fab4d17aac558cc648a1a58acff0de6deb890c29985690052c5993c2");
        assert_eq!(gen.header.time, 1345090000);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1d0fffff));
        assert_eq!(gen.header.nonce, 122894938);
        assert_eq!(gen.header.block_hash().to_string(), "00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06");
    }

    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network: Network) {
        use crate::hashes::sha256;

        // The genesis block hash is a double-sha256 and it is displayed backwards.
        let genesis_hash = genesis_block(network).block_hash();
        // We abuse the sha256 hash here so we get a LowerHex impl that does not print the hex backwards.
        let hash = sha256::Hash::from_slice(genesis_hash.as_byte_array()).unwrap();
        let want = format!("{:02x}", hash);

        let chain_hash = ChainHash::using_genesis_block(network);
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);

        match network {
            Network::Peercoin => {},
            Network::Testnet => {},
            Network::Signet => {},
            Network::Regtest => {},
            // Update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants.
        }
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, Network::Peercoin;
        testnet_chain_hash_genesis_block, Network::Testnet;
        signet_chain_hash_genesis_block, Network::Signet;
        regtest_chain_hash_genesis_block, Network::Regtest;
    }

    // Test vector taken from: https://github.com/lightning/bolts/blob/master/00-introduction.md
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block(Network::Peercoin).to_string();
        let want = "e327cd80c8b17efda4ea08c5877e95d877462ab66349d5667167fe3200000000";
        assert_eq!(got, want);
    }
}
