// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Peercoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use crate::prelude::*;

use core::fmt;

use crate::merkle_tree;
use crate::error::Error::{self, BlockBadTarget, BlockBadProofOfWork};
use crate::hashes::{Hash, HashEngine};
use crate::hash_types::{Wtxid, TxMerkleNode, WitnessMerkleNode, WitnessCommitment};
use crate::consensus::{encode, Encodable, Decodable};
use crate::blockdata::transaction::Transaction;
use crate::blockdata::script;
use crate::pow::{CompactTarget, Target, Work};
use crate::VarInt;
use crate::internal_macros::impl_consensus_encoding;
use crate::io;
use super::Weight;

pub use crate::hash_types::BlockHash;

/// Peercoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] commiting to all transactions in the block.
///
/// [merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// ### Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

impl_consensus_encoding!(Header, version, prev_blockhash, merkle_root, time, bits, nonce);

impl Header {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine).expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
    pub fn target(&self) -> Target {
        self.bits.into()
    }

    /// Computes the popular "difficulty" measure for mining.
    pub fn difficulty(&self) -> u128 {
        self.target().difficulty()
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    pub fn difficulty_float(&self) -> f64 {
        self.target().difficulty_float()
    }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_pow(&self, required_target: Target) -> Result<BlockHash, Error> {
        let target = self.target();
        if target != required_target {
            return Err(BlockBadTarget);
        }
        let block_hash = self.block_hash();
        if target.is_met_by(block_hash) {
            Ok(block_hash)
        } else {
            Err(BlockBadProofOfWork)
        }
    }

    /// Returns the total work of the block.
    pub fn work(&self) -> Work {
        self.target().to_work()
    }
}

/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if version bits is
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// ### Relevant BIPs
///
/// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-34 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-9 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-9 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Creates a [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn from_consensus(v: i32) -> Self {
        Version(v)
    }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn to_consensus(self) -> i32 {
        self.0
    }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-9 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(&self, bit: u8) -> bool {
        // Only bits [0, 28] inclusive are used for signalling.
        if bit > 28 {
            return false;
        }

        // To signal using version bits, the first three bits must be `001`.
        if (self.0 as u32) & !Self::VERSION_BITS_MASK != Self::USE_VERSION_BITS {
            return false;
        }

        // The bit is set if signalling a soft fork.
        (self.0 as u32 & Self::VERSION_BITS_MASK) & (1 << bit) > 0
    }
}

impl Default for Version {
    fn default() -> Version {
        Self::NO_SOFT_FORK_SIGNALLING
    }
}

impl Encodable for Version {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version)
    }
}

/// Peercoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// ### Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>,
    /// Block signature
    pub signature: Vec<u8>,
}

impl_consensus_encoding!(Block, header, txdata, signature);

impl Block {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Checks if merkle root of header matches merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    pub fn check_witness_commitment(&self) -> bool {
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.txdata.iter().all(|t| t.input.iter().all(|i| i.witness.is_empty())) {
            return true;
        }

        if self.txdata.is_empty() {
            return false;
        }

        let coinbase = &self.txdata[0];
        if !coinbase.is_coin_base() {
            return false;
        }

        // Commitment is in the last output that starts with magic bytes.
        if let Some(pos) = coinbase.output.iter()
            .rposition(|o| o.script_pubkey.len () >= 38 && o.script_pubkey.as_bytes()[0..6] ==  MAGIC)
        {
            let commitment = WitnessCommitment::from_slice(&coinbase.output[pos].script_pubkey.as_bytes()[6..38]).unwrap();
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some(witness_root) = self.witness_root() {
                    return commitment == Self::compute_witness_commitment(&witness_root, witness_vec[0]);
                }
            }
        }

        false
    }

    /// Computes the transaction merkle root.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.txid().to_raw_hash());
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Computes the witness commitment for the block's transaction list.
    pub fn compute_witness_commitment(witness_root: &WitnessMerkleNode, witness_reserved_value: &[u8]) -> WitnessCommitment {
        let mut encoder = WitnessCommitment::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_engine(encoder)
    }

    /// Computes the merkle root of transactions hashed for witness.
    pub fn witness_root(&self) -> Option<WitnessMerkleNode> {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::all_zeros().to_raw_hash()
            } else {
                t.wtxid().to_raw_hash()
            }
        });
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// base_size == size of header + size of encoded transaction count.
    fn base_size(&self) -> usize {
        80 + VarInt(self.txdata.len() as u64).len() + VarInt(self.signature.len() as u64).len()
    }

    /// Returns the size of the block.
    ///
    /// size == size of header + size of encoded transaction count + total size of transactions.
    pub fn size(&self) -> usize {
        let txs_size: usize = self.txdata.iter().map(Transaction::size).sum();
        self.base_size() + txs_size + self.signature.len()
    }

    /// Returns the strippedsize of the block.
    pub fn strippedsize(&self) -> usize {
        let txs_size: usize = self.txdata.iter().map(Transaction::strippedsize).sum();
        self.base_size() + txs_size + self.signature.len()
    }

    /// Returns the weight of the block.
    pub fn weight(&self) -> Weight {
        let base_weight = Weight::from_non_witness_data_size(self.base_size() as u64);
        let txs_weight: Weight = self.txdata.iter().map(Transaction::weight).sum();
        base_weight + txs_weight
    }

    /// Returns the coinbase transaction, if one is present.
    pub fn coinbase(&self) -> Option<&Transaction> {
        self.txdata.first()
    }

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).

        if self.header.version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase().ok_or(Bip34Error::NotPresent)?;
        let input = cb.input.first().ok_or(Bip34Error::NotPresent)?;
        let push = input.script_sig.instructions_minimal().next().ok_or(Bip34Error::NotPresent)?;
        match push.map_err(|_| Bip34Error::NotPresent)? {
            script::Instruction::PushBytes(b) => {
                // Check that the number is encoded in the minimal way.
                let h = script::read_scriptint(b.as_bytes()).map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    Ok(h as u64)
                }
            }
            _ => Err(Bip34Error::NotPresent),
        }
    }
}

/// An error when looking up a BIP34 block height.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip34Error {
    /// The block does not support BIP34 yet.
    Unsupported,
    /// No push was present where the BIP34 push was expected.
    NotPresent,
    /// The BIP34 push was larger than 8 bytes.
    UnexpectedPush(Vec<u8>),
    /// The BIP34 push was negative.
    NegativeHeight,
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Bip34Error::Unsupported => write!(f, "block doesn't support BIP34"),
            Bip34Error::NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            Bip34Error::UnexpectedPush(ref p) => {
                write!(f, "unexpected byte push of > 8 bytes: {:?}", p)
            }
            Bip34Error::NegativeHeight => write!(f, "negative BIP34 height"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Bip34Error::*;

        match self {
            Unsupported |
            NotPresent |
            UnexpectedPush(_) |
            NegativeHeight => None,
        }
    }
}

impl From<Header> for BlockHash {
    fn from(header: Header) -> BlockHash {
        header.block_hash()
    }
}

impl From<&Header> for BlockHash {
    fn from(header: &Header) -> BlockHash {
        header.block_hash()
    }
}

impl From<Block> for BlockHash {
    fn from(block: Block) -> BlockHash {
        block.block_hash()
    }
}

impl From<&Block> for BlockHash {
    fn from(block: &Block) -> BlockHash {
        block.block_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::consensus::encode::{deserialize, serialize};
    use crate::internal_macros::hex;

    #[test]
    fn test_coinbase_and_bip34() {
        // testnet block 500,000
        const BLOCK_HEX: &str = "030000003eb14c9c244e07d792b02a3c92181c37cdd62cfa8b37eca168ff16191e8183022d20ad595a4eadb236f714fe8a29490cc0456da0a8f7aa560f16e5a1f5620bfa28ef326365bf0c1c0000000002030000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff060320a1070101ffffffff020000000000000000000000000000000000266a24aa21a9ed3c001c044e0c32430f95f96c71b12cf8623c55aadcf4bb40aa6d365c44df330801200000000000000000000000000000000000000000000000000000000000000000000000000300000001c99d6b3758960d0967384a217b580f8a3a4c6d30fbf92fbf5757079617655e7902000000484730440220294d114fc7de7b2ac79107ef4b05fbd5396186cb33fc905f19071882a8429e81022074e251fc2f7b9a4df305d473c49808a292f8e6231a2eea4257dcc3dbbc8df3d201ffffffff020000000000000000000cc74415000000002321029183c4d19283bdf83049019502ee0cc174a2ece72b16524b2c60c1abaa6ffa79ac00000000463044022007cf331d0231f0d3d47cd2813b80a8e53798e38679f52adc2344d9309fd8a62002203da848ddd7cfc95a5c135fc252aa7fad1758c829b821eedd4ee25f5ec0c7d82c";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();

        let cb_txid = "7d1fcb7f13626e8ae64cf0edb3f7168100e8a462ef80a01cea975b89db732717";
        assert_eq!(block.coinbase().unwrap().txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(500_000));


        // block with unsupported bip34
        const BAD_HEX: &str = "010000001c65dc356546836195b5749868fea4fe853e5f7781ab72d9833667b8143bb0a7b8683cced353c7dce180d50c230e137e6df1e64919d724692cde834417a74fdb1574d053c8ec051c0000000002010000001574d053010000000000000000000000000000000000000000000000000000000000000000ffffffff0f041574d053026905062f503253482fffffffff0100000000000000000000000000010000001574d05301c0e1957064cb60c533e9862dcf9039e75a324511d4015e93598d2a86055ddda601000000484730440220636679fc06dd732110053188a92b6ea4d5f0b2786692af14770a6d9d9573cc190220128691e31e45dd62472a1ddbf79364de609e9997fde123be6c7a8d17c2a9e71801ffffffff0300000000000000000000bc75870000000023210251110fbb64c45854505ea3d1855ffbcc512fc4ccc6416a1b11b93da2d2ae1d4bac00bc75870000000023210251110fbb64c45854505ea3d1855ffbcc512fc4ccc6416a1b11b93da2d2ae1d4bac000000004630440220529d685afdda29cb4b20dbda1be16ce210357a8b78ae8eea7bc60151676073f0022068169513f4d177d898ef95371853b363304fcd838d92ff394bf4481063879ea9";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();

        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::Unsupported));
    }

    #[test]
    fn block_test() {
        // Mainnet block 00000000000000011f7ba19adb5dc1d9a277e8d6f6a17818150acb88bb04538c
        let some_block = hex!("04a00000dbc2c2021ecf523279e2e840e279d20af8d42f63ca023c481902dd146a5d6613e3bc183eab2f77a31c9bee7eac335eb4a445f6b0e25ac1db3ee10d64610bc3f4e31fba652a3b01199684da140201000000e31fba650001010000000000000000000000000000000000000000000000000000000000000000ffffffff5303a11b0b04e41fba6508fabe6d6d2f7cf03438156edefa06b78fef9eba2e3d3d08a8d75e3bcb328a93fb26601be2000100000000000004be43957980f8017700122f4d696e696e672d44757463682f2d313133000000000220bf730200000000232103cfa7d3e19d5cc5396d4a89f023b5968967bd10cef2aca448ee94b589b18d545cac0000000000000000266a24aa21a9ede04b1f147c9dadf30a80949f77da99664c293de82faae52e9f28040967252a9b01200000000000000000000000000000000000000000000000000000000000000000000000000300000001286c9408a77f09714939edbc8db206b11af1289aab9593c47b2803b767451689010000006a473044022036021ae0be4cafd42fd2d431ee8d2c3aa78d02d8e47aee71832333a0debc095102202226c1b9eaabfe37610d4b29f071633e436bb55ba218054aef27425602cf09ca0121029b67e45043a924d494d31e360e16363f700e736e9fcbaf9181730a6ae8ee8d28ffffffff0264570100000000001976a914fea3ed4cc0ef8db6a67656bc06fd61837737441d88aca1100300000000001976a9141d91721daec07180f1cb8813fba96aba067e8af788ac0000000000");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("dbc2c2021ecf523279e2e840e279d20af8d42f63ca023c481902dd146a5d6613");
        let merkle = hex!("e3bc183eab2f77a31c9bee7eac335eb4a445f6b0e25ac1db3ee10d64610bc3f4");
        let work = Work::from(0xcff1470ad85b6e86_u128);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(40964));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1706696675);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(419511082));
        assert_eq!(real_decode.header.nonce, 349865110);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(real_decode.header.validate_pow(real_decode.header.target()).unwrap(), real_decode.block_hash());
        assert_eq!(real_decode.header.difficulty(), 3488642841);
        assert_eq!(real_decode.header.difficulty_float(), 3488642841.567636);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.size(), some_block.len());
        //assert_eq!(real_decode.strippedsize(), some_block.len());
        //assert_eq!(real_decode.weight(), Weight::from_non_witness_data_size(some_block.len() as u64));

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[test]
    fn segwit_block_test() {
        let segwit_block = include_bytes!("../../tests/data/testnet_6093ffd84105c381b51149721bc440035d9ff2649bd617b8c23a71c975abc13e.raw").to_vec();

        //println!("segwit_block len {:?}", segwit_block.len());
        //println!("segwit_block {:?}", segwit_block.to_lower_hex_string());
        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("45dedffa1948bf579902389898ace9ed6dea1d95b68fe3bab05b4f70e8d7b1a3");
        let merkle = hex!("f2bba63248ad1d388836de8ddfd571b2e5c77f78c44ccd8d4d6814c6deddadf2");
        let work = Work::from(0x215a99bc0c_u64);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(4));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(real_decode.header.time, 1698835070);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(0x1c07acde));
        assert_eq!(real_decode.header.nonce, 0);
        assert_eq!(real_decode.header.work(), work);
        //assert_eq!(real_decode.header.validate_pow(real_decode.header.target()).unwrap(), real_decode.block_hash());
        assert_eq!(real_decode.header.difficulty(), 33);
        assert_eq!(real_decode.header.difficulty_float(), 33.35339936302947);
        // [test] TODO: check the transaction data
        //println!("{:?}", real_decode);
        //println!("{:?}", serialize(&real_decode).to_lower_hex_string());
        assert_eq!(real_decode.size(), segwit_block.len());
        assert_eq!(real_decode.strippedsize(), 455);
        assert_eq!(real_decode.weight(), Weight::from_wu(1645));

        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), segwit_block);
    }

    #[test]
    fn block_version_test() {
        let block = hex!("ffffff7f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(2147483647));

        let block2 = hex!("00000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap();
        assert_eq!(real_decode2.header.version, Version(-2147483648));
    }

    #[test]
    fn validate_pow_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");
        let some_header: Header = deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(some_header.validate_pow(some_header.target()).unwrap(), some_header.block_hash());

        // test with zero target
        match some_header.validate_pow(Target::ZERO) {
            Err(BlockBadTarget) => (),
            _ => panic!("unexpected result from validate_pow"),
        }

        // test with modified header
        let mut invalid_header: Header = some_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_pow(invalid_header.target()) {
            Err(BlockBadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn compact_roundrtip_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");

        let header: Header = deserialize(&some_header).expect("Can't deserialize correct block header");

        assert_eq!(header.bits, header.target().to_compact_lossy());
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ 1<<i) as i32;
            let version = Version(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version(0x20000000 ^ 1<<1);
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }
}

#[cfg(bench)]
mod benches {
    use super::Block;
    use crate::EmptyWrite;
    use crate::consensus::{deserialize, Encodable, Decodable};
    use test::{black_box, Bencher};

    #[bench]
    pub fn bench_stream_reader(bh: &mut Bencher) {
        let big_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        assert_eq!(big_block.len(), 1_381_836);
        let big_block = black_box(big_block);

        bh.iter(|| {
            let mut reader = &big_block[..];
            let block = Block::consensus_decode(&mut reader).unwrap();
            black_box(&block);
        });
    }

    #[bench]
    pub fn bench_block_serialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        let mut data = Vec::with_capacity(raw_block.len());

        bh.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        bh.iter(|| {
            let block: Block = deserialize(&raw_block[..]).unwrap();
            black_box(&block);
        });
    }
}
