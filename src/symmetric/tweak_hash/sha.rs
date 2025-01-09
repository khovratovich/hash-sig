use sha2::{Digest, Sha256};

use super::TweakableHash;

/// Enum to implement tweaks.
pub enum Sha256Tweak {
    TreeTweak {
        level: u8,
        pos_in_level: u32,
    },
    ChainTweak {
        epoch: u32,
        chain_index: u16,
        pos_in_chain: u16,
    },
}

impl Sha256Tweak {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Sha256Tweak::TreeTweak {
                level,
                pos_in_level,
            } => {
                let mut bytes = Vec::new();
                // this is a tree tweak, so we start with a 0x00 byte
                bytes.push(0x00);
                // then we extend with the actual data
                bytes.extend(&level.to_be_bytes());
                bytes.extend(&pos_in_level.to_be_bytes());
                // Note: it is fine that both tweaks have different
                // lengths as the domain separator (0x00 or 0x01)
                // ensures that the length is known and we know when
                // the tweak ends.
                bytes
            }
            Sha256Tweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            } => {
                let mut bytes = Vec::new();
                // this is a chain tweak, so we start with a 0x01 byte
                bytes.push(0x01);
                // then we extend with the actual data
                bytes.extend(&epoch.to_be_bytes());
                bytes.extend(&chain_index.to_be_bytes());
                bytes.extend(&pos_in_chain.to_be_bytes());
                bytes
            }
        }
    }
}

/// A tweakable hash function implemented using
/// SHA-256, given a parameter length and the hash output length.
/// Both lengths must be given in Bytes.
/// Both lengths must be less than 255 bits.
pub struct Sha256TweakHash<const PARAMETER_LEN: usize, const HASH_LEN: usize>;

impl<const PARAMETER_LEN: usize, const HASH_LEN: usize> TweakableHash
    for Sha256TweakHash<PARAMETER_LEN, HASH_LEN>
{
    type Parameter = [u8; PARAMETER_LEN];

    type Tweak = Sha256Tweak;

    type Domain = [u8; HASH_LEN];

    fn rand_parameter<R: rand::Rng>(rng: &mut R) -> Self::Parameter {
        let mut par = [0u8; PARAMETER_LEN];
        rng.fill_bytes(&mut par);
        par
    }

    fn rand_domain<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        let mut dom = [0u8; HASH_LEN];
        rng.fill_bytes(&mut dom);
        dom
    }

    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak {
        Sha256Tweak::TreeTweak {
            level,
            pos_in_level,
        }
    }

    fn chain_tweak(epoch: u32, chain_index: u16, pos_in_chain: u16) -> Self::Tweak {
        Sha256Tweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        }
    }

    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain {
        assert!(
            PARAMETER_LEN < 256 / 8,
            "SHA256-Tweak Hash: Parameter Length must be less than 256 bit"
        );
        assert!(
            HASH_LEN < 256 / 8,
            "SHA256-Tweak Hash: Hash Length must be less than 256 bit"
        );

        let mut hasher = Sha256::new();

        // add the parameter and tweak
        hasher.update(parameter);
        hasher.update(tweak.to_bytes());

        // now add the actual message to be hashed
        for m in message {
            hasher.update(m);
        }

        // finalize the hash, and take as many bytes as we need
        let result = hasher.finalize();
        result[0..HASH_LEN].try_into().unwrap()
    }
}

// Example instantiations
pub type Sha256Tweak128128 = Sha256TweakHash<16, 16>;
pub type Sha256Tweak128192 = Sha256TweakHash<16, 24>;
pub type Sha256Tweak192192 = Sha256TweakHash<24, 24>;

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_apply_128_128() {
        let mut rng = thread_rng();

        // test that nothing is panicking
        let parameter = Sha256Tweak128128::rand_parameter(&mut rng);
        let message_one = Sha256Tweak128128::rand_domain(&mut rng);
        let message_two = Sha256Tweak128128::rand_domain(&mut rng);
        let tweak_tree = Sha256Tweak128128::tree_tweak(0, 3);
        Sha256Tweak128128::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = Sha256Tweak128128::rand_parameter(&mut rng);
        let message_one = Sha256Tweak128128::rand_domain(&mut rng);
        let message_two = Sha256Tweak128128::rand_domain(&mut rng);
        let tweak_chain = Sha256Tweak128128::chain_tweak(2, 3, 4);
        Sha256Tweak128128::apply(&parameter, &tweak_chain, &[message_one, message_two]);
    }

    #[test]
    fn test_apply_128_192() {
        let mut rng = thread_rng();

        // test that nothing is panicking
        let parameter = Sha256Tweak128192::rand_parameter(&mut rng);
        let message_one = Sha256Tweak128192::rand_domain(&mut rng);
        let message_two = Sha256Tweak128192::rand_domain(&mut rng);
        let tweak_tree = Sha256Tweak128192::tree_tweak(0, 3);
        Sha256Tweak128192::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = Sha256Tweak128192::rand_parameter(&mut rng);
        let message_one = Sha256Tweak128192::rand_domain(&mut rng);
        let message_two = Sha256Tweak128192::rand_domain(&mut rng);
        let tweak_chain = Sha256Tweak128192::chain_tweak(2, 3, 4);
        Sha256Tweak128192::apply(&parameter, &tweak_chain, &[message_one, message_two]);
    }

    #[test]
    fn test_apply_192_192() {
        let mut rng = thread_rng();

        // test that nothing is panicking
        let parameter = Sha256Tweak192192::rand_parameter(&mut rng);
        let message_one = Sha256Tweak192192::rand_domain(&mut rng);
        let message_two = Sha256Tweak192192::rand_domain(&mut rng);
        let tweak_tree = Sha256Tweak192192::tree_tweak(0, 3);
        Sha256Tweak192192::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = Sha256Tweak192192::rand_parameter(&mut rng);
        let message_one = Sha256Tweak192192::rand_domain(&mut rng);
        let message_two = Sha256Tweak192192::rand_domain(&mut rng);
        let tweak_chain = Sha256Tweak192192::chain_tweak(2, 3, 4);
        Sha256Tweak192192::apply(&parameter, &tweak_chain, &[message_one, message_two]);
    }
}
