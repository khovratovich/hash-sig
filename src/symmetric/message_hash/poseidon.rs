use zkhash::ark_ff::One;
use zkhash::ark_ff::UniformRand;
use zkhash::ark_ff::PrimeField;
use zkhash::fields::babybear::FpBabyBear;
use zkhash::fields::babybear::FqConfig;
use zkhash::ark_ff::MontConfig;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_babybear::POSEIDON2_BABYBEAR_24_PARAMS;
use num_bigint::BigUint;

use crate::symmetric::tweak_hash::poseidon::poseidon_compress;
use crate::MESSAGE_LENGTH; 
use super::MessageHash;

// TODO: Check if we want to use this field or a different one
type F = FpBabyBear;

/// Function to encode a message as a vector of field elements
fn encode_message<const HASH_LEN_FE: usize>(message: &[u8; MESSAGE_LENGTH]) -> [F;HASH_LEN_FE] {
     let mut msg_uint =  message.iter()
        .fold(BigUint::ZERO, |acc, &item|{
        acc*BigUint::from(256 as u32)+item
    }); //collect the vector into a number

    let mut message_fe: [F;HASH_LEN_FE] = [F::from(0);HASH_LEN_FE];
    message_fe.iter_mut()
        .fold(msg_uint, |acc,  item|{  
        let tmp = acc.clone()% BigUint::from(FqConfig::MODULUS);
        *item = F::from(tmp.clone());
        (acc-tmp)/(BigUint::from(FqConfig::MODULUS)) 
    }); //interpreting the number base-p
    message_fe
}

/// Function to encode an epoch (= tweak in the message hash)
/// as a vector of field elements.
fn encode_epoch<const TWEAK_LEN_FE: usize>(epoch: u32) ->[F;TWEAK_LEN_FE] {
    let mut epoch_uint =  BigUint::from(epoch)*(256 as u32)+crate::TWEAK_SEPARATOR_FOR_MESSAGE_HASH;
     //collect the vector into a number

    let mut tweak_fe: [F;TWEAK_LEN_FE] = [F::from(0);TWEAK_LEN_FE];
    tweak_fe.iter_mut()
        .fold(epoch_uint, |acc,  item|{  
        let tmp = acc.clone()% BigUint::from(FqConfig::MODULUS);
        *item = F::from(tmp.clone());
        (acc-tmp)/(BigUint::from(FqConfig::MODULUS))
    }); //interpreting the number base-p
    tweak_fe
}

/// Function to decode a vector of field elements into
/// a vector of NUM_CHUNKS many chunks. One chunk is
/// between 0 and 2^CHUNK_SIZE - 1 (inclusive).
fn decode_to_chunks<const NUM_CHUNKS: usize, const CHUNK_SIZE: usize, const HASH_LEN_FE: usize>(
    field_elements: &[F],
) -> Vec<u8> {
    let mut hash_uint =  field_elements.iter()
        .fold(BigUint::ZERO, |acc, &item|{
        acc*BigUint::from(FqConfig::MODULUS)+BigUint::from(item.into_bigint())
    }); //collect the vector into a number

    let chunk_len =  (1<<CHUNK_SIZE) as u8; 

    let mut hash_chunked: [u8;NUM_CHUNKS] = [0 as u8;NUM_CHUNKS];
    hash_chunked.iter_mut()
        .fold(hash_uint, |acc,  item|{  
        let tmp = acc.clone()% chunk_len;
        *item = tmp.to_bytes_le()[0]%chunk_len;
        (acc-tmp)/ chunk_len
    }); //interpreting the number base-p
    Vec::from(hash_chunked)
}

/// A message hash implemented using Poseidon2
///
/// Note: PARAMETER_LEN, RAND_LEN, and HASH_LEN_FE
/// must be given in the unit "number of field elements".
///
/// HASH_LEN_FE specifies how many field elements the
/// hash output needs to be before it is decoded to chunks.
///
/// CHUNK_SIZE has to be 1,2,4, or 8.
pub struct PoseidonMessageHash<
    const PARAMETER_LEN: usize,
    const RAND_LEN: usize,
    const HASH_LEN_FE: usize,
    const NUM_CHUNKS: usize,
    const CHUNK_SIZE: usize,
    const TWEAK_LEN_FE: usize
>;

impl<
        const PARAMETER_LEN: usize,
        const RAND_LEN: usize,
        const HASH_LEN_FE: usize,
        const NUM_CHUNKS: usize,
        const CHUNK_SIZE: usize,
        const TWEAK_LEN_FE: usize
    > MessageHash
    for PoseidonMessageHash<PARAMETER_LEN, RAND_LEN, HASH_LEN_FE, NUM_CHUNKS, CHUNK_SIZE,TWEAK_LEN_FE>
{
    type Parameter = [F; PARAMETER_LEN];

    type Randomness = [F; RAND_LEN];

    const NUM_CHUNKS: usize = NUM_CHUNKS;

    const CHUNK_SIZE: usize = CHUNK_SIZE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        let mut rnd = [F::one(); RAND_LEN];
        for i in 0..RAND_LEN {
            rnd[i] = F::rand(rng);
        }
        rnd
    }

    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Vec<u8> {
        // TODO: we should assert that lengths small enough for Poseidon parameters

        // We need a Poseidon instance
        let instance = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);

        // first, encode the message and the epoch as field elements
        let message_fe = encode_message::<HASH_LEN_FE>(message);
        let epoch_fe = encode_epoch::<TWEAK_LEN_FE>(epoch);

        // now, we hash parameters, epoch, message, randomness using PoseidonCompress
        let combined_input: Vec<F> = parameter
            .iter()
            .chain(epoch_fe.iter())
            .chain(message_fe.iter())
            .chain(randomness.iter())
            .cloned()
            .collect();
        let hash_fe = poseidon_compress::<HASH_LEN_FE>(&instance, &combined_input);

        // decode field elements into chunks and return them
        decode_to_chunks::<NUM_CHUNKS, CHUNK_SIZE, HASH_LEN_FE>(&hash_fe)
    }
}

// Example instantiations
// TODO: check if this instantiation makes any sense
pub type PoseidonMessageHash445 = PoseidonMessageHash<4, 4, 5, 128, 2,2>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use zkhash::ark_ff::UniformRand;

    #[test]
    fn test_apply() {
        let mut rng = thread_rng();

        let mut parameter = [F::one(); 4];
        for i in 0..4 {
            parameter[i] = F::rand(&mut rng);
        }

        let mut message = [0u8; MESSAGE_LENGTH];
        rng.fill(&mut message);

        let epoch = 13;
        let randomness = PoseidonMessageHash445::rand(&mut rng);

        PoseidonMessageHash445::apply(&parameter, epoch, &randomness, &message);
    }
}
