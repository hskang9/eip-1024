extern crate nacl_mini;
#[macro_use]
extern crate arrayref;
extern crate hex;
use std::str;
use nacl_mini::{KeyPair,Public, Secret, Error};
use nacl_mini::traits::FromUnsafeSlice;
/// Returns user's public Encryption key derived from private Ethereum key
/// receiver<&str> private key for the receiver of the message
/// sender &str public key for the sender
/// 
/// returns
pub fn getEncryptionPublicKey(receiver: &str) -> [u8; 32] {
    let secret: [u8; 32] = to_array(receiver.as_bytes());
    let keypair = nacl_mini::crypto_box::gen_keypair_from_secret(&secret);
    return **keypair.public();
}

pub fn to_array(keystring: &[u8]) -> [u8; 32] {
    array_ref!(keystring, 0, 32).clone()
}


pub fn encrypt(message: &str, nonce: Option<[u8; 24]>, pk: &str) {
    let sk = nacl_mini::crypto_box::gen_keypair();
    let msg_bytes = message.as_bytes();
    let nonce = match nonce {
        Some(n) => n,
        None => nacl_mini::gen_nonce()
    };
    let pk_byte32 = to_array(&hex::decode(pk).unwrap());
    let key = Public::from_unsafe_slice(&pk_byte32).unwrap();
    let result = nacl_mini::crypto_box::seal(msg_bytes, &nonce, &key, sk.secret()).unwrap();
    let result_hex = hex::encode(&result);

    println!("result: {}", result_hex);
}


pub fn decrypt(message: &str, nonce: Option<[u8; 24]>, pk: [u8; 32]) {
    
}



#[cfg(test)]
mod tests {

    #[test]
    fn getEncryptionPublicKey_works() {
        let a = crate::getEncryptionPublicKey("mJxmrVq8pfeR80HMZBTkjV+RiND1lqPqLuCdDUiduis=");
    }

    #[test]
    fn encrypt_works() {
        let key = [38, 44, 89, 166, 187, 131, 181, 138, 129, 32, 145, 27, 246, 237, 72, 99, 21, 112, 137, 252, 75, 240, 178, 148, 169, 82, 6, 217, 49, 70, 173, 20];
        let key_encode = hex::encode(key);
        println!("{:?}", key_encode.clone());
        let ok = crate::encrypt("Hello world!", None, "262c59a6bb83b58a8120911bf6ed4863157089fc4bf0b294a95206d93146ad14");
    }

    fn decrypt_works() {

    }
}
