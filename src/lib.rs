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
pub fn getEncryptionPublicKey(receiver: &str) -> String {
    let secret: [u8; 32] = to_array(receiver.as_bytes());
    let keypair = nacl_mini::crypto_box::gen_keypair_from_secret(&secret);
    return hex::encode(**keypair.public());
}

pub fn to_array(keystring: &[u8]) -> [u8; 32] {
    array_ref!(keystring, 0, 32).clone()
}


pub fn encrypt(message: &str, nonce: Option<[u8; 24]>, send_pk: &str, recv_sk: &str) -> String {
    let msg_bytes = message.as_bytes();
    let nonce = match nonce {
        Some(n) => n,
        None => {
            let nonce = nacl_mini::gen_nonce();
            println!("Generated nonce: {}", hex::encode(nonce));
            nonce
        }
    };
    let sk_bytes32 = to_array(&hex::decode(recv_sk).unwrap());
    let recv_sk = KeyPair::<Secret, Public>::from_secret_slice(&sk_bytes32).unwrap();
    let pk_byte32 = to_array(&hex::decode(send_pk).unwrap());
    let send_pk = Public::from_unsafe_slice(&pk_byte32).unwrap();
    let result = nacl_mini::crypto_box::seal(msg_bytes, &nonce, &send_pk, recv_sk.secret()).unwrap();
    let result_hex = hex::encode(&result);

    println!("result: {}", result_hex);
    return result_hex
}


pub fn decrypt(cipher: &str, nonce: Option<[u8; 24]>, send_pk: &str, recv_sk: &str) {
    let cipher_bytes = hex::decode(cipher).unwrap();
    let nonce = match nonce {
        Some(n) => n,
        None => {
            nacl_mini::gen_nonce()
        }
    };
    let sk_bytes32 = to_array(&hex::decode(recv_sk).unwrap());
    let recv_sk = KeyPair::<Secret, Public>::from_secret_slice(&sk_bytes32).unwrap();
    let pk_byte32 = to_array(&hex::decode(send_pk).unwrap());
    let send_pk = Public::from_unsafe_slice(&pk_byte32).unwrap();
    println!("cipher_bytes: {:?}\n nonce: {:?}\n key: {:?}\n sk: {:?}\n", cipher_bytes, nonce, send_pk, recv_sk.secret() );
    let result = nacl_mini::crypto_box::open(&cipher_bytes, &nonce, &send_pk, &recv_sk.secret()).unwrap();
    println!("Result: {}", str::from_utf8(&result).unwrap());
}

pub fn gen_keypair() -> KeyPair<Secret, Public> {
    
    KeyPair::<Secret, Public>::generate_keypair().unwrap()
    
}



#[cfg(test)]
mod tests {
    extern crate nacl_mini;
    extern crate hex;
    use std::str;
    use nacl_mini::*;
    use nacl_mini::crypto_box::*; 

    #[test]
    fn getEncryptionPublicKey_works() {
        let public = crate::getEncryptionPublicKey("mJxmrVq8pfeR80HMZBTkjV+RiND1lqPqLuCdDUiduis=");
        println!("Generated public: {}", public);
    }

    #[test]
    fn encrypt_works() {
        let pk_slice = [38, 44, 89, 166, 187, 131, 181, 138, 129, 32, 145, 27, 246, 237, 72, 99, 21, 112, 137, 252, 75, 240, 178, 148, 169, 82, 6, 217, 49, 70, 173, 20];
        let sk_slice = [70, 124, 179, 196, 90, 64, 193, 211, 66, 6, 232, 30, 144, 217, 38, 111, 0, 195, 118, 42, 201, 156, 193, 129, 118, 165, 67, 180, 227, 40, 180, 69];

        let pk_encode = hex::encode(pk_slice);
        let sk = KeyPair::<Secret, Public>::from_secret_slice(&sk_slice).unwrap();
        let sk_encode = hex::encode(sk.secret());
        let nonce_decode = hex::decode("3135373434363836303800a79573fc6f2003d86b2c067ed2").unwrap();
        let nonce = array_ref!(nonce_decode, 0, 24).clone();
        println!("Public: {:?}", pk_encode.clone());
        let encrypted = crate::encrypt("Hello world", Some(nonce), &pk_encode, &sk_encode);
        println!("Encrypted: {}", encrypted);
    }

    #[test]
    fn decrypt_works() {
        let pk_slice = [38, 44, 89, 166, 187, 131, 181, 138, 129, 32, 145, 27, 246, 237, 72, 99, 21, 112, 137, 252, 75, 240, 178, 148, 169, 82, 6, 217, 49, 70, 173, 20];
        let sk_slice = [70, 124, 179, 196, 90, 64, 193, 211, 66, 6, 232, 30, 144, 217, 38, 111, 0, 195, 118, 42, 201, 156, 193, 129, 118, 165, 67, 180, 227, 40, 180, 69];

        let pk_encode = hex::encode(pk_slice);
        let sk = KeyPair::<Secret, Public>::from_secret_slice(&sk_slice).unwrap();
        let sk_encode = hex::encode(sk.secret());
        let nonce_decode = hex::decode("3135373434363836303800a79573fc6f2003d86b2c067ed2").unwrap();
        let nonce = array_ref!(nonce_decode, 0, 24).clone();
        
        let decrypted = crate::decrypt("6df824f6843d1f9f81731a2955da69acb4f9903c7804f0014afb35", Some(nonce), &pk_encode, &sk_encode);
    }
}
