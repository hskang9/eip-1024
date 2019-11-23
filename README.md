# EIP-1024 ![Crates.io](https://img.shields.io/crates/d/EIP-1024.svg) [![Released API docs](https://docs.rs/EIP-1024/badge.svg)](https://docs.rs/EIP-1024)

## Example

```rust
use eip_1024::{get_encryption};

fn main() {
	let bob_sk = "mJxmrVq8pfeR80HMZBTkjV+RiND1lqPqLuCdDUiduis=";
    let bob_sk_slice: [u8; 32] = crate::to_byte32(bob_sk.as_bytes());
    let alice_sk = "Rz2i6pXUKcpWt6/b+mYtPPH+PiwhyLswOjcP8ZM0dyI=";
    let alice_sk_slice: [u8; 32] = crate::to_byte32(alice_sk.as_bytes());
    let alice = nacl_mini::crypto_box::gen_keypair_from_secret(&bob_sk_slice);
    let bob = nacl_mini::crypto_box::gen_keypair_from_secret(&alice_sk_slice);
    // Alice requests Bob's public encryption key so bob sends his encryption public key
    let bob_encrypt_keypair = crate::get_encryption_keypair(*bob.secret());

    // Alice generates a random ephemeralKeyPair 
    let alice_ephemeral_keypair = nacl_mini::crypto_box::gen_keypair_from_secret(alice.secret());

        
    // Encrypt data first
    let encrypted_data = crate::encrypt(b"Hello world", None, **bob_encrypt_keypair.public(), *alice_ephemeral_keypair.secret()).unwrap();
        

    // Bob generates his encryptionPrivateKey
    let bob_encrypt_secret = bob_encrypt_keypair.secret(); 


    // Bob passes his encryptionPrivateKey
    // along with the encrypted blob 
    // to nacl.box.open(ciphertext, nonce, ephemPublicKey, myEncryptionPrivatekey)
    let decrypted = crate::decrypt(encrypted_data, *bob_encrypt_secret).unwrap();
    
    // Decrypted message
    println!("{:?}", decrypted);
	assert_eq!(
		decrypted,
		"Hello world"
	);
}

```

## License

This crate is distributed under the terms of GNU GENERAL PUBLIC LICENSE version 3.0.

See [LICENSE](../../LICENSE) for details.
