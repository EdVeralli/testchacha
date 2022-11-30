use aead::{AeadInPlace, Key, NewAead, Nonce};
use xchacha8blake3siv::XChaCha8Blake3Siv;

fn main() {

    // texto para hacer el cifrado
    let key = Key::<XChaCha8Blake3Siv>::from_slice(b"an example very very secret key."); // 32-bytes
    // hace el cifrado usando el texto de arriba
    let cipher = XChaCha8Blake3Siv::new(key);
    // crea el nonce basado en un texto
    let nonce = Nonce::<XChaCha8Blake3Siv>::from_slice(b"extra long unique nonce!"); // 24-bytes; unique per message
    // texto util a cifrar
    let mut buffer = b"plaintext message".to_owned();

    //"associated data" lo usa para hacer distinto el largo del plain text.

    let tag = cipher.encrypt_in_place_detached(nonce, b"associated data", &mut buffer)
        .expect("encryption failure!");  // NOTE: handle this error to avoid panics!
        
    cipher.decrypt_in_place_detached(nonce, b"associated data", &mut buffer, &tag)
        .expect("decryption failure!");  // NOTE: handle this error to avoid panics!
    
    assert_eq!(&buffer, b"plaintext message");
}
