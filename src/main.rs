use aead::{AeadInPlace, Key, NewAead, Nonce};
use std::ops::Deref;
use xchacha8blake3siv::XChaCha8Blake3Siv;

fn main() {
    let mut buffer = b"plaintext message".to_owned();

    let _tag_01 = encrypt(
        b"an example very very secret key.",
        b"extra long unique nonce!",
        b"asoc data",
        &mut buffer,
    );
}

fn encrypt(
    text_key: &[u8; 32],
    text_nonce: &[u8; 24],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> Vec<u8> {
    // texto para hacer el cifrado
    let key = Key::<XChaCha8Blake3Siv>::from_slice(text_key); // 32-bytes
                                                              // hace el cifrado usando el texto de arriba
    let cipher = XChaCha8Blake3Siv::new(key);
    // crea el nonce basado en un texto
    let nonce = Nonce::<XChaCha8Blake3Siv>::from_slice(text_nonce); // 24-bytes; unique per message
                                                                    // texto util a cifrar
                                                                    //"associated data" lo usa para hacer distinto el largo del plain text.
    let tag = cipher
        .encrypt_in_place_detached(nonce, associated_data, buffer)
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    Vec::<u8>::from(tag.deref())
}

/*
fn decrypt(
    text_key: &[u8; 32],
    text_nonce: &[u8; 24],
    associated_data: &[u8],
) -> Vec<u8> {

    cipher
        .decrypt_in_place_detached(nonce, associated_data, &mut buffer, &tag)
        .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

    assert_eq!(&buffer, b"plaintext message");

}
*/
