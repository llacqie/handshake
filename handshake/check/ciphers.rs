use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use snow::types::Cipher;

#[derive(Default)]
pub struct CipherChaChaPoly {
	key: chacha20poly1305::Key,
}

impl Cipher for CipherChaChaPoly {
	fn name(&self) -> &'static str {
		"ChaChaPoly"
	}

	fn set(&mut self, key: &[u8]) {
		self.key.copy_from_slice(key);
	}

	fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
		let mut nonce_bytes = [0u8; 12];
		nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());

		let (data, tag_data) = out.split_at_mut(plaintext.len());

		data.copy_from_slice(plaintext);

		let tag = ChaCha20Poly1305::new(&self.key.into())
			.encrypt_in_place_detached(&nonce_bytes.into(), authtext, data)
			.unwrap();

		tag_data[..tag.len()].copy_from_slice(tag.as_slice());

		plaintext.len() + tag.len()
	}

	fn decrypt(
		&self,
		nonce: u64,
		authtext: &[u8],
		ciphertext: &[u8],
		out: &mut [u8],
	) -> Result<usize, snow::Error> {
		let mut nonce_bytes = [0u8; 12];
		nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());

		let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);

		let data = &mut out[..ciphertext.len()];

		data.copy_from_slice(&ciphertext);

		ChaCha20Poly1305::new(&self.key.into())
			.decrypt_in_place_detached(&nonce_bytes.into(), authtext, data, tag.into())
			.map_err(|_| snow::Error::Decrypt)?;

		Ok(ciphertext.len())
	}
}
