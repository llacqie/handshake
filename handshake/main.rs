use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

mod models;
pub use models::{Error, RemoteKeys, Result};

mod transport;
pub use transport::Transport;

pub const NOISE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

pub const MESSAGE_A_LEN: usize = 32 + 32 + 16 + 16;
pub const MESSAGE_B_LEN: usize = 32 + 16;

pub struct Handshake<T>
where
	T: RngCore + CryptoRng + Clone,
{
	ns: StaticSecret,

	hash: models::Hash,
	ck: models::Hash,

	k: chacha20poly1305::Key,
	n: u64,

	random: T,
}

fn array_from_slice(slice: &[u8]) -> [u8; 32] {
	let mut array = [0; 32];

	array.copy_from_slice(&slice[..32]);

	array
}

impl<T> Handshake<T>
where
	T: RngCore + CryptoRng + Clone,
{
	pub fn new(ns: StaticSecret, random: T) -> Self {
		let mut hash = models::Hash::new(NOISE);

		let ck = hash.clone();

		hash.update([]);

		Self {
			ns,

			hash,
			ck,

			k: chacha20poly1305::Key::default(),
			n: 0,

			random,
		}
	}

	fn mix_key(&mut self, data: &[u8]) -> Result<()> {
		let ck = self.ck.data.as_slice();

		// With the chaining_key as HKDF salt.
		let hkdf = hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(ck), data);

		let mut data = [0u8; 64];

		// And zero-length HKDF info.
		hkdf.expand(&[], data.as_mut_slice())
			.map_err(|_| Error::BadLength)?;

		self.ck.data.as_mut_slice().copy_from_slice(&data[..32]);
		self.k.as_mut_slice().copy_from_slice(&data[32..]);

		self.n = 0;

		Ok(())
	}

	fn nonce(&self) -> Nonce {
		let mut nonce = [0u8; 12];

		nonce[4..].copy_from_slice(&self.n.to_le_bytes());

		Nonce::from(nonce)
	}

	pub fn decrypt(&mut self, m: &mut [u8]) -> Result<()> {
		// We need to hash ciphertext, but we also need previous hash.
		let previous_hash = self.hash.clone();

		self.hash.update(&m);

		// Buffer with ciphertext for plaintext.
		let (data, tag_data) = m.split_at_mut(m.len() - 16);

		let tag = chacha20poly1305::Tag::from_slice(tag_data);

		ChaCha20Poly1305::new(&self.k)
			.decrypt_in_place_detached(&self.nonce(), previous_hash.data.as_slice(), data, tag)
			.map_err(|_| Error::ChaCha20Poly1305)?;

		self.n = self.n.checked_add(1).ok_or(Error::Exhausted)?;

		Ok(())
	}

	pub fn encrypt(&mut self, m: &mut [u8]) -> Result<()> {
		// Buffer with plaintext for ciphertext.
		let (data, tag_data) = m.split_at_mut(m.len() - 16);

		let tag = ChaCha20Poly1305::new(&self.k)
			.encrypt_in_place_detached(&self.nonce(), self.hash.data.as_slice(), data)
			.map_err(|_| Error::ChaCha20Poly1305)?;

		tag_data.copy_from_slice(tag.as_slice());

		// We need to hash ciphertext.
		self.hash.update(m);

		self.n = self.n.checked_add(1).ok_or(Error::Exhausted)?;

		Ok(())
	}

	pub fn transport(self) -> Result<(chacha20poly1305::Key, chacha20poly1305::Key)> {
		let ck = self.ck.data.as_slice();

		// With the chaining_key as HKDF salt.
		let hkdf = hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(ck), &[]);

		let mut data = [0u8; 64];

		// And zero-length HKDF info.
		hkdf.expand(&[], data.as_mut_slice())
			.map_err(|_| Error::BadLength)?;

		Ok((
			Key::clone_from_slice(&data[..32]),
			Key::clone_from_slice(&data[32..]),
		))
	}

	pub fn make_message_aa(&mut self, m: &mut [u8], rs: PublicKey) -> Result<StaticSecret> {
		if m.len() < 32 {
			return Err(Error::Input);
		}

		// prepare state
		let ephemeral = StaticSecret::new(self.random.clone());

		self.hash.update(rs.as_bytes());

		// -> e
		let ne = m.split_at_mut(32).0;

		ne.copy_from_slice(PublicKey::from(&ephemeral).as_bytes());

		self.hash.update(ne);

		// -> e, es
		let shared = ephemeral.diffie_hellman(&rs);

		self.mix_key(shared.as_bytes())?;

		//
		Ok(ephemeral)
	}

	pub fn make_message_ab(&mut self, m: &mut [u8], rs: PublicKey) -> Result<()> {
		if m.len() < 48 {
			return Err(Error::Input);
		}

		// -> e, es, s
		let ns = m.split_at_mut(48).0;

		ns[..32].copy_from_slice(PublicKey::from(&self.ns).as_bytes());

		self.encrypt(ns)?;

		// -> e, es, s, ss
		let shared = self.ns.diffie_hellman(&rs);

		self.mix_key(shared.as_bytes())?;

		Ok(())
	}

	pub fn make_message_a(&mut self, m: &mut [u8], rs: PublicKey) -> Result<StaticSecret> {
		if m.len() < MESSAGE_A_LEN {
			return Err(Error::Input);
		}

		// -> e, es
		let (aa, m) = m.split_at_mut(32);

		let ephemeral = self.make_message_aa(aa, rs)?;

		// -> e, es, s, ss
		let (ab, m) = m.split_at_mut(48);

		self.make_message_ab(ab, rs)?;

		// payload
		self.encrypt(m)?;

		Ok(ephemeral)
	}

	pub fn read_message_aa(&mut self, m: &mut [u8]) -> Result<PublicKey> {
		if m.len() < 32 {
			return Err(Error::Input);
		}

		// prepare state
		self.hash.update(PublicKey::from(&self.ns).as_bytes());

		// <- e
		let re = m.split_at_mut(32).0;

		let remote_ephemeral = PublicKey::from(array_from_slice(re));

		self.hash.update(remote_ephemeral.as_bytes());

		// <- e, se
		let shared = self.ns.diffie_hellman(&remote_ephemeral);

		self.mix_key(shared.as_bytes())?;

		Ok(remote_ephemeral)
	}

	pub fn read_message_ab(&mut self, m: &mut [u8]) -> Result<PublicKey> {
		if m.len() < 48 {
			return Err(Error::Input);
		}
		// <- e, se, s
		let rs = m.split_at_mut(48).0;

		self.decrypt(rs)?;

		let remote_static = PublicKey::from(array_from_slice(rs));

		// <- e, se, s, ss
		let shared = self.ns.diffie_hellman(&remote_static);

		self.mix_key(shared.as_bytes())?;

		Ok(remote_static)
	}

	pub fn read_message_a(&mut self, m: &mut [u8]) -> Result<RemoteKeys> {
		if m.len() < MESSAGE_A_LEN {
			return Err(Error::Input);
		}

		// <- e, se
		let (aa, m) = m.split_at_mut(32);

		let remote_ephemeral = self.read_message_aa(aa)?;

		// <- e, se, s, ss
		let (ab, m) = m.split_at_mut(48);

		let remote_static = self.read_message_ab(ab)?;

		// payload
		self.decrypt(m)?;

		Ok(RemoteKeys {
			re: remote_ephemeral,
			rs: remote_static,
		})
	}

	pub fn make_message_ba(&mut self, m: &mut [u8], re: PublicKey, rs: PublicKey) -> Result<()> {
		if m.len() < 32 {
			return Err(Error::Input);
		}

		// prepare state
		let ephemeral = StaticSecret::new(self.random.clone());

		// -> e
		let ne = m.split_at_mut(32).0;

		ne.copy_from_slice(PublicKey::from(&ephemeral).as_bytes());

		self.hash.update(ne);

		// -> e, ee
		let shared = ephemeral.diffie_hellman(&re);

		self.mix_key(shared.as_bytes())?;

		// -> e, ee, es
		let shared = ephemeral.diffie_hellman(&rs);

		self.mix_key(shared.as_bytes())?;

		Ok(())
	}

	pub fn make_message_b(mut self, m: &mut [u8], rk: RemoteKeys) -> Result<Transport> {
		if m.len() < MESSAGE_B_LEN {
			return Err(Error::Input);
		}

		// -> e, ee, es
		let (ba, m) = m.split_at_mut(32);

		self.make_message_ba(ba, rk.re, rk.rs)?;

		// payload
		self.encrypt(m)?;

		// We responder
		let (decrypt, encrypt) = self.transport()?;

		Ok(Transport::new(encrypt, decrypt))
	}

	pub fn read_message_ba(&mut self, m: &mut [u8], ne: StaticSecret) -> Result<()> {
		if m.len() < 32 {
			return Err(Error::Input);
		}

		// <- e
		let re = m.split_at_mut(32).0;

		let remote_ephemeral = PublicKey::from(array_from_slice(re));

		self.hash.update(re);

		// <- e, ee
		let shared = ne.diffie_hellman(&remote_ephemeral);

		self.mix_key(shared.as_bytes())?;

		// <- e, ee, se
		let shared = self.ns.diffie_hellman(&remote_ephemeral);

		self.mix_key(shared.as_bytes())?;

		Ok(())
	}

	pub fn read_message_b(mut self, m: &mut [u8], ne: StaticSecret) -> Result<Transport> {
		if m.len() < MESSAGE_B_LEN {
			return Err(Error::Input);
		}

		// <- e, ee, se
		let (ba, m) = m.split_at_mut(32);

		self.read_message_ba(ba, ne)?;

		// payload
		self.decrypt(m)?;

		// We requester
		let (encrypt, decrypt) = self.transport()?;

		Ok(Transport::new(encrypt, decrypt))
	}
}

#[cfg(test)]
mod check {
	use x25519_dalek::{PublicKey, StaticSecret};

	use crate::{
		check::{bad_rng::BadRng, resolve::MyResolver},
		MESSAGE_A_LEN, MESSAGE_B_LEN,
	};

	use super::Handshake;

	mod bad_rng;
	mod blake2s;
	mod ciphers;
	mod dh25519;
	mod resolve;

	#[test]
	fn handshake() {
		// Fake RNG
		let random = BadRng(0);

		// Generate keys
		let server_ns = StaticSecret::new(random.clone());
		let client_ns = StaticSecret::new(random.clone());

		// Let client know server's static pkey
		let client_rs = PublicKey::from(&server_ns);

		// Initialize handshake states
		let mut server = Handshake::new(server_ns.clone(), random.clone());
		let mut client = Handshake::new(client_ns.clone(), random);

		// Initialize snow's ones for state comparison
		let mut server_snow =
			snow::Builder::with_resolver(super::NOISE.parse().unwrap(), Box::new(MyResolver))
				.local_private_key(&server_ns.to_bytes())
				.build_responder()
				.unwrap();
		let mut client_snow =
			snow::Builder::with_resolver(super::NOISE.parse().unwrap(), Box::new(MyResolver))
				.local_private_key(&client_ns.to_bytes())
				.remote_public_key(client_rs.as_bytes())
				.build_initiator()
				.unwrap();

		// Allocate buffers
		let mut message_a_snow = [0u8; MESSAGE_A_LEN];
		let mut message_a = message_a_snow.clone();

		let mut message_b_snow = [0u8; MESSAGE_B_LEN];
		let mut message_b = message_b_snow.clone();

		// Make 1st messages
		client_snow.write_message(&[], &mut message_a_snow).unwrap();

		let client_ne = client.make_message_a(&mut message_a, client_rs).unwrap();

		// Check that states were the same
		assert_eq!(message_a_snow, message_a);

		// Consume 1st messages
		server_snow.read_message(&message_a_snow, &mut []).unwrap();

		let rk = server.read_message_a(&mut message_a).unwrap();

		// Make 2nd messages
		server_snow.write_message(&[], &mut message_b_snow).unwrap();

		let mut server_ts = server.make_message_b(&mut message_b, rk).unwrap();

		// Check that states were the same
		assert_eq!(message_b_snow, message_b);

		// Consume 2nd messages
		client_snow.read_message(&message_b_snow, &mut []).unwrap();

		let mut client_ts = client.read_message_b(&mut message_b, client_ne).unwrap();

		// Convert snow's handshake into transport state
		let mut server_ts_snow = server_snow.into_transport_mode().unwrap();
		let mut client_ts_snow = client_snow.into_transport_mode().unwrap();

		// Allocate buffers
		let mut message = [0; 32];
		let mut message_snow = [0; 32];

		for _ in 0..6 {
			// Make messages
			client_ts_snow
				.write_message(&message[..16], &mut message_snow)
				.unwrap();

			let length = message.len();

			let (data, tag_data) = message.split_at_mut(length - 16);

			client_ts.encrypt(data, tag_data).unwrap();

			// Check that states were the same
			assert_eq!(message, message_snow);

			// Consume messages
			server_ts_snow
				.read_message(&message, &mut message_snow)
				.unwrap();

			let length = message.len();

			let (data, tag_data) = message.split_at_mut(length - 16);

			server_ts.decrypt(data, tag_data).unwrap();

			// Check that states were the same
			assert_eq!(message, message_snow);
		}
	}
}
