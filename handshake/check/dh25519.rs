use x25519_dalek::{PublicKey, StaticSecret};

pub struct Dh25519 {
	privkey: [u8; 32],
	pubkey: PublicKey,
}

impl Dh25519 {
	pub fn new() -> Self {
		Self {
			privkey: [0u8; 32],
			pubkey: PublicKey::from([0; 32]),
		}
	}
}

impl snow::types::Dh for Dh25519 {
	fn name(&self) -> &'static str {
		"25519"
	}

	fn pub_len(&self) -> usize {
		32
	}

	fn priv_len(&self) -> usize {
		32
	}

	fn set(&mut self, privkey: &[u8]) {
		self.privkey = crate::array_from_slice(privkey);

		self.pubkey = PublicKey::from(&StaticSecret::from(self.privkey));
	}

	fn generate(&mut self, rng: &mut dyn snow::types::Random) {
		rng.fill_bytes(&mut self.privkey);

		self.pubkey = PublicKey::from(&StaticSecret::from(self.privkey));
	}

	fn pubkey(&self) -> &[u8] {
		self.pubkey.as_bytes()
	}

	fn privkey(&self) -> &[u8] {
		&self.privkey
	}

	fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
		let privkey = StaticSecret::from(self.privkey);

		let their_public = PublicKey::from(crate::array_from_slice(pubkey));

		let shared = privkey.diffie_hellman(&their_public);

		out[..32].copy_from_slice(shared.as_bytes());

		Ok(())
	}
}
