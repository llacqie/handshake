use blake2::{
	digest::{generic_array::GenericArray, OutputSizeUser},
	Blake2s256, Digest,
};
use thiserror::Error;
use x25519_dalek::PublicKey;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
	#[error("")]
	ChaCha20Poly1305,
	#[error("")]
	Exhausted,
	#[error("")]
	BadLength,
	#[error("")]
	Input,
}

#[derive(Clone)]
pub struct Hash {
	pub data: GenericArray<u8, <Blake2s256 as OutputSizeUser>::OutputSize>,
}

impl Hash {
	pub fn new(data: impl AsRef<[u8]>) -> Self {
		let mut hash = Blake2s256::new();

		hash.update(data);

		Self {
			data: hash.finalize(),
		}
	}

	pub fn update(&mut self, data: impl AsRef<[u8]>) {
		let mut hash = Blake2s256::new();

		hash.update(self.data);
		hash.update(data);

		self.data = hash.finalize();
	}
}

pub struct RemoteKeys {
	pub re: PublicKey,
	pub rs: PublicKey,
}
