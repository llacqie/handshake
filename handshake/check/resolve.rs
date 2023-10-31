use snow::{
	params::{CipherChoice, DHChoice, HashChoice},
	resolvers::CryptoResolver,
};

use super::{bad_rng::BadRng, blake2s::HashBLAKE2s, ciphers::CipherChaChaPoly, dh25519::Dh25519};

pub struct MyResolver;

impl CryptoResolver for MyResolver {
	fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
		Some(Box::new(BadRng(0)))
	}

	fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn snow::types::Dh>> {
		match *choice {
			DHChoice::Curve25519 => Some(Box::new(Dh25519::new())),
			_ => unreachable!(),
		}
	}

	fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn snow::types::Hash>> {
		match *choice {
			HashChoice::Blake2s => Some(Box::new(HashBLAKE2s::default())),
			_ => unreachable!(),
		}
	}

	fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn snow::types::Cipher>> {
		match *choice {
			CipherChoice::ChaChaPoly => Some(Box::new(CipherChaChaPoly::default())),
			_ => unreachable!(),
		}
	}
}
