use blake2::Digest;

#[derive(Default)]
pub struct HashBLAKE2s {
	hasher: blake2::Blake2s256,
}

impl snow::types::Hash for HashBLAKE2s {
	fn name(&self) -> &'static str {
		"BLAKE2s"
	}

	fn block_len(&self) -> usize {
		64
	}

	fn hash_len(&self) -> usize {
		32
	}

	fn reset(&mut self) {
		self.hasher = blake2::Blake2s::default();
	}

	fn input(&mut self, data: &[u8]) {
		self.hasher.update(data);
	}

	fn result(&mut self, out: &mut [u8]) {
		let hash = self.hasher.finalize_reset();

		out[..32].copy_from_slice(hash.as_slice());
	}
}
