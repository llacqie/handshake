use chacha20poly1305::aead::rand_core::Error;

#[derive(Clone)]
pub struct BadRng(pub u8);

impl rand_core::RngCore for BadRng {
	fn next_u32(&mut self) -> u32 {
		self.0 = self.0.checked_add(1).unwrap();

		self.0 as u32
	}

	fn next_u64(&mut self) -> u64 {
		self.next_u32() as u64
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		for b in dest {
			self.0 = self.0.checked_add(1).unwrap();

			*b = self.0;
		}
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
		self.fill_bytes(dest);

		Ok(())
	}
}

impl chacha20poly1305::aead::rand_core::RngCore for BadRng {
	fn next_u32(&mut self) -> u32 {
		self.0 = self.0.checked_add(1).unwrap();

		self.0 as u32
	}

	fn next_u64(&mut self) -> u64 {
		self.next_u32() as u64
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		for b in dest {
			self.0 = self.0.checked_add(1).unwrap();

			*b = self.0;
		}
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
		self.fill_bytes(dest);

		Ok(())
	}
}

impl rand_core::CryptoRng for BadRng {}

impl chacha20poly1305::aead::rand_core::CryptoRng for BadRng {}

impl snow::types::Random for BadRng {}

unsafe impl Send for BadRng {}

unsafe impl Sync for BadRng {}
