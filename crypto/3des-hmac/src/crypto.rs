use block_cipher_trait::BlockCipher;
use des::Des;
use generic_array::GenericArray;
use rand::rngs::OsRng;
use rand::Rng;

#[derive(Clone)]
pub struct TripleDES {
    keys: [[u8; 8]; 3],
}

#[derive(Clone)]
pub struct HMac {
    key: [u8; 16],
}

#[derive(Clone)]
pub struct AuthEnc {
    pub hmac: HMac,
    pub triple_des: TripleDES,
}

#[derive(Debug)]
pub enum CryptoError {
    BufferTooSmall,
    InvalidPadding,
    InvalidCiphertext,
    InvalidTag,
}

pub fn padding_length(message_len: usize, block_size: usize) -> usize {
    block_size - (message_len % block_size)
}

pub fn pad(message: &mut [u8], length: usize, block_size: usize) -> Result<&[u8], CryptoError> {
    let padding_length = padding_length(message[..length].len(), block_size);
    if message.len() < length + padding_length {
        Err(CryptoError::BufferTooSmall)
    } else {
        for b in &mut message[length..length + padding_length] {
            *b = padding_length as u8;
        }
        Ok(&message[..length + padding_length])
    }
}

pub fn unpad(padded_message: &[u8]) -> Result<&[u8], CryptoError> {
    let padded_length = padded_message.len();
    let padding_length = padded_message[padded_length - 1] as usize;
    if padding_length == 0 || padding_length > padded_length {
        return Err(CryptoError::InvalidPadding);
    }
    let message_length = padded_length - padding_length;
    let mut tmp = 0;
    for b in &padded_message[message_length..] {
        tmp |= b ^ padding_length as u8;
    }
    if tmp != 0 {
        return Err(CryptoError::InvalidPadding);
    }
    Ok(&padded_message[..padded_length - padding_length])
}

impl TripleDES {
    const BLOCK_SIZE: usize = 8;
    const IV_SIZE: usize = 3 * Self::BLOCK_SIZE;

    pub fn new() -> TripleDES {
        let mut rng = OsRng::new().unwrap();
        let mut keys = [[0u8; 8]; 3];
        for key in keys.iter_mut() {
            rng.fill(key);
        }
        TripleDES { keys }
    }

    #[allow(dead_code)]
    pub fn ciphertext_size(message: &[u8]) -> usize {
        Self::IV_SIZE + message.len() + padding_length(message.len(), Self::BLOCK_SIZE)
    }

    fn xor(xs: &mut [u8], ys: &[u8]) {
        for (x, y) in xs.iter_mut().zip(ys) {
            *x ^= y;
        }
    }

    fn encrypt_cbc(des: Des, buffer: &mut [u8]) {
        assert_eq!(buffer.len() % Self::BLOCK_SIZE, 0);
        let num_blocks = buffer.len() / Self::BLOCK_SIZE;
        let mut buffer = buffer;
        for _ in 1..num_blocks {
            let (previous_block, right) = buffer.split_at_mut(Self::BLOCK_SIZE);
            Self::xor(&mut right[..Self::BLOCK_SIZE], previous_block);
            des.encrypt_block(&mut GenericArray::from_mut_slice(
                &mut right[..Self::BLOCK_SIZE],
            ));
            buffer = right;
        }
    }

    fn decrypt_cbc(des: Des, buffer: &mut [u8]) {
        assert_eq!(buffer.len() % Self::BLOCK_SIZE, 0);
        let num_blocks = buffer.len() / Self::BLOCK_SIZE;
        let mut buffer = buffer;
        for block in (1..num_blocks).rev() {
            let (left, mut current_block) = buffer.split_at_mut(block * Self::BLOCK_SIZE);
            des.decrypt_block(&mut GenericArray::from_mut_slice(&mut current_block));
            let previous_block = &left[(block - 1) * Self::BLOCK_SIZE..block * Self::BLOCK_SIZE];
            Self::xor(&mut current_block, previous_block);
            buffer = left;
        }
    }

    // Assume padded message to encrypt starts at offset IV_SIZE
    pub fn encrypt_inplace<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        if buffer.len() < Self::IV_SIZE || buffer.len() % Self::BLOCK_SIZE != 0 {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut rng = OsRng::new().unwrap();
        rng.fill(&mut buffer[..Self::IV_SIZE]);
        for i in 0..3 {
            let des = Des::new(GenericArray::from_slice(&self.keys[i]));
            Self::encrypt_cbc(des, &mut buffer[(2 - i) * Self::BLOCK_SIZE..]);
        }
        Ok(buffer)
    }

    #[allow(dead_code)]
    pub fn encrypt<'a>(
        &self,
        message: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        let ciphertext_length =
            Self::IV_SIZE + message.len() + padding_length(message.len(), Self::BLOCK_SIZE);
        if ciphertext.len() < ciphertext_length {
            return Err(CryptoError::BufferTooSmall);
        }
        let ciphertext = &mut ciphertext[..ciphertext_length];

        ciphertext[Self::IV_SIZE..Self::IV_SIZE + message.len()].copy_from_slice(message);
        pad(
            &mut ciphertext[Self::IV_SIZE..],
            message.len(),
            Self::BLOCK_SIZE,
        )?;

        self.encrypt_inplace(ciphertext)
    }

    pub fn decrypt<'a>(&self, ciphertext: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        if ciphertext.len() % Self::BLOCK_SIZE != 0 || ciphertext.len() < Self::IV_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }
        for i in 0..3 {
            let des = Des::new(GenericArray::from_slice(&self.keys[2 - i]));
            Self::decrypt_cbc(des, &mut ciphertext[i * Self::BLOCK_SIZE..]);
        }
        let decrypted_message = unpad(&ciphertext[Self::IV_SIZE..]).unwrap();
        Ok(decrypted_message)
    }
}

impl HMac {
    pub const TAG_SIZE: usize = 16;

    pub fn new() -> HMac {
        let mut rng = OsRng::new().unwrap();
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        HMac { key }
    }

    pub fn mac<'a>(&self, data: &[u8], tag: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        if tag.len() < Self::TAG_SIZE {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut md5_ctx = md5::Context::new();
        md5_ctx.consume(self.key);
        md5_ctx.consume(data);
        &tag[..16].copy_from_slice(&md5_ctx.compute().0); //.compute();
        Ok(&tag[..16])
    }

    pub fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        let mut md5_ctx = md5::Context::new();
        md5_ctx.consume(self.key);
        md5_ctx.consume(data);
        let cmp_tag = md5_ctx.compute();
        tag.len() == Self::TAG_SIZE && tag == &cmp_tag.0
    }
}

impl AuthEnc {
    pub fn new() -> AuthEnc {
        AuthEnc {
            hmac: HMac::new(),
            triple_des: TripleDES::new(),
        }
    }

    pub fn ciphertext_size(message: &[u8]) -> usize {
        let padded_msg_length = message.len() + HMac::TAG_SIZE;
        TripleDES::IV_SIZE
            + padded_msg_length
            + padding_length(padded_msg_length, TripleDES::BLOCK_SIZE)
    }

    pub fn auth_encrypt<'a>(
        &self,
        message: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        let tagged_msg_length = message.len() + HMac::TAG_SIZE;
        let ciphertext_length = TripleDES::IV_SIZE
            + tagged_msg_length
            + padding_length(tagged_msg_length, TripleDES::BLOCK_SIZE);
        if ciphertext.len() < ciphertext_length {
            return Err(CryptoError::BufferTooSmall);
        }
        // let mut ciphertext = &mut ciphertext[..ciphertext_length];

        ciphertext[TripleDES::IV_SIZE + HMac::TAG_SIZE
            ..TripleDES::IV_SIZE + HMac::TAG_SIZE + message.len()]
            .copy_from_slice(message);
        {
            let (tag, msg) = ciphertext.split_at_mut(TripleDES::IV_SIZE + HMac::TAG_SIZE);
            let mut tag = &mut tag[TripleDES::IV_SIZE..];
            self.hmac.mac(&msg[..message.len()], &mut tag)?;
        }
        pad(
            &mut ciphertext[TripleDES::IV_SIZE..],
            tagged_msg_length,
            TripleDES::BLOCK_SIZE,
        )?;
        self.triple_des
            .encrypt_inplace(&mut ciphertext[..ciphertext_length])
    }

    pub fn auth_decrypt<'a>(&self, ciphertext: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        if ciphertext.len() < TripleDES::IV_SIZE || ciphertext.len() % TripleDES::BLOCK_SIZE != 0 {
            return Err(CryptoError::InvalidCiphertext);
        }
        let plaintext = self.triple_des.decrypt(ciphertext)?;
        if plaintext.len() < HMac::TAG_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }
        if !self
            .hmac
            .verify(&plaintext[HMac::TAG_SIZE..], &plaintext[..HMac::TAG_SIZE])
        {
            return Err(CryptoError::InvalidTag);
        }
        Ok(&plaintext[HMac::TAG_SIZE..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_length() {
        let bs = 8;
        assert_eq!(padding_length(0, bs), 8);
        assert_eq!(padding_length(1, bs), 7);
        assert_eq!(padding_length(2, bs), 6);
        assert_eq!(padding_length(3, bs), 5);
        assert_eq!(padding_length(4, bs), 4);
        assert_eq!(padding_length(5, bs), 3);
        assert_eq!(padding_length(6, bs), 2);
        assert_eq!(padding_length(7, bs), 1);
        assert_eq!(padding_length(8, bs), 8);
    }

    #[test]
    fn test_padding() {
        let block_size = 8;
        let data = b"Lorem ipsum dolor sit";
        for i in 0..9 {
            let mut buffer = vec![0; i + padding_length(i, block_size)];
            buffer[..i].copy_from_slice(&data[..i]);
            let padded_message = pad(&mut buffer, i, block_size).unwrap();
            let unpadded_message = unpad(padded_message).unwrap();
            assert_eq!(&data[..i], unpadded_message);
        }
    }

    #[test]
    fn test_tripledes_correctness() {
        let tdes = TripleDES::new();
        let data = b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua.";
        let mut ct = vec![0; TripleDES::ciphertext_size(data)];
        let _ = tdes.encrypt(data, &mut ct).unwrap();
        let pt = tdes.decrypt(&mut ct).unwrap();
        assert_eq!(pt, &data[..]);
    }

    #[test]
    fn test_hmac_correctness() {
        let hmac = HMac::new();
        let data = b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua.";
        let mut tag = [0; HMac::TAG_SIZE];
        let _ = hmac.mac(data, &mut tag);
        assert!(hmac.verify(data, &tag))
    }

    #[test]
    fn test_authenc_correctness() {
        let authenc = AuthEnc::new();
        let data = b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua.";
        let mut ct = vec![0; AuthEnc::ciphertext_size(data)];
        let _ = authenc.auth_encrypt(data, &mut ct).unwrap();
        let pt = authenc.auth_decrypt(&mut ct).unwrap();
        assert_eq!(pt, &data[..]);
    }
}
