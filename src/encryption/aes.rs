use std::mem;

use winapi::shared::{
    bcrypt::{
        BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptEncrypt, BCryptGenerateSymmetricKey,
        BCryptGetProperty, BCryptOpenAlgorithmProvider, BCryptSetProperty, BCRYPT_AES_ALGORITHM,
        BCRYPT_ALG_HANDLE, BCRYPT_BLOCK_LENGTH, BCRYPT_BLOCK_PADDING, BCRYPT_CHAINING_MODE,
        BCRYPT_CHAIN_MODE_CBC, BCRYPT_KEY_HANDLE, BCRYPT_OBJECT_LENGTH, NTSTATUS,
    },
    ntdef::{LPCWSTR, NT_SUCCESS, PVOID},
};

fn to_wchar(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[derive(Debug)]
pub enum AESError {
    AlgorithmProvider,
    GetProperty,
    SetProperty,
    GenerateSymmetricKey,
    Encrypt,
    BadBlockSize,
}

pub type AESErrorResult<T> = Result<T, AESError>;

pub const AES256_BLOCK_SIZE: usize = 16;
pub const AES256_KEY_SIZE: usize = 32;
pub const AES256_IV_SIZE: usize = 16;

pub struct AES256CBC {
    key: [u8; AES256_KEY_SIZE],
    iv: [u8; AES256_IV_SIZE],
    plaintext: Vec<u8>,
}

impl AES256CBC {
    pub fn new(key: &[u8], iv: &[u8], plaintext: Vec<u8>) -> Self {
        let mut key = key.to_vec();
        let mut iv = iv.to_vec();

        key.resize(AES256_KEY_SIZE, 0);
        iv.resize(16, 0);

        AES256CBC {
            key: key.try_into().unwrap(),
            iv: iv.try_into().unwrap(),
            plaintext,
        }
    }

    pub fn encrypt(&self) -> AESErrorResult<Vec<u8>> {
        let mut h_algorithm: BCRYPT_ALG_HANDLE = unsafe { std::mem::zeroed() };

        println!("[i] AES: Initializing the algorithm provider");

        // Initialize the algorithm provider for AES
        h_algorithm = self.get_algorithm_provider(h_algorithm)?;

        println!("[i] AES: Get the size of the key object and block size");

        // Get the size of the key object, used for generate_symmetric_key() later
        let key_object_size = self.get_property(h_algorithm, BCRYPT_OBJECT_LENGTH)?;

        // Get the size of the block used
        let block_size = self.get_property(h_algorithm, BCRYPT_BLOCK_LENGTH)?;

        println!(
            "[i] AES: key_object_size = {}, block_size = {}",
            key_object_size, block_size
        );

        // Check block size
        if block_size as u8 != AES256_BLOCK_SIZE as u8 {
            return Err(AESError::BadBlockSize);
        }

        // Set Block Cipher mode to CBC, this uses a 32 byte key and a 16 byte IV
        self.set_cbc_mode(h_algorithm)?;

        // Generate key object from our key
        let h_key = self.generate_symmetric_key(h_algorithm, key_object_size as u32)?;

        // Run BCryptEncrypt a first time to get the size of the output buffer
        let output_size = self.get_output_buffer_size(h_key)?;

        // Encrypt the data
        let cipher_text = self.encrypt_data(h_key, output_size)?;

        // Clean up
        unsafe {
            BCryptCloseAlgorithmProvider(h_algorithm, 0);
            BCryptDestroyKey(h_key);
        }

        Ok(cipher_text)
    }

    pub fn decrypt(&self) -> Vec<u8> {
        todo!();
    }

    fn get_algorithm_provider(
        &self,
        mut h_algorithm: BCRYPT_ALG_HANDLE,
    ) -> AESErrorResult<BCRYPT_ALG_HANDLE> {
        let status: NTSTATUS = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut h_algorithm,
                to_wchar(BCRYPT_AES_ALGORITHM).as_ptr() as LPCWSTR,
                std::ptr::null(),
                0,
            )
        };

        if !NT_SUCCESS(status) {
            return Err(AESError::AlgorithmProvider);
        }

        Ok(h_algorithm)
    }

    fn get_property(&self, h_algorithm: BCRYPT_ALG_HANDLE, property: &str) -> AESErrorResult<u32> {
        // The address of a buffer that receives the property value.
        // The cbOutput parameter contains the size of this buffer.
        let output: u32 = 0;
        let mut bytes_copied = 0; // useless for now

        let mut test = [0; 4];

        let status: NTSTATUS = unsafe {
            BCryptGetProperty(
                h_algorithm,
                to_wchar(property).as_ptr(),
                test.as_mut_ptr(),
                std::mem::size_of::<u32>() as u32,
                &mut bytes_copied,
                0,
            )
        };

        if !NT_SUCCESS(status) {
            return Err(AESError::GetProperty);
        }
        println!("DBG: output = {}", output);
        println!("DBG: bytes_copied = {}", bytes_copied);
        Ok(output)
    }

    fn set_cbc_mode(&self, h_algorithm: BCRYPT_ALG_HANDLE) -> AESErrorResult<()> {
        let chaining_mode = to_wchar(BCRYPT_CHAINING_MODE).as_ptr() as LPCWSTR;
        let cbc = to_wchar(BCRYPT_CHAIN_MODE_CBC).as_ptr() as *mut u8;
        let cbc_size = std::mem::size_of::<u8>();

        let status: NTSTATUS =
            unsafe { BCryptSetProperty(h_algorithm, chaining_mode, cbc, cbc_size as u32, 0) };

        if !NT_SUCCESS(status) {
            return Err(AESError::SetProperty);
        }

        Ok(())
    }

    fn generate_symmetric_key(
        &self,
        h_algorithm: BCRYPT_ALG_HANDLE,
        key_object_size: u32,
    ) -> AESErrorResult<BCRYPT_KEY_HANDLE> {
        let mut h_key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();

        let key_object = std::ptr::null_mut();

        let key = self.key.as_ptr();
        let key_size = self.key.len() as u32;

        let flags = 0;

        let status: NTSTATUS = unsafe {
            BCryptGenerateSymmetricKey(
                h_algorithm,
                h_key as *mut BCRYPT_KEY_HANDLE,
                key_object,
                key_object_size,
                key as *mut u8,
                key_size,
                flags,
            )
        };

        if !NT_SUCCESS(status) {
            return Err(AESError::GenerateSymmetricKey);
        }

        Ok(h_key)
    }

    fn encrypt_data(&self, h_key: BCRYPT_KEY_HANDLE, size: u32) -> AESErrorResult<Vec<u8>> {
        let plaintext = self.plaintext.as_ptr();
        let plaintext_size = self.plaintext.len() as u32;

        let iv = self.iv.as_ptr();
        let iv_size = AES256_IV_SIZE as u32;

        let output = vec![0; size as usize];

        let status: NTSTATUS = unsafe {
            BCryptEncrypt(
                h_key,
                plaintext as *mut u8,
                plaintext_size,
                std::ptr::null_mut() as PVOID,
                iv as *mut u8,
                iv_size,
                output.as_ptr() as *mut u8,
                size,
                std::ptr::null_mut(),
                BCRYPT_BLOCK_PADDING,
            )
        };

        if !NT_SUCCESS(status) {
            return Err(AESError::Encrypt);
        }

        Ok(output)
    }

    fn get_output_buffer_size(&self, h_key: BCRYPT_KEY_HANDLE) -> AESErrorResult<u32> {
        let plaintext = self.plaintext.as_ptr();
        let plaintext_size = self.plaintext.len() as u32;

        let iv = self.iv.as_ptr();
        let iv_size = AES256_IV_SIZE as u32;

        let size: u32 = 0;

        let status: NTSTATUS = unsafe {
            BCryptEncrypt(
                h_key,
                plaintext as *mut u8,
                plaintext_size,
                std::ptr::null_mut() as PVOID,
                iv as *mut u8,
                iv_size,
                std::ptr::null_mut(),
                0,
                size as *mut u32,
                BCRYPT_BLOCK_PADDING,
            )
        };

        if !NT_SUCCESS(status) {
            return Err(AESError::Encrypt);
        }

        Ok(size)
    }
}
