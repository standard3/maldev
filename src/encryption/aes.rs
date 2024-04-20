use std::mem;

use winapi::shared::{
    bcrypt::{
        BCryptGetProperty, BCryptOpenAlgorithmProvider, BCryptSetProperty, BCRYPT_AES_ALGORITHM,
        BCRYPT_ALG_HANDLE, BCRYPT_BLOCK_LENGTH, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC,
        BCRYPT_KEY_HANDLE, BCRYPT_OBJECT_LENGTH, NTSTATUS,
    },
    ntdef::{LPCWSTR, NT_SUCCESS, PVOID},
};

fn to_wchar(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[derive(Debug)]
enum AESError {
    AlgorithmProvider,
    GetProperty,
    SetProperty,
    GenerateSymmetricKey,
    Encrypt,
    BadBlockSize,
}

type AESErrorResult<T> = Result<T, AESError>;

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

    pub fn encrypt(&self) -> AESErrorResult<u8> {
        let mut h_algorithm: BCRYPT_ALG_HANDLE = std::ptr::null_mut();

        // Initialize the algorithm provider for AES
        h_algorithm = self.get_algorithm_provider(h_algorithm)?;

        // Get the size of the key object, used for generate_symmetric_key() later
        let key_object_size = self.get_property(
            h_algorithm,
            to_wchar(BCRYPT_OBJECT_LENGTH).as_ptr() as LPCWSTR,
        )?;

        // Get the size of the block used
        let block_size = self.get_property(
            h_algorithm,
            to_wchar(BCRYPT_BLOCK_LENGTH).as_ptr() as LPCWSTR,
        )?;

        // Check block size
        if block_size != AES256_BLOCK_SIZE as u8 {
            return Err(AESError::BadBlockSize);
        }

        // Set Block Cipher mode to CBC, this uses a 32 byte key and a 16 byte IV

        todo!();
    }

    pub fn decrypt(&self) -> Vec<u8> {
        todo!();
    }

    fn get_algorithm_provider(
        &self,
        h_algorithm: BCRYPT_ALG_HANDLE,
    ) -> AESErrorResult<BCRYPT_ALG_HANDLE> {
        let implementation = std::ptr::null();

        let status: NTSTATUS = unsafe {
            BCryptOpenAlgorithmProvider(
                h_algorithm as *mut PVOID,
                to_wchar(BCRYPT_AES_ALGORITHM).as_ptr() as LPCWSTR,
                implementation,
                0,
            )
        };

        if !NT_SUCCESS(status) {
            return Err(AESError::AlgorithmProvider);
        }

        Ok(h_algorithm)
    }

    fn get_property(
        &self,
        h_algorithm: BCRYPT_ALG_HANDLE,
        property: LPCWSTR,
    ) -> AESErrorResult<u8> {
        // The address of a buffer that receives the property value.
        // The cbOutput parameter contains the size of this buffer.
        let output: u8 = 0;

        let result = std::ptr::null_mut();
        let flags = 0;

        let status: NTSTATUS = unsafe {
            BCryptGetProperty(
                h_algorithm,
                property,
                output as *mut u8,
                mem::size_of::<u8>() as u32,
                result,
                flags,
            )
        };

        if !NT_SUCCESS(status) {
            return Err(AESError::GetProperty);
        }

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

    fn generate_symmetric_key(&self,)
}
