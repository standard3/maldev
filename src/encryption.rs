use rc4::{KeyInit, Rc4, StreamCipher};
use winapi::{
    shared::bcrypt::NTSTATUS,
    um::{
        libloaderapi::{GetProcAddress, LoadLibraryA},
        winnt::{LPCSTR, PVOID},
    },
};

mod aes;

#[allow(dead_code)]

pub fn entry() {
    println!("[i] Payload encryption");

    xor_shellcode();
    rc4_shellcode();
    rc4_shellcode2();
    aes_shellcode();
}

fn xor_shellcode() {
    let shellcode = vec![0, 1, 2, 3, 4, 5, 6, 7];
    let key = "uncrackable key".bytes().collect::<Vec<u8>>();

    println!("[*] XOR: shellcode = {:?}, key = {:?}", shellcode, key);

    let cipher = xor(&shellcode, &key);
    println!("[*] XOR: encrypted = {:?}", cipher);
    println!("[*] XOR: decrypted = {:?}", xor(&cipher, &key));
}

fn xor(shellcode: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();
    let key_size = key.len();

    for (i, j) in (0..shellcode.len()).zip(0..key_size) {
        let j = j % key_size;
        result.push(shellcode[i] ^ key[j]);
    }

    result
}

fn rc4_shellcode() {
    let mut shellcode = vec![0, 1, 2, 3, 4, 5, 6, 7];
    let key = b"uncrackable key";

    println!("[*] RC4: shellcode = {:?}, key = {:?}", shellcode, key);

    let mut rc4 = Rc4::new(key.into());
    rc4.apply_keystream(&mut shellcode);
    println!("[*] RC4: encrypted = {:?}", shellcode);
}

#[repr(C)]
#[derive(Debug)]
struct USTRING {
    length: u32,
    maximum_length: u32,
    buffer: PVOID,
}

type FNSYSTEMFUNCTION032 = extern "system" fn(*mut USTRING, *mut USTRING) -> NTSTATUS;

fn print_hex_data(data: *const u8, size: usize) {
    for i in 0..size {
        if i < size - 1 {
            print!("0x{:02X}, ", unsafe { *data.add(i) });
        } else {
            print!("0x{:02X} ", unsafe { *data.add(i) });
        }
    }
}

fn rc4_shellcode2() {
    let system_function032: FNSYSTEMFUNCTION032 = unsafe {
        let p_system_function032 = GetProcAddress(
            LoadLibraryA("Advapi32\0".as_ptr() as LPCSTR),
            "SystemFunction032\0".as_ptr() as LPCSTR,
        );

        if p_system_function032.is_null() {
            println!("[-] Failed to get address of SystemFunction032");
            return;
        }
        std::mem::transmute(p_system_function032)
    };

    println!(
        "[*] RC42: system_function032 address = {:p}",
        &system_function032
    );

    let shellcode = vec![0, 1, 2, 3, 4, 5, 6, 7];
    let key = b"uncrackable key";

    let mut img = USTRING {
        length: shellcode.len() as u32,
        maximum_length: shellcode.len() as u32,
        buffer: shellcode.as_ptr() as PVOID,
    };

    let mut key = USTRING {
        length: key.len() as u32,
        maximum_length: key.len() as u32,
        buffer: key.as_ptr() as PVOID,
    };

    println!("[*] RC42: shellcode = {:?}, key = {:?}", &img, &key);

    // See https://source.winehq.org/WineAPI/SystemFunction032.html
    if system_function032(&mut img as *mut USTRING, &mut key as *mut USTRING) != 0x0 {
        println!("[-] SystemFunction32 FAILED");
        return;
    }

    print!("[*] RC42: encrypted: ");
    print_hex_data(img.buffer as *const u8, img.length as usize);
    println!();
}

fn aes_shellcode() {
    let shellcode = vec![0, 1, 2, 3, 4, 5, 6, 7];
    let key = b"uncrackable key";
    let iv = b"initialization vector";

    println!(
        "[*] AES: shellcode = {:?}, key = {:?}, iv = {:?}",
        shellcode, key, iv
    );

    let test = aes::AES256CBC::new(key, iv, shellcode.into());

    let cipher_text = test.encrypt();

    match cipher_text {
        Ok(cipher_text) => {
            println!("[*] AES: encrypted = {:?}", cipher_text);
        }
        Err(e) => {
            println!("[-] AES: error = {:?}", e);
        }
    }
}
