pub fn entry() {
    println!("[i] Payload encryption");

    let shellcode: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];

    println!("[*] Obfuscation: IPv4: shellcode = {:?}", shellcode);
    let obfuscated = ipv4_obfuscation(shellcode);
}

pub fn bytes_to_ipv4(bytes: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

pub fn bytes_to_ipv6(bytes: &[u8; 16]) -> String {
    format!(
        "{}{}:{}{}:{}{}:{}{}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
    )
}

pub fn ipv4_obfuscation(payload: Vec<u8>) -> Vec<String> {
    let mut ipv4_array: Vec<String> = Vec::new();

    for i in (0..payload.len()).step_by(4) {
        let mut ipv4: [u8; 4] = [0; 4];
        ipv4.copy_from_slice(&payload[i..i + 4]);

        ipv4_array.push(bytes_to_ipv4(&ipv4));
    }

    ipv4_array
}
