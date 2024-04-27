mod encryption;
mod obfuscation;
mod payloadplacement;

fn main() {
    #[cfg(feature = "payloadplacement")]
    payloadplacement::entry();

    #[cfg(feature = "encryption")]
    encryption::entry();

    #[cfg(feature = "obfuscation")]
    obfuscation::entry();
}
