mod encryption;
mod payloadplacement;

fn main() {
    #[cfg(feature = "payloadplacement")]
    payloadplacement::entry();

    #[cfg(feature = "encryption")]
    encryption::entry();
}
