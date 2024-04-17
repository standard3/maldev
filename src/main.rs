mod payloadplacement;

fn main() {
    #[cfg(feature = "payloadplacement")]
    payloadplacement::entry();
}
