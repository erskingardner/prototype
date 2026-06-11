use std::collections::HashMap;

const GUEST_PACKAGE: &str = "encrypted-spaces-ffproof-bench";

fn main() {
    risc0_build::embed_methods_with_options(guest_options());
}

fn guest_options() -> HashMap<&'static str, risc0_build::GuestOptions> {
    let mut options = HashMap::new();
    if std::env::var_os("CARGO_FEATURE_MRT").is_some() {
        let mut guest_options = risc0_build::GuestOptions::default();
        guest_options.features.push("mrt".to_string());
        options.insert(GUEST_PACKAGE, guest_options);
    }
    options
}
