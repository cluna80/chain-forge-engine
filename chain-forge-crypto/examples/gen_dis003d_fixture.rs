//! One-time tool: generate DIS-003D test fixture keys and print as JSON.
//! Run with: cargo run --example gen_dis003d_fixture -p chain-forge-crypto --features real-pqc
//! Copy the output into chain-forge-node/tests/devnet/keys/dis003d-*.key.json
//! and update the public_key in genesis-dis003d.json to match.

use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let fixtures = &[
        ("dis003d-pilot",    "dis003d-pilot-device-seed-000000000000000000000000001"),
        ("dis003d-guardian1","dis003d-guardian-1-seed-000000000000000000000000000010"),
        ("dis003d-guardian2","dis003d-guardian-2-seed-000000000000000000000000000020"),
        ("dis003d-guardian3","dis003d-guardian-3-seed-000000000000000000000000000030"),
    ];
    for (name, seed) in fixtures {
        let kp = MlDsaScheme.generate_keypair(seed).expect("keygen");
        println!("{{");
        println!("  \"name\": \"{name}\",");
        println!("  \"seed\": \"{seed}\",");
        println!("  \"scheme\": \"ml-dsa-65\",");
        println!("  \"public_key\": \"{}\",", to_hex(&kp.public_key));
        println!("  \"private_key\": \"{}\"", to_hex(&kp.private_key));
        println!("}}");
    }
}
