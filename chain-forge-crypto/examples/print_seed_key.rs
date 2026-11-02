use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

fn main() {
    let seeds = &[
        ("SEED_PILOT", "dis003d-pilot-device-seed-000000000000000000000000001"),
        ("SEED_G1",    "dis003d-guardian-1-seed-000000000000000000000000000010"),
        ("SEED_G2",    "dis003d-guardian-2-seed-000000000000000000000000000020"),
        ("SEED_G3",    "dis003d-guardian-3-seed-000000000000000000000000000030"),
    ];
    for (name, seed) in seeds {
        let kp = MlDsaScheme.generate_keypair(seed).expect("keygen");
        let hex: String = kp.public_key.iter().map(|b| format!("{b:02x}")).collect();
        println!("{name}: {hex}");
    }
}
