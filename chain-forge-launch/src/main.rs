//! `qcb-launch verify --manifest <file> --genesis <file>`
//!
//! Exit 0 and `{"ok":true,...}` when the genesis is deployable as the Qattice public alpha; exit 1 and
//! `{"ok":false,"violations":[{"code":...,"detail":...}]}` otherwise; exit 2 for usage or I/O errors. It never passes on
//! an input it could not read.

use chain_forge_launch::verify;

fn usage() -> ! {
    eprintln!("usage: qcb-launch verify --manifest <file> --genesis <file>");
    std::process::exit(2)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| { eprintln!("error: cannot read {path}: {e}"); std::process::exit(2) })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("verify") { usage(); }
    let (mut manifest, mut genesis) = (None::<String>, None::<String>);
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => { i += 1; manifest = args.get(i).cloned(); }
            "--genesis" => { i += 1; genesis = args.get(i).cloned(); }
            _ => usage(),
        }
        i += 1;
    }
    let (Some(m), Some(g)) = (manifest, genesis) else { usage() };
    let (mt, gt) = (read(&m), read(&g));
    match verify(&mt, &gt) {
        Ok(r) => println!("{}", serde_json::json!({ "ok": true, "network": r.network, "chain_id": r.chain_id, "genesis_hash": r.genesis_hash })),
        Err(vs) => {
            println!("{}", serde_json::json!({ "ok": false, "violations": vs }));
            std::process::exit(1);
        }
    }
}
