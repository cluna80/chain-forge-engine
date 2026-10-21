use dis_core::{canonical_request, Request, SUITE_ML_DSA_65};

fn main() {
    let req1 = Request {
        suite_id: SUITE_ML_DSA_65,
        rp_id: "vendor-acme".into(),
        rp_origin: "https://acme.example.com".into(),
        challenge_id: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],
        nonce: [16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1],
        issued_at: 1_700_000_000,
        expires_at: 1_700_000_300,
        resource_id: "document:001".into(),
        action: "read".into(),
        scopes: vec!["document:read".into()],
        operation_digest: None,
        policy_id: "v1".into(),
    };

    let req2 = Request {
        suite_id: SUITE_ML_DSA_65,
        rp_id: "vendor-beta".into(),
        rp_origin: "https://beta.example.com".into(),
        challenge_id: [0xaa; 16],
        nonce: [0xbb; 16],
        issued_at: 1_700_001_000,
        expires_at: 1_700_001_299,
        resource_id: "invoice:42".into(),
        action: "approve".into(),
        scopes: vec!["invoice:approve".into(), "invoice:read".into()],
        operation_digest: Some([0xab; 32]),
        policy_id: "v1".into(),
    };

    let bytes1 = canonical_request(&req1).expect("req1");
    let bytes2 = canonical_request(&req2).expect("req2");

    println!("VEC1={}", hex::encode(&bytes1));
    println!("VEC2={}", hex::encode(&bytes2));
}
