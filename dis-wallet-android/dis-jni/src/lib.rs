use dis_core::{Request, SUITE_ML_DSA_65};
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jstring, jobjectArray};
use jni::JNIEnv;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use std::collections::HashMap;
use std::sync::Mutex;

struct WalletKey {
    origin: String,
    policy: String,
    pk: Vec<u8>,
    sk: Vec<u8>,
}

static WALLET: std::sync::OnceLock<Mutex<HashMap<String, WalletKey>>> =
    std::sync::OnceLock::new();

fn wallet() -> &'static Mutex<HashMap<String, WalletKey>> {
    WALLET.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_string(env: &mut JNIEnv, s: &JString) -> String {
    match env.get_string(s) {
        Ok(v) => v.to_string_lossy().into_owned(),
        Err(_) => String::new(),
    }
}

fn to_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(v) => v.into_raw(),
        Err(_) => JObject::null().into_raw() as jstring,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_bytes16(v: &serde_json::Value) -> [u8; 16] {
    let mut arr = [0u8; 16];
    if let Some(a) = v.as_array() {
        for (i, b) in a.iter().take(16).enumerate() {
            arr[i] = b.as_u64().unwrap_or(0) as u8;
        }
    }
    arr
}

#[no_mangle]
pub extern "C" fn Java_com_chainforge_diswallet_DisWallet_provision(
    mut env: JNIEnv,
    _class: JClass,
    vendor_id: JString,
    vendor_origin: JString,
    policy_id: JString,
) -> jstring {
    let id = get_string(&mut env, &vendor_id);
    let origin = get_string(&mut env, &vendor_origin);
    let policy = get_string(&mut env, &policy_id);

    if id.is_empty() || origin.is_empty() || policy.is_empty() {
        return to_jstring(&mut env, "ERROR: empty fields");
    }

    let mut w = wallet().lock().unwrap();
    if w.contains_key(&id) {
        return to_jstring(&mut env, "ERROR: vendor already provisioned");
    }

    let (pk, sk) = dilithium3::keypair();
    let pk_hex = hex_encode(pk.as_bytes());
    w.insert(id, WalletKey {
        origin,
        policy,
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    });

    to_jstring(&mut env, &pk_hex)
}

#[no_mangle]
pub extern "C" fn Java_com_chainforge_diswallet_DisWallet_signChallenge(
    mut env: JNIEnv,
    _class: JClass,
    vendor_id: JString,
    challenge_json: JString,
) -> jstring {
    let id = get_string(&mut env, &vendor_id);
    let json = get_string(&mut env, &challenge_json);

    let w = wallet().lock().unwrap();
    let key = match w.get(&id) {
        Some(k) => k,
        None => return to_jstring(&mut env, "ERROR: vendor not provisioned"),
    };

    let challenge: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => return to_jstring(&mut env, &format!("ERROR: invalid JSON: {e}")),
    };

    let request = Request {
        suite_id: SUITE_ML_DSA_65,
        rp_id: id.clone(),
        rp_origin: key.origin.clone(),
        challenge_id: parse_bytes16(&challenge["challenge_id"]),
        nonce: parse_bytes16(&challenge["nonce"]),
        issued_at: challenge["issued_at"].as_u64().unwrap_or(0),
        expires_at: challenge["expires_at"].as_u64().unwrap_or(0),
        resource_id: challenge["resource_id"].as_str().unwrap_or("").into(),
        action: challenge["action"].as_str().unwrap_or("").into(),
        scopes: challenge["scopes"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|s| s.as_str().map(String::from))
            .collect(),
        operation_digest: None,
        policy_id: key.policy.clone(),
    };

    let transcript = match dis_core::canonical_request(&request) {
        Ok(t) => t,
        Err(e) => return to_jstring(&mut env, &format!("ERROR: {e:?}")),
    };

    let sk = match dilithium3::SecretKey::from_bytes(&key.sk) {
        Ok(s) => s,
        Err(_) => return to_jstring(&mut env, "ERROR: invalid secret key"),
    };

    let sig = dilithium3::detached_sign(&transcript, &sk);

    let proof = serde_json::json!({
        "vendor_id": id,
        "public_key": hex_encode(&key.pk),
        "signature": hex_encode(sig.as_bytes()),
        "resource_id": request.resource_id,
        "action": request.action,
    });

    to_jstring(&mut env, &proof.to_string())
}

#[no_mangle]
pub extern "C" fn Java_com_chainforge_diswallet_DisWallet_listVendors(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    let w = wallet().lock().unwrap();
    let keys: Vec<String> = w.keys().cloned().collect();
    let string_class = env.find_class("java/lang/String").unwrap();
    let empty = env.new_string("").unwrap();
    let arr = env
        .new_object_array(keys.len() as i32, &string_class, &empty)
        .unwrap();
    for (i, k) in keys.iter().enumerate() {
        let s = env.new_string(k).unwrap();
        env.set_object_array_element(&arr, i as i32, s).unwrap();
    }
    arr.into_raw()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
        .collect()
}


#[no_mangle]
pub extern "C" fn Java_com_chainforge_diswallet_DisWallet_exportKey(
    mut env: JNIEnv,
    _class: JClass,
    vendor_id: JString,
) -> jstring {
    let id = get_string(&mut env, &vendor_id);
    let w = wallet().lock().unwrap();
    match w.get(&id) {
        Some(k) => to_jstring(&mut env, &format!("{}:{}", hex_encode(&k.pk), hex_encode(&k.sk))),
        None => to_jstring(&mut env, "ERROR: vendor not found"),
    }
}

#[no_mangle]
pub extern "C" fn Java_com_chainforge_diswallet_DisWallet_importKey(
    mut env: JNIEnv,
    _class: JClass,
    vendor_id: JString,
    vendor_origin: JString,
    policy_id: JString,
    pk_hex: JString,
    sk_hex: JString,
) -> jstring {
    let id = get_string(&mut env, &vendor_id);
    let origin = get_string(&mut env, &vendor_origin);
    let policy = get_string(&mut env, &policy_id);
    let pk = get_string(&mut env, &pk_hex);
    let sk = get_string(&mut env, &sk_hex);

    let pk_bytes = match hex_decode(&pk) {
        Some(b) => b,
        None => return to_jstring(&mut env, "ERROR: invalid pk hex"),
    };
    let sk_bytes = match hex_decode(&sk) {
        Some(b) => b,
        None => return to_jstring(&mut env, "ERROR: invalid sk hex"),
    };

    let mut w = wallet().lock().unwrap();
    w.insert(id, WalletKey { origin, policy, pk: pk_bytes, sk: sk_bytes });
    to_jstring(&mut env, "OK")
}
