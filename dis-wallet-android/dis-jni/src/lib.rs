use dis_core::{wallet::DemoWallet, Request, SUITE_ML_DSA_65};
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jstring, jobjectArray};
use jni::JNIEnv;
use std::sync::Mutex;

static WALLET: std::sync::OnceLock<Mutex<DemoWallet>> = std::sync::OnceLock::new();

fn wallet() -> &'static Mutex<DemoWallet> {
    WALLET.get_or_init(|| Mutex::new(DemoWallet::new()))
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
    dis_core::hex::encode(bytes)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    dis_core::hex::decode(s).ok()
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

/// Provision a new vendor keypair. Returns the hex-encoded public key on success.
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
    match wallet().lock().unwrap().provision(&id, &origin, &policy) {
        Ok(pk) => to_jstring(&mut env, &hex_encode(&pk)),
        Err(e) => to_jstring(&mut env, &format!("ERROR: {e:?}")),
    }
}

/// Sign a challenge JSON from the vendor server. Returns a JSON proof object.
#[no_mangle]
pub extern "C" fn Java_com_chainforge_diswallet_DisWallet_signChallenge(
    mut env: JNIEnv,
    _class: JClass,
    vendor_id: JString,
    challenge_json: JString,
) -> jstring {
    let id = get_string(&mut env, &vendor_id);
    let json_str = get_string(&mut env, &challenge_json);

    let challenge: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => return to_jstring(&mut env, &format!("ERROR: invalid JSON: {e}")),
    };

    let resource_id = challenge["resource_id"].as_str().unwrap_or("").to_string();
    let action = challenge["action"].as_str().unwrap_or("").to_string();
    let scopes: Vec<String> = challenge["scopes"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|s| s.as_str().map(String::from))
        .collect();
    let policy_id = challenge["policy_id"].as_str().unwrap_or("v1").to_string();

    let w = wallet().lock().unwrap();
    let origin = match w.get_public_key(&id) {
        Some(_) => {
            // We need origin from the wallet; use export_key to get it, but
            // DemoWallet doesn't expose origin directly — reconstruct Request
            // via the stored key metadata. For the JNI, embed origin in challenge JSON.
            challenge["rp_origin"].as_str().unwrap_or("").to_string()
        }
        None => return to_jstring(&mut env, "ERROR: vendor not provisioned"),
    };

    let request = Request {
        suite_id: SUITE_ML_DSA_65,
        rp_id: id.clone(),
        rp_origin: origin,
        challenge_id: parse_bytes16(&challenge["challenge_id"]),
        nonce: parse_bytes16(&challenge["nonce"]),
        issued_at: challenge["issued_at"].as_u64().unwrap_or(0),
        expires_at: challenge["expires_at"].as_u64().unwrap_or(0),
        resource_id: resource_id.clone(),
        action: action.clone(),
        scopes,
        operation_digest: None,
        policy_id,
    };

    match w.sign(&request, &resource_id, &action) {
        Ok(proof) => {
            let result = serde_json::json!({
                "vendor_id": id,
                "public_key": hex_encode(&proof.public_key),
                "signature": hex_encode(&proof.signature),
                "resource_id": resource_id,
                "action": action,
            });
            to_jstring(&mut env, &result.to_string())
        }
        Err(e) => to_jstring(&mut env, &format!("ERROR: {e:?}")),
    }
}

/// List all provisioned vendor IDs.
#[no_mangle]
pub extern "C" fn Java_com_chainforge_diswallet_DisWallet_listVendors(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    let w = wallet().lock().unwrap();
    let ids = w.list_vendors();
    let string_class = env.find_class("java/lang/String").unwrap();
    let empty = env.new_string("").unwrap();
    let arr = env
        .new_object_array(ids.len() as i32, &string_class, &empty)
        .unwrap();
    for (i, id) in ids.iter().enumerate() {
        let s = env.new_string(id).unwrap();
        env.set_object_array_element(&arr, i as i32, s).unwrap();
    }
    arr.into_raw()
}

/// Export key bytes as "pk_hex:sk_hex" for persistent storage.
/// Store the result in hardware-backed encrypted storage (Android Keystore).
#[no_mangle]
pub extern "C" fn Java_com_chainforge_diswallet_DisWallet_exportKey(
    mut env: JNIEnv,
    _class: JClass,
    vendor_id: JString,
) -> jstring {
    let id = get_string(&mut env, &vendor_id);
    match wallet().lock().unwrap().export_key(&id) {
        Some((pk, sk)) => to_jstring(&mut env, &format!("{}:{}", hex_encode(&pk), hex_encode(&sk))),
        None => to_jstring(&mut env, "ERROR: vendor not found"),
    }
}

/// Restore a vendor key from encrypted persistent storage on app restart.
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
    let pk = match hex_decode(&get_string(&mut env, &pk_hex)) {
        Some(b) => b,
        None => return to_jstring(&mut env, "ERROR: invalid pk hex"),
    };
    let sk = match hex_decode(&get_string(&mut env, &sk_hex)) {
        Some(b) => b,
        None => return to_jstring(&mut env, "ERROR: invalid sk hex"),
    };
    match wallet().lock().unwrap().import_key(&id, &origin, &policy, &pk, &sk) {
        Ok(()) => to_jstring(&mut env, "OK"),
        Err(e) => to_jstring(&mut env, &format!("ERROR: {e:?}")),
    }
}

/// Rotate the keypair for a vendor. Returns "old_pk_hex:new_pk_hex".
/// After this call: re-enroll the new key with the vendor server and persist
/// the new key to Android Keystore before the app restarts.
#[no_mangle]
pub extern "C" fn Java_com_chainforge_diswallet_DisWallet_rotateKey(
    mut env: JNIEnv,
    _class: JClass,
    vendor_id: JString,
) -> jstring {
    let id = get_string(&mut env, &vendor_id);
    match wallet().lock().unwrap().rotate(&id) {
        Ok((old_pk, new_pk)) => to_jstring(
            &mut env,
            &format!("{}:{}", hex_encode(&old_pk), hex_encode(&new_pk)),
        ),
        Err(e) => to_jstring(&mut env, &format!("ERROR: {e:?}")),
    }
}
