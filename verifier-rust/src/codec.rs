//! JSON round-trip for ScanSession (ScanSessionCodec.kt port). Decode grades a
//! truncated document DOWN to the suspicious value, never to the benign
//! default — a missing boolean always reads as the dangerous one.

use serde_json::Value;

// Decode grades missing/truncated fields DOWN to the suspicious value.
pub fn decode(json_text: &str) -> Result<Value, String> {
    let o: Value = serde_json::from_str(json_text).map_err(|e| e.to_string())?;
    let key = o["attestedKey"]
        .as_str()
        .ok_or("session has no attestedKey")?
        .to_string();
    let app = o["attestedApp"].as_object().map(|app| {
        serde_json::json!({
            "packageNames": app["packageNames"].as_array().cloned().unwrap_or_default(),
            "signatureDigests": app["signatureDigests"].as_array().cloned().unwrap_or_default(),
        })
    });
    let fp = o["fingerprint"].as_object().map(|fp| {
        serde_json::json!({
            "id": fp["id"], "aid": fp["aid"], "securityLevel": fp["securityLevel"],
            "build": fp["build"], "kernel": fp["kernel"], "patch": fp["patch"],
            "installer": fp["installer"],
        })
    });
    let assurance = match o["assurance"].as_str() {
        Some("TEE") => "TEE",
        Some("STRONGBOX") => "STRONGBOX",
        _ => "SOFTWARE",
    };
    Ok(serde_json::json!({
        "attestedKey": key,
        "attestedApp": app,
        "assurance": assurance,
        "bootState": o["bootState"].as_str().unwrap_or("?"),
        "deviceLocked": o["deviceLocked"] == true,
        "chainTrusted": o["chainTrusted"] == true,
        "keyboxRevoked": o["keyboxRevoked"] != false,
        "crossLevelReuse": o["crossLevelReuse"] != false,
        "devicePropMismatch": o["devicePropMismatch"] != false,
        "bootStateSpoofer": o["bootStateSpoofer"] != false,
        "strongboxChainMissing": o["strongboxChainMissing"] != false,
        "softwareAttested": o["softwareAttested"] != false,
        "osPatchLevel": o["osPatchLevel"],
        "vendorPatchLevel": o["vendorPatchLevel"],
        "bootPatchLevel": o["bootPatchLevel"],
        "fingerprint": fp,
    }))
}

fn json_or_null(v: &Value) -> String {
    if v.is_null() {
        "null".into()
    } else {
        v.to_string()
    }
}

// Encode writes the fields in the exact wire order every port agrees on.
pub fn encode(s: &Value) -> String {
    let mut f: Vec<String> = Vec::new();
    f.push(format!(
        "\"attestedKey\":{}",
        serde_json::json!(s["attestedKey"])
    ));
    match s["attestedApp"] {
        Value::Null => f.push("\"attestedApp\":null".into()),
        ref app => f.push(format!(
            "\"attestedApp\":{{\"packageNames\":{},\"signatureDigests\":{}}}",
            app["packageNames"], app["signatureDigests"]
        )),
    }
    f.push(format!("\"assurance\":\"{}\"", s["assurance"]));
    f.push(format!(
        "\"bootState\":{}",
        serde_json::json!(s["bootState"])
    ));
    f.push(format!("\"deviceLocked\":{}", s["deviceLocked"]));
    f.push(format!("\"chainTrusted\":{}", s["chainTrusted"]));
    f.push(format!("\"keyboxRevoked\":{}", s["keyboxRevoked"]));
    f.push(format!("\"crossLevelReuse\":{}", s["crossLevelReuse"]));
    f.push(format!(
        "\"devicePropMismatch\":{}",
        s["devicePropMismatch"]
    ));
    f.push(format!("\"bootStateSpoofer\":{}", s["bootStateSpoofer"]));
    f.push(format!(
        "\"strongboxChainMissing\":{}",
        s["strongboxChainMissing"]
    ));
    f.push(format!("\"softwareAttested\":{}", s["softwareAttested"]));
    f.push(format!(
        "\"osPatchLevel\":{}",
        json_or_null(&s["osPatchLevel"])
    ));
    f.push(format!(
        "\"vendorPatchLevel\":{}",
        json_or_null(&s["vendorPatchLevel"])
    ));
    f.push(format!(
        "\"bootPatchLevel\":{}",
        json_or_null(&s["bootPatchLevel"])
    ));
    match s["fingerprint"] {
        Value::Null => f.push("\"fingerprint\":null".into()),
        ref fp => f.push(format!("\"fingerprint\":{}", fp)),
    }
    format!("{{{}}}", f.join(","))
}
