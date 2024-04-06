use bjj_ecdsa_nova_wasm::{
    console_log, performance,
    input::{example_input},
    nova::{continue_proof, generate_proof, obfuscate_proof, verify_proof},
};
use js_sys::{Number, BigInt as JsBigInt};
use num::{Num, BigInt};
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
async fn fold_depth_8_test() {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);

    // set base url
    let bucket_url = "https://bjj-ecdsa-nova.us-southeast-1.linodeobjects.com/depth_8";
    let r1cs_url = format!("{}/{}.r1cs", bucket_url, "bjj_ecdsa_batch_fold");
    let wasm_url = format!("{}/{}.wasm", bucket_url, "bjj_ecdsa_batch_fold");
    let params_url = format!("{}/{}.json", bucket_url, "public_params");

    // download public params
    console_log!("Downloading public params...");
    let start = performance.now();
    let params_string = reqwest::get(params_url)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let end = performance.now();
    console_log!("Downloaded params in {}ms", end - start);

    // get example membership input

    let (membership, root) = example_input();
    let membership_string = serde_json::to_string(&membership).unwrap();

    // PROVE PROOF 1 //
    let start = performance.now();
    let proof: String = generate_proof(
        r1cs_url.clone(),
        wasm_url.clone(),
        params_string.clone(),
        root.clone(),
        membership_string.clone(),
    )
    .await;
    let end = performance.now();
    console_log!("Time to complete proof 1: {}ms", end - start);

    // VERIFY PROOF 1 //
    let start = performance.now();
    let zi_primary = verify_proof(params_string.clone(), proof.clone(), root.clone(), Number::from(1)).await;
    let end = performance.now();
    console_log!("Time to complete verification 1: {}ms", end - start);

    // PROVE PROOF 2 //
    let start = performance.now();
    let proof: String = continue_proof(
        r1cs_url.clone(),
        wasm_url.clone(),
        params_string.clone(),
        proof,
        membership_string.clone(),
        zi_primary,
    )
    .await;
    let end = performance.now();
    console_log!("Time to complete proof 2: {}ms", end - start);

    // PROVE PROOF 2 //
    let start = performance.now();
    let zi_primary = verify_proof(params_string.clone(), proof.clone(), root.clone(), Number::from(2)).await;
    let end = performance.now();
    console_log!("Time to complete verification 2: {}ms", end - start);

    console_log!("Res: {:?}", zi_primary);

    // PROVE PROOF 3 //
    let start = performance.now();
    let proof: String = continue_proof(
        r1cs_url.clone(),
        wasm_url.clone(),
        params_string.clone(),
        proof,
        membership_string.clone(),
        zi_primary,
    )
    .await;
    let end = performance.now();
    console_log!("Time to complete proof 3: {}ms", end - start);

    // PROVE PROOF 3 //
    let start = performance.now();
    let zi_primary = verify_proof(params_string.clone(), proof.clone(), root.clone(), Number::from(3)).await;
    let end = performance.now();
    console_log!("Time to complete verification 3: {}ms", end - start);

    // FINALIZE BY PROVING OBFUSCATION FOLD //
    let start = performance.now();
    let proof: String = obfuscate_proof(
        r1cs_url.clone(),
        wasm_url.clone(),
        params_string.clone(),
        proof,
        zi_primary,
    )
    .await;
    let end = performance.now();
    console_log!("Time to complete obfuscation proof: {}ms", end - start);

    // VERIFY OBFUSCATION PROOF //
    let start = performance.now();
    let zi_primary = verify_proof(params_string.clone(), proof.clone(), root.clone(), Number::from(4)).await;
    let end = performance.now();
    console_log!("Time to complete verification 3: {}ms", end - start);

    // CHECK OUTPUTS OF PROOF //
    // let expected_root = BigInt::from_str_radix(&root, 10).unwrap();
    // let empirical_root = BigInt::from_str_radix(&zi_primary.get(0).as_string().unwrap(), 16).unwrap();
    // console_log!("Expected root: {:?}", expected_root);
    // console_log!("Empirical root: {:?}", &zi_primary.get(0).as_string().unwrap());
    // assert_eq!(empirical_root, expected_root);

    console_log!("zi_primary: {:?}", zi_primary);

    // let expected_num_verified = 3f64;
    // let empirical_num_verified = zi_primary.get(1).as_f64().unwrap();
    // assert_eq!(expected_num_verified, empirical_num_verified);
}
