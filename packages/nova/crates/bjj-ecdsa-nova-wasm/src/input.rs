use crate::{random_fr, DEFAULT_TREE_DEPTH};
use getrandom::getrandom;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use std::collections::HashMap;



#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub s: String,
    // #[serde(rename = "Tx")]
    pub tx: String,
    // #[serde(rename = "Tx")]
    pub ty: String,
    // #[serde(rename = "Ux")]
    pub ux: String,
    // #[serde(rename = "Uy")]
    pub uy: String,
    pub path_indices: Vec<u8>,
    pub siblings: Vec<String>,
}

impl Membership {
    /**
     * Convert the membership struct to a hashmap of inputs for the circuit
     * 
     * @return - a hashmap of inputs for the circuit
     */
    pub fn to_inputs(&self) -> HashMap<String, Value> {
        let mut inputs = HashMap::new();
        inputs.insert(String::from("s"), json!(vec![self.s.clone()]));
        inputs.insert(String::from("Tx"), json!(vec![self.tx.clone()]));
        inputs.insert(String::from("Ty"), json!(vec![self.ty.clone()]));
        inputs.insert(String::from("Ux"), json!(vec![self.ux.clone()]));
        inputs.insert(String::from("Uy"), json!(vec![self.uy.clone()]));
        let path_indices: Vec<String> = self.path_indices.iter().map(|s| s.to_string()).collect();
        inputs.insert(String::from("pathIndices"), json!(vec![path_indices]));
        inputs.insert(String::from("siblings"), json!(vec![self.siblings.clone()]));
        inputs.insert(String::from("inactive"), json!(vec![String::from("0")]));

        inputs
    }

    /**
     * Generate random membership inputs for fold chaffing
     * 
     * @return - a hashmap of random inputs for the circuit
     */
    pub fn chaff() -> HashMap<String, Value> {
        let mut inputs = HashMap::new();
        inputs.insert(String::from("s"), json!(vec![random_fr()]));
        inputs.insert(String::from("Tx"), json!(vec![random_fr()]));
        inputs.insert(String::from("Ty"), json!(vec![random_fr()]));
        inputs.insert(String::from("Ux"), json!(vec![random_fr()]));
        inputs.insert(String::from("Uy"), json!(vec![random_fr()]));
        let path_indices: Vec<String> = (0..DEFAULT_TREE_DEPTH).map(|_| {
            let mut buf = [0u8; 1];
            getrandom(&mut buf).unwrap();
            (buf[0] % 2).to_string()
        }).collect();
        inputs.insert(String::from("pathIndices"), json!(vec![path_indices]));
        let siblings: Vec<String> = (0..DEFAULT_TREE_DEPTH).map(|_| random_fr()).collect();
        inputs.insert(String::from("siblings"), json!(vec![siblings]));
        inputs.insert(String::from("inactive"), json!(vec![String::from("1")]));

        inputs
    }
}