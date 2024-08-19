use crate::{random_fr, DEFAULT_TREE_DEPTH};
use getrandom::getrandom;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use std::collections::HashMap;



#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub s: String,
    #[serde(rename = "Tx")]
    pub tx: String,
    #[serde(rename = "Ty")]
    pub ty: String,
    #[serde(rename = "Ux")]
    pub ux: String,
    #[serde(rename = "Uy")]
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
        inputs.insert(String::from("active"), json!(vec![String::from("0")]));

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
        inputs.insert(String::from("Tx"), json!(vec![0]));
        inputs.insert(String::from("Ty"), json!(vec![1]));
        inputs.insert(String::from("Ux"), json!(vec![0]));
        inputs.insert(String::from("Uy"), json!(vec![1]));
        let path_indices: Vec<String> = (0..DEFAULT_TREE_DEPTH).map(|_| {
            let mut buf = [0u8; 1];
            getrandom(&mut buf).unwrap();
            (buf[0] % 2).to_string()
        }).collect();
        inputs.insert(String::from("pathIndices"), json!(vec![path_indices]));
        let siblings: Vec<String> = (0..DEFAULT_TREE_DEPTH).map(|_| random_fr()).collect();
        inputs.insert(String::from("siblings"), json!(vec![siblings]));
        inputs.insert(String::from("active"), json!(vec![String::from("1")]));

        inputs
    }
}

/**
 * Get example input for use in testing
 * 
 * @returns (example private inputs, example tree root)
 */
pub fn example_input() -> (Membership, String) {
    let membership = Membership {
        s: String::from("1556192236082850800011477753789706164136184180458744644984084897070345066570"),
        tx: String::from("11796026433945242671642728009981778919257130899633207712788256867701213124641"),
        ty: String::from("14123514812924309349601388555201142092835117152213858542018278815110993732603"),
        ux: String::from("0"),
        uy: String::from("1"),
        path_indices: vec![0, 1, 0, 0, 0, 0, 0, 0],
        siblings: vec![
            String::from("19588054228312086345868691355666543386017663516009792796758663539234820257351"),
            String::from("17039564632945388764306088555981902867518200276453168439618972583980589320757"),
            String::from("7423237065226347324353380772367382631490014989348495481811164164159255474657"),
            String::from("11286972368698509976183087595462810875513684078608517520839298933882497716792"),
            String::from("3607627140608796879659380071776844901612302623152076817094415224584923813162"),
            String::from("19712377064642672829441595136074946683621277828620209496774504837737984048981"),
            String::from("20775607673010627194014556968476266066927294572720319469184847051418138353016"),
            String::from("3396914609616007258851405644437304192397291162432396347162513310381425243293"),
        ],
    };

    let root = String::from("1799182282238172949735919814155076722550339245418717182904975644657694908682");
    
    (membership, root)
}