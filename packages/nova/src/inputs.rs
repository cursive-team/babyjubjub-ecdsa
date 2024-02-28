use serde_json::{json, Value};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/**
 * Use the example pub inputs given in ../../circuits/instances/example_input.json
 * @dev why did I not just read the file?
 * @dev folded circuit should not allow same signature to be used, probably needs to track sig nullifiers (smt nullifier tree maybe)
 * 
 * @returns {HashMap<String, Value>} The example pub inputs formatted for the nova-scotia processor
 */
pub fn get_example_input() -> HashMap<String, Value> {
    let mut inputs = HashMap::new();
    inputs.insert(String::from("s"), json!("1556192236082850800011477753789706164136184180458744644984084897070345066570"));
    inputs.insert(String::from("root"), json!("1799182282238172949735919814155076722550339245418717182904975644657694908682"));
    inputs.insert(String::from("Tx"), json!("11796026433945242671642728009981778919257130899633207712788256867701213124641"));
    inputs.insert(String::from("Ty"), json!("14123514812924309349601388555201142092835117152213858542018278815110993732603"));
    inputs.insert(String::from("Ux"), json!("0"));
    inputs.insert(String::from("Uy"), json!("1"));
    inputs.insert(String::from("pathIndices"), json!(["0", "1", "0", "0", "0", "0", "0", "0"]));
    let siblings = [
        "19588054228312086345868691355666543386017663516009792796758663539234820257351",
        "17039564632945388764306088555981902867518200276453168439618972583980589320757",
        "7423237065226347324353380772367382631490014989348495481811164164159255474657",
        "11286972368698509976183087595462810875513684078608517520839298933882497716792",
        "3607627140608796879659380071776844901612302623152076817094415224584923813162",
        "19712377064642672829441595136074946683621277828620209496774504837737984048981",
        "20775607673010627194014556968476266066927294572720319469184847051418138353016",
        "3396914609616007258851405644437304192397291162432396347162513310381425243293"
    ].iter().map(|s| String::from(*s)).collect::<Vec<_>>();
    inputs.insert(String::from("siblings"), json!(siblings));
    inputs.insert(String::from("sigNullifierRandomness"), json!("0"));
    inputs.insert(String::from("pubKeyNullifierRandomness"), json!("0"));

    inputs
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Membership<const D: usize> {
    pub s: String,
    pub root: String,
    #[serde(rename = "Tx")]
    pub t_x: String,
    #[serde(rename = "Tx")]
    pub t_y: String,
    #[serde(rename = "Ux")]
    pub u_x: String,
    #[serde(rename = "Uy")]
    pub u_y: String,
    pub path_indices: Vec<String>,
    pub siblings: Vec<String>,
    pub sig_nullifier_randomness: String,
    pub pub_key_nullifier_randomness: String,
}

impl<const D: usize> Membership<D> {
    pub fn to_inputs(&self) -> HashMap<String, Value> {
        let mut inputs = HashMap::new();
        inputs.insert(String::from("s"), json!(self.s));
        inputs.insert(String::from("root"), json!(self.root));
        inputs.insert(String::from("Tx"), json!(self.t_x));
        inputs.insert(String::from("Ty"), json!(self.t_y));
        inputs.insert(String::from("Ux"), json!(self.u_x));
        inputs.insert(String::from("Uy"), json!(self.u_y));
        inputs.insert(String::from("pathIndices"), json!(self.path_indices));
        inputs.insert(String::from("siblings"), json!(self.siblings));
        inputs.insert(String::from("sigNullifierRandomness"), json!(self.sig_nullifier_randomness));
        inputs.insert(String::from("pubKeyNullifierRandomness"), json!(self.pub_key_nullifier_randomness));
        inputs
    }
}