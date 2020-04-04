#[derive(Deserialize)]
pub struct Field {
    pub m: String,
    pub p: String,
}

#[derive(Deserialize)]
pub struct Map {
    pub name: String,
    pub sgn0: String,
}

#[derive(Deserialize)]
pub struct Point {
    pub x: String,
    pub y: String,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct Bls12381G2 {
    pub L: String,
    pub Z: String,
    pub ciphersuite: String,
    pub curve: String,
    pub dst: String,
    pub expand: String,
    pub field: Field,
    pub hash: String,
    pub k: String,
    pub map: Map,
    pub randomOracle: bool,
    pub vectors: Vec<Bls12381G2RoVectors>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct Bls12381G2RoVectors {
    pub P: Point,
    pub Q0: Point,
    pub Q1: Point,
    pub msg: String,
    pub u: Vec<String>,
}
