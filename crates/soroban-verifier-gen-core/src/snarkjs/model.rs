use crate::error::{Error, Result};
use serde::Deserialize;
use serde_json::Value;
use std::str::FromStr;

pub type DecimalValue = String;

#[derive(Debug, Clone, Deserialize)]
pub struct VerificationKey {
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub curve: Option<String>,
    #[serde(rename = "nPublic", default)]
    pub n_public: usize,
    #[serde(rename = "vk_alpha_1")]
    pub vk_alpha_1: SnarkJsG1,
    #[serde(rename = "vk_beta_2")]
    pub vk_beta_2: SnarkJsG2,
    #[serde(rename = "vk_gamma_2")]
    pub vk_gamma_2: SnarkJsG2,
    #[serde(rename = "vk_delta_2")]
    pub vk_delta_2: SnarkJsG2,
    #[serde(rename = "IC")]
    pub ic: Vec<SnarkJsG1>,
}

#[derive(Debug, Clone)]
pub struct Proof {
    pub protocol: Option<String>,
    pub curve: Option<String>,
    pub pi_a: SnarkJsG1,
    pub pi_b: SnarkJsG2,
    pub pi_c: SnarkJsG1,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SnarkJsG1 {
    pub x: DecimalValue,
    pub y: DecimalValue,
    pub z: DecimalValue,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SnarkJsG2 {
    pub x0: DecimalValue,
    pub x1: DecimalValue,
    pub y0: DecimalValue,
    pub y1: DecimalValue,
    pub z0: DecimalValue,
    pub z1: DecimalValue,
}

impl SnarkJsG1 {
    pub fn from_value(value: Value, field: &str) -> Result<Self> {
        match value {
            Value::Array(items) => {
                if items.len() != 3 {
                    return Err(Error::MalformedG1(format!(
                        "{field} expected [x,y,z], got length {}",
                        items.len()
                    )));
                }
                Ok(Self {
                    x: parse_scalar(&items[0], &format!("{field}.x"))?,
                    y: parse_scalar(&items[1], &format!("{field}.y"))?,
                    z: parse_scalar(&items[2], &format!("{field}.z"))?,
                })
            }
            _ => Err(Error::MalformedG1(format!("{field} must be array [x,y,z]"))),
        }
    }
}

impl SnarkJsG2 {
    pub fn from_value(value: Value, field: &str) -> Result<Self> {
        match value {
            Value::Array(items) => {
                if items.len() != 3 {
                    return Err(Error::MalformedG2(format!(
                        "{field} expected [[x0,x1],[y0,y1],[z0,z1]], got length {}",
                        items.len()
                    )));
                }
                let x = pair_from_value(&items[0], &format!("{field}.x"))?;
                let y = pair_from_value(&items[1], &format!("{field}.y"))?;
                let z = pair_from_value(&items[2], &format!("{field}.z"))?;
                Ok(Self {
                    x0: x.0,
                    x1: x.1,
                    y0: y.0,
                    y1: y.1,
                    z0: z.0,
                    z1: z.1,
                })
            }
            _ => Err(Error::MalformedG2(format!(
                "{field} must be [[x0,x1],[y0,y1],[z0,z1]]"
            ))),
        }
    }
}

fn pair_from_value(value: &Value, field: &str) -> Result<(DecimalValue, DecimalValue)> {
    let items = match value.as_array() {
        Some(items) => items,
        None => return Err(Error::MalformedG2(format!("{field} must be pair [a,b]"))),
    };

    if items.len() != 2 {
        return Err(Error::MalformedG2(format!(
            "{field} expected pair, got length {}",
            items.len()
        )));
    }

    Ok((
        parse_scalar(&items[0], &format!("{field}[0]"))?,
        parse_scalar(&items[1], &format!("{field}[1]"))?,
    ))
}

fn parse_scalar(value: &Value, field: &str) -> Result<String> {
    let decimal = match value {
        Value::String(s) => return Ok(s.clone()),
        Value::Number(n) => n.to_string(),
        _ => {
            return Err(Error::MalformedG1(format!(
                "{field} expected decimal string or number"
            )));
        }
    };

    // reject floats or non-decimal notation.
    if !decimal.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::DecimalParse(format!(
            "{field} expected decimal string, got {decimal}"
        )));
    }

    Ok(decimal)
}

pub fn parse_decimal(value: &str, field: &str) -> Result<num_bigint::BigUint> {
    num_bigint::BigUint::from_str(value)
        .map_err(|_| Error::DecimalParse(format!("{field} must be decimal integer, got {value}")))
}

#[derive(Debug, Deserialize)]
pub struct RawVerificationKey {
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub curve: Option<String>,
    #[serde(rename = "nPublic", default)]
    pub n_public: usize,
    #[serde(rename = "vk_alpha_1", default)]
    pub vk_alpha_1: Value,
    #[serde(rename = "vk_beta_2", default)]
    pub vk_beta_2: Value,
    #[serde(rename = "vk_gamma_2", default)]
    pub vk_gamma_2: Value,
    #[serde(rename = "vk_delta_2", default)]
    pub vk_delta_2: Value,
    #[serde(rename = "IC", default)]
    pub ic: Vec<Value>,
}

#[derive(Debug, Deserialize)]
pub struct RawProof {
    pub protocol: Option<String>,
    pub curve: Option<String>,
    pub pi_a: Value,
    pub pi_b: Value,
    pub pi_c: Value,
}

#[derive(Debug, Deserialize)]
pub struct PackedArtifact {
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub curve: Option<String>,
    #[serde(default)]
    pub vk: Option<String>,
    #[serde(default)]
    pub proof: Option<String>,
    #[serde(rename = "public_input", default)]
    pub public_input: Option<Value>,
    #[serde(rename = "proof_a", default)]
    pub proof_a: Option<String>,
    #[serde(rename = "proof_b", default)]
    pub proof_b: Option<String>,
    #[serde(rename = "proof_c", default)]
    pub proof_c: Option<String>,
    #[serde(rename = "vk_alpha_g1", default)]
    pub vk_alpha_g1: Option<String>,
    #[serde(rename = "vk_beta_g2", default)]
    pub vk_beta_g2: Option<String>,
    #[serde(rename = "vk_gamma_g2", default)]
    pub vk_gamma_g2: Option<String>,
    #[serde(rename = "vk_delta_g2", default)]
    pub vk_delta_g2: Option<String>,
}
