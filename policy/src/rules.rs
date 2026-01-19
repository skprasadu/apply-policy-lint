use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub category: String,
    pub message: String,
    #[serde(default)]
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    pub version: u32,
    pub rules: Vec<Rule>,
}

// Embedded default rules (ship in the binary)
const DEFAULT_RULES_JSON: &str = include_str!("../rules/default.json");

pub type SymbolIndex = HashMap<String, Vec<usize>>;

pub fn build_symbol_index(rules: &[Rule]) -> SymbolIndex {
    let mut idx: SymbolIndex = HashMap::new();
    for (i, rule) in rules.iter().enumerate() {
        for sym in &rule.symbols {
            idx.entry(sym.clone()).or_default().push(i);
        }
    }
    idx
}

pub fn load_rules(
    root: &Path,
    config_path: Option<&Path>,
    rules_path: Option<&str>,
) -> Result<Vec<Rule>> {
    let raw = if let Some(rp) = rules_path {
        let p = PathBuf::from(rp);

        // If rules_path is relative, resolve relative to the config.json folder (nice UX).
        let base = config_path.and_then(|p| p.parent()).unwrap_or(root);

        let abs = if p.is_absolute() { p } else { base.join(p) };

        fs::read_to_string(&abs)
            .with_context(|| format!("failed reading rules file: {}", abs.display()))?
    } else {
        DEFAULT_RULES_JSON.to_string()
    };

    let pack: RulePack = serde_json::from_str(&raw).context("failed parsing rules JSON")?;

    if pack.version != 1 {
        anyhow::bail!("unsupported rules pack version: {}", pack.version);
    }

    Ok(pack.rules)
}
