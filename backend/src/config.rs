use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen_address: String,
    pub max_concurrent_vms: usize,
    pub clang_path: PathBuf,
    pub includes_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub vmlinux_path: PathBuf,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
