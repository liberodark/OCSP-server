use clap::{crate_authors, Parser};
use ocsp::common::asn1::Bytes;
use serde::Deserialize;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[clap(
    author = crate_authors!("\n"),
    before_help = "This script listens and answers to OCSP requests/response.",
    after_help = "A config file is required for the script to work.",
    help_template = "\
    {name} {version}
    Authors: {author-section}
    {before-help}
    About: {about-with-newline}
    {usage-heading} {usage}

    {all-args}{after-help}
    "
)]
#[command(version, author, about, long_about = None)]
pub(crate) struct Cli {
    #[arg(default_value = "config.toml")]
    pub(crate) config_path: String,
}

pub(crate) const CACHEFORMAT: &str = "%Y-%m-%d-%H-%M-%S";
pub(crate) const DEFAULT_PORT: u16 = 9000;
pub(crate) const DEFAULT_TIMEOUT: u8 = 5;
pub(crate) const DEFAULT_MYSQL_PORT: u16 = 3306;
pub(crate) const DEFAULT_POSTGRES_PORT: u16 = 5432;

#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) issuer_hash: (Vec<u8>, Vec<u8>, bool),
    pub(crate) cert: Bytes,
    pub(crate) revocextended: bool,
    pub(crate) time: u8,
    pub(crate) rsakey: ring::signature::RsaKeyPair,
    pub(crate) cachedays: u16,
    pub(crate) caching: bool,
    pub(crate) dbip: Option<String>,
    pub(crate) dbuser: String,
    pub(crate) dbpassword: String,
    pub(crate) dbname: String,
    pub(crate) db_type: String,
    pub(crate) dbport: Option<u16>,
    pub(crate) create_table: bool,
    pub(crate) cachefolder: String,
}

impl Drop for Config {
    fn drop(&mut self) {
        self.dbip.zeroize();
        self.dbuser.zeroize();
        self.dbpassword.zeroize();
        self.dbname.zeroize();
    }
}

#[derive(Deserialize)]
pub(crate) struct Fileconfig {
    pub(crate) cachedays: u16,
    pub(crate) caching: Option<bool>,
    pub(crate) revocextended: Option<bool>,
    pub(crate) dbip: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) timeout: Option<u8>,
    pub(crate) dbuser: String,
    pub(crate) dbpassword: String,
    pub(crate) dbname: String,
    pub(crate) db_type: Option<String>,
    pub(crate) dbport: Option<u16>,
    pub(crate) create_table: Option<bool>,
    pub(crate) cachefolder: String,
    pub(crate) itkey: String,
    pub(crate) itcert: String,
}

impl Drop for Fileconfig {
    fn drop(&mut self) {
        self.dbip.zeroize();
        self.dbuser.zeroize();
        self.dbpassword.zeroize();
        self.dbname.zeroize();
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Certinfo {
    pub(crate) status: String,
    pub(crate) revocation_time: Option<mysql::Value>,
    pub(crate) revocation_reason: Option<String>,
}
