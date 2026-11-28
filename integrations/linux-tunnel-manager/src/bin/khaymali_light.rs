use khaymali_manager::kmlight::config::KmLightConfig;
use khaymali_manager::kmlight::link::Link;
use khaymali_manager::system::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut config = PathBuf::from("/etc/khaymali-light/config.json");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" | "-V" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--config" => {
                if let Some(p) = args.next() {
                    config = PathBuf::from(p);
                }
            }
            "-h" | "--help" => {
                println!("khaymali-light [--config PATH] [--version]");
                return Ok(());
            }
            _ => {}
        }
    }
    let cfg = KmLightConfig::load(&config)?;
    Link::run(cfg)
}
