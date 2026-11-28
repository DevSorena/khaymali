use khaymali_manager::config::ensure_state_dir;
use khaymali_manager::managers::persistence;
use khaymali_manager::menu;
use khaymali_manager::protocols::cleanup::auto_cleanup;
use khaymali_manager::system::{check_root, Result};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") | Some("-V") => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--restore") => {
            check_root()?;
            ensure_state_dir().ok();
            persistence::restore_all()
        }
        Some("--clean") => {
            check_root()?;
            auto_cleanup(true);
            Ok(())
        }
        Some("-h") | Some("--help") => {
            println!("khaymali-manager [ --restore | --clean | --version ]");
            Ok(())
        }
        _ => menu::main_menu(),
    }
}
