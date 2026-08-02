mod autostart;
mod cli;
mod gpgconf;
mod logging;
mod relay;
mod serve;
mod socketfile;
mod status;
mod win;

use std::process::ExitCode;

/// The crate version, carrying the git description of the build when there was
/// a checkout to read one from.
pub fn version() -> String {
    match option_env!("HEDWIG_GIT_DESCRIBE") {
        Some(describe) => format!("{} ({describe})", env!("CARGO_PKG_VERSION")),
        None => env!("CARGO_PKG_VERSION").to_string(),
    }
}

pub fn run() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let cmd = match cli::parse(&args) {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    let result = match cmd {
        cli::Cmd::Serve(cfg) => serve::run(&cfg),
        cli::Cmd::Install(cfg) => autostart::install(&cfg),
        cli::Cmd::Uninstall => autostart::uninstall(),
        cli::Cmd::Status(cfg) => status::run(&cfg),
        cli::Cmd::Version => {
            println!("hedwig {}", version());
            Ok(())
        }
        cli::Cmd::Help => {
            println!("{}", cli::USAGE);
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
