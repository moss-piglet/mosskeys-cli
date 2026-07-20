//! MossKeys CLI entrypoint.
//!
//! Parses args, dispatches to a subcommand, and translates the result into a
//! stable process exit code (see [`output::exit`]). All error rendering funnels
//! through the [`output::Reporter`] so human and `--json` modes stay consistent.

// No `unsafe` in the binary either — mirrors the crypto/log core's posture.
#![forbid(unsafe_code)]

mod cli;
mod commands;
mod output;
mod theme;

use clap::Parser;

use cli::{Cli, Command};
use output::{Reporter, exit, exit_code};

fn main() {
    let cli = Cli::parse();
    let code = run(&cli);
    std::process::exit(code);
}

fn run(cli: &Cli) -> i32 {
    let reporter = Reporter::new(cli.global.json);
    reporter.banner();

    let result = match &cli.command {
        Command::Keygen(args) => commands::keygen::run(&cli.global, args),
        Command::Publish(args) => commands::publish::run(&cli.global, args),
        Command::Sync(args) => commands::sync::run(&cli.global, args),
        Command::Checkpoint(args) => commands::checkpoint::run(&cli.global, args),
        Command::Verify(args) => commands::verify::run(&cli.global, args),
        Command::Config(cmd) => commands::config::run(&cli.global, cmd),
    };

    match result {
        Ok(()) => exit::OK,
        Err(err) => {
            // Build a reporter honouring --json even if Ctx failed to load.
            Reporter::new(cli.global.json).report_error(&err);
            exit_code(&err)
        }
    }
}
