//! `mosskeys completions` — print the shell completion script for one shell
//! to stdout.
//!
//! The script is generated from this same CLI definition (clap_complete), so
//! subcommands and flags can never drift out of sync with the parser. Install
//! it into the shell's completion directory and subcommands/flags complete on
//! <TAB> in NEW shells (the current shell has already cached its command
//! table — that is also why a just-installed binary does not tab-complete its
//! name until `rehash`).

use clap::Args;

/// `mosskeys completions <SHELL>` — print the completion script to stdout.
#[derive(Debug, Args)]
#[command(after_long_help = "EXAMPLES:\n\
    \x20   # zsh (macOS + Homebrew prefix; site-functions is on the default fpath):\n\
    \x20   mosskeys completions zsh > \"$(brew --prefix)/share/zsh/site-functions/_mosskeys\"\n\
    \n\
    \x20   # bash (per-user dir, picked up by bash-completion):\n\
    \x20   mosskeys completions bash > ~/.local/share/bash-completion/completions/mosskeys\n\
    \n\
    \x20   # fish (per-user dir):\n\
    \x20   mosskeys completions fish > ~/.config/fish/completions/mosskeys.fish\n\
    \n\
    \x20   Homebrew installs do this for you: the formula wires these into\n\
    \x20   the brew-managed completion dirs at install time.")]
pub struct CompletionsArgs {
    /// The shell to generate the script for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Print the generated script to stdout.
///
/// Generated into memory first, then written in one go: clap_complete
/// `.expect()`s its writes, so a direct render would PANIC on EPIPE when the
/// consumer closes early (`completions zsh | head`). A closed pipe is a quiet
/// success instead — standard CLI behaviour, and no `unsafe` SIGPIPE games in
/// a `forbid(unsafe_code)` crate.
pub fn run(args: &CompletionsArgs) -> mosskeys_core::Result<()> {
    use clap::CommandFactory as _;
    use std::io::Write as _;

    let mut buf = Vec::new();
    clap_complete::generate(
        args.shell,
        &mut crate::cli::Cli::command(),
        "mosskeys",
        &mut buf,
    );
    match std::io::stdout()
        .write_all(&buf)
        .and_then(|_| std::io::stdout().flush())
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(mosskeys_core::Error::Io(format!(
            "writing completions to stdout: {e}"
        ))),
    }
}
