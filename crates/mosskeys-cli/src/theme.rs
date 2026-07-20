//! CLI theme — a terminal personality mirroring the MossKeys web brand (#343).
//!
//! The web design system in `assets/css/app.css` builds on an emerald→cyan
//! gradient (`--color-brand-*` → `--color-cyber-*`) over an ink base, in a
//! JetBrains-Mono voice. This module reproduces that identity in the terminal
//! with 24-bit ANSI: a gradient banner, consistent status glyphs, and a brand
//! accent — so the paid product feels like one product across web and CLI.
//!
//! ## Respecting the environment
//! Colour is enabled only when ALL of the following hold:
//!   * `NO_COLOR` is unset (the informal standard), and
//!   * output is a TTY, and
//!   * we are not in `--json` mode (machine output is never decorated).
//!
//! Otherwise every helper degrades to plain text, so pipes, CI logs, and JSON
//! consumers get clean bytes.

use std::io::IsTerminal;

/// A 24-bit RGB colour.
#[derive(Clone, Copy)]
struct Rgb(u8, u8, u8);

// Brand palette, sampled from the web design system's DARK-mode shades — a
// terminal is effectively dark mode, so we mirror exactly what `design_system.ex`
// renders on ink: `text-brand-400`, `emerald-300`, `amber-300`, `red-300`,
// `cyber-{300,400}`. This keeps the CLI pixel-consistent with the web brand.
const BRAND: Rgb = Rgb(52, 211, 153); // brand-400 / emerald-400 (dark brand text)
const BRAND_LIGHT: Rgb = Rgb(110, 231, 183); // emerald-300 (success)
const CYBER: Rgb = Rgb(34, 211, 238); // cyber-400 (gradient endpoint, accent)
const INK_DIM: Rgb = Rgb(148, 163, 184); // ink-300 (secondary text)
const DANGER: Rgb = Rgb(252, 165, 165); // red-300
const WARN: Rgb = Rgb(252, 211, 77); // amber-300

/// The active theme, resolved once from the environment.
#[derive(Clone, Copy)]
pub struct Theme {
    color: bool,
}

impl Theme {
    /// Resolve the theme. Pass `json = true` in machine-output mode.
    #[must_use]
    pub fn resolve(json: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let tty = std::io::stdout().is_terminal();
        Theme {
            color: !no_color && tty && !json,
        }
    }

    /// Whether colour output is active.
    #[must_use]
    pub fn color_enabled(self) -> bool {
        self.color
    }

    fn paint(self, Rgb(r, g, b): Rgb, s: &str) -> String {
        if self.color {
            format!("\x1b[38;2;{r};{g};{b}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn bold(self, s: &str) -> String {
        if self.color {
            format!("\x1b[1m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    /// Brand-accented text (emerald).
    #[must_use]
    pub fn brand(self, s: &str) -> String {
        self.paint(BRAND, s)
    }

    /// Cyber-accented text (cyan) — used for values/identifiers.
    #[must_use]
    pub fn accent(self, s: &str) -> String {
        self.paint(CYBER, s)
    }

    /// Muted secondary text.
    #[must_use]
    pub fn dim(self, s: &str) -> String {
        self.paint(INK_DIM, s)
    }

    /// A success line: `✓ …` in emerald (web `text-emerald-300`).
    #[must_use]
    pub fn success(self, s: &str) -> String {
        format!("{} {}", self.paint(BRAND_LIGHT, "✓"), s)
    }

    /// An informational line: `→ …`.
    #[must_use]
    pub fn info(self, s: &str) -> String {
        format!("{} {}", self.accent("→"), s)
    }

    /// A warning line: `! …` in amber.
    #[must_use]
    pub fn warn(self, s: &str) -> String {
        format!("{} {}", self.paint(WARN, "!"), s)
    }

    /// An error line: `✗ …` in danger red.
    #[must_use]
    pub fn error(self, s: &str) -> String {
        format!("{} {}", self.paint(DANGER, "✗"), s)
    }

    /// The gradient wordmark banner (emerald→cyan), or a plain wordmark when
    /// colour is disabled. Rendered once at the top of interactive commands.
    #[must_use]
    pub fn banner(self) -> String {
        const WORD: &str = "mosskeys";
        if !self.color {
            return WORD.to_string();
        }
        // Interpolate each glyph from brand-400 → cyber-400 for the gradient.
        let n = WORD.chars().count().max(1) - 1;
        let mut out = String::from("\x1b[1m");
        for (i, ch) in WORD.chars().enumerate() {
            let t = if n == 0 { 0.0 } else { i as f32 / n as f32 };
            let Rgb(r, g, b) = lerp(BRAND_LIGHT, CYBER, t);
            out.push_str(&format!("\x1b[38;2;{r};{g};{b}m{ch}"));
        }
        out.push_str("\x1b[0m");
        out
    }

    /// A `key: value` field line with a muted key and accented value.
    #[must_use]
    pub fn field(self, key: &str, value: &str) -> String {
        format!("  {} {}", self.dim(&format!("{key}:")), self.accent(value))
    }

    /// Bold text passthrough (used for headings).
    #[must_use]
    pub fn heading(self, s: &str) -> String {
        self.bold(&self.brand(s))
    }

    /// A passed check line: `✓ …` in emerald. (Alias of [`Theme::success`], read
    /// at the `verify` call sites as a verification result rather than a status.)
    #[must_use]
    pub fn check_pass(self, s: &str) -> String {
        self.success(s)
    }

    /// A skipped / not-checked line: `· …`, fully muted, so it reads as neutral
    /// (neither a pass nor a failure) in the check column.
    #[must_use]
    pub fn check_skip(self, s: &str) -> String {
        format!("{} {}", self.dim("·"), self.dim(s))
    }

    /// An aligned `key   value` detail row: a muted, left-padded key and an
    /// accented value, indented under the check lines for visual hierarchy.
    #[must_use]
    pub fn kv(self, key: &str, value: &str) -> String {
        format!(
            "  {}  {}",
            self.dim(&format!("{key:<6}")),
            self.accent(value)
        )
    }
}

fn lerp(a: Rgb, b: Rgb, t: f32) -> Rgb {
    let f = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
    Rgb(f(a.0, b.0), f(a.1, b.1), f(a.2, b.2))
}
