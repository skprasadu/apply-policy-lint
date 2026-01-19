use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use tree_sitter::{Node, Parser as TsParser};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Lint Swift sources under --root and emit reports
    Lint {
        #[arg(long, default_value = ".")]
        root: PathBuf,

        #[arg(long, default_value = "out/apple_policy_report.md")]
        report: PathBuf,

        #[arg(long, default_value = "out/apple_policy_report.json")]
        json: PathBuf,

        #[arg(long)]
        github_annotations: bool,

        /// Optional file containing newline-separated Swift file paths (relative to --root).
        /// If provided, only these files are scanned.
        #[arg(long)]
        paths_file: Option<PathBuf>,

        /// Optional baseline JSON report (same schema as output JSON).
        /// Used only when --only-new is set.
        #[arg(long)]
        baseline_json: Option<PathBuf>,

        /// If set, only report issues that are NOT present in the baseline_json.
        /// Requires --baseline-json.
        #[arg(long, default_value_t = false)]
        only_new: bool,

        /// Optional config JSON file for ignore rules/paths, etc.
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Clone, Copy)]
struct Rule {
    id: &'static str,
    category: &'static str,
    message: &'static str,
    symbols: &'static [&'static str],
}

// PoC HARD-CODED RULEPACK (replace with JSON policy book later)
const RULES: &[Rule] = &[
    Rule {
        id: "APPLE_REQUIRED_REASON_DISK_SPACE",
        category: "Required Reason API: Disk Space",
        message: "Potential Disk Space API usage detected. If this is real usage, ensure PrivacyInfo.xcprivacy declares NSPrivacyAccessedAPITypes with an approved reason.",
        symbols: &[
            "volumeAvailableCapacityKey",
            "volumeAvailableCapacityForImportantUsageKey",
            "volumeAvailableCapacityForOpportunisticUsageKey",
            "volumeTotalCapacityKey",
            "attributesOfFileSystem",
            // REMOVE these (too collision-prone):
            // "systemFreeSize",
            // "systemSize",
            "statfs",
            "fstatfs",
        ],
    },
    Rule {
        id: "APPLE_REQUIRED_REASON_ACTIVE_KEYBOARDS",
        category: "Required Reason API: Active Keyboards",
        message: "Potential Active Keyboards API usage detected. If this is real usage, ensure PrivacyInfo.xcprivacy declares NSPrivacyAccessedAPITypes with an approved reason.",
        symbols: &[
            "activeInputModes", // UITextInputMode.activeInputModes
        ],
    },
];

#[derive(Serialize, Deserialize, Clone)]
struct Issue {
    file: String,
    line: usize,
    column: usize,
    rule_id: String,
    category: String,
    symbol: String,
    message: String,
    snippet: String,
}

#[derive(Serialize, Deserialize)]
struct Report {
    count: usize,
    issues: Vec<Issue>,
}

#[derive(Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    ignore_rules: Vec<String>,

    #[serde(default)]
    ignore_paths: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Lint {
            root,
            report,
            json,
            github_annotations,
            paths_file,
            baseline_json,
            only_new,
            config,
        } => run_lint(
            &root,
            &report,
            &json,
            github_annotations,
            paths_file.as_deref(),
            baseline_json.as_deref(),
            only_new,
            config.as_deref(),
        ),
    }
}

fn run_lint(
    root: &Path,
    report_md: &Path,
    report_json: &Path,
    github_annotations: bool,
    paths_file: Option<&Path>,
    baseline_json: Option<&Path>,
    only_new: bool,
    config_path: Option<&Path>,
) -> Result<()> {
    if !root.exists() {
        anyhow::bail!("--root does not exist: {}", root.display());
    }

    if let Some(pf) = paths_file {
        if !pf.exists() {
            anyhow::bail!("--paths-file does not exist: {}", pf.display());
        }
    }

    if only_new && baseline_json.is_none() {
        anyhow::bail!("--only-new requires --baseline-json");
    }
    if let Some(b) = baseline_json {
        if !b.exists() {
            anyhow::bail!("--baseline-json does not exist: {}", b.display());
        }
    }

    let cfg = load_config(config_path)?;
    let ignore_rule_ids: HashSet<String> = cfg.ignore_rules.into_iter().collect();
    let ignore_path_prefixes: Vec<String> = cfg
        .ignore_paths
        .into_iter()
        .map(|s| normalize_slashes(&s))
        .collect();

    let targets = collect_swift_targets(root, paths_file, &ignore_path_prefixes)?;

    let mut parser = TsParser::new();
    let language = tree_sitter_swift::LANGUAGE.into();
    parser
        .set_language(&language)
        .context("failed to load tree-sitter Swift language")?;

    let mut issues: Vec<Issue> = vec![];

    for (abs_path, display_path) in targets {
        let src_bytes = match fs::read(&abs_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("WARN: failed to read {}: {}", abs_path.display(), e);
                continue;
            }
        };

        let src_str = match std::str::from_utf8(&src_bytes) {
            Ok(s) => s,
            Err(_) => {
                // Skip non-UTF8 files explicitly
                eprintln!("WARN: skipping non-UTF8 file: {}", abs_path.display());
                continue;
            }
        };

        let tree = match parser.parse(src_str, None) {
            Some(t) => t,
            None => {
                eprintln!("WARN: failed to parse file: {}", abs_path.display());
                continue;
            }
        };

        scan_tree(
            tree.root_node(),
            src_str.as_bytes(),
            &display_path,
            &ignore_rule_ids,
            &mut issues,
        );
    }

    // Baseline filtering (only-new)
    if only_new {
        if let Some(baseline_path) = baseline_json {
            let baseline = load_baseline(baseline_path)?;
            let baseline_set: HashSet<String> =
                baseline.issues.iter().map(issue_fingerprint).collect();

            issues.retain(|i| !baseline_set.contains(&issue_fingerprint(i)));
        }
    }

    // NEW: stable + set semantics
    sort_and_dedupe_issues(&mut issues);

    let report = Report {
        count: issues.len(),
        issues,
    };

    // Write JSON
    if let Some(parent) = report_json.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(report_json, serde_json::to_string_pretty(&report)?)
        .with_context(|| format!("failed writing JSON report: {}", report_json.display()))?;

    // Write Markdown
    if let Some(parent) = report_md.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(report_md, render_markdown(&report))
        .with_context(|| format!("failed writing Markdown report: {}", report_md.display()))?;

    // GitHub annotations
    if github_annotations {
        for issue in &report.issues {
            println!(
                "::error file={},line={},col={}::{}",
                issue.file,
                issue.line,
                issue.column,
                escape_workflow_command(&issue.message)
            );
        }
    }

    Ok(())
}

fn load_config(config_path: Option<&Path>) -> Result<ConfigFile> {
    let Some(path) = config_path else {
        return Ok(ConfigFile::default());
    };

    if !path.exists() {
        anyhow::bail!("--config does not exist: {}", path.display());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading config: {}", path.display()))?;

    let cfg: ConfigFile = serde_json::from_str(&raw)
        .with_context(|| format!("failed parsing JSON config: {}", path.display()))?;

    Ok(cfg)
}

fn load_baseline(path: &Path) -> Result<Report> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading baseline JSON: {}", path.display()))?;

    let rep: Report = serde_json::from_str(&raw)
        .with_context(|| format!("failed parsing baseline JSON: {}", path.display()))?;

    Ok(rep)
}

fn issue_fingerprint(i: &Issue) -> String {
    // Stable fingerprint (don’t include line/col; those churn).
    // Enough to suppress “same issue moved” noise.
    format!("{}|{}|{}", i.rule_id, i.file, i.symbol)
}

fn collect_swift_targets(
    root: &Path,
    paths_file: Option<&Path>,
    ignore_path_prefixes: &[String],
) -> Result<Vec<(PathBuf, String)>> {
    let mut out: Vec<(PathBuf, String)> = vec![];
    let mut seen: HashSet<PathBuf> = HashSet::new();

    // Helper: only include a file once (canonical path identity).
    let mut push_unique = |abs: PathBuf, display: String| {
        let canon = fs::canonicalize(&abs).unwrap_or_else(|_| abs.clone());
        if seen.insert(canon) {
            out.push((abs, display));
        }
    };

    // --- Diff mode: use the provided paths list ---
    if let Some(pf) = paths_file {
        let raw = fs::read_to_string(pf)
            .with_context(|| format!("failed reading --paths-file: {}", pf.display()))?;

        for line in raw.lines() {
            let rel = line.trim();
            if rel.is_empty() {
                continue;
            }

            let display = normalize_slashes(rel);

            if !display.ends_with(".swift") {
                continue;
            }

            if is_ignored_path(&display, ignore_path_prefixes) {
                continue;
            }

            let abs = root.join(rel);
            if !abs.exists() {
                // In diff mode, a file can be deleted/renamed; don't fail the run.
                continue;
            }

            push_unique(abs, display);
        }

        // Stable ordering => stable reports
        out.sort_by(|a, b| a.1.cmp(&b.1));
        return Ok(out);
    }

    // --- Full scan mode: walk repo, but PRUNE ignored dirs early ---
    let walker = WalkDir::new(root)
        .follow_links(false) // safer default; avoids wandering outside repo
        .into_iter()
        .filter_entry(|e| {
            // Always keep the root itself
            if e.depth() == 0 {
                return true;
            }
            let rel = repo_relative(root, e.path());
            !is_ignored_path(&rel, ignore_path_prefixes)
        });

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("swift") {
            continue;
        }

        let display = repo_relative(root, path);
        // We already prune dirs, but keep this for safety on files:
        if is_ignored_path(&display, ignore_path_prefixes) {
            continue;
        }

        push_unique(path.to_path_buf(), display);
    }

    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

fn repo_relative(root: &Path, path: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(root) {
        normalize_slashes(&rel.display().to_string())
    } else {
        normalize_slashes(&path.display().to_string())
    }
}

fn normalize_slashes(s: &str) -> String {
    s.replace('\\', "/").trim_start_matches("./").to_string()
}

fn is_ignored_path(path: &str, ignore_prefixes: &[String]) -> bool {
    let p = normalize_slashes(path);
    for raw_prefix in ignore_prefixes {
        let pref = normalize_slashes(raw_prefix)
            .trim_end_matches('/')
            .to_string();
        if pref.is_empty() {
            continue;
        }
        if p == pref || p.starts_with(&(pref.clone() + "/")) {
            return true;
        }
    }
    false
}

fn scan_tree(
    node: Node,
    src: &[u8],
    file: &str,
    ignore_rule_ids: &HashSet<String>,
    issues: &mut Vec<Issue>,
) {
    // Heuristic: match ANY node type containing "identifier" to avoid depending on exact Swift grammar node names.
    // This still buys us: no false positives from comments/strings.
    let kind_lc = node.kind().to_ascii_lowercase();
    if kind_lc.contains("identifier") {
        if let Ok(text) = node.utf8_text(src) {
            for rule in RULES {
                if ignore_rule_ids.contains(rule.id) {
                    continue;
                }

                if rule.symbols.iter().any(|s| *s == text) {
                    let pos = node.start_position();
                    let line = pos.row + 1;
                    let col = pos.column + 1;
                    let snippet = extract_line(src, node.start_byte());

                    issues.push(Issue {
                        file: file.to_string(),
                        line,
                        column: col,
                        rule_id: rule.id.to_string(),
                        category: rule.category.to_string(),
                        symbol: text.to_string(),
                        message: format!("{} (symbol: `{}`)", rule.message, text),
                        snippet,
                    });
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        scan_tree(child, src, file, ignore_rule_ids, issues);
    }
}

fn render_markdown(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("<!-- apple-policy-bot -->\n");
    out.push_str("##🍏 Apple Policy Lint (Swift AST)\n\n");
    if report.count == 0 {
        out.push_str("No policy-relevant API usage detected.\n\n");
    } else {
        out.push_str(&format!(
            "**Findings:** Found **{}** potential policy-relevant API usages.\n\n",
            report.count
        ));
    }

    out.push_str("| Category | Symbol | File | Line | Rule |\n");
    out.push_str("|---|---|---|---:|---|\n");
    for i in &report.issues {
        out.push_str(&format!(
            "| {} | `{}` | `{}` | {} | `{}` |\n",
            i.category, i.symbol, i.file, i.line, i.rule_id
        ));
    }

    out.push_str("\n### Details\n");
    for i in &report.issues {
        out.push_str(&format!(
            "- **{}** in `{}`:{}:{}  \n  Rule: `{}`  \n  {}\n",
            i.symbol, i.file, i.line, i.column, i.rule_id, i.message
        ));
        if !i.snippet.is_empty() {
            out.push_str("  ```swift\n");
            out.push_str(&i.snippet);
            out.push_str("\n  ```\n");
        }
        out.push('\n');
    }

    out.push_str(
        "### Notes\n\
- This is a PoC hardcoded rulepack.\n\
- Next step is to move RULES into JSON policy files and add allowlists/justifications.\n",
    );

    out
}

fn extract_line(src: &[u8], byte_idx: usize) -> String {
    if byte_idx >= src.len() {
        return String::new();
    }
    // Find line start
    let mut start = byte_idx;
    while start > 0 && src[start - 1] != b'\n' {
        start -= 1;
    }
    // Find line end
    let mut end = byte_idx;
    while end < src.len() && src[end] != b'\n' {
        end += 1;
    }
    String::from_utf8_lossy(&src[start..end]).to_string()
}

fn escape_workflow_command(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn sort_and_dedupe_issues(issues: &mut Vec<Issue>) {
    issues.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.rule_id.cmp(&b.rule_id))
            .then(a.symbol.cmp(&b.symbol))
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });

    let mut seen: HashSet<String> = HashSet::new();
    issues.retain(|i| seen.insert(issue_fingerprint(i)));
}
