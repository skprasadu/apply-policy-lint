use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
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

        #[arg(long, default_value = "out/swift_policy_report.md")]
        report: PathBuf,

        #[arg(long, default_value = "out/swift_policy_report.json")]
        json: PathBuf,

        #[arg(long)]
        github_annotations: bool,
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
            "systemFreeSize",
            "systemSize",
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

#[derive(Serialize)]
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

#[derive(Serialize)]
struct Report {
    count: usize,
    issues: Vec<Issue>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Lint {
            root,
            report,
            json,
            github_annotations,
        } => run_lint(&root, &report, &json, github_annotations),
    }
}

fn run_lint(root: &Path, report_md: &Path, report_json: &Path, github_annotations: bool) -> Result<()> {
    if !root.exists() {
        anyhow::bail!("--root does not exist: {}", root.display());
    }

    let mut parser = TsParser::new();
    let language = tree_sitter_swift::LANGUAGE.into();
    parser
        .set_language(&language)
        .context("failed to load tree-sitter Swift language")?;

    let mut issues: Vec<Issue> = vec![];

    for entry in WalkDir::new(root).follow_links(true) {
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

        let src_bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let src_str = match std::str::from_utf8(&src_bytes) {
            Ok(s) => s,
            Err(_) => {
                // Skip non-UTF8 files explicitly
                continue;
            }
        };

        let tree = match parser.parse(src_str, None) {
            Some(t) => t,
            None => continue,
        };

        let file_display = path_to_repo_relative(path);
        scan_tree(tree.root_node(), src_str.as_bytes(), &file_display, &mut issues);
    }

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
            // Use ::error for PoC so it’s loud
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

fn scan_tree(node: Node, src: &[u8], file: &str, issues: &mut Vec<Issue>) {
    // Heuristic: match ANY node type containing "identifier" to avoid depending on exact Swift grammar node names.
    // This still buys us: no false positives from comments/strings.
    let kind_lc = node.kind().to_ascii_lowercase();
    if kind_lc.contains("identifier") {
        if let Ok(text) = node.utf8_text(src) {
            for rule in RULES {
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
        scan_tree(child, src, file, issues);
    }
}

fn render_markdown(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("<!-- swift-policy-bot -->\n");
    out.push_str("## 🍏 Apple Policy Lint (Swift AST)\n\n");
    out.push_str(&format!("Found **{}** potential policy-relevant API usages.\n\n", report.count));

    if report.count == 0 {
        out.push_str("✅ No issues found.\n");
        return out;
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
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

fn path_to_repo_relative(path: &Path) -> String {
    // Best-effort: make paths pretty in GitHub UI
    // If canonicalize fails, just return the display form.
    let cwd = std::env::current_dir().ok();
    if let Some(cwd) = cwd {
        if let Ok(abs) = path.canonicalize() {
            if let Ok(cwd_abs) = cwd.canonicalize() {
                if let Ok(rel) = abs.strip_prefix(&cwd_abs) {
                    return rel.display().to_string();
                }
            }
        }
    }
    path.display().to_string()
}