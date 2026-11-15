//! Structured event log + colored console reporting.

use crate::engine::Alert;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize)]
struct LogLine<'a> {
    ts: String,
    level: &'a str,
    signal: &'a str,
    score: u32,
    message: &'a str,
    evidence: &'a [String],
    metrics: &'a [(String, String)],
}

pub struct Reporter {
    log_path: PathBuf,
    use_color: bool,
}

impl Reporter {
    pub fn new(state_dir: &std::path::Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let log_path = state_dir.join("ransomguard-events.jsonl");
        Ok(Self {
            log_path,
            use_color: std::io::IsTerminal::is_terminal(&std::io::stdout()),
        })
    }

    pub fn report(&self, alert: &Alert, actions: &[String]) {
        let level = match alert.level {
            crate::engine::AlertLevel::Critical => "CRITICAL",
            crate::engine::AlertLevel::Warning => "WARNING",
        };
        // JSONL append (the durable audit trail).
        let line = LogLine {
            ts: chrono::DateTime::from_timestamp(alert.ts, 0)
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| alert.ts.to_string()),
            level,
            signal: &alert.signal,
            score: alert.score,
            message: &alert.message,
            evidence: &alert.evidence,
            metrics: &alert.metrics,
        };
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        {
            if let Ok(json) = serde_json::to_string(&line) {
                let _ = writeln!(f, "{json}");
            }
        }

        // Console rendering.
        let (red, yellow, reset, bold) = if self.use_color {
            ("\x1b[31m", "\x1b[33m", "\x1b[0m", "\x1b[1m")
        } else {
            ("", "", "", "")
        };
        let color = match alert.level {
            crate::engine::AlertLevel::Critical => red,
            crate::engine::AlertLevel::Warning => yellow,
        };
        println!(
            "\n{bold}{color}========== {level} [{}/100] {}{reset}",
            alert.score, alert.signal
        );
        println!("{color}{}{reset}", alert.message);
        if !alert.evidence.is_empty() {
            println!("相关文件 (最多 {} 个):", alert.evidence.len());
            for e in &alert.evidence {
                println!("  - {e}");
            }
        }
        for (k, v) in &alert.metrics {
            println!("  {k} = {v}");
        }
        for a in actions {
            println!("{bold}  -> {a}{reset}");
        }
    }
}
