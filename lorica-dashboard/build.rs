use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let frontend_dir = Path::new("frontend");

    // Re-run build.rs when frontend sources change
    println!("cargo:rerun-if-changed=frontend/src");
    println!("cargo:rerun-if-changed=frontend/index.html");
    println!("cargo:rerun-if-changed=frontend/package.json");
    println!("cargo:rerun-if-changed=frontend/vite.config.ts");

    // Skip frontend build if SKIP_FRONTEND_BUILD is set (for CI or quick Rust-only builds)
    if env::var("SKIP_FRONTEND_BUILD").is_ok() {
        ensure_dist_exists(frontend_dir);
        return;
    }

    // Install npm dependencies if node_modules is missing
    let node_modules = frontend_dir.join("node_modules");
    if !node_modules.exists() {
        let status = Command::new("npm")
            .arg("install")
            .current_dir(frontend_dir)
            .status()
            .expect("failed to run npm install - is Node.js installed?");
        assert!(status.success(), "npm install failed");
    }

    // Build the frontend
    let status = Command::new("npm")
        .args(["run", "build"])
        .current_dir(frontend_dir)
        .status()
        .expect("failed to run npm run build - is Node.js installed?");
    assert!(status.success(), "frontend build failed");
}

fn ensure_dist_exists(frontend_dir: &Path) {
    let dist = frontend_dir.join("dist");
    if !dist.exists() {
        std::fs::create_dir_all(&dist).expect("failed to create dist directory");
        // Create a minimal index.html so rust-embed has something to embed
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><html><body><p>Frontend not built. Run npm run build in lorica-dashboard/frontend/</p></body></html>",
        )
        .expect("failed to write placeholder index.html");
    }
}
