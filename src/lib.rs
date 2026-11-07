//! Cargo Guard: flags outdated or yanked crates.io dependencies in a manifest.
//!
//! Everything is read-only. Declared dependencies come from Cargo.toml (with
//! `workspace = true` resolved from the workspace root manifest), locked
//! versions from Cargo.lock, freshness from the crates.io sparse index. No
//! `cargo` process runs and no file is written.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use openidea_plugin::{
    Context, Diagnostic, Error, Event, EventKind, HttpRequest, Invocation, LogLevel, Plugin, Position,
    Project, Range, Severity, host, register_plugin,
};
use semver::{Version, VersionReq};

type Table = toml::Table;
type Toml = toml::Value;

const CACHE_PREFIX: &str = "crate:";
const DEFAULT_REFRESH_HOURS: u64 = 24;
const MANIFEST_LIMIT: u32 = 200;

#[derive(Default)]
pub struct Main {}

impl Plugin for Main {
    fn activate(&mut self, _ctx: &Context) -> Result<(), Error> {
        host::subscribe(EventKind::FileOpened)?;
        host::subscribe(EventKind::FileSaved)?;
        Ok(())
    }

    fn run_command(&mut self, id: &str, ctx: &Invocation, _arg: Option<&str>) -> Result<Option<String>, Error> {
        match id {
            "check-deps" => {
                let project = ctx.project().ok_or("没有打开的项目 / No project is open")?;
                let manifests = manifests_in(&project);
                if manifests.is_empty() {
                    return Err("没有找到 Cargo.toml / No Cargo.toml found".into());
                }
                Ok(Some(check(ctx, &manifests)?.summary()))
            }
            "clear-cache" => {
                let mut removed = 0;
                for key in host::storage::keys(CACHE_PREFIX).unwrap_or_default() {
                    if host::storage::delete(&key).is_ok() {
                        removed += 1;
                    }
                }
                Ok(Some(format!("已清空 {removed} 条 crates.io 缓存 / Cleared {removed} cached crates.io responses")))
            }
            _ => Err(format!("未知命令 / Unknown command {id}").into()),
        }
    }

    fn handle_events(&mut self, events: &[Event], ctx: &Invocation) {
        let mut manifests: Vec<String> = events
            .iter()
            .filter_map(|event| match event {
                Event::FileOpened(path) | Event::FileSaved(path) if is_cargo_toml(path) => Some(path.clone()),
                _ => None,
            })
            .collect();
        if manifests.is_empty() {
            return;
        }
        manifests.sort();
        manifests.dedup();
        if let Err(error) = check(ctx, &manifests) {
            host::log(LogLevel::Warn, &format!("Cargo Guard: {error}"));
        }
    }
}

register_plugin!(Main);

fn is_cargo_toml(path: &str) -> bool {
    path == "Cargo.toml" || path.ends_with("/Cargo.toml")
}

#[derive(Default)]
struct Outcome {
    manifests: usize,
    deps: usize,
    outdated: usize,
    yanked: usize,
    network: usize,
    unresolved: usize,
    lock_missing: usize,
}

impl Outcome {
    fn summary(&self) -> String {
        let mut zh = format!(
            "检查完成：{} 个清单，{} 个直接依赖，{} 个可升级，{} 个已被撤回",
            self.manifests, self.deps, self.outdated, self.yanked
        );
        let mut en = format!(
            "Checked {} manifest(s), {} direct dependency(ies): {} outdated, {} yanked",
            self.manifests, self.deps, self.outdated, self.yanked
        );
        if self.network > 0 {
            zh.push_str(&format!("，{} 个未查到（索引不可用）", self.network));
            en.push_str(&format!("; {} could not be checked (index unavailable)", self.network));
        }
        if self.unresolved > 0 {
            zh.push_str(&format!("，{} 个不在 Cargo.lock 中（锁文件可能过期）", self.unresolved));
            en.push_str(&format!("; {} missing from Cargo.lock (the lock may be stale)", self.unresolved));
        }
        if self.lock_missing > 0 {
            zh.push_str(&format!("；{} 个清单没有 Cargo.lock，已跳过", self.lock_missing));
            en.push_str(&format!("; {} manifest(s) skipped without Cargo.lock", self.lock_missing));
        }
        format!("{zh}\n{en}")
    }
}

#[derive(Debug)]
struct Declared {
    /// Key as written in this manifest (the rename, if any).
    key: String,
    /// Actual crates.io package name.
    package: String,
    req: Option<String>,
    /// Disabled optional deps are often absent from Cargo.lock; stay quiet then.
    optional: bool,
}

#[derive(Debug)]
struct Locked {
    name: String,
    version: String,
}

struct Workspace {
    dir: String,
    deps: Option<Table>,
}

fn check(ctx: &Invocation, manifests: &[String]) -> Result<Outcome, Error> {
    let project = ctx.project().ok_or("没有打开的项目")?;
    let include_dev = host::setting_bool("includeDev").unwrap_or(false);
    let ttl = host::setting_number("refreshHours").unwrap_or(DEFAULT_REFRESH_HOURS as f64).max(0.0) as u64 * 3600;

    let mut outcome = Outcome::default();
    let mut locks: HashMap<String, Option<Vec<Locked>>> = HashMap::new();

    for path in manifests {
        let Ok(text) = project.read_file(path) else { continue };
        let Ok(manifest) = toml::from_str::<Table>(&text) else { continue };
        // A virtual workspace root declares no dependencies of its own.
        if manifest.get("package").is_none() {
            continue;
        }
        outcome.manifests += 1;

        let workspace = workspace_for(&project, path, &manifest);
        let lock_path = join(&workspace.dir, "Cargo.lock");
        let locked = locks
            .entry(lock_path.clone())
            .or_insert_with(|| project.read_file(&lock_path).ok().map(|text| parse_lock(&text)));
        let Some(locked) = locked.as_deref() else {
            outcome.lock_missing += 1;
            host::publish_diagnostics(path, &[])?;
            continue;
        };

        let declared = declared_deps(&manifest, workspace.deps.as_ref(), include_dev);
        let mut items = Vec::new();
        let mut seen = HashSet::new();

        for dep in declared {
            if !seen.insert(dep.package.clone()) {
                continue;
            }
            outcome.deps += 1;
            let Some(resolved) = locked_version(locked, &dep.package, dep.req.as_deref()) else {
                if !dep.optional {
                    outcome.unresolved += 1;
                }
                continue;
            };
            let Some(info) = crate_info(&dep.package, &resolved, ttl) else {
                outcome.network += 1;
                continue;
            };
            let Some((severity, message, code, kind)) = describe(&dep, &resolved, &info) else {
                continue;
            };
            if kind == "outdated" {
                outcome.outdated += 1;
            } else {
                outcome.yanked += 1;
            }
            let mut diagnostic = Diagnostic::new(line_range(&text, &dep.key), severity, message).code(code);
            diagnostic.source = Some("cargo-guard".into());
            items.push(diagnostic);
        }
        host::publish_diagnostics(path, &items)?;
    }

    Ok(outcome)
}

fn describe(
    dep: &Declared,
    resolved: &str,
    info: &CrateInfo,
) -> Option<(Severity, String, &'static str, &'static str)> {
    if info.yanked {
        return Some((
            Severity::Warning,
            format!(
                "{} {} 已被 crates.io 撤回（yanked），最新稳定版为 {}\n{} {} has been yanked from crates.io; latest stable is {}",
                dep.package, resolved, info.latest, dep.package, resolved, info.latest
            ),
            "yanked",
            "yanked",
        ));
    }
    let current = Version::parse(resolved).ok()?;
    let latest = Version::parse(&info.latest).ok()?;
    if current >= latest {
        return None;
    }
    let parsed = match dep.req.as_deref() {
        Some(req) => Some(VersionReq::parse(req).ok()?),
        None => None,
    };
    let (zh_advice, en_advice) = match parsed {
        Some(req) if req.matches(&latest) => (
            format!("可运行 cargo update -p {}", dep.package),
            format!("run cargo update -p {}", dep.package),
        ),
        Some(_) => (
            "当前版本约束不允许，需要手动改 Cargo.toml".to_string(),
            "the version requirement blocks it; edit Cargo.toml".to_string(),
        ),
        None => (
            format!("可运行 cargo update -p {}", dep.package),
            format!("run cargo update -p {}", dep.package),
        ),
    };
    Some((
        Severity::Info,
        format!(
            "{} {} → {}（crates.io 最新稳定版），{}\n{} {} → {} (latest stable on crates.io); {}",
            dep.package, resolved, info.latest, zh_advice, dep.package, resolved, info.latest, en_advice
        ),
        "outdated",
        "outdated",
    ))
}

fn manifests_in(project: &Project) -> Vec<String> {
    let mut found = project.find_files("**/Cargo.toml", MANIFEST_LIMIT).unwrap_or_default();
    found.retain(|path| !is_generated(path));
    if found.is_empty() {
        if let Ok(root) = project.root() {
            let candidate = join(root.trim_end_matches('/'), "Cargo.toml");
            if project.read_file(&candidate).is_ok() {
                found.push(candidate);
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

fn is_generated(path: &str) -> bool {
    ["/vendor/", "/target/", "/.cargo/"].iter().any(|marker| path.contains(marker))
}

/// The workspace containing `manifest`: nearest ancestor whose Cargo.toml has a
/// `[workspace]` table, else the manifest's own directory.
fn workspace_for(project: &Project, manifest_path: &str, manifest: &Table) -> Workspace {
    let own_dir = dir_of(manifest_path).to_owned();
    let own_deps = manifest
        .get("workspace")
        .and_then(Toml::as_table)
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(Toml::as_table)
        .cloned();
    if manifest.get("workspace").is_some() {
        return Workspace { dir: own_dir, deps: own_deps };
    }

    let project_root = project.root().unwrap_or_default();
    let project_root = project_root.trim_end_matches('/');
    let mut dir = dir_of(manifest_path).to_owned();
    loop {
        if !dir.is_empty() && dir != "/" {
            let candidate = join(&dir, "Cargo.toml");
            if candidate != manifest_path {
                if let Ok(text) = project.read_file(&candidate) {
                    if let Ok(root) = toml::from_str::<Table>(&text) {
                        if let Some(workspace) = root.get("workspace") {
                            let deps = workspace.get("dependencies").and_then(Toml::as_table).cloned();
                            return Workspace { dir, deps };
                        }
                    }
                }
            }
        }
        if dir.is_empty() || dir == "/" || dir == project_root {
            break;
        }
        dir = dir_of(&dir).to_owned();
    }
    Workspace { dir: own_dir, deps: own_deps }
}

/// Direct dependencies declared by this manifest, including target-specific
/// tables and `workspace = true` entries resolved from the workspace root.
fn declared_deps(manifest: &Table, workspace_deps: Option<&Table>, include_dev: bool) -> Vec<Declared> {
    const SECTIONS: [(&str, bool); 3] =
        [("dependencies", false), ("build-dependencies", false), ("dev-dependencies", true)];
    let mut out = Vec::new();
    for (section, dev) in SECTIONS {
        if dev && !include_dev {
            continue;
        }
        if let Some(table) = manifest.get(section).and_then(Toml::as_table) {
            collect(table, workspace_deps, &mut out);
        }
    }
    if let Some(targets) = manifest.get("target").and_then(Toml::as_table) {
        for target in targets.values() {
            let Some(table) = target.as_table() else { continue };
            for (section, dev) in SECTIONS {
                if dev && !include_dev {
                    continue;
                }
                if let Some(deps) = table.get(section).and_then(Toml::as_table) {
                    collect(deps, workspace_deps, &mut out);
                }
            }
        }
    }
    out
}

fn collect(table: &Table, workspace_deps: Option<&Table>, out: &mut Vec<Declared>) {
    for (key, value) in table {
        let (package, req, optional) = match value {
            Toml::String(req) => (key.clone(), Some(req.clone()), false),
            Toml::Table(entry) => {
                if is_foreign(entry) {
                    continue;
                }
                let optional = entry.get("optional").and_then(Toml::as_bool).unwrap_or(false);
                if entry.get("workspace").and_then(Toml::as_bool) == Some(true) {
                    let Some(inherited) = workspace_deps.and_then(|deps| deps.get(key)) else { continue };
                    match inherited {
                        Toml::String(req) => (key.clone(), Some(req.clone()), optional),
                        Toml::Table(entry) => {
                            if is_foreign(entry) {
                                continue;
                            }
                            let package = entry.get("package").and_then(Toml::as_str).unwrap_or(key);
                            (
                                package.to_owned(),
                                entry.get("version").and_then(Toml::as_str).map(str::to_owned),
                                optional,
                            )
                        }
                        _ => continue,
                    }
                } else {
                    let package = entry.get("package").and_then(Toml::as_str).unwrap_or(key);
                    (package.to_owned(), entry.get("version").and_then(Toml::as_str).map(str::to_owned), optional)
                }
            }
            _ => continue,
        };
        out.push(Declared { key: key.clone(), package, req, optional });
    }
}

/// Path, git and third-party-registry dependencies have no crates.io version.
fn is_foreign(entry: &Table) -> bool {
    entry.contains_key("path") || entry.contains_key("git") || entry.contains_key("registry")
}

fn parse_lock(text: &str) -> Vec<Locked> {
    let Ok(root) = toml::from_str::<Table>(text) else { return Vec::new() };
    let Some(packages) = root.get("package").and_then(Toml::as_array) else { return Vec::new() };
    packages
        .iter()
        .filter_map(|package| {
            let package = package.as_table()?;
            let name = package.get("name")?.as_str()?;
            let version = package.get("version")?.as_str()?;
            let source = package.get("source")?.as_str()?;
            source.contains("crates.io").then(|| Locked { name: name.into(), version: version.into() })
        })
        .collect()
}

fn locked_version(locked: &[Locked], package: &str, req: Option<&str>) -> Option<String> {
    let req = match req {
        Some(req) => Some(VersionReq::parse(req).ok()?),
        None => None,
    };
    locked
        .iter()
        .filter(|entry| entry.name == package)
        .filter_map(|entry| Version::parse(&entry.version).ok().map(|version| (version, entry.version.clone())))
        .filter(|(version, _)| req.as_ref().is_none_or(|req| req.matches(version)))
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, text)| text)
}

struct CrateInfo {
    latest: String,
    yanked: bool,
}

fn crate_info(name: &str, resolved: &str, ttl_secs: u64) -> Option<CrateInfo> {
    let key = format!("{CACHE_PREFIX}{name}@{resolved}");
    let cached = host::storage::get(&key).ok().flatten().and_then(|text| parse_cached(&text));
    if let Some(cached) = &cached {
        if cached.fresh(ttl_secs) {
            return Some(CrateInfo { latest: cached.latest.clone(), yanked: cached.yanked });
        }
    }
    match fetch_index(name, resolved) {
        Some(info) => {
            let entry = serde_json::json!({
                "latest": info.latest,
                "yanked": info.yanked,
                "at": now(),
            });
            let _ = host::storage::set(&key, &entry.to_string());
            Some(info)
        }
        // A failed refresh keeps yesterday's answer rather than no answer.
        None => cached.map(|cached| CrateInfo { latest: cached.latest, yanked: cached.yanked }),
    }
}

fn parse_cached(text: &str) -> Option<TimedCrateInfo> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let latest = value["latest"].as_str()?.to_owned();
    let yanked = value["yanked"].as_bool().unwrap_or(false);
    let at = value["at"].as_u64().unwrap_or(0);
    Some(TimedCrateInfo { latest, yanked, at })
}

struct TimedCrateInfo {
    latest: String,
    yanked: bool,
    at: u64,
}

impl TimedCrateInfo {
    fn fresh(&self, ttl_secs: u64) -> bool {
        ttl_secs > 0 && now().saturating_sub(self.at) <= ttl_secs
    }
}

fn fetch_index(name: &str, resolved: &str) -> Option<CrateInfo> {
    let url = format!("https://index.crates.io/{}", index_path(name));
    let mut request = HttpRequest::get(&url)
        .header("User-Agent", concat!("zaojiaoci.cargo-guard/", env!("CARGO_PKG_VERSION")))
        .header("Accept", "application/json");
    request.timeout_ms = Some(10_000);
    let response = host::fetch(&request).ok()?;
    if response.status != 200 {
        return None;
    }
    parse_index(&response.text(), resolved)
}

fn index_path(name: &str) -> String {
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

/// The sparse index is newline-delimited JSON, one line per published version.
fn parse_index(text: &str, resolved: &str) -> Option<CrateInfo> {
    let mut latest: Option<Version> = None;
    let mut latest_text = String::new();
    let mut yanked = false;

    for line in text.lines() {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let Some(version) = entry["vers"].as_str() else { continue };
        if entry["yanked"].as_bool() == Some(true) {
            yanked |= version == resolved;
            continue;
        }
        let Ok(parsed) = Version::parse(version) else { continue };
        if !parsed.pre.is_empty() {
            continue;
        }
        if latest.as_ref().is_none_or(|current| parsed > *current) {
            latest = Some(parsed);
            latest_text = version.to_owned();
        }
    }

    if latest_text.is_empty() {
        None
    } else {
        Some(CrateInfo { latest: latest_text, yanked })
    }
}

fn line_range(text: &str, key: &str) -> Range {
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let indent = (line.len() - trimmed.len()) as u32;
        let matched = trimmed
            .strip_prefix(key)
            .is_some_and(|rest| {
                let rest = rest.trim_start();
                rest.starts_with('=') || rest.starts_with('.')
            })
            || (trimmed.starts_with('[') && trimmed.contains(&format!(".{key}]")));
        if matched {
            return Range::new(
                Position::new(index as u32, indent),
                Position::new(index as u32, line.len() as u32),
            );
        }
    }
    Range::default()
}

fn dir_of(path: &str) -> &str {
    path.rfind('/').map_or("", |index| if index == 0 { "/" } else { &path[..index] })
}

fn join(dir: &str, file: &str) -> String {
    if dir.is_empty() {
        file.to_owned()
    } else if dir.ends_with('/') {
        format!("{dir}{file}")
    } else {
        format!("{dir}/{file}")
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openidea_plugin::HttpResponse;
    use openidea_plugin::mock::MockHost;

    const MANIFEST: &str = "/project/Cargo.toml";
    const LOCK: &str = "/project/Cargo.lock";

    const BASIC_MANIFEST: &str = "[package]\nname = \"myapp\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nold-crate = \"^0.5\"\nyanked-crate = \"2\"\nlocal = { path = \"local\" }\n\n[dev-dependencies]\ndev-only = \"0.1\"\n";
    const BASIC_LOCK: &str = "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"old-crate\"\nversion = \"0.5.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"yanked-crate\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"dev-only\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"transitive\"\nversion = \"9.9.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"local\"\nversion = \"0.1.0\"\n";

    fn index_lines(name: &str, versions: &[(&str, bool)]) -> String {
        versions
            .iter()
            .map(|(version, yanked)| {
                serde_json::json!({"name": name, "vers": version, "yanked": yanked}).to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn index(host: &MockHost) {
        host.on_fetch(|request| {
            let name = request.url.rsplit('/').next().unwrap_or_default();
            let body = match name {
                "serde" => index_lines("serde", &[("1.0.200", false), ("1.0.229", false), ("2.0.0", true)]),
                "old-crate" => index_lines("old-crate", &[("0.5.0", false), ("0.5.9", false), ("0.6.0-beta.1", false)]),
                "yanked-crate" => index_lines("yanked-crate", &[("1.9.0", false), ("2.0.0", true)]),
                "dev-only" => index_lines("dev-only", &[("0.1.0", false), ("0.2.0", false)]),
                _ => String::new(),
            };
            Ok(HttpResponse { status: 200, headers: vec![], body: body.into_bytes() })
        });
    }

    fn host() -> MockHost {
        let host = MockHost::install().with_capabilities(&[
            "project.read",
            "events",
            "net:index.crates.io",
            "storage",
        ]);
        host.add_file(MANIFEST, BASIC_MANIFEST);
        host.add_file(LOCK, BASIC_LOCK);
        index(&host);
        host
    }

    #[test]
    fn flags_outdated_and_yanked_direct_deps_only() {
        let host = host();
        let mut plugin = Main::default();
        plugin.activate(&host.context("zaojiaoci.cargo-guard")).unwrap();
        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());

        let items = host.diagnostics().get(MANIFEST).cloned().unwrap_or_default();
        assert_eq!(items.len(), 2, "{items:?}");

        let outdated = items.iter().find(|d| d.code.as_deref() == Some("outdated")).unwrap();
        assert_eq!(outdated.severity, Severity::Info);
        assert!(outdated.message.contains("old-crate 0.5.0 → 0.5.9"), "{}", outdated.message);
        assert!(outdated.message.contains("cargo update -p old-crate"), "{}", outdated.message);
        assert!(outdated.message.contains("latest stable on crates.io"), "{}", outdated.message);
        assert_eq!(outdated.range.start.line, 6);

        let yanked = items.iter().find(|d| d.code.as_deref() == Some("yanked")).unwrap();
        assert_eq!(yanked.severity, Severity::Warning);
        assert!(yanked.message.contains("已被 crates.io 撤回"), "{}", yanked.message);
        assert!(yanked.message.contains("has been yanked from crates.io"), "{}", yanked.message);
        assert_eq!(yanked.range.start.line, 7);

        // serde is at the latest stable; dev-only is excluded by default.
        assert!(items.iter().all(|d| !d.message.contains("serde")));
        assert!(items.iter().all(|d| !d.message.contains("dev-only")));
        assert!(items.iter().all(|d| !d.message.contains("local")));
        // No cargo process is involved.
        assert!(host.process_runs().is_empty());
    }

    #[test]
    fn resolves_workspace_inheritance_from_root_manifest() {
        let host = host();
        host.add_file(
            "/project/Cargo.toml",
            "[workspace]\nmembers = [\"app\"]\n\n[workspace.dependencies]\ninherited = { package = \"inherited-crate\", version = \"^0.1\" }\n",
        );
        let member = "/project/app/Cargo.toml";
        host.add_file(
            member,
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ninherited.workspace = true\nplain = \"1\"\n",
        );
        host.add_file(
            "/project/Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"inherited-crate\"\nversion = \"0.1.5\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"plain\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        );
        host.on_fetch(|request| {
            let body = match request.url.rsplit('/').next().unwrap_or_default() {
                "inherited-crate" => index_lines("inherited-crate", &[("0.1.5", false), ("0.2.0", false)]),
                "plain" => index_lines("plain", &[("1.0.0", false)]),
                _ => String::new(),
            };
            Ok(HttpResponse { status: 200, headers: vec![], body: body.into_bytes() })
        });

        let mut plugin = Main::default();
        plugin.handle_events(&[Event::FileSaved(member.into())], &host.invocation());

        let items = host.diagnostics().get(member).cloned().unwrap_or_default();
        assert_eq!(items.len(), 1, "{items:?}");
        assert!(items[0].message.contains("inherited-crate 0.1.5 → 0.2.0"), "{}", items[0].message);
        assert!(items[0].message.contains("需要手动改 Cargo.toml"), "{}", items[0].message);
        assert_eq!(items[0].range.start.line, 5);
        assert!(host.diagnostics().get("/project/Cargo.toml").is_none());
    }

    #[test]
    fn reports_renamed_dependency_by_real_name() {
        let host = host();
        host.add_file(
            "/project/Cargo.toml",
            "[package]\nname = \"myapp\"\n\n[dependencies]\nalias = { package = \"real-crate\", version = \"^1\" }\n",
        );
        host.add_file(
            "/project/Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"real-crate\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        );
        host.on_fetch(|_| {
            let body = index_lines("real-crate", &[("1.0.0", false), ("1.1.0", false)]);
            Ok(HttpResponse { status: 200, headers: vec![], body: body.into_bytes() })
        });

        let mut plugin = Main::default();
        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());

        let items = host.diagnostics().get(MANIFEST).cloned().unwrap_or_default();
        assert_eq!(items.len(), 1, "{items:?}");
        assert!(items[0].message.contains("real-crate 1.0.0 → 1.1.0"), "{}", items[0].message);
        assert_eq!(items[0].range.start.line, 4);
    }

    #[test]
    fn skips_manifest_without_lockfile() {
        let host = MockHost::install().with_capabilities(&["project.read", "net:index.crates.io", "storage"]);
        host.add_file(MANIFEST, "[package]\nname = \"myapp\"\n\n[dependencies]\nserde = \"1\"\n");
        index(&host);

        let mut plugin = Main::default();
        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());

        assert!(host.diagnostics().is_empty());
        assert!(host.requests().is_empty());
        let summary = plugin.run_command("check-deps", &host.invocation(), None).unwrap().unwrap();
        assert!(summary.contains("没有 Cargo.lock"), "{summary}");
    }

    #[test]
    fn ignores_transitive_and_non_manifest_events() {
        let host = host();
        let mut plugin = Main::default();
        plugin.handle_events(&[Event::FileSaved("/project/src/main.rs".into())], &host.invocation());
        assert!(host.requests().is_empty());
        assert!(host.diagnostics().is_empty());

        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());
        let items = host.diagnostics().get(MANIFEST).cloned().unwrap_or_default();
        assert!(items.iter().all(|d| !d.message.contains("transitive")));
    }

    #[test]
    fn includes_dev_dependencies_when_asked() {
        let host = host();
        host.set_setting("includeDev", "true");
        let mut plugin = Main::default();
        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());
        let items = host.diagnostics().get(MANIFEST).cloned().unwrap_or_default();
        assert!(items.iter().any(|d| d.message.contains("dev-only 0.1.0 → 0.2.0")), "{items:?}");
    }

    #[test]
    fn caches_index_answers() {
        let host = host();
        let mut plugin = Main::default();
        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());
        assert_eq!(host.requests().len(), 3, "serde, old-crate and yanked-crate; dev-only is off");

        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());
        assert_eq!(host.requests().len(), 3, "第二次应全部命中缓存");
        assert_eq!(host.storage().keys().filter(|key| key.starts_with(CACHE_PREFIX)).count(), 3);
    }

    #[test]
    fn clear_cache_empties_storage() {
        let host = host();
        let mut plugin = Main::default();
        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());
        assert!(!host.storage().is_empty());
        let out = plugin.run_command("clear-cache", &host.invocation(), None).unwrap();
        assert!(out.as_deref().unwrap().contains("Cleared 3"), "{out:?}");
        assert!(host.storage().is_empty());
    }

    #[test]
    fn offline_check_keeps_old_answers() {
        let host = host();
        let mut plugin = Main::default();
        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());
        let before = host.diagnostics().get(MANIFEST).cloned().unwrap_or_default();

        // Every cached answer expires, and the index is unreachable.
        host.set_setting("refreshHours", "0");
        host.on_fetch(|_| Err("network down".into()));
        plugin.handle_events(&[Event::FileSaved(MANIFEST.into())], &host.invocation());
        assert_eq!(host.diagnostics().get(MANIFEST).cloned().unwrap_or_default(), before);
    }

    #[test]
    fn disabled_optional_dep_missing_from_lock_is_quiet() {
        let host = MockHost::install().with_capabilities(&["project.read", "net:index.crates.io", "storage"]);
        host.add_file(
            MANIFEST,
            "[package]\nname = \"myapp\"\n\n[dependencies]\nserde = \"1\"\nopt = { version = \"1\", optional = true }\n",
        );
        host.add_file(
            LOCK,
            "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        );
        index(&host);

        let mut plugin = Main::default();
        let summary = plugin.run_command("check-deps", &host.invocation(), None).unwrap().unwrap();
        assert!(!summary.contains("不在 Cargo.lock 中"), "{summary}");
    }

    #[test]
    fn command_reports_summary() {
        let host = host();
        let mut plugin = Main::default();
        let summary = plugin.run_command("check-deps", &host.invocation(), None).unwrap().unwrap();
        assert!(summary.contains("1 个清单"), "{summary}");
        assert!(summary.contains("3 个直接依赖"), "{summary}");
        assert!(summary.contains("1 个可升级"), "{summary}");
        assert!(summary.contains("1 个已被撤回"), "{summary}");
        assert!(summary.contains("Checked 1 manifest"), "{summary}");
        assert!(summary.contains("1 outdated, 1 yanked"), "{summary}");
    }

    #[test]
    fn parses_this_crates_own_manifest_and_lock() {
        // Real files, not fixtures: catches format drift in Cargo.toml/Cargo.lock.
        let dir = env!("CARGO_MANIFEST_DIR");
        let manifest = toml::from_str::<Table>(&std::fs::read_to_string(format!("{dir}/Cargo.toml")).unwrap()).unwrap();
        let locked = parse_lock(&std::fs::read_to_string(format!("{dir}/Cargo.lock")).unwrap());

        let declared = declared_deps(&manifest, None, false);
        assert!(declared.iter().any(|dep| dep.package == "serde_json"), "{declared:?}");
        assert!(
            declared.iter().all(|dep| dep.package != "openidea-plugin"),
            "git dependencies are skipped: {declared:?}"
        );
        assert!(locked.iter().all(|entry| entry.name != "openidea-plugin"));
        for dep in &declared {
            assert!(
                locked_version(&locked, &dep.package, dep.req.as_deref()).is_some(),
                "{} should resolve from Cargo.lock",
                dep.package
            );
        }
    }

    #[test]
    fn index_paths_follow_crates_io_layout() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("serde"), "se/rd/serde");
    }

    #[test]
    fn parses_req_that_blocks_latest() {
        let dep = Declared {
            key: "pinned".into(),
            package: "pinned".into(),
            req: Some("=1.0.0".into()),
            optional: false,
        };
        let info = CrateInfo { latest: "1.2.0".into(), yanked: false };
        let (_, message, _, _) = describe(&dep, "1.0.0", &info).unwrap();
        assert!(message.contains("需要手动改 Cargo.toml"), "{message}");
    }
}
