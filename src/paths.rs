use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub fn join_rel_path(parent: &str, child: &str) -> String {
    let child = child.trim_start_matches('/');
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    }
}

pub fn sanitize_segment(name: &str) -> String {
    let trimmed = name.trim();
    let mut sanitized: String = trimmed
        .chars()
        .filter_map(|ch| {
            if ch == '\0' {
                // Drop NUL bytes outright. They are illegal in path segments
                // on every platform we target.
                None
            } else if matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                // Replace path separators and the characters Windows
                // forbids in file names. Doing this on every platform keeps
                // a Mac/Linux export portable to Windows and back without
                // round-trip surprises.
                Some('_')
            } else if (ch as u32) < 0x20 {
                // Drop ASCII control characters; NTFS rejects them and
                // they cannot meaningfully appear in real photo names.
                None
            } else {
                Some(ch)
            }
        })
        .collect();

    // Windows refuses trailing dots or spaces in path segments, and a few
    // base names are reserved as legacy device aliases (CON, PRN, AUX, NUL,
    // COM1-9, LPT1-9). Make those safe for everyone so a library exported
    // on macOS can be moved to a Windows machine without losing files.
    while sanitized.ends_with('.') || sanitized.ends_with(' ') {
        sanitized.pop();
    }
    if let Some(escaped) = escape_reserved_windows_basename(&sanitized) {
        sanitized = escaped;
    }

    match sanitized.as_str() {
        "" | "." | ".." => "_".to_owned(),
        _ => sanitized,
    }
}

/// Returns a Windows-safe variant of `name` if its base stem matches one
/// of the legacy device aliases (CON, PRN, AUX, NUL, COM1-9, LPT1-9). The
/// trailing underscore is inserted right after the stem so the file
/// extension is preserved: `CON.jpg` becomes `CON_.jpg`, not `CON.jpg_`.
fn escape_reserved_windows_basename(name: &str) -> Option<String> {
    let stem_end = name.find('.').unwrap_or(name.len());
    let stem = &name[..stem_end];
    let upper = stem.to_ascii_uppercase();
    let is_reserved = matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );
    if !is_reserved {
        return None;
    }
    let mut escaped = String::with_capacity(name.len() + 1);
    escaped.push_str(stem);
    escaped.push('_');
    escaped.push_str(&name[stem_end..]);
    Some(escaped)
}

pub fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

pub fn disambiguated_name(seen: &mut HashMap<String, usize>, name: &str, id: &str) -> String {
    let mut base = sanitize_segment(name);
    if base == "_" && !id.is_empty() {
        base = format!("file_{}", short_id(id));
    }

    let key = base.to_lowercase();
    let count = seen.entry(key).and_modify(|value| *value += 1).or_insert(1);
    if *count == 1 {
        return base;
    }

    if id.is_empty() {
        format!("{base}_{count}")
    } else {
        format!("{base}_{}", short_id(id))
    }
}

pub fn local_path(root: &Path, rel_path: &str) -> PathBuf {
    if rel_path.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel_path)
    }
}

pub fn launch_dir() -> Result<PathBuf> {
    env::current_dir().context("determine current working directory")
}

pub fn default_accounts_dir() -> Result<PathBuf> {
    launch_dir()
}

pub fn default_account_dir(email: &str) -> Result<PathBuf> {
    Ok(default_accounts_dir()?.join(sanitize_segment(email.trim())))
}

pub fn account_file_name(email: &str) -> String {
    let _ = email;
    "session.json".to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::path::Path;

    use super::{
        account_file_name, default_account_dir, default_accounts_dir, disambiguated_name,
        join_rel_path, local_path, sanitize_segment,
    };

    #[test]
    fn sanitize_segment_replaces_path_separators() {
        assert_eq!(sanitize_segment(" a/b\\c "), "a_b_c");
        assert_eq!(sanitize_segment("a/b\\c\0"), "a_b_c");
    }

    #[test]
    fn sanitize_segment_replaces_windows_forbidden_characters() {
        // The full set of Windows-illegal characters in NTFS file names.
        assert_eq!(sanitize_segment("a:b"), "a_b");
        assert_eq!(sanitize_segment("a*b"), "a_b");
        assert_eq!(sanitize_segment("a?b"), "a_b");
        assert_eq!(sanitize_segment("a\"b"), "a_b");
        assert_eq!(sanitize_segment("a<b"), "a_b");
        assert_eq!(sanitize_segment("a>b"), "a_b");
        assert_eq!(sanitize_segment("a|b"), "a_b");
    }

    #[test]
    fn sanitize_segment_drops_ascii_control_characters() {
        assert_eq!(sanitize_segment("a\x01b\x07c"), "abc");
    }

    #[test]
    fn sanitize_segment_strips_trailing_dots_and_spaces() {
        assert_eq!(sanitize_segment("photo."), "photo");
        assert_eq!(sanitize_segment("photo "), "photo");
        assert_eq!(sanitize_segment("photo..."), "photo");
        assert_eq!(sanitize_segment("photo. ."), "photo");
    }

    #[test]
    fn sanitize_segment_escapes_reserved_windows_basenames() {
        assert_eq!(sanitize_segment("CON"), "CON_");
        assert_eq!(sanitize_segment("con"), "con_");
        assert_eq!(sanitize_segment("nul"), "nul_");
        assert_eq!(sanitize_segment("CON.jpg"), "CON_.jpg");
        assert_eq!(sanitize_segment("LPT1"), "LPT1_");
        assert_eq!(sanitize_segment("COM5.txt"), "COM5_.txt");
        // Names that merely contain a reserved alias are fine.
        assert_eq!(sanitize_segment("CONversation.jpg"), "CONversation.jpg");
        assert_eq!(sanitize_segment("MyCON"), "MyCON");
    }

    #[test]
    fn sanitize_segment_replaces_dot_only_and_empty_with_underscore() {
        assert_eq!(sanitize_segment(""), "_");
        assert_eq!(sanitize_segment("."), "_");
        assert_eq!(sanitize_segment(".."), "_");
        assert_eq!(sanitize_segment("   "), "_");
    }

    #[test]
    fn join_rel_path_keeps_relative_form() {
        assert_eq!(join_rel_path("", "child"), "child");
        assert_eq!(join_rel_path("parent", "/child"), "parent/child");
        assert_eq!(join_rel_path("parent", "child"), "parent/child");
    }

    #[test]
    fn disambiguated_name_uses_id_for_duplicates() {
        let mut seen = HashMap::new();
        assert_eq!(
            disambiguated_name(&mut seen, "photo.jpg", "abcdef012345"),
            "photo.jpg"
        );
        assert_eq!(
            disambiguated_name(&mut seen, "photo.jpg", "1234567890ab"),
            "photo.jpg_12345678"
        );
    }

    #[test]
    fn disambiguated_name_handles_blank_names_and_duplicates_without_ids() {
        let mut seen = HashMap::new();
        assert_eq!(
            disambiguated_name(&mut seen, " .. ", "abcdef012345"),
            "file_abcdef01"
        );
        assert_eq!(disambiguated_name(&mut seen, ".", ""), "_");
        assert_eq!(disambiguated_name(&mut seen, ".", ""), "__2");
    }

    #[test]
    fn local_path_returns_root_for_empty_relative_path() {
        let root = Path::new("/tmp/photos");
        assert_eq!(local_path(root, ""), root);
        assert_eq!(
            local_path(root, "2026/photo.jpg"),
            root.join("2026/photo.jpg")
        );
    }

    #[test]
    fn account_file_name_uses_session_json() {
        assert_eq!(account_file_name("user@example.com"), "session.json");
        assert_eq!(account_file_name(" user/example.com "), "session.json");
    }

    #[test]
    fn default_accounts_dir_uses_current_directory() {
        assert_eq!(
            default_accounts_dir().expect("accounts dir"),
            env::current_dir().expect("cwd")
        );
    }

    #[test]
    fn default_account_dir_uses_email_folder() {
        let path = default_account_dir("user@example.com").expect("account dir");
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("user@example.com")
        );
    }
}
