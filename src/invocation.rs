use std::{
    env,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::error::{GuardError, Result};

#[derive(Debug, Clone, Serialize)]
pub struct Invocation {
    pub original_command: String,
    pub original_args: Vec<String>,
    pub original_argv: Vec<String>,
    pub effective_command: String,
    pub effective_args: Vec<String>,
    pub shell_script: Option<String>,
    pub cwd: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub real_command: Option<PathBuf>,
}

impl Invocation {
    pub fn from_runtime_argv(argv: Vec<String>) -> Result<Self> {
        let (original_command, original_args) = split_argv(argv)?;
        Self::new(original_command, original_args)
    }

    pub fn from_check_argv(argv: Vec<String>) -> Result<Self> {
        let (original_command, original_args) = split_argv(argv)?;
        Self::new(original_command, original_args)
    }

    pub fn new(original_command: String, original_args: Vec<String>) -> Result<Self> {
        if original_command.is_empty() {
            return Err(GuardError::EmptyCommand);
        }
        let original_command = command_basename(&original_command);
        let mut original_argv = Vec::with_capacity(original_args.len() + 1);
        original_argv.push(original_command.clone());
        original_argv.extend(original_args.clone());

        let cwd = env::current_dir()?;
        let (effective_command, effective_args, shell_script) =
            normalize_effective_invocation(&original_command, &original_args);

        Ok(Self {
            original_command,
            original_args,
            original_argv,
            effective_command,
            effective_args,
            shell_script,
            cwd,
            real_command: None,
        })
    }

    pub fn argv_string(&self) -> String {
        let mut argv = Vec::with_capacity(self.effective_args.len() + 1);
        argv.push(self.effective_command.clone());
        argv.extend(self.effective_args.clone());
        shell_words::join(argv)
    }

    pub fn original_argv_string(&self) -> String {
        shell_words::join(self.original_argv.clone())
    }

    pub fn effective_argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.effective_args.len() + 1);
        argv.push(self.effective_command.clone());
        argv.extend(self.effective_args.clone());
        argv
    }
}

pub fn command_basename(value: &str) -> String {
    let normalized = value.trim_start_matches('\\');
    let path = Path::new(normalized);
    let mut command = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(normalized)
        .to_string();
    if command.to_ascii_lowercase().ends_with(".exe") && command.len() > 4 {
        command.truncate(command.len() - 4);
    }
    command
}

fn split_argv(argv: Vec<String>) -> Result<(String, Vec<String>)> {
    let mut iter = argv.into_iter();
    let command = iter.next().ok_or(GuardError::EmptyCommand)?;
    Ok((command, iter.collect()))
}

fn normalize_effective_invocation(
    original_command: &str,
    original_args: &[String],
) -> (String, Vec<String>, Option<String>) {
    let is_shell = matches!(original_command, "sh" | "bash");
    if !is_shell {
        return (original_command.to_string(), original_args.to_vec(), None);
    }

    let Some((script_index, script)) = find_shell_script_arg(original_args) else {
        return (original_command.to_string(), original_args.to_vec(), None);
    };

    match shell_words::split(script) {
        Ok(words) if !words.is_empty() => {
            let (command, args) = normalize_words(words);
            (command, args, Some(script.clone()))
        }
        _ => {
            let mut args = original_args.to_vec();
            if script_index < args.len() {
                args[script_index] = script.clone();
            }
            (original_command.to_string(), args, Some(script.clone()))
        }
    }
}

fn normalize_words(words: Vec<String>) -> (String, Vec<String>) {
    let mut words = strip_wrapper_words(words);
    if words.is_empty() {
        return ("".to_string(), Vec::new());
    }
    let command = command_basename(&words.remove(0));
    (command, words)
}

fn strip_wrapper_words(mut words: Vec<String>) -> Vec<String> {
    const MAX_ITERATIONS: usize = 16;
    for _ in 0..MAX_ITERATIONS {
        if words.is_empty() {
            return words;
        }
        let command = command_basename(&words[0]);
        let consumed = match command.as_str() {
            "sudo" => consume_sudo_prefix(&words),
            "env" => consume_env_prefix(&words),
            "command" | "builtin" | "exec" => consume_command_prefix(&words),
            "nohup" | "time" => Some(1),
            "nice" => consume_nice_prefix(&words),
            _ => None,
        };
        let Some(consumed) = consumed else {
            break;
        };
        if consumed >= words.len() {
            break;
        }
        words.drain(0..consumed);
    }
    words
}

fn consume_sudo_prefix(words: &[String]) -> Option<usize> {
    let mut index = 1;
    while index < words.len() {
        let word = &words[index];
        if word == "--" {
            index += 1;
            break;
        }
        if !word.starts_with('-') || word == "-" {
            break;
        }
        if word.starts_with("--") {
            return None;
        }
        let mut needs_arg = false;
        let mut unknown = false;
        let mut chars = word[1..].chars().peekable();
        while let Some(flag) = chars.next() {
            match flag {
                'E' | 'H' | 'n' | 'k' | 'K' | 'S' | 's' | 'b' | 'i' | 'P' | 'A' | 'B' => {}
                'u' | 'g' | 'h' | 'p' | 'C' | 'r' | 'U' | 'D' | 't' | 'a' | 'T' => {
                    needs_arg = chars.peek().is_none();
                    break;
                }
                _ => {
                    unknown = true;
                    break;
                }
            }
        }
        if unknown {
            return None;
        }
        index += 1;
        if needs_arg {
            if index >= words.len() {
                return None;
            }
            index += 1;
        }
    }
    Some(index).filter(|consumed| *consumed < words.len())
}

fn consume_env_prefix(words: &[String]) -> Option<usize> {
    let mut index = 1;
    while index < words.len() {
        let word = &words[index];
        if word == "--" {
            index += 1;
            break;
        }
        if is_env_assignment(word) {
            index += 1;
            continue;
        }
        if !word.starts_with('-') || word == "-" {
            break;
        }
        if matches!(
            word.as_str(),
            "-i" | "-" | "-0" | "-v" | "--ignore-environment" | "--null" | "--debug"
        ) {
            index += 1;
            continue;
        }
        if matches!(
            word.as_str(),
            "-u" | "-C"
                | "-f"
                | "-a"
                | "--unset"
                | "--chdir"
                | "--file"
                | "--argv0"
                | "--ignore-signal"
        ) {
            index += 2;
            continue;
        }
        if word.starts_with("-u") && word.len() > 2 {
            index += 1;
            continue;
        }
        return None;
    }
    while index < words.len() && is_env_assignment(&words[index]) {
        index += 1;
    }
    Some(index).filter(|consumed| *consumed < words.len())
}

fn consume_command_prefix(words: &[String]) -> Option<usize> {
    let mut index = 1;
    while index < words.len() {
        let word = &words[index];
        if word == "--" {
            index += 1;
            break;
        }
        if !word.starts_with('-') {
            break;
        }
        if word.contains('v') || word.contains('V') {
            return None;
        }
        if word.chars().skip(1).all(|flag| flag == 'p') {
            index += 1;
            continue;
        }
        return None;
    }
    Some(index).filter(|consumed| *consumed < words.len())
}

fn consume_nice_prefix(words: &[String]) -> Option<usize> {
    let mut index = 1;
    while index < words.len() {
        let word = &words[index];
        if word == "-n" || word == "--adjustment" {
            index += 2;
            continue;
        }
        if word.starts_with("-n") && word.len() > 2 {
            index += 1;
            continue;
        }
        if word.starts_with("--adjustment=") {
            index += 1;
            continue;
        }
        if word.starts_with('-')
            && word
                .chars()
                .skip(1)
                .all(|ch| ch == '+' || ch == '-' || ch.is_ascii_digit())
        {
            index += 1;
            continue;
        }
        break;
    }
    Some(index).filter(|consumed| *consumed < words.len())
}

fn is_env_assignment(word: &str) -> bool {
    let Some((key, _value)) = word.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !word.starts_with('-')
}

fn find_shell_script_arg(args: &[String]) -> Option<(usize, &String)> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-c" || arg == "-lc" {
            return args.get(index + 1).map(|script| (index + 1, script));
        }
        if arg == "--" {
            index += 1;
            continue;
        }
        if arg.starts_with('-') && arg.contains('c') {
            return args.get(index + 1).map(|script| (index + 1, script));
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_direct_command() {
        let invocation = Invocation::new("git".to_string(), vec!["status".to_string()]).unwrap();
        assert_eq!(invocation.effective_command, "git");
        assert_eq!(invocation.effective_args, ["status"]);
        assert!(invocation.shell_script.is_none());
    }

    #[test]
    fn normalizes_shell_command() {
        let invocation = Invocation::new(
            "bash".to_string(),
            vec!["-lc".to_string(), "git push origin main".to_string()],
        )
        .unwrap();
        assert_eq!(invocation.original_command, "bash");
        assert_eq!(invocation.effective_command, "git");
        assert_eq!(invocation.effective_args, ["push", "origin", "main"]);
        assert_eq!(
            invocation.shell_script.as_deref(),
            Some("git push origin main")
        );
    }

    #[test]
    fn strips_shell_wrapper_prefixes() {
        let invocation = Invocation::new(
            "bash".to_string(),
            vec![
                "-lc".to_string(),
                "sudo -E env GIT_DIR=.git command git push".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(invocation.effective_command, "git");
        assert_eq!(invocation.effective_args, ["push"]);
    }

    #[test]
    fn command_query_is_not_treated_as_execution_wrapper() {
        let invocation = Invocation::new(
            "bash".to_string(),
            vec!["-lc".to_string(), "command -v git".to_string()],
        )
        .unwrap();
        assert_eq!(invocation.effective_command, "command");
        assert_eq!(invocation.effective_args, ["-v", "git"]);
    }

    #[test]
    fn normalizes_obfuscated_command_word() {
        let invocation = Invocation::new(
            "bash".to_string(),
            vec![
                "-lc".to_string(),
                r#""/usr/bin/git.exe" status"#.to_string(),
            ],
        )
        .unwrap();
        assert_eq!(invocation.effective_command, "git");
        assert_eq!(invocation.effective_args, ["status"]);
    }
}
