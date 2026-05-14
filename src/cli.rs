use std::{env, path::PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::{
    config::Config,
    delegate::{decision_after_delegate, run_delegate},
    error::Result,
    install::{
        install_wrappers, list_wrappers, uninstall_wrappers, InstallOptions, UninstallOptions,
    },
    invocation::{command_basename, Invocation},
    policy::{evaluate, Decision},
    resolve::resolve_real_command,
    runtime,
};

#[derive(Debug, Parser)]
#[command(name = "shell-command-guard")]
#[command(about = "Local command interception and policy guard")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Install(InstallCmd),
    Uninstall(UninstallCmd),
    Validate(ConfigOpt),
    Check(CheckCmd),
    Explain(CheckCmd),
    ListWrappers(ListWrappersCmd),
}

#[derive(Debug, Args)]
struct ConfigOpt {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct InstallCmd {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    bin_dir: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct UninstallCmd {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    bin_dir: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct ListWrappersCmd {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    bin_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CheckCmd {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(last = true, required = true)]
    argv: Vec<String>,
}

pub fn entry() -> i32 {
    let argv: Vec<String> = env::args().collect();
    let invoked = argv
        .first()
        .map(|value| command_basename(value))
        .unwrap_or_else(|| "shell-command-guard".to_string());
    if invoked != "shell-command-guard" {
        return runtime::run_wrapper(argv);
    }

    match run_cli() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    }
}

fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Install(cmd) => {
            let config = Config::load_for_management(cmd.config.as_deref())?;
            let guard_exe = env::current_exe()?;
            for action in install_wrappers(
                &config,
                &guard_exe,
                &InstallOptions {
                    bin_dir: cmd.bin_dir,
                    dry_run: cmd.dry_run,
                    force: cmd.force,
                },
            )? {
                println!("{action}");
            }
        }
        Commands::Uninstall(cmd) => {
            let config = Config::load_for_management(cmd.config.as_deref())?;
            let guard_exe = env::current_exe()?;
            for action in uninstall_wrappers(
                &config,
                &guard_exe,
                &UninstallOptions {
                    bin_dir: cmd.bin_dir,
                    dry_run: cmd.dry_run,
                },
            )? {
                println!("{action}");
            }
        }
        Commands::Validate(cmd) => {
            Config::load_for_management(cmd.config.as_deref())?;
            println!("valid");
        }
        Commands::Check(cmd) => check(cmd, false)?,
        Commands::Explain(cmd) => check(cmd, true)?,
        Commands::ListWrappers(cmd) => {
            let config = Config::load_for_management(cmd.config.as_deref())?;
            let guard_exe = env::current_exe()?;
            for line in list_wrappers(&config, &guard_exe, cmd.bin_dir.as_deref()) {
                println!("{line}");
            }
        }
    }
    Ok(())
}

fn check(cmd: CheckCmd, explain: bool) -> Result<()> {
    let config = Config::load_for_management(cmd.config.as_deref())?;
    let guard_exe = env::current_exe()?;
    let mut invocation = Invocation::from_check_argv(cmd.argv)?;
    if let Ok(real_command) =
        resolve_real_command(&config, &invocation.original_command, &guard_exe)
    {
        invocation.real_command = Some(real_command);
    }
    let mut decision = evaluate(&config, &invocation)?;
    let mut delegate_result = None;
    if let Decision::Delegate {
        rule_id, delegate, ..
    } = &decision
    {
        let outcome = run_delegate(&config, &invocation, rule_id.as_deref(), delegate)?;
        delegate_result = Some(format!("{outcome:?}"));
        decision = decision_after_delegate(&decision, outcome);
    }
    println!("decision: {}", decision.action_name());
    if let Some(rule_id) = decision.rule_id() {
        println!("rule: {rule_id}");
    } else {
        println!("rule: <default>");
    }
    if let Decision::Deny {
        message: Some(message),
        ..
    } = &decision
    {
        println!("message: {message}");
    }
    if explain {
        println!("original_command: {}", invocation.original_command);
        println!("effective_command: {}", invocation.effective_command);
        println!(
            "effective_args: {}",
            serde_json::to_string(&invocation.effective_args).unwrap()
        );
        println!("argv_string: {}", invocation.argv_string());
        println!("cwd: {}", invocation.cwd.display());
        if let Some(shell_script) = &invocation.shell_script {
            println!("shell_script: {shell_script}");
        }
        if let Some(real_command) = &invocation.real_command {
            println!("real_command: {}", real_command.display());
        }
        if let Some(delegate_result) = delegate_result {
            println!("delegate_result: {delegate_result}");
        }
    }
    Ok(())
}
