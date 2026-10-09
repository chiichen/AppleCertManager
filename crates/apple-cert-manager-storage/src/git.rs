use std::path::{Path, PathBuf};
use std::process::Command;

use super::files::Scratch;
use apple_cert_manager_error::{Error, Result};

pub struct GitRepo {
    url: String,
    branch: String,
    user_name: String,
    user_email: String,
    shallow: bool,
    scratch: Option<Scratch>,
}

impl GitRepo {
    pub fn new(
        url: String,
        branch: String,
        user_name: String,
        user_email: String,
        shallow: bool,
    ) -> Self {
        Self {
            url,
            branch,
            user_name,
            user_email,
            shallow,
            scratch: None,
        }
    }

    pub fn open(&mut self) -> Result<PathBuf> {
        if let Some(scratch) = &self.scratch {
            return Ok(scratch.path.clone());
        }
        let scratch = Scratch::new()?;
        if self.remote_has_branch()? {
            let mut args = vec![
                "clone".to_string(),
                "--branch".to_string(),
                self.branch.clone(),
            ];
            if self.shallow {
                args.push("--depth".into());
                args.push("1".into());
            }
            args.push(self.url.clone());
            args.push(scratch.path.display().to_string());
            git(&args, None)?;
        } else {
            git(
                &[
                    "init".to_string(),
                    "-b".to_string(),
                    self.branch.clone(),
                    scratch.path.display().to_string(),
                ],
                None,
            )?;
            git(
                &[
                    "remote".into(),
                    "add".into(),
                    "origin".into(),
                    self.url.clone(),
                ],
                Some(&scratch.path),
            )?;
        }
        let path = scratch.path.clone();
        self.scratch = Some(scratch);
        Ok(path)
    }

    pub fn commit(&mut self, message: &str) -> Result<()> {
        let dir = self.working_dir()?.to_path_buf();
        git(&["add".into(), "-A".into()], Some(&dir))?;
        let status = git_output(&["status".into(), "--porcelain".into()], Some(&dir))?;
        if status.stdout.is_empty() {
            return Ok(());
        }
        let mut commit = Command::new("git");
        commit
            .current_dir(&dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["-c", "core.autocrlf=false"])
            .arg("-c")
            .arg(format!("user.name={}", self.user_name))
            .arg("-c")
            .arg(format!("user.email={}", self.user_email))
            .args(["commit", "-m", message]);
        run(&mut commit)?;
        git(
            &[
                "push".into(),
                "--set-upstream".into(),
                "origin".into(),
                format!("HEAD:{}", self.branch),
            ],
            Some(&dir),
        )?;
        Ok(())
    }

    pub fn description(&self) -> String {
        format!("git {} ({})", self.url, self.branch)
    }

    pub fn working_dir(&self) -> Result<&Path> {
        self.scratch
            .as_ref()
            .map(|scratch| scratch.path.as_path())
            .ok_or_else(|| super::storage_err("git repository is not open"))
    }

    fn remote_has_branch(&self) -> Result<bool> {
        let output = git_output(
            &[
                "ls-remote".into(),
                "--heads".into(),
                self.url.clone(),
                self.branch.clone(),
            ],
            None,
        )?;
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(text.contains(&format!("refs/heads/{}", self.branch)))
    }
}

fn git(args: &[String], dir: Option<&Path>) -> Result<()> {
    let output = git_output(args, dir)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Command {
            command: format!("git {}", args.join(" ")),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn git_output(args: &[String], dir: Option<&Path>) -> Result<std::process::Output> {
    let mut command = Command::new("git");
    command
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", "core.autocrlf=false"]);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    command.args(args);
    Ok(command.output()?)
}

fn run(command: &mut Command) -> Result<()> {
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Command {
            command: format!("{command:?}"),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}
