use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use apple_cert_manager::config::{Config, SAMPLE_CONFIG};
use apple_cert_manager::crypto::{self, encryption_version};
use apple_cert_manager::devices::{self, DeviceRecord};
use apple_cert_manager::engine::{self, NukeRequest, SyncPlan};
use apple_cert_manager::install::{self, InstallOutcome};
use apple_cert_manager::portal::ConnectClient;
use apple_cert_manager::signing;
use apple_cert_manager::storage::Repo;
use apple_cert_manager::types::{Platform, SigningType};
use apple_cert_manager::{Error, Result};
use clap::{Parser, Subcommand};

const SAMPLE_DEVICES: &str = "\
# Device ID	Device Name	Device Platform
# 00008030-001C25E40A68802E	前台 iPhone	ios
";

#[derive(Debug, Parser)]
#[command(
    name = "acm",
    version,
    about = "One-command Apple certificate manager compatible with fastlane match"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Write acm.toml and a sample devices.txt.
    Init {
        #[arg(long, default_value = "acm.toml")]
        config: PathBuf,
        /// Replace an existing acm.toml and devices.txt.
        #[arg(long)]
        force: bool,
    },
    /// Register devices, create missing certificates and profiles, and write signing files.
    Sync {
        #[arg(long, default_value = "acm.toml")]
        config: PathBuf,
        #[arg(long)]
        readonly: bool,
        #[arg(long)]
        force: bool,
        /// Skip the macOS keychain and Xcode profile install.
        #[arg(long)]
        skip_install: bool,
        #[arg(long)]
        skip_profiles: bool,
        /// Write match v1 Salted__ encryption instead of v2.
        #[arg(long)]
        legacy: bool,
    },
    /// Revoke certificates and delete their repository files.
    Nuke {
        #[arg(long, default_value = "acm.toml")]
        config: PathBuf,
        #[arg(long = "type", required = true)]
        signing_types: Vec<String>,
        #[arg(long = "platform")]
        platforms: Vec<String>,
        /// Required. Nuke deletes Apple certificates.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        legacy: bool,
    },
    /// Copy an existing .cer, .p12, or profile into the repository.
    Import {
        #[arg(long, default_value = "acm.toml")]
        config: PathBuf,
        #[arg(long = "type")]
        signing_type: String,
        #[arg(long)]
        legacy: bool,
        files: Vec<PathBuf>,
    },
    /// Re-encrypt the repository. The new passphrase comes from MATCH_PASSWORD_NEW.
    ChangePassword {
        #[arg(long, default_value = "acm.toml")]
        config: PathBuf,
        #[arg(long, default_value = "MATCH_PASSWORD_NEW")]
        new_password_env: String,
        #[arg(long)]
        legacy: bool,
    },
    /// Copy an encrypted repository into another storage backend.
    Migrate {
        #[arg(long, default_value = "acm.toml")]
        config: PathBuf,
        /// acm.toml whose storage section is the destination.
        #[arg(long)]
        dest: PathBuf,
        #[arg(long)]
        legacy: bool,
    },
    /// Encrypt a signing file, or every signing file in a directory.
    Encrypt {
        path: PathBuf,
        #[arg(long)]
        legacy: bool,
    },
    /// Decrypt a signing file, or every signing file in a directory.
    Decrypt { path: PathBuf },
    /// Check the configuration, password, and Apple key without calling Apple.
    Doctor {
        #[arg(long, default_value = "acm.toml")]
        config: PathBuf,
    },
}

pub fn run() -> Result<()> {
    match Cli::parse().command {
        Commands::Init { config, force } => cmd_init(&config, force),
        Commands::Sync {
            config,
            readonly,
            force,
            skip_install,
            skip_profiles,
            legacy,
        } => cmd_sync(SyncArgs {
            config,
            readonly,
            force,
            skip_install,
            skip_profiles,
            legacy,
        }),
        Commands::Nuke {
            config,
            signing_types,
            platforms,
            yes,
            legacy,
        } => cmd_nuke(&config, &signing_types, &platforms, yes, legacy),
        Commands::Import {
            config,
            signing_type,
            legacy,
            files,
        } => cmd_import(&config, &signing_type, legacy, &files),
        Commands::ChangePassword {
            config,
            new_password_env,
            legacy,
        } => cmd_change_password(&config, &new_password_env, legacy),
        Commands::Migrate {
            config,
            dest,
            legacy,
        } => cmd_migrate(&config, &dest, legacy),
        Commands::Encrypt { path, legacy } => crypt_path(&path, false, legacy),
        Commands::Decrypt { path } => crypt_path(&path, true, false),
        Commands::Doctor { config } => cmd_doctor(&config),
    }
}

struct SyncArgs {
    config: PathBuf,
    readonly: bool,
    force: bool,
    skip_install: bool,
    skip_profiles: bool,
    legacy: bool,
}

fn cmd_init(config_path: &Path, force: bool) -> Result<()> {
    if config_path.exists() && !force {
        return Err(Error::msg(format!(
            "{} already exists. Pass --force to replace it",
            config_path.display()
        )));
    }
    if let Some(parent) = config_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(config_path, SAMPLE_CONFIG)?;
    let devices_path = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("devices.txt");
    if !devices_path.exists() || force {
        fs::write(&devices_path, SAMPLE_DEVICES)?;
    }
    println!("wrote {}", config_path.display());
    println!("wrote {}", devices_path.display());
    println!("export MATCH_PASSWORD before acm sync. The passphrase is not stored in acm.toml.");
    Ok(())
}

fn cmd_sync(args: SyncArgs) -> Result<()> {
    let mut config = Config::load(&args.config)?;
    if args.readonly {
        config.sync.readonly = true;
    }
    if args.force {
        config.sync.force = true;
    }
    if args.skip_install {
        config.sync.skip_install = true;
    }
    if args.skip_profiles {
        config.sync.skip_profiles = true;
    }
    if args.legacy {
        config.sync.force_legacy_encryption = true;
    }
    let password = Config::password_from_env()?;
    let devices = load_devices(&config)?;
    let plan = SyncPlan::from_config(&config, devices);
    let mut repo = Repo::from_config(&config)?;
    println!("storage: {}", repo.description());
    let client = if plan.readonly {
        None
    } else {
        Some(ConnectClient::from_config(&config)?)
    };
    let report = engine::sync(&mut repo, client.as_ref(), &password, &plan)?;
    let written = signing::write_signing_files(&report, &config.sync.output_dir)?;
    println!("devices registered: {}", report.registered_devices);
    println!("certificates created: {}", report.created_certificates);
    println!("profiles created: {}", report.created_profiles);
    println!("signing env: {}", written.env_path.display());
    if config.sync.skip_install {
        println!("keychain: skipped");
    } else {
        print_install(&install::install_into_system(&report, &config.sync)?)?;
    }
    Ok(())
}

fn print_install(outcome: &InstallOutcome) -> Result<()> {
    println!("profiles installed: {}", outcome.profiles_installed);
    println!("identities installed: {}", outcome.identities_installed);
    if let Some(note) = &outcome.note {
        println!("{note}");
    }
    Ok(())
}

fn cmd_nuke(
    config_path: &Path,
    signing_types: &[String],
    platforms: &[String],
    yes: bool,
    legacy: bool,
) -> Result<()> {
    let config = Config::load(config_path)?;
    let password = Config::password_from_env()?;
    let signing_types = parse_types(signing_types)?;
    let platforms = parse_platforms(platforms)?;
    let mut repo = Repo::from_config(&config)?;
    let client = if yes {
        Some(ConnectClient::from_config(&config)?)
    } else {
        None
    };
    engine::nuke(
        &mut repo,
        client.as_ref(),
        &password,
        &NukeRequest {
            signing_types,
            platforms,
            confirmed: yes,
            legacy_encryption: legacy,
        },
    )?;
    println!("revoked certificates in {}", repo.description());
    Ok(())
}

fn cmd_import(
    config_path: &Path,
    signing_type: &str,
    legacy: bool,
    files: &[PathBuf],
) -> Result<()> {
    let config = Config::load(config_path)?;
    let password = Config::password_from_env()?;
    let signing = SigningType::parse(signing_type)?;
    let mut repo = Repo::from_config(&config)?;
    engine::import(&mut repo, &password, signing, legacy, files)?;
    println!(
        "imported {} file{} into {}",
        files.len(),
        if files.len() == 1 { "" } else { "s" },
        repo.description()
    );
    Ok(())
}

fn cmd_change_password(config_path: &Path, new_password_env: &str, legacy: bool) -> Result<()> {
    let config = Config::load(config_path)?;
    let old_password = Config::password_from_env()?;
    let new_password = std::env::var(new_password_env).map_err(|_| {
        Error::Config(format!(
            "{new_password_env} is not set. This is the new repository passphrase"
        ))
    })?;
    if new_password.is_empty() {
        return Err(Error::Config(format!("{new_password_env} is empty")));
    }
    let mut repo = Repo::from_config(&config)?;
    engine::change_password(&mut repo, &old_password, &new_password, legacy)?;
    println!("updated the passphrase for {}", repo.description());
    Ok(())
}

fn cmd_migrate(config_path: &Path, dest_path: &Path, legacy: bool) -> Result<()> {
    let source_config = Config::load(config_path)?;
    let dest_config = Config::load(dest_path)?;
    let password = Config::password_from_env()?;
    let mut source = Repo::from_config(&source_config)?;
    let mut destination = Repo::from_config(&dest_config)?;
    engine::migrate(&mut source, &mut destination, &password, legacy)?;
    println!(
        "migrated {} to {}",
        source.description(),
        destination.description()
    );
    Ok(())
}

fn crypt_path(path: &Path, decrypt: bool, legacy: bool) -> Result<()> {
    let password = Config::password_from_env()?;
    crypto::require_password(&password)?;
    if path.is_dir() {
        if decrypt {
            crypto::decrypt_tree(path, &password)?;
        } else {
            crypto::encrypt_tree(path, &password, encryption_version(legacy))?;
        }
    } else if path.is_file() {
        if decrypt {
            crypto::decrypt_file(path, &password)?;
        } else {
            crypto::encrypt_file(path, &password, encryption_version(legacy))?;
        }
    } else {
        return Err(Error::msg(format!("{} does not exist", path.display())));
    }
    println!(
        "{} {}",
        if decrypt { "decrypted" } else { "encrypted" },
        path.display()
    );
    Ok(())
}

fn cmd_doctor(config_path: &Path) -> Result<()> {
    let mut failed = false;
    let config = match Config::load(config_path) {
        Ok(config) => {
            report(true, "config", &config_path.display().to_string());
            Some(config)
        }
        Err(err) => {
            report(false, "config", &err.to_string());
            failed = true;
            None
        }
    };
    if let Some(config) = &config {
        match config.validate_storage() {
            Ok(()) => {
                let repo = Repo::from_config(config)?;
                report(true, "storage", &repo.description());
            }
            Err(err) => {
                report(false, "storage", &err.to_string());
                failed = true;
            }
        }
        match Config::password_from_env() {
            Ok(_) => report(true, "password", "MATCH_PASSWORD is set"),
            Err(err) => {
                report(false, "password", &err.to_string());
                failed = true;
            }
        }
        match apple_check(config) {
            Ok(detail) => report(true, "apple", &detail),
            Err(err) => {
                report(false, "apple", &err.to_string());
                failed = true;
            }
        }
        match devices_check(config) {
            Ok(detail) => report(true, "devices", &detail),
            Err(err) => {
                report(false, "devices", &err.to_string());
                failed = true;
            }
        }
        if config.storage_mode == apple_cert_manager::config::StorageMode::Git {
            match Command::new("git").arg("--version").output() {
                Ok(output) if output.status.success() => report(true, "git", "git is available"),
                _ => {
                    report(false, "git", "git is not available");
                    failed = true;
                }
            }
        }
        let keychain = keychain_check(config);
        report(keychain.0, "keychain", &keychain.1);
        failed |= !keychain.0;
    }
    if failed {
        Err(Error::msg("doctor found a problem"))
    } else {
        Ok(())
    }
}

fn apple_check(config: &Config) -> Result<String> {
    if config.sync.readonly {
        return Ok("readonly sync does not call App Store Connect".into());
    }
    config.require_apple()?;
    if config.apple.key_pem.is_some() {
        return Ok(format!(
            "API key {} supplied in the environment",
            config.apple.key_id
        ));
    }
    let path = config
        .apple
        .key_path
        .as_ref()
        .ok_or_else(|| Error::Config("apple.key_path is empty".into()))?;
    let metadata = fs::metadata(path)
        .map_err(|err| Error::Config(format!("cannot read API key {}: {err}", path.display())))?;
    if metadata.len() == 0 {
        return Err(Error::Config(format!(
            "API key {} is empty",
            path.display()
        )));
    }
    Ok(format!(
        "API key {} at {}",
        config.apple.key_id,
        path.display()
    ))
}

fn devices_check(config: &Config) -> Result<String> {
    match load_devices(config) {
        Ok(devices) => Ok(format!("{} device{}", devices.len(), plural(devices.len()))),
        Err(err) => Err(err),
    }
}

fn load_devices(config: &Config) -> Result<Vec<DeviceRecord>> {
    let Some(path) = &config.devices_file else {
        return Ok(Vec::new());
    };
    if !path.exists() {
        if config.sync.readonly {
            return Ok(Vec::new());
        }
        return Err(Error::msg(format!(
            "device list {} does not exist",
            path.display()
        )));
    }
    devices::load_devices(path)
}

fn keychain_check(config: &Config) -> (bool, String) {
    #[cfg(target_os = "macos")]
    {
        (
            true,
            format!(
                "Security.framework imports into {}",
                config.sync.keychain_name
            ),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        (
            true,
            format!(
                "Security.framework install runs on macOS and would use {}. This host writes signing files.",
                config.sync.keychain_name
            ),
        )
    }
}

fn report(ok: bool, name: &str, detail: &str) {
    println!(
        "{:<6} {:<10} {detail}",
        if ok { "ok" } else { "fail" },
        name
    );
}

fn parse_types(values: &[String]) -> Result<Vec<SigningType>> {
    values
        .iter()
        .map(|value| SigningType::parse(value))
        .collect()
}

fn parse_platforms(values: &[String]) -> Result<Vec<Platform>> {
    values.iter().map(|value| Platform::parse(value)).collect()
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}
