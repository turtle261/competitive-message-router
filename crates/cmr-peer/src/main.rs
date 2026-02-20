//! CMR peer daemon and optional terminal dashboard.

use clap::{Parser, Subcommand};
use cmr_core::protocol::TransportKind;

use cmr_peer::app::{
    AppError, ingest_stdin_once, run_http_self_test, run_http_self_test_with_runtime, run_peer,
};
use cmr_peer::config::{PeerConfig, write_example_config};
#[cfg(feature = "tui")]
use cmr_peer::tui::run_tui;

/// CMR peer CLI.
#[derive(Debug, Parser)]
#[command(name = "cmr-peer")]
#[command(about = "Competitive Message Routing peer")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

/// CLI subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Run daemon listeners.
    Run {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
    },
    /// Create an example config file.
    InitConfig {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
        /// Overwrite existing file.
        #[arg(long)]
        force: bool,
    },
    /// Execute an end-to-end local HTTP self-test.
    SelfTest {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
        /// Start the runtime, test it, then shut down.
        #[arg(long, default_value_t = true)]
        spawn_runtime: bool,
    },
    /// Receive one CMR message from stdin (for ssh forced-command flows).
    ReceiveStdin {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
        /// Inbound transport kind used for policy checks.
        #[arg(long, default_value = "ssh")]
        transport: String,
    },
    /// Open the high-level terminal dashboard (requires `--features tui`).
    #[cfg(feature = "tui")]
    Ui {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or_else(default_command);

    let result = match command {
        Command::Run { config } => match load_config(&config) {
            Ok(cfg) => run_peer(cfg).await,
            Err(err) => Err(err),
        },
        Command::InitConfig { config, force } => {
            if let Err(err) = write_example_config(&config, force) {
                Err(AppError::Runtime(format!(
                    "failed to write config template: {err}"
                )))
            } else {
                println!("wrote example config to {config}");
                Ok(())
            }
        }
        Command::SelfTest {
            config,
            spawn_runtime,
        } => match load_config(&config) {
            Ok(cfg) => {
                let report = if spawn_runtime {
                    run_http_self_test_with_runtime(cfg).await
                } else {
                    run_http_self_test(&cfg).await
                };
                match report {
                    Ok(report) => {
                        println!(
                            "self-test passed: {} bytes -> {} (status {})",
                            report.bytes_sent, report.destination, report.status
                        );
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        },
        Command::ReceiveStdin { config, transport } => match load_config(&config) {
            Ok(cfg) => ingest_stdin_once(cfg, parse_transport_kind(&transport)).await,
            Err(err) => Err(err),
        },
        #[cfg(feature = "tui")]
        Command::Ui { config } => run_tui(config).await,
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn default_command() -> Command {
    #[cfg(feature = "tui")]
    {
        Command::Ui {
            config: "cmr-peer.toml".to_owned(),
        }
    }

    #[cfg(not(feature = "tui"))]
    {
        Command::Run {
            config: "cmr-peer.toml".to_owned(),
        }
    }
}

fn load_config(path: &str) -> Result<PeerConfig, AppError> {
    PeerConfig::from_toml_file(path).map_err(|err| AppError::Runtime(err.to_string()))
}

fn parse_transport_kind(input: &str) -> TransportKind {
    match input.to_ascii_lowercase().as_str() {
        "http" => TransportKind::Http,
        "https" => TransportKind::Https,
        "smtp" => TransportKind::Smtp,
        "udp" => TransportKind::Udp,
        "ssh" => TransportKind::Ssh,
        other => TransportKind::Other(other.to_owned()),
    }
}
