//! CMR peer daemon.

use clap::{Parser, Subcommand};
use cmr_core::protocol::TransportKind;

use cmr_peer::app::{ingest_stdin_once, run_peer};
use cmr_peer::config::PeerConfig;

/// CMR peer CLI.
#[derive(Debug, Parser)]
#[command(name = "cmr-peer")]
#[command(about = "Competitive Message Routing peer daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
    /// Receive one CMR message from stdin (for ssh forced-command flows).
    ReceiveStdin {
        /// TOML config file path.
        #[arg(long, default_value = "cmr-peer.toml")]
        config: String,
        /// Inbound transport kind used for policy checks.
        #[arg(long, default_value = "ssh")]
        transport: String,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run { config } => match PeerConfig::from_toml_file(&config) {
            Ok(cfg) => run_peer(cfg).await,
            Err(err) => Err(cmr_peer::app::AppError::Runtime(err.to_string())),
        },
        Command::ReceiveStdin { config, transport } => match PeerConfig::from_toml_file(&config) {
            Ok(cfg) => ingest_stdin_once(cfg, parse_transport_kind(&transport)).await,
            Err(err) => Err(cmr_peer::app::AppError::Runtime(err.to_string())),
        },
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
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
