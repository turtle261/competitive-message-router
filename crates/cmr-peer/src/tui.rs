//! Optional terminal UI for high-level peer control.

use std::collections::VecDeque;
use std::path::Path;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::app::{AppError, PeerRuntime, run_http_self_test, start_peer};
use crate::config::{PeerConfig, write_example_config};

const LOG_LIMIT: usize = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeStatus {
    Stopped,
    Running,
}

struct DashboardState {
    config_path: String,
    config: Option<PeerConfig>,
    runtime: Option<PeerRuntime>,
    status: RuntimeStatus,
    logs: VecDeque<String>,
}

impl DashboardState {
    fn new(config_path: String) -> Self {
        Self {
            config_path,
            config: None,
            runtime: None,
            status: RuntimeStatus::Stopped,
            logs: VecDeque::new(),
        }
    }

    fn push_log(&mut self, message: impl Into<String>) {
        self.logs.push_back(message.into());
        while self.logs.len() > LOG_LIMIT {
            self.logs.pop_front();
        }
    }

    fn load_config(&mut self) -> Result<(), AppError> {
        let cfg = PeerConfig::from_toml_file(&self.config_path)
            .map_err(|e| AppError::Runtime(format!("failed to load config: {e}")))?;
        self.push_log(format!(
            "loaded config for {} (security={:?})",
            cfg.local_address, cfg.security_level
        ));
        self.config = Some(cfg);
        Ok(())
    }

    fn ensure_config_loaded(&mut self) -> Result<(), AppError> {
        if self.config.is_none() {
            self.load_config()?;
        }
        Ok(())
    }

    async fn start_runtime(&mut self) -> Result<(), AppError> {
        if self.runtime.is_some() {
            self.push_log("runtime already running");
            return Ok(());
        }
        self.ensure_config_loaded()?;
        let config = self
            .config
            .clone()
            .ok_or_else(|| AppError::Runtime("config unavailable".to_owned()))?;
        let runtime = start_peer(config).await?;
        self.push_log(format!(
            "runtime started with {} listener task(s)",
            runtime.listener_count()
        ));
        self.status = RuntimeStatus::Running;
        self.runtime = Some(runtime);
        Ok(())
    }

    async fn stop_runtime(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown().await;
            self.push_log("runtime stopped");
        }
        self.status = RuntimeStatus::Stopped;
    }

    async fn run_self_test(&mut self) -> Result<(), AppError> {
        if self.runtime.is_none() {
            self.push_log("start the runtime first (press s)");
            return Ok(());
        }
        self.ensure_config_loaded()?;
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| AppError::Runtime("config unavailable".to_owned()))?;
        let report = run_http_self_test(config).await?;
        self.push_log(format!(
            "self-test OK: {} bytes -> {} (status {})",
            report.bytes_sent, report.destination, report.status
        ));
        Ok(())
    }

    fn create_config_if_missing(&mut self) -> Result<(), AppError> {
        let path = Path::new(&self.config_path);
        if path.exists() {
            self.push_log(format!("config already exists at {}", self.config_path));
            return Ok(());
        }
        write_example_config(path, false)
            .map_err(|e| AppError::Runtime(format!("failed to write config template: {e}")))?;
        self.push_log(format!("created config template at {}", self.config_path));
        Ok(())
    }

    fn overwrite_config(&mut self) -> Result<(), AppError> {
        write_example_config(&self.config_path, true)
            .map_err(|e| AppError::Runtime(format!("failed to overwrite config template: {e}")))?;
        self.push_log(format!("overwrote config template at {}", self.config_path));
        Ok(())
    }
}

/// Runs the optional terminal dashboard.
pub async fn run_tui(config_path: String) -> Result<(), AppError> {
    let mut terminal = setup_terminal()?;
    let mut state = DashboardState::new(config_path);
    state.push_log("CMR peer dashboard ready");
    state.push_log(
        "keys: s=start, x=stop, t=self-test, r=reload, c=create config, C=overwrite, q=quit",
    );

    let loop_result = tui_loop(&mut terminal, &mut state).await;
    state.stop_runtime().await;
    teardown_terminal(&mut terminal)?;
    loop_result
}

async fn tui_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    state: &mut DashboardState,
) -> Result<(), AppError> {
    loop {
        terminal
            .draw(|frame| render_dashboard(frame, state))
            .map_err(|e| AppError::Runtime(format!("terminal draw failed: {e}")))?;

        if event::poll(Duration::from_millis(120))? {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('s') => {
                    if let Err(err) = state.start_runtime().await {
                        state.push_log(format!("start failed: {err}"));
                    }
                }
                KeyCode::Char('x') => state.stop_runtime().await,
                KeyCode::Char('t') => {
                    if let Err(err) = state.run_self_test().await {
                        state.push_log(format!("self-test failed: {err}"));
                    }
                }
                KeyCode::Char('r') => {
                    if let Err(err) = state.load_config() {
                        state.push_log(format!("reload failed: {err}"));
                    }
                }
                KeyCode::Char('c') => {
                    if let Err(err) = state.create_config_if_missing() {
                        state.push_log(format!("create failed: {err}"));
                    }
                }
                KeyCode::Char('C') => {
                    if let Err(err) = state.overwrite_config() {
                        state.push_log(format!("overwrite failed: {err}"));
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn render_dashboard(frame: &mut ratatui::Frame, state: &DashboardState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let status_style = match state.status {
        RuntimeStatus::Running => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        RuntimeStatus::Stopped => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "CMR Peer Control Console",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("   status: "),
        Span::styled(
            match state.status {
                RuntimeStatus::Running => "RUNNING",
                RuntimeStatus::Stopped => "STOPPED",
            },
            status_style,
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Overview"));
    frame.render_widget(header, layout[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(layout[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(5)])
        .split(body[0]);

    let config_lines = match &state.config {
        Some(cfg) => vec![
            Line::from(format!("path: {}", state.config_path)),
            Line::from(format!("local: {}", cfg.local_address)),
            Line::from(format!("security: {:?}", cfg.security_level)),
            Line::from(format!("http listener: {}", cfg.listen.http.is_some())),
            Line::from(format!("https listener: {}", cfg.listen.https.is_some())),
            Line::from(format!("udp listener: {}", cfg.listen.udp.is_some())),
            Line::from(format!("compressor: {}", cfg.compressor.command)),
        ],
        None => vec![
            Line::from(format!("path: {}", state.config_path)),
            Line::from("config not loaded"),
            Line::from("press c to create template"),
            Line::from("press r to reload"),
        ],
    };
    let config_widget = Paragraph::new(config_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Configuration"),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(config_widget, left[0]);

    let actions = vec![
        ListItem::new("s  start runtime"),
        ListItem::new("x  stop runtime"),
        ListItem::new("t  run local end-to-end self-test"),
        ListItem::new("r  reload config"),
        ListItem::new("c  create config template if missing"),
        ListItem::new("C  overwrite config with template"),
        ListItem::new("q  quit"),
    ];
    let action_list = List::new(actions)
        .block(Block::default().borders(Borders::ALL).title("Actions"))
        .style(Style::default().fg(Color::White));
    frame.render_widget(action_list, left[1]);

    let log_items: Vec<ListItem> = state
        .logs
        .iter()
        .rev()
        .take(40)
        .map(|line| ListItem::new(line.as_str()))
        .collect();
    let logs = List::new(log_items)
        .block(Block::default().borders(Borders::ALL).title("Event Log"))
        .style(Style::default().fg(Color::LightBlue));
    frame.render_widget(logs, body[1]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            "Usage",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(": `cmr-peer` now defaults to this dashboard when built with `--features tui`."),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Help"))
    .wrap(Wrap { trim: true });
    frame.render_widget(footer, layout[2]);
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>, AppError> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}

fn teardown_terminal(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
) -> Result<(), AppError> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
