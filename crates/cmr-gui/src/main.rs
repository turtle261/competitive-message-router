//! CMR GUI — native GTK4 desktop client for Competitive Message Routing.
//!
//! On first launch a setup wizard collects the user's identity (local HTTP
//! inbox or email address), a pairwise signing key, and the router URL, then
//! saves the configuration to `~/.config/cmr-gui/config.toml`.  On subsequent
//! launches the main window is shown directly.

#![warn(clippy::all, clippy::pedantic)]

mod app;
mod config;
mod crypto;
mod wizard;

use config::{Config, default_config_path};
use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, gio};

fn main() {
    // Build a multi-threaded Tokio runtime and enter its context so that
    // `tokio::runtime::Handle::current()` works in all GTK callbacks for the
    // lifetime of the process.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime");
    let _enter = rt.enter();

    let app = Application::builder()
        .application_id("io.cmr.gui")
        .flags(gio::ApplicationFlags::FLAGS_NONE)
        .build();

    app.connect_activate(build_ui);
    app.run();

    // Keep the runtime alive until after `app.run()` returns so that
    // in-flight async tasks can complete cleanly.
    drop(rt);
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("CMR Client")
        .default_width(860)
        .default_height(640)
        .build();

    let config_path = default_config_path();

    if Config::exists(&config_path) {
        match Config::load(&config_path) {
            Ok(config) => {
                app::show_main_app(&window, &config);
            }
            Err(e) => {
                // Corrupted or unreadable config — show wizard to recreate it.
                eprintln!(
                    "cmr-gui: failed to load config at {}: {e}",
                    config_path.display()
                );
                let path = config_path.clone();
                let window_for_done = window.clone();
                wizard::show_wizard(&window, move |config| {
                    if let Err(e) = config.save(&path) {
                        eprintln!("cmr-gui: failed to save config: {e}");
                    }
                    app::show_main_app(&window_for_done, &config);
                });
            }
        }
    } else {
        let path = config_path.clone();
        // Capture `window` as a weak reference so the closure does not
        // prevent it from being destroyed if the user closes the window
        // before the wizard finishes.
        let window_for_done = window.clone();
        wizard::show_wizard(&window, move |config| {
            if let Err(e) = config.save(&path) {
                eprintln!("cmr-gui: failed to save config: {e}");
            }
            app::show_main_app(&window_for_done, &config);
        });
    }

    window.present();
}
