//! Multi-step setup wizard for first-run configuration.
//!
//! The wizard guides the user through choosing an identity type, configuring
//! the inbox (if local HTTP), setting a signing key, and pointing at a router.
//! On completion it calls `on_done` with the finished [`Config`].

use std::cell::RefCell;
use std::rc::Rc;

use gtk4 as gtk;
use gtk4::prelude::*;

use crate::config::{Config, IdentityConfig, KeyConfig, RouterConfig};
use crate::crypto::generate_key_hex;

// ── Internal helpers ────────────────────────────────────────────────────────

/// Creates a bold, large title label left-aligned with Pango markup.
fn heading(text: &str) -> gtk::Label {
    let label = gtk::Label::new(None);
    label.set_markup(&format!("<b><big>{}</big></b>", glib::markup_escape_text(text)));
    label.set_xalign(0.0);
    label
}

/// Creates a wrapping body-text label left-aligned.
fn body_label(text: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    label
}

/// Creates a short form-field label left-aligned.
fn field_label(text: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_xalign(0.0);
    label
}

/// Returns a `(ScrolledWindow, content_Box)` pair for a wizard page.
///
/// The scroll window expands in both directions; the content box is vertical
/// with 20 px spacing and 32 px margins on all sides.
fn make_scrolled_page() -> (gtk::ScrolledWindow, gtk::Box) {
    let content = gtk::Box::new(gtk::Orientation::Vertical, 20);
    content.set_margin_top(32);
    content.set_margin_bottom(32);
    content.set_margin_start(32);
    content.set_margin_end(32);
    let scroll = gtk::ScrolledWindow::new();
    scroll.set_child(Some(&content));
    scroll.set_hexpand(true);
    scroll.set_vexpand(true);
    scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    (scroll, content)
}

/// Updates the error label: shows red markup when `msg` is non-empty, clears it
/// when `msg` is empty.
fn set_error(label: &gtk::Label, msg: &str) {
    if msg.is_empty() {
        label.set_markup("");
    } else {
        let escaped = glib::markup_escape_text(msg);
        label.set_markup(&format!("<span foreground='red'>{escaped}</span>"));
    }
}

// ── Page builders ────────────────────────────────────────────────────────────

/// Builds the welcome page (page 1 of 7).
fn build_welcome_page() -> gtk::ScrolledWindow {
    let (scroll, content) = make_scrolled_page();
    content.append(&heading("Welcome to CMR"));
    content.append(&body_label(
        "CMR (Competitive Message Routing) is a content-searchable message pool \
         system. Messages are routed based on information distance: a router \
         forwards messages whose body is semantically close to a stored query, \
         approximating Kolmogorov complexity with fast compression. \
         Senders broadcast into the pool; matched messages are delivered to \
         registered recipient addresses.",
    ));
    content.append(&body_label("Click Next to set up your identity."));
    scroll
}

/// Builds the identity-type selection page (page 2 of 7).
///
/// Returns `(page, local_radio, email_radio)`.
fn build_identity_type_page() -> (gtk::ScrolledWindow, gtk::CheckButton, gtk::CheckButton) {
    let (scroll, content) = make_scrolled_page();
    content.append(&heading("Choose Your Identity Type"));
    content.append(&body_label(
        "How should the router identify you and deliver matched messages?",
    ));

    let local_radio = gtk::CheckButton::with_label(
        "Local (HTTP) — run a small HTTP inbox server on this machine. \
         The router can deliver matched messages directly here.",
    );
    local_radio.set_active(true);

    let email_radio = gtk::CheckButton::with_label(
        "Email — use a mailto: identity. Matched messages are sent to your \
         email address and are not displayed in this app.",
    );
    email_radio.set_group(Some(&local_radio));

    content.append(&local_radio);
    content.append(&email_radio);
    (scroll, local_radio, email_radio)
}

/// Builds the local HTTP identity configuration page (page 3a of 7).
///
/// Returns `(page, bind_entry, path_entry)`.
fn build_identity_local_page() -> (gtk::ScrolledWindow, gtk::Entry, gtk::Entry) {
    let (scroll, content) = make_scrolled_page();
    content.append(&heading("Local HTTP Inbox"));
    content.append(&body_label(
        "The router will deliver matched messages to this address over HTTP. \
         Make sure the router can reach the host and port you specify.",
    ));

    content.append(&field_label("Listen address"));
    let bind_entry = gtk::Entry::new();
    bind_entry.set_text("0.0.0.0:8080");
    bind_entry.set_placeholder_text(Some("host:port for the local HTTP inbox"));
    content.append(&bind_entry);

    content.append(&field_label("Path"));
    let path_entry = gtk::Entry::new();
    path_entry.set_text("/cmr");
    path_entry.set_placeholder_text(Some("URL path, e.g. /cmr"));
    content.append(&path_entry);

    content.append(&body_label(
        "The full inbox URL will be http://<host>:<port><path>. \
         Use 0.0.0.0 to listen on all interfaces.",
    ));
    (scroll, bind_entry, path_entry)
}

/// Builds the email identity configuration page (page 3b of 7).
///
/// Returns `(page, email_entry)`.
fn build_identity_email_page() -> (gtk::ScrolledWindow, gtk::Entry) {
    let (scroll, content) = make_scrolled_page();
    content.append(&heading("Email Identity"));
    content.append(&body_label(
        "You will be identified as mailto:<address>. \
         The router cannot deliver messages back inline; \
         check your email inbox for responses.",
    ));

    content.append(&field_label("Email address"));
    let email_entry = gtk::Entry::new();
    email_entry.set_placeholder_text(Some("you@example.com"));
    content.append(&email_entry);

    content.append(&body_label(
        "Note: to receive messages in this app, configure a Local (HTTP) \
         identity instead.",
    ));
    (scroll, email_entry)
}

/// Builds the signing-key setup page (page 4 of 7).
///
/// Returns `(page, key_entry)`.
fn build_key_setup_page() -> (gtk::ScrolledWindow, gtk::Entry) {
    let (scroll, content) = make_scrolled_page();
    content.append(&heading("Signing Key"));
    content.append(&body_label(
        "A pairwise HMAC-SHA-256 key signs your messages so the router can \
         verify your identity. Share this key with your router operator — \
         they must register it on the router side.",
    ));

    content.append(&field_label("Key (64 hex characters = 32 bytes)"));
    let key_entry = gtk::Entry::new();
    key_entry.set_text(&generate_key_hex());
    key_entry.set_placeholder_text(Some("64 lowercase hex characters"));
    content.append(&key_entry);

    let regen_btn = gtk::Button::with_label("Generate New Key");
    {
        let key_entry = key_entry.clone();
        regen_btn.connect_clicked(move |_| {
            key_entry.set_text(&generate_key_hex());
        });
    }
    content.append(&regen_btn);

    content.append(&body_label(
        "You can also paste your own 32-byte key as lowercase hexadecimal.",
    ));
    content.append(&body_label(
        "Keep this key secret — anyone holding it can forge messages as you.",
    ));
    (scroll, key_entry)
}

/// Builds the router URL configuration page (page 5 of 7).
///
/// Returns `(page, router_entry)`.
fn build_router_setup_page() -> (gtk::ScrolledWindow, gtk::Entry) {
    let (scroll, content) = make_scrolled_page();
    content.append(&heading("Router Connection"));
    content.append(&body_label(
        "The CMR router daemon receives your messages and routes them through \
         the network. Enter the HTTP(S) address of your router.",
    ));

    content.append(&field_label("Router URL"));
    let router_entry = gtk::Entry::new();
    router_entry.set_text("http://localhost:7777/cmr");
    router_entry.set_placeholder_text(Some("http://host:port/path"));
    content.append(&router_entry);

    content.append(&body_label(
        "This must be reachable from this machine. \
         Ask your router operator for the correct URL.",
    ));
    (scroll, router_entry)
}

/// Builds the summary + finish page (page 6 of 7).
///
/// Returns `(page, summary_label)`.
fn build_summary_page() -> (gtk::ScrolledWindow, gtk::Label) {
    let (scroll, content) = make_scrolled_page();
    content.append(&heading("Configuration Summary"));
    content.append(&body_label(
        "Review your settings below. Click Finish to save and start the app.",
    ));

    let summary_label = gtk::Label::new(Some(""));
    summary_label.set_xalign(0.0);
    summary_label.set_wrap(true);
    summary_label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    summary_label.set_selectable(true);
    content.append(&summary_label);

    (scroll, summary_label)
}

// ── Navigation helpers ───────────────────────────────────────────────────────

/// Returns the next page name given the current page and identity-type choice.
///
/// Returns `None` when the current page is the last one ("summary").
fn next_page_name(current: &str, use_local: bool) -> Option<&'static str> {
    match current {
        "welcome" => Some("identity-type"),
        "identity-type" => {
            if use_local {
                Some("identity-local")
            } else {
                Some("identity-email")
            }
        }
        "identity-local" | "identity-email" => Some("key-setup"),
        "key-setup" => Some("router-setup"),
        "router-setup" => Some("summary"),
        _ => None,
    }
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Replaces the window content with a multi-step setup wizard.
///
/// When the user completes all pages and clicks **Finish**, `on_done` is called
/// with the finished [`Config`].  The caller is responsible for saving the
/// config and transitioning to the main app UI.
pub fn show_wizard(window: &gtk4::ApplicationWindow, on_done: impl Fn(Config) + 'static) {
    // ── Outer layout ────────────────────────────────────────────────────────
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);

    let stack = gtk::Stack::new();
    stack.set_hexpand(true);
    stack.set_vexpand(true);
    stack.set_transition_type(gtk::StackTransitionType::SlideLeftRight);

    // ── Navigation bar ───────────────────────────────────────────────────────
    let nav_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    nav_box.set_margin_start(16);
    nav_box.set_margin_end(16);
    nav_box.set_margin_top(8);
    nav_box.set_margin_bottom(16);

    let back_btn = gtk::Button::with_label("Back");
    back_btn.set_sensitive(false);

    let error_label = gtk::Label::new(None);
    error_label.set_hexpand(true);
    error_label.set_xalign(0.0);

    let next_btn = gtk::Button::with_label("Next");
    next_btn.add_css_class("suggested-action");

    nav_box.append(&back_btn);
    nav_box.append(&error_label);
    nav_box.append(&next_btn);

    outer.append(&stack);
    outer.append(&nav_box);

    window.set_child(Some(&outer));

    // ── Build pages ──────────────────────────────────────────────────────────
    let welcome_page = build_welcome_page();
    stack.add_named(&welcome_page, Some("welcome"));

    let (identity_type_page, local_radio, _email_radio) = build_identity_type_page();
    stack.add_named(&identity_type_page, Some("identity-type"));

    let (identity_local_page, bind_entry, path_entry) = build_identity_local_page();
    stack.add_named(&identity_local_page, Some("identity-local"));

    let (identity_email_page, email_entry) = build_identity_email_page();
    stack.add_named(&identity_email_page, Some("identity-email"));

    let (key_setup_page, key_entry) = build_key_setup_page();
    stack.add_named(&key_setup_page, Some("key-setup"));

    let (router_setup_page, router_entry) = build_router_setup_page();
    stack.add_named(&router_setup_page, Some("router-setup"));

    let (summary_page, summary_label) = build_summary_page();
    stack.add_named(&summary_page, Some("summary"));

    stack.set_visible_child_name("welcome");

    // ── Shared state ─────────────────────────────────────────────────────────
    // Page navigation history: first entry is always "welcome".
    let history: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(vec!["welcome".to_owned()]));
    let on_done = Rc::new(on_done);

    // ── Back button ──────────────────────────────────────────────────────────
    {
        let history = history.clone();
        let stack = stack.clone();
        let back_btn_c = back_btn.clone();
        let next_btn_c = next_btn.clone();
        let error_label = error_label.clone();

        back_btn.connect_clicked(move |_| {
            let prev = {
                let mut h = history.borrow_mut();
                if h.len() > 1 {
                    h.pop();
                    h.last().map(String::clone)
                } else {
                    None
                }
            };
            if let Some(page) = prev {
                stack.set_visible_child_name(&page);
                let is_first = history.borrow().len() <= 1;
                back_btn_c.set_sensitive(!is_first);
                next_btn_c.set_label("Next");
                set_error(&error_label, "");
            }
        });
    }

    // ── Next / Finish button ─────────────────────────────────────────────────
    {
        let history = history.clone();
        let stack = stack.clone();
        let back_btn_c = back_btn.clone();
        let next_btn_c = next_btn.clone();
        let error_label = error_label.clone();
        let local_radio = local_radio.clone();
        let bind_entry = bind_entry.clone();
        let path_entry = path_entry.clone();
        let email_entry = email_entry.clone();
        let key_entry = key_entry.clone();
        let router_entry = router_entry.clone();
        let summary_label = summary_label.clone();
        let on_done = on_done.clone();

        next_btn.connect_clicked(move |_| {
            let current: String = history
                .borrow()
                .last()
                .map(String::clone)
                .unwrap_or_else(|| "welcome".to_owned());

            set_error(&error_label, "");

            // Validate the current page before advancing or finishing.
            match current.as_str() {
                "identity-local" => {
                    if bind_entry.text().is_empty() {
                        set_error(&error_label, "Listen address cannot be empty.");
                        return;
                    }
                    if path_entry.text().is_empty() {
                        set_error(&error_label, "Path cannot be empty.");
                        return;
                    }
                }
                "identity-email" => {
                    if email_entry.text().is_empty() {
                        set_error(&error_label, "Email address cannot be empty.");
                        return;
                    }
                }
                "key-setup" => {
                    let key_text = key_entry.text();
                    match crate::crypto::parse_key_hex(key_text.as_str()) {
                        Ok(_) => {}
                        Err(e) => {
                            set_error(&error_label, &format!("Invalid key: {e}"));
                            return;
                        }
                    }
                }
                "router-setup" => {
                    if router_entry.text().is_empty() {
                        set_error(&error_label, "Router URL cannot be empty.");
                        return;
                    }
                }
                "summary" => {
                    // Build config and call on_done.
                    let use_local = local_radio.is_active();
                    let identity = if use_local {
                        IdentityConfig::Local {
                            bind: bind_entry.text().to_string(),
                            path: path_entry.text().to_string(),
                        }
                    } else {
                        IdentityConfig::Email {
                            email: email_entry.text().to_string(),
                        }
                    };
                    let config = Config {
                        identity,
                        router: RouterConfig {
                            url: router_entry.text().to_string(),
                        },
                        key: KeyConfig {
                            hex: key_entry.text().to_string(),
                        },
                    };
                    on_done(config);
                    return;
                }
                _ => {}
            }

            // Determine next page name.
            let use_local = local_radio.is_active();
            let next = match next_page_name(current.as_str(), use_local) {
                Some(p) => p,
                None => return,
            };

            // Pre-populate summary text before showing it.
            if next == "summary" {
                let identity_block = if use_local {
                    format!(
                        "Identity:  Local HTTP\n  Bind:    {}\n  Path:    {}",
                        bind_entry.text(),
                        path_entry.text()
                    )
                } else {
                    format!("Identity:  Email (mailto:{})", email_entry.text())
                };
                summary_label.set_text(&format!(
                    "{}\nKey:       {}\nRouter:    {}",
                    identity_block,
                    key_entry.text(),
                    router_entry.text()
                ));
            }

            {
                let mut h = history.borrow_mut();
                h.push(next.to_owned());
            }

            stack.set_visible_child_name(next);
            back_btn_c.set_sensitive(true);

            if next == "summary" {
                next_btn_c.set_label("Finish");
            } else {
                next_btn_c.set_label("Next");
            }
        });
    }
}
