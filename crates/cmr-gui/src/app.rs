//! Main application window with Compose and Inbox tabs.
//!
//! The window contains a two-tab [`gtk4::Notebook`]:
//! - **Compose** — write messages, send to the router, decode received wire
//!   messages, and verify the round-trip.
//! - **Inbox** — live feed of messages routed back to the local HTTP inbox
//!   (only available when the identity is `Local`; email users see a notice).
//!
//! In glib 0.20 the channel API was removed, so this module bridges the Tokio
//! async inbox receiver with the GTK main thread using `std::sync::mpsc`
//! combined with `glib::timeout_add_local` polling every 50 ms.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use cmr_client::{ClientTransportConfig, CmrClient, ReceivedMessage};
use cmr_core::protocol::{CmrTimestamp, ParseContext, Signature, parse_message};
use gtk4 as gtk;
use gtk4::prelude::*;

use crate::config::{Config, IdentityConfig};
use crate::distance::{format_distance, nearest_neighbor_distance};

// ── Public entry point ───────────────────────────────────────────────────────

/// Replaces the window content with the main CMR client UI.
///
/// Builds both tabs, starts the HTTP inbox server if the identity is `Local`,
/// and wires up all async interactions with the Tokio runtime that was entered
/// before the GTK main loop started.
pub fn show_main_app(window: &gtk4::ApplicationWindow, config: Config) {
    let handle = tokio::runtime::Handle::current();

    // ── Create the CMR client ─────────────────────────────────────────────
    let cmr_identity = config.identity.address();

    let client_result = handle.block_on(async {
        CmrClient::new(cmr_identity.clone(), ClientTransportConfig::default()).await
    });

    let client = match client_result {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cmr-gui: failed to create CmrClient: {e}");
            show_error_window(window, &format!("Failed to initialise CMR client:\n{e}"));
            return;
        }
    };

    // Register the pairwise key for the router if one is configured.
    if let Some(key_bytes) = config.key.bytes() {
        if let Err(e) =
            client.set_shared_key_for_destination(config.router.url.clone(), key_bytes)
        {
            eprintln!("cmr-gui: could not register signing key: {e}");
        }
    }

    let client = Arc::new(client);
    let signing_enabled = config.key.bytes().is_some();

    // ── Outer layout ──────────────────────────────────────────────────────
    let outer = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(0)
        .build();

    let header = build_header(&cmr_identity);
    outer.append(&header);

    // ── Notebook ──────────────────────────────────────────────────────────
    let notebook = gtk::Notebook::builder()
        .vexpand(true)
        .hexpand(true)
        .build();

    let compose_tab = build_compose_tab(
        Arc::clone(&client),
        config.router.url.clone(),
        signing_enabled,
    );
    notebook.append_page(&compose_tab, Some(&gtk::Label::new(Some("Compose"))));

    match &config.identity {
        IdentityConfig::Local { bind, path } => {
            let inbox_tab =
                build_local_inbox_tab(bind.clone(), path.clone(), cmr_identity, &handle);
            notebook.append_page(&inbox_tab, Some(&gtk::Label::new(Some("Inbox"))));
        }
        IdentityConfig::Email { email } => {
            let inbox_tab = build_email_inbox_tab(email);
            notebook.append_page(&inbox_tab, Some(&gtk::Label::new(Some("Inbox"))));
        }
    }

    outer.append(&notebook);
    window.set_child(Some(&outer));
}

// ── Header ───────────────────────────────────────────────────────────────────

fn build_header(identity: &str) -> gtk::Box {
    let hbar = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(16)
        .margin_end(16)
        .build();

    let title = gtk::Label::builder().label("CMR Client").build();
    title.add_css_class("title-4");

    let id_label = gtk::Label::builder()
        .label(&format!("Identity: {identity}"))
        .hexpand(true)
        .halign(gtk::Align::End)
        .selectable(true)
        .ellipsize(gtk::pango::EllipsizeMode::Start)
        .build();

    hbar.append(&title);
    hbar.append(&id_label);
    hbar
}

// ── Compose tab ──────────────────────────────────────────────────────────────

fn build_compose_tab(
    client: Arc<CmrClient>,
    router_url: String,
    sign: bool,
) -> gtk::ScrolledWindow {
    let outer = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(16)
        .margin_bottom(16)
        .margin_start(20)
        .margin_end(20)
        .build();

    // ── Compose section ───────────────────────────────────────────────────
    let compose_heading = gtk::Label::builder()
        .label("<b>Compose a CMR Message</b>")
        .use_markup(true)
        .halign(gtk::Align::Start)
        .build();
    outer.append(&compose_heading);

    let body_view = gtk::TextView::builder()
        .vexpand(true)
        .hexpand(true)
        .wrap_mode(gtk::WrapMode::Word)
        .build();
    body_view.set_monospace(true);
    body_view.buffer().set_text("Hello World!\n");

    let body_scroll = gtk::ScrolledWindow::builder()
        .child(&body_view)
        .min_content_height(120)
        .vexpand(true)
        .build();
    outer.append(&body_scroll);

    let status_label = gtk::Label::builder()
        .halign(gtk::Align::Start)
        .build();
    status_label.set_visible(false);
    outer.append(&status_label);

    let btn_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .build();

    let copy_btn = gtk::Button::with_label("Copy Wire Format");
    let send_btn = gtk::Button::builder()
        .label("Send to Router")
        .css_classes(vec!["suggested-action".to_owned()])
        .build();

    btn_box.append(&copy_btn);
    btn_box.append(&send_btn);
    outer.append(&btn_box);

    // ── Copy wire format ──────────────────────────────────────────────────
    {
        let client_c = Arc::clone(&client);
        let router_url_c = router_url.clone();
        let body_view_c = body_view.clone();
        let status_c = status_label.clone();
        copy_btn.connect_clicked(move |btn| {
            let body = text_view_text(&body_view_c);
            match client_c.build_message(body.as_bytes()) {
                Ok(msg) => match client_c.render_for_destination(&router_url_c, msg, sign) {
                    Ok(wire) => {
                        let wire_str = String::from_utf8_lossy(&wire).into_owned();
                        btn.clipboard().set_text(&wire_str);
                        show_status(&status_c, "Wire format copied to clipboard.", false);
                    }
                    Err(e) => {
                        show_status(&status_c, &format!("Error rendering message: {e}"), true);
                    }
                },
                Err(e) => {
                    show_status(&status_c, &format!("Error building message: {e}"), true);
                }
            }
        });
    }

    // ── Send to router (channel: tokio → GTK via mpsc + timeout_add_local) ───
    let (send_tx, send_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let send_rx = Rc::new(RefCell::new(send_rx));
    {
        let rx = Rc::clone(&send_rx);
        let status_c = status_label.clone();
        glib::timeout_add_local(Duration::from_millis(50), move || {
            while let Ok(result) = rx.borrow().try_recv() {
                match result {
                    Ok(()) => show_status(&status_c, "Message sent!", false),
                    Err(e) => show_status(&status_c, &format!("Error: {e}"), true),
                }
            }
            glib::ControlFlow::Continue
        });
    }

    {
        let client_c = Arc::clone(&client);
        let router_url_c = router_url.clone();
        let body_view_c = body_view.clone();
        let status_c = status_label.clone();
        let tx = send_tx;
        send_btn.connect_clicked(move |_| {
            let body = text_view_text(&body_view_c);
            if body.trim().is_empty() {
                show_status(&status_c, "Message body cannot be empty.", true);
                return;
            }
            show_status(&status_c, "Sending…", false);
            let client_c2 = Arc::clone(&client_c);
            let url = router_url_c.clone();
            let tx2 = tx.clone();
            tokio::spawn(async move {
                let result = client_c2.send_body(&url, body.as_bytes(), sign).await;
                let _ = tx2.send(result.map_err(|e| e.to_string()));
            });
        });
    }

    // ── Separator ─────────────────────────────────────────────────────────
    outer.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    // ── Decode section ────────────────────────────────────────────────────
    outer.append(
        &gtk::Label::builder()
            .label("<b>Decode a CMR Wire Message</b>")
            .use_markup(true)
            .halign(gtk::Align::Start)
            .build(),
    );

    let decode_info = gtk::Label::builder()
        .label(
            "Paste a CMR wire-format message below to inspect it. \
             Use this to decode messages received by email or from a peer.",
        )
        .wrap(true)
        .halign(gtk::Align::Start)
        .build();
    outer.append(&decode_info);

    let paste_view = gtk::TextView::builder()
        .hexpand(true)
        .wrap_mode(gtk::WrapMode::Word)
        .build();
    paste_view.set_monospace(true);

    let paste_scroll = gtk::ScrolledWindow::builder()
        .child(&paste_view)
        .min_content_height(100)
        .build();
    outer.append(&paste_scroll);

    let decode_btn = gtk::Button::with_label("Decode");
    outer.append(&decode_btn);

    let output_view = gtk::TextView::builder()
        .editable(false)
        .hexpand(true)
        .wrap_mode(gtk::WrapMode::Word)
        .build();
    output_view.set_monospace(true);

    let output_scroll = gtk::ScrolledWindow::builder()
        .child(&output_view)
        .min_content_height(120)
        .build();
    outer.append(&output_scroll);

    // ── Decode logic ──────────────────────────────────────────────────────
    {
        let paste_view_c = paste_view.clone();
        let output_view_c = output_view.clone();
        let body_view_c = body_view.clone();
        decode_btn.connect_clicked(move |_| {
            let raw_text = text_view_text(&paste_view_c);
            let raw_bytes = raw_text.as_bytes();
            let now = CmrTimestamp::now_utc();
            let ctx = ParseContext {
                now,
                recipient_address: None,
                max_message_bytes: 8 * 1024 * 1024,
                max_header_ids: 1024,
            };
            match parse_message(raw_bytes, &ctx) {
                Ok(msg) => {
                    let sig_line = match &msg.signature {
                        Signature::Unsigned => "Unsigned (no HMAC)".to_owned(),
                        Signature::Sha256(d) => format!("SHA-256 HMAC: {}", hex::encode(d)),
                    };

                    let hops: Vec<String> = msg
                        .header
                        .iter()
                        .enumerate()
                        .map(|(i, id)| {
                            let tag = if i == 0 {
                                "[sender]"
                            } else if i + 1 == msg.header.len() {
                                "[origin]"
                            } else {
                                "[relay] "
                            };
                            format!("  {tag}  {} {}", id.timestamp, id.address)
                        })
                        .collect();

                    let body_display = match std::str::from_utf8(&msg.body) {
                        Ok(s) => s.to_owned(),
                        Err(_) => format!(
                            "<binary {} bytes: {}>",
                            msg.body.len(),
                            hex::encode(&msg.body[..msg.body.len().min(64)])
                        ),
                    };

                    let reencoded = msg.to_bytes();
                    let roundtrip_ok = reencoded.len() == raw_bytes.len();

                    let composed_body = text_view_text(&body_view_c);
                    let dist = crate::distance::normalized_distance(
                        &msg.body,
                        composed_body.as_bytes(),
                    );

                    let decoded_text = format!(
                        "=== CMR Message ===\n\
                         Signature:  {sig_line}\n\
                         Header ({} entries):\n{}\n\
                         Body ({} bytes):\n{}\n\
                         ---\n\
                         Round-trip re-encode: {}\n\
                         Info-distance vs. compose body: {}\n",
                        msg.header.len(),
                        hops.join("\n"),
                        msg.body.len(),
                        body_display,
                        if roundtrip_ok { "OK ✓" } else { "size mismatch !" },
                        format_distance(dist),
                    );
                    output_view_c.buffer().set_text(&decoded_text);
                }
                Err(e) => {
                    output_view_c
                        .buffer()
                        .set_text(&format!("Parse error: {e}"));
                }
            }
        });
    }

    // Wrap in a vertical ScrolledWindow.
    let sw = gtk::ScrolledWindow::builder()
        .child(&outer)
        .vexpand(true)
        .hexpand(true)
        .build();
    sw.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    sw
}

// ── Inbox tab — email notice ──────────────────────────────────────────────────

fn build_email_inbox_tab(email: &str) -> gtk::Box {
    let outer = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .margin_top(40)
        .margin_bottom(40)
        .margin_start(40)
        .margin_end(40)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .build();

    let icon_label = gtk::Label::builder()
        .label("[ Email Identity ]")
        .build();
    icon_label.add_css_class("title-2");
    outer.append(&icon_label);

    let notice_text = format!(
        "Your identity is mailto:{email}.\n\n\
         Messages that the router matches to your posts are sent \
         to your email address. Check your email inbox for replies.\n\n\
         To receive messages inline here, configure a Local (HTTP) \
         identity in the setup wizard."
    );
    let notice = gtk::Label::builder()
        .label(&notice_text)
        .wrap(true)
        .halign(gtk::Align::Center)
        .justify(gtk::Justification::Center)
        .max_width_chars(60)
        .build();
    outer.append(&notice);

    outer
}

// ── Inbox tab — local HTTP inbox ──────────────────────────────────────────────

fn build_local_inbox_tab(
    bind: String,
    path: String,
    _identity: String,
    handle: &tokio::runtime::Handle,
) -> gtk::Box {
    let outer = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(8)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();

    let status_label = gtk::Label::builder()
        .halign(gtk::Align::Start)
        .build();

    let bind_result = handle.block_on(async {
        cmr_client::HttpInbox::bind(&bind, &path).await
    });

    match bind_result {
        Err(e) => {
            status_label.set_markup(&format!(
                "<span foreground='red'>Failed to start inbox: {}</span>",
                glib::markup_escape_text(&e.to_string())
            ));
            outer.append(&status_label);
        }
        Ok(mut inbox) => {
            let inbox_identity = inbox.identity().to_owned();
            status_label.set_markup(&format!(
                "Listening on <tt>{}</tt>",
                glib::markup_escape_text(&inbox_identity)
            ));
            outer.append(&status_label);

            let top_bar = gtk::Box::builder()
                .orientation(gtk::Orientation::Horizontal)
                .spacing(8)
                .build();

            let count_label = gtk::Label::builder()
                .label("0 messages")
                .hexpand(true)
                .halign(gtk::Align::Start)
                .build();

            let clear_btn = gtk::Button::with_label("Clear");
            top_bar.append(&count_label);
            top_bar.append(&clear_btn);
            outer.append(&top_bar);

            let list_box = gtk::ListBox::builder()
                .selection_mode(gtk::SelectionMode::None)
                .build();

            let list_scroll = gtk::ScrolledWindow::builder()
                .child(&list_box)
                .vexpand(true)
                .hexpand(true)
                .build();
            outer.append(&list_scroll);

            // Shared state.
            let corpus: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
            let message_count: Rc<RefCell<u32>> = Rc::new(RefCell::new(0));

            // Clear button.
            {
                let list_box_c = list_box.clone();
                let count_label_c = count_label.clone();
                let corpus_c = corpus.clone();
                let message_count_c = message_count.clone();
                clear_btn.connect_clicked(move |_| {
                    while let Some(child) = list_box_c.first_child() {
                        list_box_c.remove(&child);
                    }
                    corpus_c.borrow_mut().clear();
                    *message_count_c.borrow_mut() = 0;
                    count_label_c.set_text("0 messages");
                });
            }

            // Bridge: tokio → GTK via std::sync::mpsc + glib::timeout_add_local.
            let (inbox_tx, inbox_rx) =
                std::sync::mpsc::channel::<ReceivedMessage>();
            let inbox_rx = Rc::new(RefCell::new(inbox_rx));

            // Tokio task forwards HttpInbox messages into the sync channel.
            let _ = handle.spawn(async move {
                while let Some(msg) = inbox.recv().await {
                    if inbox_tx.send(msg).is_err() {
                        break;
                    }
                }
            });

            // GTK side polls every 50 ms.
            glib::timeout_add_local(Duration::from_millis(50), move || {
                while let Ok(msg) = inbox_rx.borrow().try_recv() {
                    let borrowed_corpus = corpus.borrow();
                    let existing_bodies: Vec<&[u8]> =
                        borrowed_corpus.iter().map(Vec::as_slice).collect();
                    let dist =
                        nearest_neighbor_distance(&msg.message.body, &existing_bodies);
                    drop(borrowed_corpus);
                    corpus.borrow_mut().push(msg.message.body.clone());

                    let row = build_inbox_row(&msg, dist);
                    list_box.append(&row);

                    let mut count = message_count.borrow_mut();
                    *count += 1;
                    let n = *count;
                    count_label.set_text(&format!(
                        "{n} message{}",
                        if n == 1 { "" } else { "s" }
                    ));
                }
                glib::ControlFlow::Continue
            });
        }
    }

    outer
}

// ── Inbox row builder ─────────────────────────────────────────────────────────

fn build_inbox_row(msg: &ReceivedMessage, distance: f64) -> gtk::ListBoxRow {
    let vbox = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(12)
        .margin_end(12)
        .build();

    let sender = msg.message.immediate_sender();
    let timestamp = msg
        .message
        .header
        .first()
        .map(|id| id.timestamp.to_string())
        .unwrap_or_default();
    let hops = msg.message.header.len().saturating_sub(1);

    let meta_label = gtk::Label::builder()
        .use_markup(true)
        .halign(gtk::Align::Start)
        .wrap(true)
        .build();
    meta_label.set_markup(&format!(
        "<b>From:</b> {} | <b>Time:</b> {} | <b>Hops:</b> {}",
        glib::markup_escape_text(sender),
        glib::markup_escape_text(&timestamp),
        hops,
    ));
    vbox.append(&meta_label);

    if msg.message.header.len() > 1 {
        if let Some(origin) = msg.message.origin_id() {
            let origin_label = gtk::Label::builder()
                .use_markup(true)
                .halign(gtk::Align::Start)
                .build();
            origin_label.set_markup(&format!(
                "<small><b>Origin:</b> {} {}</small>",
                glib::markup_escape_text(&origin.timestamp.to_string()),
                glib::markup_escape_text(&origin.address)
            ));
            vbox.append(&origin_label);
        }
    }

    let dist_label = gtk::Label::builder()
        .use_markup(true)
        .halign(gtk::Align::Start)
        .build();
    dist_label.set_markup(&format!(
        "<small><b>Info-Distance (NCD):</b> {}</small>",
        format_distance(distance)
    ));
    vbox.append(&dist_label);

    let body_text = String::from_utf8_lossy(&msg.message.body);
    let preview: String = if body_text.chars().count() > 240 {
        body_text.chars().take(240).collect::<String>() + "…"
    } else {
        body_text.into_owned()
    };
    let body_label = gtk::Label::builder()
        .label(&preview)
        .halign(gtk::Align::Start)
        .wrap(true)
        .selectable(true)
        .build();
    vbox.append(&body_label);

    let row = gtk::ListBoxRow::new();
    row.set_child(Some(&vbox));
    row
}

// ── Error fallback ────────────────────────────────────────────────────────────

fn show_error_window(window: &gtk4::ApplicationWindow, message: &str) {
    let label = gtk::Label::builder()
        .label(message)
        .wrap(true)
        .margin_top(40)
        .margin_bottom(40)
        .margin_start(40)
        .margin_end(40)
        .build();
    window.set_child(Some(&label));
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Extracts all text from a [`gtk::TextView`]'s buffer.
fn text_view_text(view: &gtk::TextView) -> String {
    let buf = view.buffer();
    buf.text(&buf.start_iter(), &buf.end_iter(), false)
        .to_string()
}

/// Shows a status message; uses red colour for errors.
fn show_status(label: &gtk::Label, msg: &str, is_error: bool) {
    if is_error {
        label.set_markup(&format!(
            "<span foreground='red'>{}</span>",
            glib::markup_escape_text(msg)
        ));
    } else {
        label.set_text(msg);
    }
    label.set_visible(true);
}
