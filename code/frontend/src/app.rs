//! Root Leptos component. This is a UI prototype wired to the *real*
//! `client` crate through Tauri commands (see src/api.rs) — no mock data,
//! no simulated crypto. It won't do anything meaningful outside a Tauri
//! window (see api.rs's doc comment), but the logic itself talks to a real
//! relay server over a real UDP socket.
//!
//! Screens:
//! 1. Connect  — enter the relay's Ed25519 pubkey, perform the link handshake.
//! 2. Main     — show our own identity, manage contacts, chat with one peer.
//!
//! State lives in a handful of top-level signals passed down as props,
//! rather than a router or global store — deliberately simple for a
//! prototype with only two screens.

use crate::api;
use leptos::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// One message in a conversation, for local display only. Not persisted —
/// reloading the app loses history, same as the CLI (which only prints to
/// a terminal that scrolls away). `Client`'s own state (sessions, ratchet
/// keys) *is* persisted to client_state.json; only this UI-side transcript
/// is ephemeral.
#[derive(Clone, Debug, PartialEq)]
struct ChatMessage {
    /// Unique per message so the `<For>` transcript list can key on
    /// identity rather than content — two messages with the same text
    /// from the same sender (e.g. sending "s" five times in a row) would
    /// otherwise share a key, causing Leptos to reuse/misplace the wrong
    /// DOM node instead of creating a new one.
    id: u64,
    from_me: bool,
    text: String,
}

fn next_message_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Light/dark preference. Applied to `<html data-theme="...">` (see
/// style.css, which keys both palettes' CSS custom properties off that
/// attribute) and persisted to localStorage so it survives a reload.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Theme {
    Light,
    Dark,
}

impl Theme {
    fn as_str(self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    fn flipped(self) -> Self {
        match self {
            Theme::Light => Theme::Dark,
            Theme::Dark => Theme::Light,
        }
    }
}

const THEME_STORAGE_KEY: &str = "e2e-messenger-theme";

/// Saved preference if there is one, otherwise the OS/webview's
/// `prefers-color-scheme`, defaulting to dark (this UI's original look) if
/// neither is available.
fn initial_theme() -> Theme {
    let stored = window()
        .local_storage()
        .ok()
        .flatten()
        .and_then(|storage| storage.get_item(THEME_STORAGE_KEY).ok().flatten());
    match stored.as_deref() {
        Some("light") => return Theme::Light,
        Some("dark") => return Theme::Dark,
        _ => {}
    }
    let prefers_light = window()
        .match_media("(prefers-color-scheme: light)")
        .ok()
        .flatten()
        .map(|mql| mql.matches())
        .unwrap_or(false);
    if prefers_light {
        Theme::Light
    } else {
        Theme::Dark
    }
}

/// Reflects `theme` onto `<html>` and persists it — the actual repaint
/// happens in CSS (style.css selectors keyed on `data-theme`), this just
/// flips the attribute.
fn apply_theme(theme: Theme) {
    if let Some(el) = document().document_element() {
        let _ = el.set_attribute("data-theme", theme.as_str());
    }
    if let Ok(Some(storage)) = window().local_storage() {
        let _ = storage.set_item(THEME_STORAGE_KEY, theme.as_str());
    }
}

fn copy_to_clipboard(text: &str) {
    // Fire-and-forget: `write_text` returns a Promise that the browser/webview
    // runs regardless of whether we await it from Rust, and there's nothing
    // useful to do here if it rejects (e.g. no clipboard permission).
    let _ = window().navigator().clipboard().write_text(text);
}

/// Icon button that copies `value` to the clipboard on click, swapping to a
/// checkmark briefly as feedback — lets users grab a routing token/Ed25519
/// key without manually selecting the text.
#[component]
fn CopyButton(value: String) -> impl IntoView {
    let copied = RwSignal::new(false);

    view! {
        <button
            type="button"
            class="copy-btn"
            class:copied=move || copied.get()
            title="Copy to clipboard"
            on:click=move |_| {
                copy_to_clipboard(&value);
                copied.set(true);
                set_timeout(move || copied.set(false), Duration::from_millis(1200));
            }
        >
            {move || if copied.get() {
                view! {
                    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M3 8.5l3 3 7-7" />
                    </svg>
                }.into_any()
            } else {
                view! {
                    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="5.5" y="5.5" width="8" height="9" rx="1.5" />
                        <path d="M3.5 10.5v-6a1.5 1.5 0 0 1 1.5-1.5h6" />
                    </svg>
                }.into_any()
            }}
        </button>
    }
}

#[component]
pub fn App() -> impl IntoView {
    // `None` until `bootstrap` succeeds — gates which screen renders.
    let identity = RwSignal::new(None::<api::IdentityDto>);

    let theme = RwSignal::new(initial_theme());
    Effect::new(move |_| apply_theme(theme.get()));

    view! {
        <main class="app">
            <div class="app-header">
                <h1>"E2E-Messenger"</h1>
                <button
                    class="theme-toggle"
                    on:click=move |_| theme.update(|t| *t = t.flipped())
                >
                    {move || match theme.get() {
                        Theme::Dark => "Light mode",
                        Theme::Light => "Dark mode",
                    }}
                </button>
            </div>
            {move || match identity.get() {
                None => view! { <ConnectScreen identity=identity /> }.into_any(),
                Some(id) => view! { <MainScreen identity=id /> }.into_any(),
            }}
        </main>
    }
}

/// Screen 1: paste the relay's printed Ed25519 pubkey and perform the link
/// handshake. Mirrors the CLI's required command-line argument — same
/// trust model, just entered through a text field instead of argv.
#[component]
fn ConnectScreen(identity: RwSignal<Option<api::IdentityDto>>) -> impl IntoView {
    let server_key_input = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let connecting = RwSignal::new(false);

    let on_connect = move |_| {
        let key = server_key_input.get();
        if key.trim().is_empty() {
            error.set(Some("Paste the server's Ed25519 pubkey first.".into()));
            return;
        }
        error.set(None);
        connecting.set(true);
        leptos::task::spawn_local(async move {
            match api::bootstrap(&key).await {
                Ok(id) => identity.set(Some(id)),
                Err(e) => error.set(Some(e)),
            }
            connecting.set(false);
        });
    };

    view! {
        <section class="connect-screen">
            <p>"Connect to the relay server to generate/load your identity."</p>
            <p class="hint">
                "Run the server (runserver.sh) and paste the "
                <code>"Server Static Pubkey"</code>
                " it prints on boot."
            </p>
            <input
                type="text"
                placeholder="server ed25519 pubkey (hex)"
                prop:value=move || server_key_input.get()
                on:input=move |ev| server_key_input.set(event_target_value(&ev))
            />
            <button
                disabled=move || connecting.get()
                on:click=on_connect
            >
                {move || if connecting.get() { "Connecting..." } else { "Connect" }}
            </button>
            {move || error.get().map(|e| view! { <p class="error">{e}</p> })}
        </section>
    }
}

/// Screen 2: everything after a successful handshake — our identity (to
/// share with peers), the contact list, and a chat panel for whichever
/// contact is selected.
#[component]
fn MainScreen(identity: api::IdentityDto) -> impl IntoView {
    let contacts = RwSignal::new(Vec::<api::ContactDto>::new());
    let selected = RwSignal::new(None::<String>);
    // token_hex -> transcript. Populated by both outgoing sends (added
    // immediately, optimistically) and incoming polls (added on arrival).
    let messages = RwSignal::new(HashMap::<String, Vec<ChatMessage>>::new());

    // Poll the backend every second for contact-status changes and newly
    // decrypted messages. This is deliberately simple polling rather than
    // a push/event channel — see poll_inbox's doc comment in commands.rs.
    let refresh = move || {
        leptos::task::spawn_local(async move {
            if let Ok(list) = api::list_contacts().await {
                contacts.set(list);
            }
            if let Ok(incoming) = api::poll_inbox().await
                && !incoming.is_empty()
            {
                messages.update(|map| {
                    for msg in incoming {
                        map.entry(msg.from_token).or_default().push(ChatMessage {
                            id: next_message_id(),
                            from_me: false,
                            text: msg.text,
                        });
                    }
                });
            }
        });
    };
    refresh();
    let _interval = set_interval_with_handle(refresh, Duration::from_millis(1000));

    view! {
        <section class="main-screen">
            <IdentityCard identity=identity />
            <div class="columns">
                <ContactPanel contacts=contacts selected=selected />
                <ChatPanel contacts=contacts selected=selected messages=messages />
            </div>
        </section>
    }
}

/// Our own identity — what a peer needs (routing token + Ed25519 key) to
/// add us as a contact. In a real build this would render as a QR code
/// (see documentations/doable-cryptographic-flow.md, Micro-QR); this
/// prototype just shows the hex so it can be copy-pasted between two
/// running instances during local testing. `name` (set via
/// `./runpeer.sh <name>`, see README) is shown here for your own
/// reference only — it's sent automatically as part of the KeyExchange
/// once you connect to someone, so peers see "alice" in their contact
/// list without typing anything themselves (see `Client::local_name` /
/// `contact_names` in code/client/src/lib.rs).
#[component]
fn IdentityCard(identity: api::IdentityDto) -> impl IntoView {
    view! {
        <div class="identity-card">
            <h2>"Your Identity"</h2>
            {identity.name.clone().map(|name| view! {
                <p>
                    <strong>"Name: "</strong>
                    <code>{name.clone()}</code>
                    <CopyButton value=name />
                </p>
            })}
            <p>
                <strong>"Token: "</strong>
                <code>{identity.routing_token.clone()}</code>
                <CopyButton value=identity.routing_token />
            </p>
            <p>
                <strong>"Ed25519: "</strong>
                <code>{identity.ed25519_public.clone()}</code>
                <CopyButton value=identity.ed25519_public />
            </p>
        </div>
    }
}

/// Contact list plus the "add a new contact" form. Adding a contact here
/// is the manual-entry equivalent of scanning a peer's QR code: pasting in
/// their routing token + Ed25519 key is exactly the trust anchor the QR
/// scan would establish (see KeyExchangePayload::verify in packets.rs).
#[component]
fn ContactPanel(
    contacts: RwSignal<Vec<api::ContactDto>>,
    selected: RwSignal<Option<String>>,
) -> impl IntoView {
    let token_input = RwSignal::new(String::new());
    let key_input = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);

    let on_add = move |_| {
        let token = token_input.get();
        let key = key_input.get();
        if token.trim().is_empty() || key.trim().is_empty() {
            error.set(Some("Both fields are required.".into()));
            return;
        }
        error.set(None);
        leptos::task::spawn_local(async move {
            if let Err(e) = api::connect_to_peer(&token, &key).await {
                error.set(Some(e));
            } else {
                token_input.set(String::new());
                key_input.set(String::new());
            }
        });
    };

    view! {
        <div class="contact-panel">
            <h2>"Contacts"</h2>
            <ul class="contact-list">
                <For
                    each=move || contacts.get()
                    key=|c| (c.token.clone(), c.status.clone(), c.name.clone())
                    let(contact)
                >
                    {
                        let token = contact.token.clone();
                        let token_for_click = token.clone();
                        // Deliberately NOT read from the `contact` snapshot `<For>`
                        // handed us: its `key` above is (token, status, name), so
                        // `online` flipping on its own wouldn't change the key and
                        // `<For>` would never re-render this item — the dot would
                        // freeze at whatever `online` was the instant this contact
                        // first became "established" (almost always false, since
                        // that happens well before the first presence ping). Look
                        // it up live from `contacts` instead, same pattern as
                        // `chat_label` below, so it updates every poll regardless
                        // of what `<For>` thinks changed.
                        let token_for_dot = token.clone();
                        let dot_status = move || {
                            contacts
                                .get()
                                .into_iter()
                                .find(|c| c.token == token_for_dot)
                                .filter(|c| c.status == "established")
                                .map(|c| c.online)
                        };
                        view! {
                            <li
                                class:selected=move || selected.get().as_deref() == Some(token.as_str())
                                on:click=move |_| selected.set(Some(token_for_click.clone()))
                            >
                                <span class="contact-label">
                                    {move || dot_status().map(|online| view! {
                                        <span
                                            class="presence-dot"
                                            class:online=online
                                            class:offline=!online
                                            title=if online { "Online" } else { "Offline" }
                                        ></span>
                                    })}
                                    {match &contact.name {
                                        Some(name) => view! { <span class="contact-name">{name.clone()}</span> }.into_any(),
                                        None => view! {
                                            <code>{contact.token.chars().take(8).collect::<String>()}"..."</code>
                                        }.into_any(),
                                    }}
                                </span>
                                <span class=format!("status status-{}", contact.status)>
                                    {contact.status.clone()}
                                </span>
                            </li>
                        }
                    }
                </For>
            </ul>

            <h3>"Add contact"</h3>
            <input
                type="text"
                placeholder="their routing token (hex)"
                prop:value=move || token_input.get()
                on:input=move |ev| token_input.set(event_target_value(&ev))
            />
            <input
                type="text"
                placeholder="their ed25519 pubkey (hex)"
                prop:value=move || key_input.get()
                on:input=move |ev| key_input.set(event_target_value(&ev))
            />
            <button on:click=on_add>"Send Connection Request"</button>
            {move || error.get().map(|e| view! { <p class="error">{e}</p> })}
        </div>
    }
}

/// Message transcript + send box for whichever contact is selected. Shows
/// a placeholder state until a contact is picked and until that contact's
/// session has finished the PQXDH handshake ("established" status) —
/// sending to a merely "pending" contact would fail server-side since
/// there's no ratchet key yet.
#[component]
fn ChatPanel(
    contacts: RwSignal<Vec<api::ContactDto>>,
    selected: RwSignal<Option<String>>,
    messages: RwSignal<HashMap<String, Vec<ChatMessage>>>,
) -> impl IntoView {
    let draft = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);

    // Zero-arg closure so it can be called uniformly from both a click
    // handler (which Leptos passes a MouseEvent to) and a keydown handler
    // (which passes a KeyboardEvent) — each event closure below just
    // ignores/inspects its own event and calls this with no arguments,
    // rather than this closure trying to accept either event type.
    let send_now = move || {
        let Some(token) = selected.get() else {
            return;
        };
        let text = draft.get();
        if text.trim().is_empty() {
            return;
        }
        error.set(None);
        draft.set(String::new());
        let token_for_task = token.clone();
        let text_for_history = text.clone();
        leptos::task::spawn_local(async move {
            match api::send_message(&token_for_task, &text).await {
                Ok(()) => {
                    messages.update(|map| {
                        map.entry(token_for_task).or_default().push(ChatMessage {
                            id: next_message_id(),
                            from_me: true,
                            text: text_for_history,
                        });
                    });
                }
                Err(e) => error.set(Some(e)),
            }
        });
    };

    view! {
        <div class="chat-panel">
            {move || match selected.get() {
                None => view! { <p class="hint">"Select a contact to start chatting."</p> }.into_any(),
                Some(token) => {
                    let header_token = token.clone();
                    let len_token = token.clone();
                    let history = move || messages.get().get(&token).cloned().unwrap_or_default();
                    let chat_label = move || {
                        contacts.get()
                            .iter()
                            .find(|c| c.token == header_token)
                            .and_then(|c| c.name.clone())
                            .unwrap_or_else(|| format!("{}...", header_token.chars().take(8).collect::<String>()))
                    };

                    let transcript_ref = NodeRef::<leptos::html::Div>::new();
                    // Tracks only this contact's message *count* (a Memo, so
                    // it dedups) rather than depending on `messages` itself —
                    // otherwise every contact's traffic would re-fire this
                    // and yank the scroll position back to the bottom even
                    // while the user is reading old messages in this chat.
                    let message_count = Memo::new(move |_| {
                        messages.get().get(&len_token).map(Vec::len).unwrap_or(0)
                    });
                    Effect::new(move |_| {
                        message_count.get();
                        // Deferred to a fresh task so it runs after the
                        // `<For>` list's own DOM patch has landed —
                        // otherwise `scroll_height` can still reflect the
                        // pre-update layout.
                        set_timeout(
                            move || {
                                if let Some(el) = transcript_ref.get() {
                                    el.set_scroll_top(el.scroll_height());
                                }
                            },
                            Duration::ZERO,
                        );
                    });

                    view! {
                        <h3 class="chat-header">"Chat with " {chat_label}</h3>
                        <div class="transcript" node_ref=transcript_ref>
                            <For
                                each=history
                                key=|m| m.id
                                let(msg)
                            >
                                <p class:from-me=msg.from_me class:from-peer=!msg.from_me>
                                    {msg.text.clone()}
                                </p>
                            </For>
                        </div>
                        <div class="composer">
                            <input
                                type="text"
                                placeholder="Type a message..."
                                prop:value=move || draft.get()
                                on:input=move |ev| draft.set(event_target_value(&ev))
                                on:keydown=move |ev| {
                                    if ev.key() == "Enter" {
                                        send_now();
                                    }
                                }
                            />
                            <button on:click=move |_| send_now()>"Send"</button>
                        </div>
                        {move || error.get().map(|e| view! { <p class="error">{e}</p> })}
                    }.into_any()
                }
            }}
        </div>
    }
}
