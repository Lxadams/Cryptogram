//! Root Leptos component. This is a UI prototype wired to the *real*
//! `client` crate through Tauri commands (see src/api.rs) — no mock data,
//! no simulated crypto. It won't do anything meaningful outside a Tauri
//! window (see api.rs's doc comment), but the logic itself talks to a real
//! relay server over a real UDP socket.
//!
//! Screens:
//! 1. Login    — choose a username + passcode, resolving which saved
//!    identity (if any) to use. See `LoginScreen`'s doc comment.
//! 2. Connect  — enter the relay's Ed25519 pubkey, perform the link handshake.
//! 3. Main     — show our own identity, manage contacts, chat with one peer.
//!
//! State lives in a handful of top-level signals passed down as props,
//! rather than a router or global store — deliberately simple for a
//! prototype with three screens.

use crate::api;
use leptos::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// One message in a conversation, for local display. The transcript held
/// in this UI's `messages` signal is itself rebuilt each session (from a
/// mix of persisted history and live traffic — see `MainScreen`), but the
/// messages it displays are durable: every message sent or received is
/// recorded to this identity's local SQLCipher-encrypted chat-history
/// database as it's encrypted/decrypted (see `Client::history` in the
/// `client` crate), independent of this peer's `client_state.sqlite` session
/// state and never shared with or dependent on the other peer's own copy.
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

/// Persisted chat-history rows get their own id namespace (top bit set) so
/// they can never collide with `next_message_id()`'s locally-generated ids
/// — both end up in the same `<For>` transcript list, which needs every id
/// to be unique. `next_message_id` would need over 2^63 calls in one
/// session to ever reach this range.
fn history_message_id(row_id: i64) -> u64 {
    (row_id as u64) | (1u64 << 63)
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

/// A passcode `<input>` with a small icon button to toggle between masked
/// dots and plaintext while typing — shared by the Login and Create
/// Identity screens' passcode field(s) instead of duplicating this control
/// three times.
#[component]
fn PasswordInput(value: RwSignal<String>, placeholder: &'static str) -> impl IntoView {
    let visible = RwSignal::new(false);

    view! {
        <div class="password-field">
            <input
                type=move || if visible.get() { "text" } else { "password" }
                placeholder=placeholder
                prop:value=move || value.get()
                on:input=move |ev| value.set(event_target_value(&ev))
            />
            <button
                type="button"
                class="visibility-toggle"
                title=move || if visible.get() { "Hide passcode" } else { "Show passcode" }
                on:click=move |_| visible.update(|v| *v = !*v)
            >
                {move || if visible.get() {
                    view! {
                        <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M2 8s2.5-4.5 6-4.5S14 8 14 8s-2.5 4.5-6 4.5S2 8 2 8z" />
                            <circle cx="8" cy="8" r="1.7" />
                            <path d="M2.5 2.5l11 11" />
                        </svg>
                    }.into_any()
                } else {
                    view! {
                        <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M2 8s2.5-4.5 6-4.5S14 8 14 8s-2.5 4.5-6 4.5S2 8 2 8z" />
                            <circle cx="8" cy="8" r="1.7" />
                        </svg>
                    }.into_any()
                }}
            </button>
        </div>
    }
}

/// Which of the two pre-login screens is showing. Kept separate from
/// `login`/`identity` (which gate Connect/Main) since navigating between
/// Login and Create Identity never involves either of those — it's purely
/// a UI choice, no backend call happens until one of the two forms submits.
#[derive(Clone, Copy, PartialEq)]
enum AuthScreen {
    Login,
    CreateIdentity,
}

#[component]
pub fn App() -> impl IntoView {
    let auth_screen = RwSignal::new(AuthScreen::Login);
    // Username to prefill on the Login screen right after a successful
    // Create Identity, so the user isn't retyping what they just chose.
    let just_created = RwSignal::new(None::<String>);
    // Username to prefill on the Create Identity screen when the user gets
    // there via Login's "create a new identity?" prompt (see LoginScreen),
    // so they're not retyping the username that didn't exist yet.
    let prefill_create_username = RwSignal::new(None::<String>);
    // `None` until `login` succeeds — gates the Login/Create Identity screens.
    let login = RwSignal::new(None::<api::LoginDto>);
    // `None` until `bootstrap` succeeds — gates the Connect screen. Reset
    // together with `login` by `log_out`, below.
    let identity = RwSignal::new(None::<api::IdentityDto>);

    // Tears down the backend session (stops background tasks, releases the
    // identity's session lock — see `logout`'s doc comment in commands.rs)
    // and sends the UI back to the Login screen. Shown whenever `login` is
    // `Some`, i.e. any screen past Login itself, so abandoning a stuck
    // Connect screen works the same way as logging out from Main.
    let log_out = move || {
        leptos::task::spawn_local(async move {
            let _ = api::logout().await;
            identity.set(None);
            login.set(None);
        });
    };

    let theme = RwSignal::new(initial_theme());
    Effect::new(move |_| apply_theme(theme.get()));

    view! {
        <main class="app">
            <div class="app-header">
                <h1>"E2E-Messenger"</h1>
                <div class="header-actions">
                    {move || login.get().is_some().then(|| view! {
                        <button class="theme-toggle" on:click=move |_| log_out()>
                            "Log out"
                        </button>
                    })}
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
            </div>
            {move || match (login.get(), identity.get()) {
                (None, _) => match auth_screen.get() {
                    AuthScreen::Login => view! {
                        <LoginScreen
                            login=login
                            auth_screen=auth_screen
                            just_created=just_created
                            prefill_create_username=prefill_create_username
                        />
                    }.into_any(),
                    AuthScreen::CreateIdentity => view! {
                        <CreateIdentityScreen
                            auth_screen=auth_screen
                            just_created=just_created
                            prefill_username=prefill_create_username
                        />
                    }.into_any(),
                },
                (Some(_), None) => view! { <ConnectScreen identity=identity /> }.into_any(),
                (Some(_), Some(id)) => view! { <MainScreen identity=id /> }.into_any(),
            }}
        </main>
    }
}

/// Screen 1 (default): log in with a username + passcode that already has a
/// saved identity. This is a UI-layer gate only — see `hash_passcode`'s doc
/// comment in `code/client/src/lib.rs` — it decides which pseudonym's
/// identity file the Connect screen's `bootstrap` call will load next,
/// nothing here touches the network. No saved identity for that username?
/// The "Create identity" button hands off to `CreateIdentityScreen` instead
/// of trying to create one inline.
#[component]
fn LoginScreen(
    login: RwSignal<Option<api::LoginDto>>,
    auth_screen: RwSignal<AuthScreen>,
    just_created: RwSignal<Option<String>>,
    prefill_create_username: RwSignal<Option<String>>,
) -> impl IntoView {
    let known = RwSignal::new(Vec::<String>::new());

    // Prefill (once) from a just-created identity, and surface a small
    // confirmation hint — cleared as soon as the user edits the username,
    // so it doesn't linger and describe a different name.
    let pseudonym_input = RwSignal::new(just_created.get_untracked().unwrap_or_default());
    let created_hint = RwSignal::new(just_created.get_untracked());

    let passcode_input = RwSignal::new(String::new());
    // Distinct from `error`: an unrecognized username is an expected outcome
    // (see `api::LoginOutcome`'s doc comment), not a mistake to scold the
    // user for — it gets its own message plus a direct path to fix it,
    // rather than sharing the plain error paragraph below.
    let unknown_username = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    // The "Existing identities" dropdown's current value — empty means
    // nothing selected. Selecting an option also fills `pseudonym_input`
    // (same effect the old clickable list had), and drives which identity
    // the delete control (below) acts on.
    let selected_existing = RwSignal::new(String::new());
    // Whether the delete control is showing its "Delete? Yes/No" confirm
    // (for whichever identity `selected_existing` names) instead of the
    // usual delete icon.
    let delete_confirm = RwSignal::new(None::<String>);
    let delete_busy = RwSignal::new(false);

    // Re-fetch on a timer, same pattern as MainScreen's contact/inbox
    // polling — this machine's identities aren't scoped per peer window, so
    // another peer deleting one (or creating one) should show up here
    // without needing to leave and come back to this screen. If the
    // identity currently selected/typed from a stale list just disappeared
    // out from under the user (deleted elsewhere), clear it rather than
    // leave the dropdown/delete control pointing at nothing.
    let refresh_known = move || {
        leptos::task::spawn_local(async move {
            if let Ok(list) = api::list_pseudonyms().await {
                let selected = selected_existing.get_untracked();
                if !selected.is_empty() && !list.contains(&selected) {
                    if pseudonym_input.get_untracked() == selected {
                        pseudonym_input.set(String::new());
                    }
                    selected_existing.set(String::new());
                    delete_confirm.set(None);
                }
                known.set(list);
            }
        });
    };
    refresh_known();
    let _known_refresh = set_interval_with_handle(refresh_known, Duration::from_millis(1000));

    let go_to_create_identity = move || {
        let typed = pseudonym_input.get();
        prefill_create_username.set((!typed.trim().is_empty()).then_some(typed));
        auth_screen.set(AuthScreen::CreateIdentity);
    };

    let submit = move |_| {
        let pseudonym = pseudonym_input.get();
        let passcode = passcode_input.get();
        if pseudonym.trim().is_empty() {
            error.set(Some("Enter your username.".into()));
            return;
        }
        if passcode.is_empty() {
            error.set(Some("Enter your passcode.".into()));
            return;
        }
        error.set(None);
        unknown_username.set(None);
        busy.set(true);
        leptos::task::spawn_local(async move {
            match api::login(&pseudonym, &passcode).await {
                Ok(api::LoginOutcome::Success { pseudonym }) => {
                    login.set(Some(api::LoginDto { pseudonym }))
                }
                Ok(api::LoginOutcome::UnknownUsername) => unknown_username.set(Some(pseudonym)),
                Err(e) => error.set(Some(e)),
            }
            busy.set(false);
        });
    };

    let confirm_delete = move |name: String| {
        error.set(None);
        delete_busy.set(true);
        leptos::task::spawn_local(async move {
            match api::delete_identity(&name).await {
                Ok(()) => {
                    known.update(|list| list.retain(|n| n != &name));
                    if pseudonym_input.get_untracked() == name {
                        pseudonym_input.set(String::new());
                    }
                    selected_existing.set(String::new());
                    delete_confirm.set(None);
                }
                Err(e) => error.set(Some(e)),
            }
            delete_busy.set(false);
        });
    };

    view! {
        <section class="login-screen">
            <p>"Log in with your username and passcode."</p>
            {move || created_hint.get().map(|name| view! {
                <p class="hint">"Identity \"" {name} "\" created — log in below."</p>
            })}
            {move || {
                let names = known.get();
                (!names.is_empty()).then(|| view! {
                    <h3 class="identities-heading">"Existing identities"</h3>
                    <div class="identity-select-row">
                        <select
                            class="identity-select"
                            prop:value=move || selected_existing.get()
                            on:change=move |ev| {
                                let picked = event_target_value(&ev);
                                selected_existing.set(picked.clone());
                                pseudonym_input.set(picked);
                                created_hint.set(None);
                                unknown_username.set(None);
                                delete_confirm.set(None);
                            }
                        >
                            <option value="">"-- choose an identity --"</option>
                            <For each=move || known.get() key=|n| n.clone() let(name)>
                                <option value=name.clone()>{name.clone()}</option>
                            </For>
                        </select>
                        {move || {
                            let selected = selected_existing.get();
                            (!selected.is_empty()).then(|| {
                                if delete_confirm.get().as_deref() == Some(selected.as_str()) {
                                    let yes_name = selected.clone();
                                    view! {
                                        <span class="identity-confirm">
                                            "Delete?"
                                            <button
                                                type="button"
                                                class="danger"
                                                disabled=move || delete_busy.get()
                                                on:click=move |_| confirm_delete(yes_name.clone())
                                            >
                                                "Yes"
                                            </button>
                                            <button
                                                type="button"
                                                class="secondary"
                                                on:click=move |_| delete_confirm.set(None)
                                            >
                                                "No"
                                            </button>
                                        </span>
                                    }.into_any()
                                } else {
                                    let trash_name = selected.clone();
                                    view! {
                                        <button
                                            type="button"
                                            class="icon-btn danger"
                                            title="Delete this identity"
                                            on:click=move |_| delete_confirm.set(Some(trash_name.clone()))
                                        >
                                            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">
                                                <path d="M3 4.5h10" />
                                                <path d="M6.5 4.5V3a1 1 0 0 1 1-1h1a1 1 0 0 1 1 1v1.5" />
                                                <path d="M4.5 4.5l.6 8a1 1 0 0 0 1 .9h3.8a1 1 0 0 0 1-.9l.6-8" />
                                            </svg>
                                        </button>
                                    }.into_any()
                                }
                            })
                        }}
                    </div>
                })
            }}
            <input
                type="text"
                placeholder="username"
                prop:value=move || pseudonym_input.get()
                on:input=move |ev| {
                    pseudonym_input.set(event_target_value(&ev));
                    created_hint.set(None);
                    unknown_username.set(None);
                    selected_existing.set(String::new());
                }
            />
            <PasswordInput value=passcode_input placeholder="passcode" />
            <div class="login-actions">
                <button disabled=move || busy.get() on:click=submit>
                    {move || if busy.get() { "..." } else { "Log in" }}
                </button>
                <button
                    type="button"
                    class="secondary"
                    disabled=move || busy.get()
                    on:click=move |_| go_to_create_identity()
                >
                    "Create identity"
                </button>
            </div>
            {move || unknown_username.get().map(|name| view! {
                <p class="error">
                    "Username \"" {name} "\" does not exist. "
                    <a href="#" on:click=move |ev| {
                        ev.prevent_default();
                        go_to_create_identity();
                    }>
                        "Create new identity?"
                    </a>
                </p>
            })}
            {move || error.get().map(|e| view! { <p class="error">{e}</p> })}
        </section>
    }
}

/// Screen 1b: mint a brand-new identity behind a chosen username + passcode.
/// On success, hands back to `LoginScreen` rather than proceeding straight
/// to Connect — the user logs in with what they just chose, same as any
/// other identity. This is a UI-layer gate only, same caveat as
/// `LoginScreen` — see `hash_passcode`'s doc comment in
/// `code/client/src/lib.rs`.
#[component]
fn CreateIdentityScreen(
    auth_screen: RwSignal<AuthScreen>,
    just_created: RwSignal<Option<String>>,
    /// Set by `LoginScreen` when it sends the user here because their typed
    /// username didn't match any saved identity — carries that username
    /// over so it doesn't need retyping.
    prefill_username: RwSignal<Option<String>>,
) -> impl IntoView {
    let pseudonym_input = RwSignal::new(prefill_username.get_untracked().unwrap_or_default());
    let passcode_input = RwSignal::new(String::new());
    let confirm_input = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let submit = move |_| {
        let pseudonym = pseudonym_input.get();
        let passcode = passcode_input.get();
        if pseudonym.trim().is_empty() {
            error.set(Some("Choose a username first.".into()));
            return;
        }
        if passcode.is_empty() {
            error.set(Some("Choose a passcode first.".into()));
            return;
        }
        if passcode != confirm_input.get() {
            error.set(Some("Passcodes don't match.".into()));
            return;
        }
        error.set(None);
        busy.set(true);
        let pseudonym_for_task = pseudonym.clone();
        leptos::task::spawn_local(async move {
            match api::create_identity(&pseudonym_for_task, &passcode).await {
                Ok(()) => {
                    just_created.set(Some(pseudonym_for_task));
                    auth_screen.set(AuthScreen::Login);
                }
                Err(e) => error.set(Some(e)),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="login-screen">
            <p>"Choose a username and passcode to create a new identity."</p>
            <input
                type="text"
                placeholder="username"
                prop:value=move || pseudonym_input.get()
                on:input=move |ev| pseudonym_input.set(event_target_value(&ev))
            />
            <PasswordInput value=passcode_input placeholder="passcode" />
            <PasswordInput value=confirm_input placeholder="confirm passcode" />
            <div class="login-actions">
                <button disabled=move || busy.get() on:click=submit>
                    {move || if busy.get() { "..." } else { "Create identity" }}
                </button>
                <button
                    type="button"
                    class="secondary"
                    disabled=move || busy.get()
                    on:click=move |_| auth_screen.set(AuthScreen::Login)
                >
                    "Back to login"
                </button>
            </div>
            {move || error.get().map(|e| view! { <p class="error">{e}</p> })}
        </section>
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
    // immediately, optimistically), incoming polls (added on arrival), and
    // a one-time hydration from this peer's own persisted chat history the
    // first time each contact is selected (see the Effect below) — that
    // history is a full independent copy, so it's what makes a contact's
    // past messages still show up here even if the peer lost their own
    // state, deleted the conversation, or reconnected from scratch.
    let messages = RwSignal::new(HashMap::<String, Vec<ChatMessage>>::new());
    let history_loaded_for = RwSignal::new(HashSet::<String>::new());

    Effect::new(move |_| {
        let Some(token) = selected.get() else {
            return;
        };
        if history_loaded_for.get_untracked().contains(&token) {
            return;
        }
        leptos::task::spawn_local(async move {
            if let Ok(history) = api::chat_history(&token, 200).await {
                // Merge, never replace: this fetch is async, and the 1s
                // poll below keeps running concurrently — if a live
                // message (e.g. one of Bob's) arrives via poll_inbox and
                // gets pushed into `messages` while this fetch is still in
                // flight, it must not be clobbered by this fetch's
                // now-stale (pre-arrival) snapshot resolving afterward.
                // History ids and live-generated ids are in disjoint
                // numeric ranges (see `history_message_id`), so backfilled
                // history is simply prepended ahead of whatever's already
                // live in the list.
                messages.update(|map| {
                    let existing = map.entry(token.clone()).or_default();
                    let existing_ids: std::collections::HashSet<u64> =
                        existing.iter().map(|m| m.id).collect();
                    let mut combined: Vec<ChatMessage> = history
                        .into_iter()
                        .map(|m| ChatMessage {
                            id: history_message_id(m.id),
                            from_me: m.from_me,
                            text: m.text,
                        })
                        .filter(|m| !existing_ids.contains(&m.id))
                        .collect();
                    combined.append(existing);
                    *existing = combined;
                });
                history_loaded_for.update(|set| {
                    set.insert(token);
                });
            }
        });
    });

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
                            // Use the backend's own chat-history row id when
                            // there is one, so this live-delivered message
                            // is identified the same way a later
                            // `chat_history` fetch would identify it — see
                            // `history_message_id`'s doc comment. Only
                            // falls back to a local id if no history is
                            // attached at all (shouldn't happen once logged
                            // in, but this front end has no other way to
                            // key the message if it does).
                            id: msg
                                .id
                                .map(history_message_id)
                                .unwrap_or_else(next_message_id),
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
/// running instances during local testing. `name` (chosen on the login
/// screen) is shown here for your own reference only — it's sent
/// automatically as part of the KeyExchange once you connect to someone,
/// so peers see "alice" in their contact list without typing anything
/// themselves (see `Client::local_name` / `contact_names` in
/// code/client/src/lib.rs).
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

    // Which contact (by token) is showing its "Remove?" confirm row instead
    // of the usual remove icon — same inline-confirm pattern as the Login
    // screen's identity delete. `None` means no confirm is open.
    let remove_confirm = RwSignal::new(None::<String>);
    let remove_busy = RwSignal::new(false);

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

    // Removing a contact also deletes its local chat history unconditionally
    // (see `remove_contact`'s doc comment in commands.rs) — reconnecting to
    // the same person starts a fresh conversation under a new token
    // regardless, and there's no UI to view a removed contact's old history.
    let do_remove = move |token: String| {
        error.set(None);
        remove_busy.set(true);
        leptos::task::spawn_local(async move {
            match api::remove_contact(&token).await {
                Ok(()) => {
                    contacts.update(|list| list.retain(|c| c.token != token));
                    if selected.get_untracked().as_deref() == Some(token.as_str()) {
                        selected.set(None);
                    }
                    remove_confirm.set(None);
                }
                Err(e) => error.set(Some(e)),
            }
            remove_busy.set(false);
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
                        let token_for_remove = token.clone();
                        let token_for_confirm = token.clone();
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
                                {move || {
                                    if remove_confirm.get().as_deref() == Some(token_for_confirm.as_str()) {
                                        let remove_yes = token_for_confirm.clone();
                                        view! {
                                            <span class="identity-confirm" on:click=|ev| ev.stop_propagation()>
                                                "Remove?"
                                                <button
                                                    type="button"
                                                    class="danger"
                                                    disabled=move || remove_busy.get()
                                                    on:click=move |_| do_remove(remove_yes.clone())
                                                >
                                                    "Yes"
                                                </button>
                                                <button
                                                    type="button"
                                                    class="secondary"
                                                    on:click=move |_| remove_confirm.set(None)
                                                >
                                                    "No"
                                                </button>
                                            </span>
                                        }.into_any()
                                    } else {
                                        let remove_click = token_for_remove.clone();
                                        view! {
                                            <button
                                                type="button"
                                                class="icon-btn danger"
                                                title="Remove this contact"
                                                on:click=move |ev| {
                                                    ev.stop_propagation();
                                                    remove_confirm.set(Some(remove_click.clone()));
                                                }
                                            >
                                                <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">
                                                    <path d="M3 4.5h10" />
                                                    <path d="M6.5 4.5V3a1 1 0 0 1 1-1h1a1 1 0 0 1 1 1v1.5" />
                                                    <path d="M4.5 4.5l.6 8a1 1 0 0 0 1 .9h3.8a1 1 0 0 0 1-.9l.6-8" />
                                                </svg>
                                            </button>
                                        }.into_any()
                                    }
                                }}
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
                Ok(history_id) => {
                    messages.update(|map| {
                        map.entry(token_for_task).or_default().push(ChatMessage {
                            // Same reasoning as the incoming side in
                            // `MainScreen::refresh` — use the backend's own
                            // chat-history row id so this optimistic
                            // display agrees with a later `chat_history`
                            // fetch on what identifies this message.
                            id: history_id
                                .map(history_message_id)
                                .unwrap_or_else(next_message_id),
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
