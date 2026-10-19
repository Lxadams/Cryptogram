//! Root Leptos component. This is a UI prototype wired to the *real*
//! `client` crate through Tauri commands (see src/api.rs) — no mock data,
//! no simulated crypto. It won't do anything meaningful outside a Tauri
//! window (see api.rs's doc comment), but the logic itself talks to a real
//! relay server over a real UDP socket.
//!
//! Screens:
//! 1. Login    — choose a username + passcode, resolving which saved
//!    identity (if any) to use. See `LoginScreen`'s doc comment.
//! 2. Connect  — perform the link handshake with the relay.
//! 3. Main     — show our own identity, manage contacts, chat with one peer.
//!
//! State lives in a handful of top-level signals passed down as props,
//! rather than a router or global store — deliberately simple for a
//! prototype with three screens.

use crate::qr::QrScanner;
use crate::{api, contact_code, qr};
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
    /// When it was sent or arrived, in Unix milliseconds.
    timestamp_ms: Option<i64>,
    /// For a message we sent, whether the relay has confirmed it has it.
    status: Option<SendStatus>,
}

/// What became of a message we sent: shown as nothing yet, a check mark, or
/// a red exclamation mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SendStatus {
    /// Waiting for the relay to confirm it has it.
    Sending,
    /// The relay has enough of it to deliver.
    Sent,
    /// The relay didn't confirm it in time.
    Failed,
}

impl SendStatus {
    /// From its name in `api::StoredMessageDto` and
    /// `api::SentMessageUpdateDto`.
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "sending" => Some(SendStatus::Sending),
            "sent" => Some(SendStatus::Sent),
            "failed" => Some(SendStatus::Failed),
            _ => None,
        }
    }
}

/// `timestamp_ms` as the time of day in the user's locale ("14:05", or
/// "2:05 pm"), with the date in front if it isn't today.
fn format_time(timestamp_ms: i64) -> String {
    let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(timestamp_ms as f64));
    let options = |fields: &[(&str, &str)]| {
        let object = js_sys::Object::new();
        for (key, value) in fields {
            let _ = js_sys::Reflect::set(&object, &(*key).into(), &(*value).into());
        }
        wasm_bindgen::JsValue::from(object)
    };
    let time: String = date
        .to_locale_time_string_with_options(
            "default",
            &options(&[("hour", "2-digit"), ("minute", "2-digit")]),
        )
        .into();
    let now = js_sys::Date::new_0();
    let today = date.get_full_year() == now.get_full_year()
        && date.get_month() == now.get_month()
        && date.get_date() == now.get_date();
    if today {
        time
    } else {
        let day: String = date
            .to_locale_date_string(
                "default",
                &options(&[("day", "numeric"), ("month", "short")]),
            )
            .into();
        format!("{day}, {time}")
    }
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

/// The chat-history row id behind a `history_message_id`, or `None` for a
/// `next_message_id` one.
fn history_row_id(id: u64) -> Option<i64> {
    (id & (1u64 << 63) != 0).then_some((id & !(1u64 << 63)) as i64)
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

/// Bin icon for destructive icon buttons (delete identity, remove contact).
#[component]
fn TrashIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 4.5h10" />
            <path d="M6.5 4.5V3a1 1 0 0 1 1-1h1a1 1 0 0 1 1 1v1.5" />
            <path d="M4.5 4.5l.6 8a1 1 0 0 0 1 .9h3.8a1 1 0 0 0 1-.9l.6-8" />
        </svg>
    }
}

/// A small square with how many new messages there are (see `MainScreen`'s
/// `unread`), or nothing when there are none.
#[component]
fn UnreadBadge(count: usize) -> impl IntoView {
    (count > 0).then(|| {
        let label = if count > 99 {
            "99+".to_string()
        } else {
            count.to_string()
        };
        let title = if count == 1 {
            "1 new message".to_string()
        } else {
            format!("{count} new messages")
        };
        view! { <span class="unread-badge" title=title>{label}</span> }
    })
}

/// A circular arrow, for sending a message again.
#[component]
fn RetryIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
            <path d="M13 8a5 5 0 1 1-1.5-3.55" />
            <path d="M13 2.5v3h-3" />
        </svg>
    }
}

/// Three dots, for a button that opens a menu (see `Menu`).
#[component]
fn MenuIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
            <circle cx="8" cy="3.5" r="1.4" />
            <circle cx="8" cy="8" r="1.4" />
            <circle cx="8" cy="12.5" r="1.4" />
        </svg>
    }
}

/// Clears a polling interval when the component that started it unmounts.
/// A `set_interval` otherwise outlives its screen: after logging in, the
/// Login screen's poll kept firing against disposed signals (panicking), and
/// after a logout/login cycle a stale Main screen's poll kept draining
/// `poll_inbox`, so new messages went to the dead screen instead of the
/// live one.
fn stop_on_cleanup(handle: Result<IntervalHandle, wasm_bindgen::JsValue>) {
    if let Ok(handle) = handle {
        on_cleanup(move || handle.clear());
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

    // Pick up a session the backend already has before showing anything.
    // On Android the UI reloads when the app is reopened, while the backend
    // stays logged in and connected (see `current_session` in commands.rs).
    let restoring = RwSignal::new(true);
    leptos::task::spawn_local(async move {
        if let Ok(Some(session)) = api::current_session().await {
            login.set(Some(api::LoginDto {
                pseudonym: session.pseudonym,
            }));
            identity.set(session.identity);
        }
        restoring.set(false);
    });

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
                <h1>"Cryptogram"</h1>
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
            {move || if restoring.get() { ().into_any() } else { match (login.get(), identity.get()) {
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
            }}}
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
                // `try_`: a fetch already in flight when this screen closes
                // (e.g. on a successful login) resolves after its signals
                // are disposed, and a plain `get_untracked` would panic.
                let Some(selected) = selected_existing.try_get_untracked() else {
                    return;
                };
                if !selected.is_empty() && !list.contains(&selected) {
                    if pseudonym_input.get_untracked() == selected {
                        pseudonym_input.set(String::new());
                    }
                    selected_existing.set(String::new());
                    delete_confirm.set(None);
                }
                if known.with_untracked(|current| current != &list) {
                    known.set(list);
                }
            }
        });
    };
    refresh_known();
    stop_on_cleanup(set_interval_with_handle(
        refresh_known,
        Duration::from_millis(1000),
    ));

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
                                            <TrashIcon />
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

/// How long after "Connect" is clicked the main screen appears at the
/// earliest (see `ConnectScreen`).
const CONNECT_MIN_WAIT: Duration = Duration::from_secs(2);

/// Screen 1: perform the link handshake with the relay. The relay's Ed25519
/// pubkey is built into the app (see `relay_pubkey_hex` in
/// src-tauri/src/commands.rs), so there's nothing to paste.
#[component]
fn ConnectScreen(identity: RwSignal<Option<api::IdentityDto>>) -> impl IntoView {
    let error = RwSignal::new(None::<String>);
    let connecting = RwSignal::new(false);

    // The main screen comes no sooner than `CONNECT_MIN_WAIT` after the
    // click, however fast the relay answers; an error shows straight away.
    let on_connect = move |_| {
        error.set(None);
        connecting.set(true);
        let clicked_at = js_sys::Date::now();
        leptos::task::spawn_local(async move {
            match api::bootstrap().await {
                Ok(id) => {
                    let waited = Duration::from_millis((js_sys::Date::now() - clicked_at) as u64);
                    set_timeout(
                        move || {
                            identity.try_set(Some(id));
                            connecting.try_set(false);
                        },
                        CONNECT_MIN_WAIT.saturating_sub(waited),
                    );
                }
                Err(e) => {
                    error.set(Some(e));
                    connecting.set(false);
                }
            }
        });
    };

    view! {
        <section class="connect-screen">
            <p>"Connect to the relay server to generate/load your identity."</p>
            <p class="hint">
                "Run the server (runserver.sh) first. The app checks it against "
                "the public key it was built with."
            </p>
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
    // People who tried to connect but aren't contacts yet, and whether
    // requests are muted (see `ConnectionRequestNotice`), and whether the QR
    // scanner is open. All live here so the notice can open the contact
    // panel's scanner, and the panel can unmute.
    let requests = RwSignal::new(api::ConnectionRequestsDto::default());
    let scanning = RwSignal::new(false);
    // Our QR code popup (see `QrCodeModal`), and, when it opened because we
    // just scanned someone who hasn't scanned us yet, their token: it
    // closes once they have.
    let show_qr = RwSignal::new(false);
    let qr_waiting_for = RwSignal::new(None::<String>);
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
    // token_hex -> how many messages arrived from them while their chat
    // wasn't open, shown next to their name (see `UnreadBadge`). Opening
    // the chat clears it. Live only: a restart starts from none, and
    // anything that arrived meanwhile counts once it's handed over.
    let unread = RwSignal::new(HashMap::<String, usize>::new());
    Effect::new(move |_| {
        if let Some(token) = selected.get() {
            unread.update(|counts| {
                counts.remove(&token);
            });
        }
    });
    // Send statuses that came before their message was added: `send_message`
    // returns only once the first packet is out, and a short message can be
    // confirmed by then. Keyed by message id; the send takes its status
    // from here (see `ChatPanel`).
    let early_updates = StoredValue::new(HashMap::<u64, SendStatus>::new());

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
                    let existing_ids: HashSet<u64> = existing.iter().map(|m| m.id).collect();
                    let mut combined: Vec<ChatMessage> = history
                        .into_iter()
                        .map(|m| ChatMessage {
                            id: history_message_id(m.id),
                            from_me: m.from_me,
                            text: m.text,
                            timestamp_ms: Some(m.timestamp_ms),
                            status: m.status.as_deref().and_then(SendStatus::from_name),
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

    // Android's back button goes back in the web view's history, and only
    // leaves the app when there's none (see Tauri's `AppPlugin`). So each
    // layer open over the contact list (an open chat, our QR code, the
    // scanner) gets a history entry, and going back closes the topmost
    // one: back steps out of the scanner, then the QR code, then the chat,
    // as on a phone it should, and only then out of the app. A layer that
    // closes any other way (its X, the ← button, a scan) takes its entry
    // back off, so the two stay in step.
    let layers_open = move || {
        usize::from(selected.get().is_some())
            + usize::from(show_qr.get())
            + usize::from(scanning.get())
    };
    // Entries pushed for open layers, and how many of our own trips back
    // through them (when layers closed some other way) are still to land.
    let pushed = StoredValue::new(0usize);
    let pending_pops = StoredValue::new(0usize);
    // Push or pop entries until there's one per open layer. Waits while one
    // of our pops is still on its way: history moves asynchronously, and
    // pushing meanwhile would muddle which entry it lands on.
    let sync_history = move || {
        if pending_pops.get_value() > 0 {
            return;
        }
        let Ok(history) = window().history() else {
            return;
        };
        let open = untrack(layers_open);
        let have = pushed.get_value();
        if open > have {
            for _ in have..open {
                let _ = history.push_state_with_url(&wasm_bindgen::JsValue::NULL, "", None);
            }
        } else if open < have {
            pending_pops.set_value(1);
            let _ = history.go_with_delta(-((have - open) as i32));
        }
        pushed.set_value(open);
    };
    Effect::new(move |_| {
        layers_open();
        sync_history();
    });
    let popstate = window_event_listener(leptos::ev::popstate, move |_| {
        if pending_pops.get_value() > 0 {
            // One of ours: catch up on anything that changed meanwhile.
            pending_pops.set_value(0);
            sync_history();
            return;
        }
        // The back button: that entry is gone, so close its layer.
        pushed.update_value(|n| *n = n.saturating_sub(1));
        if scanning.get_untracked() {
            scanning.set(false);
        } else if show_qr.get_untracked() {
            show_qr.set(false);
            qr_waiting_for.set(None);
        } else if selected.get_untracked().is_some() {
            selected.set(None);
        }
    });
    on_cleanup(move || popstate.remove());

    // They've scanned our code once they're past "pending": their side has
    // reached ours (see `Client::contact_status`).
    Effect::new(move |_| {
        let Some(token) = qr_waiting_for.get() else {
            return;
        };
        if contacts.with(|list| {
            list.iter()
                .any(|c| c.token == token && c.status != "pending")
        }) {
            show_qr.set(false);
            qr_waiting_for.set(None);
        }
    });

    // The network stats (see `api::network_stats`), for the Network section
    // and the unstable network warning (see `NetworkWarning`).
    let net_stats = RwSignal::new(None::<api::NetworkStatsDto>);

    // Poll the backend every second for contact-status changes and newly
    // decrypted messages. This is deliberately simple polling rather than
    // a push/event channel — see poll_inbox's doc comment in commands.rs.
    let refresh = move || {
        leptos::task::spawn_local(async move {
            if let Ok(latest) = api::network_stats().await {
                net_stats.try_set(Some(latest));
            }
            // Only notify when something actually changed: this runs every
            // second, and every `set` re-runs everything that reads
            // `contacts`. `try_`: the response can land after this screen
            // has unmounted.
            if let Ok(list) = api::list_contacts().await
                && contacts.try_with_untracked(|current| current != &list) == Some(true)
            {
                contacts.set(list);
            }
            if let Ok(list) = api::connection_requests().await
                && requests.try_with_untracked(|current| current != &list) == Some(true)
            {
                requests.set(list);
            }
            if let Ok(incoming) = api::poll_inbox().await
                && !incoming.is_empty()
            {
                // New unless their chat is the one open.
                let open = selected.try_get_untracked().flatten();
                let _ = unread.try_update(|counts| {
                    for msg in &incoming {
                        if open.as_ref() != Some(&msg.from_token) {
                            *counts.entry(msg.from_token.clone()).or_default() += 1;
                        }
                    }
                });
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
                            timestamp_ms: Some(msg.timestamp_ms),
                            status: None,
                        });
                    }
                });
            }
            // Whether the relay got what we sent: a check mark, or a red
            // exclamation mark if it didn't in time.
            if let Ok(updates) = api::sent_message_updates().await
                && !updates.is_empty()
            {
                messages.update(|map| {
                    for update in updates {
                        let id = history_message_id(update.id);
                        let status = SendStatus::from_name(&update.status);
                        if let Some(message) = map.values_mut().flatten().find(|m| m.id == id) {
                            message.status = status;
                        } else if let Some(status) = status {
                            // Its `send_message` hasn't returned yet (or
                            // failed, so it's never added: hence the bound).
                            let _ = early_updates.try_update_value(|early| {
                                if early.len() >= 64 {
                                    early.clear();
                                }
                                early.insert(id, status);
                            });
                        }
                    }
                });
            }
        });
    };
    refresh();
    stop_on_cleanup(set_interval_with_handle(
        refresh,
        Duration::from_millis(1000),
    ));

    view! {
        // `chat-open`: on narrow screens, show the chat instead of the
        // contact list (see `.main-screen.chat-open` in style.css).
        <section class="main-screen" class:chat-open=move || selected.get().is_some()>
            <NetworkWarning stats=net_stats />
            <IdentityCard identity=identity.clone() show_qr=show_qr net_stats=net_stats />
            // Before the scanner and the connection request notice, so they
            // open on top of it: accepting a request means scanning their
            // code while ours is still up.
            <QrCodeModal identity=identity show_qr=show_qr waiting_for=qr_waiting_for />
            <div class="columns">
                <ContactPanel
                    contacts=contacts
                    selected=selected
                    requests=requests
                    scanning=scanning
                    unread=unread
                    show_qr=show_qr
                    qr_waiting_for=qr_waiting_for
                />
                <ChatPanel
                    contacts=contacts
                    selected=selected
                    messages=messages
                    early_updates=early_updates
                    unread=unread
                />
            </div>
            <ConnectionRequestNotice requests=requests scanning=scanning selected=selected />
        </section>
    }
}

/// Our own identity — what a peer needs (routing token + Ed25519 key) to
/// add us as a contact, shown both as hex (to copy-paste, folded away by
/// default since it's long and the QR code is the usual way) and, via
/// "Present QR code", as a QR code of the same two values for a peer's
/// "Scan QR code" (see contact_code.rs for the payload). `name` (chosen on
/// the login screen) is shown here for your own reference only — it's sent
/// automatically as part of the KeyExchange once you connect to someone,
/// so peers see "alice" in their contact list without typing anything
/// themselves (see `Client::local_name` / `contact_names` in
/// code/client/src/lib.rs). Settings fold away under it too, where there
/// are any: whether notifications name senders, on devices that post them,
/// and the simulated network loss (see `SimulatedLoss`).
#[component]
fn IdentityCard(
    identity: api::IdentityDto,
    show_qr: RwSignal<bool>,
    net_stats: RwSignal<Option<api::NetworkStatsDto>>,
) -> impl IntoView {
    let notifications = RwSignal::new(None::<api::NotificationSettingsDto>);
    leptos::task::spawn_local(async move {
        if let Ok(settings) = api::notification_settings().await {
            notifications.try_set(Some(settings));
        }
    });

    view! {
        <div class="identity-card">
            <div class="identity-card-header">
                <h2>"Your Identity"</h2>
                {identity.name.clone().map(|name| view! {
                    <span class="identity-name">{name}</span>
                })}
                <button type="button" on:click=move |_| show_qr.set(true)>
                    "Present QR code"
                </button>
            </div>
            <details class="identity-details">
                <summary>"Show token and key"</summary>
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
            </details>
            // Read once it's loaded, then left to the checkbox: setting the
            // signal again would redraw the panel and fold it shut.
            {move || notifications.get().filter(|n| n.posted).map(|n| view! {
                <details class="identity-details">
                    <summary>"Settings"</summary>
                    <label class="setting">
                        <input
                            type="checkbox"
                            prop:checked=n.with_names
                            on:change=move |ev| {
                                let on = event_target_checked(&ev);
                                leptos::task::spawn_local(async move {
                                    let _ = api::set_notify_with_names(on).await;
                                });
                            }
                        />
                        "Say who each message is from in notifications"
                    </label>
                    <p class="hint">
                        "Off by default: notifications can show on the lock screen, where anyone holding your phone can read them."
                    </p>
                </details>
            })}
            <SimulatedLoss />
            <NetworkStats stats=net_stats />
        </div>
    }
}

/// A thin bar across the top of the main screen while the network is
/// unstable: 80% or more of packets lost either way (see
/// `Client::unstable_network`), shown until it's below 78% again. Above
/// the chat too, on a phone.
#[component]
fn NetworkWarning(stats: RwSignal<Option<api::NetworkStatsDto>>) -> impl IntoView {
    move || {
        stats.with(|s| {
            let s = s.as_ref().filter(|s| s.unstable)?;
            let sending = s.loss_sending_pct.unwrap_or(0);
            let receiving = s.loss_receiving_pct.unwrap_or(0);
            let which = match (sending >= 80, receiving >= 80) {
                (true, true) => "both ways",
                (true, false) => "sending",
                _ => "receiving",
            };
            let worst = sending.max(receiving);
            let what = if s.nothing_back {
                "nothing back from the relay in the last 10 s".to_string()
            } else {
                format!("about {worst}% of packets lost {which}")
            };
            Some(view! {
                <div class="network-warning" role="status">
                    {format!("Unstable network: {what}. Messages may be slow to arrive.")}
                </div>
            })
        })
    }
}

/// The link to the relay, the packets to and from it, what had to be sent
/// again, and how much is being lost (see `api::network_stats`), folded
/// away under the identity card and updated every second from
/// `MainScreen`'s poll. Packet counts are since the app started; the rest
/// since this login.
#[component]
fn NetworkStats(stats: RwSignal<Option<api::NetworkStatsDto>>) -> impl IntoView {
    // "1,234", with any simulated drops after it.
    let packets = |count: u64, dropped: u64| {
        if dropped == 0 {
            count.to_string()
        } else {
            format!("{count} (+{dropped} dropped by simulated loss)")
        }
    };

    view! {
        <details class="identity-details network-stats">
            <summary>"Network"</summary>
            {move || stats.get().map(|s| {
                let heard = s.last_heard_ms_ago / 1000;
                let (status_class, status) = match s.status.as_str() {
                    "reconnecting" => ("net-reconnecting", "Reconnecting…".to_string()),
                    "quiet" => ("net-quiet", format!("No reply for {heard} s")),
                    _ => ("net-connected", format!("Connected · heard {heard} s ago")),
                };
                view! {
                    <dl>
                        <dt>"Relay"</dt>
                        <dd><code>{s.relay}</code></dd>
                        <dt>"Status"</dt>
                        <dd class=status_class>{status}</dd>
                        <dt>"Packets sent"</dt>
                        <dd>{packets(s.packets_sent, s.packets_send_dropped)}</dd>
                        <dt>"Packets received"</dt>
                        <dd>{packets(s.packets_received, s.packets_receive_dropped)}</dd>
                        <dt>"Loss, last 10 s"</dt>
                        <dd>{match (s.loss_sending_pct, s.loss_receiving_pct) {
                            _ if s.nothing_back => "Nothing back from the relay".to_string(),
                            (Some(up), Some(down)) => format!("{up}% sending, {down}% receiving"),
                            _ => "Measuring…".to_string(),
                        }}</dd>
                    </dl>
                    <h4>"Retransmissions"</h4>
                    <dl>
                        <dt>"Contact setup resent"</dt>
                        <dd>{s.contact_setup_resends}</dd>
                        <dt>"Reconnects to relay"</dt>
                        <dd>{s.reconnects}</dd>
                        <dt>"PQ refreshes asked for"</dt>
                        <dd>{s.pq_requests}</dd>
                        <dt>"PQ refreshes resent"</dt>
                        <dd>{s.pq_resends}</dd>
                        <dt>"Messages retried"</dt>
                        <dd>{s.message_retries}</dd>
                        <dt>"Received twice"</dt>
                        <dd title="The relay sent it again, as our acknowledgement didn't reach it">
                            {s.duplicates_received}
                        </dd>
                    </dl>
                }
            })}
        </details>
    }
}

/// Our QR code, for a contact to scan: opened with "Present QR code", or
/// by scanning someone who hasn't scanned us yet (`waiting_for` is then
/// their token), so they can scan ours straight back. Closes when we scan
/// someone who had already scanned it, or once `waiting_for` has (see
/// `MainScreen`), as well as the usual ways.
#[component]
fn QrCodeModal(
    identity: api::IdentityDto,
    show_qr: RwSignal<bool>,
    waiting_for: RwSignal<Option<String>>,
) -> impl IntoView {
    let qr_svg = StoredValue::new(
        contact_code::encode(&identity.routing_token, &identity.ed25519_public)
            .and_then(|code| qr::svg_for(&code)),
    );
    let close = Callback::new(move |()| {
        show_qr.set(false);
        waiting_for.set(None);
    });
    view! {
        <Show when=move || show_qr.get()>
            <Modal title="Your QR code" on_close=close>
                {match qr_svg.get_value() {
                    Ok(svg) => view! { <div class="qr-code" inner_html=svg></div> }.into_any(),
                    Err(e) => view! { <p class="error">"Couldn't draw QR code: " {e}</p> }.into_any(),
                }}
                <p class="hint">
                    {move || if waiting_for.get().is_some() {
                        "Added. Now have them tap \"Scan QR code\" and scan this; it closes once they have."
                    } else {
                        "Have your contact tap \"Scan QR code\" and point their camera here, then scan theirs."
                    }}
                </p>
            </Modal>
        </Show>
    }
}

/// Two percentages of packets this device drops on purpose, one for
/// sending and one for receiving, to try the app on a bad connection
/// without making the relay lossy for everyone (see `client::netsim`).
/// Each takes effect as soon as it's changed, and lasts until the app
/// closes.
#[component]
fn SimulatedLoss() -> impl IntoView {
    let loss = RwSignal::new(api::SimulatedLossDto::default());
    let error = RwSignal::new(None::<String>);
    leptos::task::spawn_local(async move {
        if let Ok(current) = api::simulated_loss().await {
            loss.try_set(current);
        }
    });

    let apply = move |ev: leptos::ev::Event, outgoing: bool| {
        let Some(percent) = event_target_value(&ev)
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|p| *p <= 100)
        else {
            error.set(Some("Enter a whole percentage from 0 to 100.".into()));
            return;
        };
        error.set(None);
        loss.update(|l| {
            if outgoing {
                l.send = percent;
            } else {
                l.receive = percent;
            }
        });
        let api::SimulatedLossDto { send, receive } = loss.get_untracked();
        leptos::task::spawn_local(async move {
            if let Err(e) = api::set_simulated_loss(send, receive).await {
                error.try_set(Some(e));
            }
        });
    };

    view! {
        <details class="identity-details">
            <summary>"Simulated network loss"</summary>
            <label class="setting">
                "Sending loss (%)"
                <input
                    type="number" min="0" max="100" step="1"
                    prop:value=move || loss.get().send.to_string()
                    on:change=move |ev| apply(ev, true)
                />
            </label>
            <label class="setting">
                "Receiving loss (%)"
                <input
                    type="number" min="0" max="100" step="1"
                    prop:value=move || loss.get().receive.to_string()
                    on:change=move |ev| apply(ev, false)
                />
            </label>
            {move || error.get().map(|e| view! { <p class="error">{e}</p> })}
            <p class="hint">
                "Drops that share of this device's packets at random, as a bad connection would. Resets to 0 when the app closes."
            </p>
        </details>
    }
}

/// Pops up when someone who isn't a contact tries to connect (see
/// `Client::connection_requests`): the first one waiting, unless requests
/// are muted. Their request was ignored, and scanning their code is how to
/// accept it, so this only offers the scanner. "Not now" keeps that person
/// from popping up again for a day, and muting stops them all until it's
/// undone in the contact list; the client also caps how many new ones it
/// lists, so nobody can keep these coming by making new identities. Just
/// closing it (the X, a click outside it, or Escape) only hides that
/// request until the app restarts, as a stray tap shouldn't put someone
/// off for a day. Just the start of their token is shown: anything else
/// they sent, like a name, is unverified until that scan. Hidden while the
/// scanner is open.
#[component]
fn ConnectionRequestNotice(
    requests: RwSignal<api::ConnectionRequestsDto>,
    scanning: RwSignal<bool>,
    selected: RwSignal<Option<String>>,
) -> impl IntoView {
    let closed = RwSignal::new(HashSet::<String>::new());
    move || {
        let (first, waiting) = requests.with(|r| {
            let open: Vec<&String> = r
                .tokens
                .iter()
                .filter(|token| !closed.with(|closed| closed.contains(*token)))
                .collect();
            (open.first().map(|token| (*token).clone()), open.len())
        });
        let token = first.filter(|_| !scanning.get())?;
        let short = format!("{}...", token.chars().take(8).collect::<String>());
        let token_to_close = token.clone();
        let close = Callback::new(move |()| {
            closed.update(|closed| {
                closed.insert(token_to_close.clone());
            });
        });
        let dismiss = Callback::new(move |()| {
            let token = token.clone();
            requests.update(|r| r.tokens.retain(|t| *t != token));
            leptos::task::spawn_local(async move {
                let _ = api::dismiss_connection_request(&token).await;
            });
        });
        let mute = move |_| {
            requests.update(|r| {
                r.tokens.clear();
                r.muted = true;
            });
            leptos::task::spawn_local(async move {
                let _ = api::set_connection_requests_muted(true).await;
            });
        };
        Some(view! {
            <Modal title="Connection request" on_close=close>
                <p>"Someone (" <code>{short}</code> ") wants to connect with you."</p>
                <p class="hint">
                    "To accept, scan the QR code on their screen. If you don't know who this is, ignore it."
                </p>
                {(waiting > 1).then(|| view! {
                    <p class="hint">{format!("{} more waiting.", waiting - 1)}</p>
                })}
                <div class="modal-actions">
                    <button
                        type="button"
                        on:click=move |_| {
                            // On a phone the scanner lives in the contact list,
                            // which an open chat hides.
                            selected.set(None);
                            scanning.set(true);
                        }
                    >
                        "Scan their code"
                    </button>
                    <button type="button" class="secondary" on:click=move |_| dismiss.run(())>
                        "Not now"
                    </button>
                </div>
                <button type="button" class="link-btn" on:click=mute>
                    "Mute connection requests"
                </button>
            </Modal>
        })
    }
}

/// A dropdown of actions under the button that opened it (put both in a
/// `position: relative` box). Closes on a click anywhere outside it,
/// caught by a transparent backdrop the way `Modal` catches one, or on
/// Escape; each item closes it too, when chosen.
#[component]
fn Menu(on_close: Callback<()>, children: Children) -> impl IntoView {
    let escape = window_event_listener(leptos::ev::keydown, move |ev| {
        if ev.key() == "Escape" {
            on_close.run(());
        }
    });
    on_cleanup(move || escape.remove());

    view! {
        <div class="menu-backdrop" on:click=move |_| on_close.run(())></div>
        <div class="menu" role="menu">{children()}</div>
    }
}

/// Centered dialog over a dimmed backdrop. Closes on the X button, a click
/// on the backdrop, or Escape.
#[component]
fn Modal(title: &'static str, on_close: Callback<()>, children: Children) -> impl IntoView {
    let escape = window_event_listener(leptos::ev::keydown, move |ev| {
        if ev.key() == "Escape" {
            on_close.run(());
        }
    });
    on_cleanup(move || escape.remove());

    view! {
        <div class="modal-backdrop" on:click=move |_| on_close.run(())>
            <div class="modal" role="dialog" on:click=|ev| ev.stop_propagation()>
                <div class="modal-header">
                    <h3>{title}</h3>
                    <button type="button" class="icon-btn" title="Close" on:click=move |_| on_close.run(())>
                        <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
                            <path d="M4 4l8 8M12 4l-8 8" />
                        </svg>
                    </button>
                </div>
                {children()}
            </div>
        </div>
    }
}

/// Contact list plus the two ways to add a contact: "Scan QR code" (reads
/// a peer's presented QR with the camera) or pasting their routing token +
/// Ed25519 key by hand as a fallback. Both end in the same
/// `connect_to_peer` call with the same two values, so both establish the
/// same trust anchor (see KeyExchangePayload::verify in packets.rs).
#[component]
fn ContactPanel(
    contacts: RwSignal<Vec<api::ContactDto>>,
    selected: RwSignal<Option<String>>,
    requests: RwSignal<api::ConnectionRequestsDto>,
    scanning: RwSignal<bool>,
    unread: RwSignal<HashMap<String, usize>>,
    show_qr: RwSignal<bool>,
    qr_waiting_for: RwSignal<Option<String>>,
) -> impl IntoView {
    let token_input = RwSignal::new(String::new());
    let key_input = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);

    // Which contact (by token) is showing its "Remove?" confirm row instead
    // of the usual remove icon — same inline-confirm pattern as the Login
    // screen's identity delete. `None` means no confirm is open.
    let remove_confirm = RwSignal::new(None::<String>);
    let remove_busy = RwSignal::new(false);
    // Adding someone accepts their connection request, so stop showing it
    // now rather than at the next poll.
    let clear_request = move |token: &str| {
        let token = token.trim().to_ascii_lowercase();
        requests.update(|r| r.tokens.retain(|t| *t != token));
    };
    let unmute = move |_| {
        requests.update(|r| r.muted = false);
        leptos::task::spawn_local(async move {
            let _ = api::set_connection_requests_muted(false).await;
        });
    };

    // Runs for every QR code the scanner decodes. Anything that isn't a
    // contact code goes back to the scanner as an error so it keeps
    // looking; a valid one closes the scanner and sends the request. Then
    // our own QR code: if they'd already scanned it (they're asking to
    // connect), it has done its job and closes; if not, it opens for them
    // to scan, and closes once they have (see `QrCodeModal`).
    let on_scan = Callback::new(move |raw: String| {
        let code = contact_code::parse(&raw)?;
        let token = code.token_hex.trim().to_ascii_lowercase();
        let scanned_us = requests.with_untracked(|r| r.tokens.contains(&token));
        clear_request(&token);
        scanning.set(false);
        error.set(None);
        leptos::task::spawn_local(async move {
            match api::connect_to_peer(&code.token_hex, &code.ed25519_hex).await {
                Ok(()) if scanned_us => {
                    show_qr.set(false);
                    qr_waiting_for.set(None);
                }
                Ok(()) => {
                    qr_waiting_for.set(Some(token));
                    show_qr.set(true);
                }
                Err(e) => error.set(Some(e)),
            }
        });
        Ok(())
    });

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
                clear_request(&token);
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
                        let token_for_remove = token.clone();
                        let token_for_confirm = token.clone();
                        view! {
                            <li
                                class:selected=move || selected.get().as_deref() == Some(token.as_str())
                                on:click=move |_| selected.set(Some(token_for_click.clone()))
                            >
                                <span class="contact-label">
                                    {match &contact.name {
                                        Some(name) => view! { <span class="contact-name">{name.clone()}</span> }.into_any(),
                                        None => view! {
                                            <code>{contact.token.chars().take(8).collect::<String>()}"..."</code>
                                        }.into_any(),
                                    }}
                                    {
                                        let token = contact.token.clone();
                                        move || view! {
                                            <UnreadBadge count=unread.with(|counts| counts.get(&token).copied().unwrap_or(0)) />
                                        }
                                    }
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
                                                <TrashIcon />
                                            </button>
                                        }.into_any()
                                    }
                                }}
                                {match contact.status.as_str() {
                                    "pending" => Some(view! {
                                        <span class="contact-hint">"Waiting for them to scan your code"</span>
                                    }.into_any()),
                                    "connecting" => Some(view! {
                                        <span class="contact-hint">"They've added you. Connecting..."</span>
                                    }.into_any()),
                                    _ => None,
                                }}
                            </li>
                        }
                    }
                </For>
            </ul>

            {move || requests.with(|r| r.muted).then(|| view! {
                <p class="hint">
                    "Connection requests are muted. "
                    <button type="button" class="link-btn" on:click=unmute>"Unmute"</button>
                </p>
            })}
            <h3>"Add contact"</h3>
            <p class="hint">
                "You each add the other. A contact stays pending until they've added you too."
            </p>
            <button type="button" class="scan-btn" on:click=move |_| scanning.set(true)>
                "Scan QR code"
            </button>
            <p class="hint">"Or enter their details manually:"</p>
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
            <Show when=move || scanning.get()>
                <Modal title="Scan QR code" on_close=Callback::new(move |()| scanning.set(false))>
                    <QrScanner on_scan=on_scan />
                </Modal>
            </Show>
        </div>
    }
}

/// The chat header's "⋮" menu: what can be done about the session with
/// the open contact. So far, repairing it, for when one side can no longer
/// read the other's messages: both drop the session and set up a new one
/// (see `api::repair_session`). Hidden while the contact is pending, as
/// there's no session yet.
#[component]
fn ChatMenu(token: String, error: RwSignal<Option<String>>) -> impl IntoView {
    let open = RwSignal::new(false);
    let repairing = RwSignal::new(false);
    let token = StoredValue::new(token);
    let repair = move |_| {
        open.set(false);
        error.set(None);
        repairing.set(true);
        let token = token.get_value();
        leptos::task::spawn_local(async move {
            if let Err(e) = api::repair_session(&token).await {
                error.try_set(Some(e));
            }
            repairing.try_set(false);
        });
    };

    view! {
        <div class="chat-menu">
            <button
                type="button"
                class="icon-btn menu-btn"
                title="More"
                aria-haspopup="menu"
                aria-expanded=move || open.get().to_string()
                on:click=move |_| open.update(|o| *o = !*o)
            >
                <MenuIcon />
            </button>
            <Show when=move || open.get()>
                <Menu on_close=Callback::new(move |()| open.set(false))>
                    <button
                        type="button"
                        role="menuitem"
                        title="Set up a new secure session with them, if messages aren't getting through"
                        disabled=move || repairing.get()
                        on:click=repair
                    >
                        "Repair session"
                    </button>
                </Menu>
            </Show>
        </div>
    }
}

/// Message transcript + send box for whichever contact is selected. Shows
/// a placeholder state until a contact is picked and until that contact's
/// session has finished the PQXDH handshake ("established" status) —
/// sending to a "pending" or "connecting" contact fails, since there's no
/// session both sides have yet.
#[component]
fn ChatPanel(
    contacts: RwSignal<Vec<api::ContactDto>>,
    selected: RwSignal<Option<String>>,
    messages: RwSignal<HashMap<String, Vec<ChatMessage>>>,
    early_updates: StoredValue<HashMap<u64, SendStatus>>,
    unread: RwSignal<HashMap<String, usize>>,
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
                Ok(sent) => {
                    // Same reasoning as the incoming side in
                    // `MainScreen::refresh` — use the backend's own
                    // chat-history row id so this optimistic display
                    // agrees with a later `chat_history` fetch on what
                    // identifies this message.
                    let id = sent
                        .id
                        .map(history_message_id)
                        .unwrap_or_else(next_message_id);
                    // Its check mark (or not) comes later, from
                    // `api::sent_message_updates`, unless it came already.
                    let status = early_updates
                        .try_update_value(|early| early.remove(&id))
                        .flatten()
                        .unwrap_or(SendStatus::Sending);
                    messages.update(|map| {
                        map.entry(token_for_task).or_default().push(ChatMessage {
                            id,
                            from_me: true,
                            text: text_for_history,
                            timestamp_ms: Some(sent.timestamp_ms),
                            status: Some(status),
                        });
                    });
                }
                Err(e) => {
                    // Put the text back so a rejected message (e.g. over
                    // the length limit) can be edited and resent rather
                    // than lost — unless the user has already started
                    // typing a new one. `try_`: same disposed-signal
                    // reasoning as `refresh_known` above.
                    if draft.try_get_untracked().is_some_and(|d| d.is_empty()) {
                        draft.set(text);
                    }
                    error.set(Some(e));
                }
            }
        });
    };

    view! {
        <div class="chat-panel">
            {move || match selected.get() {
                None => view! { <p class="hint">"Select a contact to start chatting."</p> }.into_any(),
                Some(token) => {
                    let header_token = token.clone();
                    let menu_token = token.clone();
                    let len_token = token.clone();
                    let status_token = token.clone();
                    let status = move || {
                        contacts.get()
                            .iter()
                            .find(|c| c.token == status_token)
                            .map(|c| c.status.clone())
                    };
                    // Send a message the relay didn't confirm (a "!") again.
                    // It shows as sending meanwhile, and on success is
                    // replaced, at the bottom, by the new message.
                    let retry_token = StoredValue::new(token.clone());
                    let retry = move |old_id: u64| {
                        let Some(row_id) = history_row_id(old_id) else {
                            return;
                        };
                        let token = retry_token.get_value();
                        let set_status = move |status: SendStatus| {
                            let token = retry_token.get_value();
                            messages.update(|map| {
                                if let Some(m) = map
                                    .get_mut(&token)
                                    .and_then(|list| list.iter_mut().find(|m| m.id == old_id))
                                {
                                    m.status = Some(status);
                                }
                            });
                        };
                        error.set(None);
                        set_status(SendStatus::Sending);
                        leptos::task::spawn_local(async move {
                            match api::retry_message(&token, row_id).await {
                                Ok(sent) => {
                                    let id = sent
                                        .id
                                        .map(history_message_id)
                                        .unwrap_or_else(next_message_id);
                                    let status = early_updates
                                        .try_update_value(|early| early.remove(&id))
                                        .flatten()
                                        .unwrap_or(SendStatus::Sending);
                                    messages.update(|map| {
                                        let list = map.entry(token).or_default();
                                        if let Some(at) = list.iter().position(|m| m.id == old_id) {
                                            let old = list.remove(at);
                                            list.push(ChatMessage {
                                                id,
                                                from_me: true,
                                                text: old.text,
                                                timestamp_ms: Some(sent.timestamp_ms),
                                                status: Some(status),
                                            });
                                        }
                                    });
                                }
                                Err(e) => {
                                    set_status(SendStatus::Failed);
                                    error.try_set(Some(e));
                                }
                            }
                        });
                    };
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
                    // Whether the transcript is scrolled to its newest
                    // message. Opening the keyboard shrinks the whole web
                    // view (see `keepClearOfSystemBars` in MainActivity.kt),
                    // and the transcript with it, but its scroll position
                    // counts from the top, so the newest messages would
                    // slip out of sight below the composer. If it was at
                    // the newest, keep it there through any resize; if
                    // they've scrolled up to read, leave them be.
                    let at_bottom = StoredValue::new(true);
                    let on_transcript_scroll = move |_| {
                        if let Some(el) = transcript_ref.get_untracked() {
                            let below = el.scroll_height() - el.scroll_top() - el.client_height();
                            at_bottom.set_value(below < 24);
                        }
                    };
                    let resize = window_event_listener(leptos::ev::resize, move |_| {
                        if at_bottom.get_value()
                            && let Some(el) = transcript_ref.get_untracked()
                        {
                            el.set_scroll_top(el.scroll_height());
                        }
                    });
                    on_cleanup(move || resize.remove());

                    view! {
                        <div class="chat-header">
                            <button
                                type="button"
                                class="back-btn secondary"
                                title="Back to contacts"
                                aria-label="Back to contacts"
                                on:click=move |_| selected.set(None)
                            >
                                "←"
                                // From the others: in the one-column layout,
                                // the list (and their badges) is hidden while
                                // a chat is open.
                                {move || view! {
                                    <UnreadBadge count=unread.with(|counts| counts.values().sum()) />
                                }}
                            </button>
                            <h3>{chat_label}</h3>
                            {move || contacts.with(|list| {
                                list.iter().any(|c| c.token == menu_token && c.status != "pending")
                            }).then(|| view! { <ChatMenu token=menu_token.clone() error=error /> })}
                        </div>
                        {move || match status().as_deref() {
                            Some("pending") => Some(view! {
                                <p class="hint chat-pending">
                                    "Waiting for them to scan your code. You can chat once they have."
                                </p>
                            }.into_any()),
                            Some("connecting") => Some(view! {
                                <p class="hint chat-pending">
                                    "They've added you. Setting up a secure session; you can chat in a moment."
                                </p>
                            }.into_any()),
                            _ => None,
                        }}
                        <div class="transcript" node_ref=transcript_ref on:scroll=on_transcript_scroll>
                            // Keyed on the status too, so a message is drawn
                            // again when its check mark comes.
                            <For
                                each=history
                                key=|m| (m.id, m.status)
                                let(msg)
                            >
                                <p class:from-me=msg.from_me class:from-peer=!msg.from_me>
                                    {msg.text.clone()}
                                    <span class="msg-meta">
                                        {msg.timestamp_ms.map(|ms| view! {
                                            <span class="msg-time">{format_time(ms)}</span>
                                        })}
                                        {match msg.status {
                                            Some(SendStatus::Sending) => Some(view! {
                                                <span class="msg-status sending" title="Sending" aria-label="Sending"></span>
                                            }.into_any()),
                                            Some(SendStatus::Sent) => Some(view! {
                                                <span class="msg-status sent" title="The relay has it">"✓"</span>
                                            }.into_any()),
                                            Some(SendStatus::Failed) => {
                                                let id = msg.id;
                                                Some(view! {
                                                    <span class="msg-status failed" title="It didn't get to the relay.">"!"</span>
                                                    {history_row_id(id).map(|_| view! {
                                                        <button
                                                            type="button"
                                                            class="retry-btn"
                                                            title="Send it again"
                                                            aria-label="Send it again"
                                                            on:click=move |_| retry(id)
                                                        >
                                                            <RetryIcon />
                                                        </button>
                                                    })}
                                                }.into_any())
                                            }
                                            None => None,
                                        }}
                                    </span>
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
