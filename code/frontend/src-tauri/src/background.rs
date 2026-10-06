//! Keeps the app receiving while it isn't on screen.
//!
//! On Android this is the Rust half of a small bridge to Kotlin (see
//! `NativeBridge.kt` and `MessageService.kt` under `gen/android/app/src/main/java/`).
//! A Kotlin thread blocks in `nextEvent` and reacts to the events sent from
//! here:
//! - While someone is logged in, it runs a foreground service, so Android
//!   doesn't freeze the process and the UDP socket keeps receiving.
//! - It posts a notification for each message that arrives while the app
//!   is in the background.
//!
//! Kotlin calls into Rust rather than the other way round because Tauri's
//! own Rust-to-Kotlin calls need a live activity, and there isn't one once
//! the app has been swiped away.
//!
//! Swiping the app away is also handled here (see `on_run_event`), and so
//! is pausing presence pings while the app is off screen (see `on_screen`).
//!
//! On other platforms all of this does nothing.

use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_os = "android"))]
use tauri::{AppHandle, RunEvent};
use tokio::sync::Notify;

/// Wakes `spawn_keepalive_loop` to sync with the relay right away. Android
/// signals it when the app comes back to the foreground, so messages the
/// relay is holding arrive at once instead of on the next 15s tick.
pub static RESYNC: Notify = Notify::const_new();

/// See `on_screen`. Only Android ever changes it.
static ON_SCREEN: AtomicBool = AtomicBool::new(true);

/// Wakes `spawn_presence_loop` when the app comes back on screen, so
/// contacts see us online again straight away rather than on its next tick.
pub static BACK_ON_SCREEN: Notify = Notify::const_new();

/// Whether the app is on screen. `spawn_presence_loop` skips its pings
/// while it isn't, to save battery: each one wakes the phone's radio, and
/// they only feed contacts' online markers. Always true on desktop.
pub fn on_screen() -> bool {
    ON_SCREEN.load(Ordering::Relaxed)
}

/// Someone logged in and connected to the relay.
pub fn session_started() {
    emit("session_started".to_string());
}

/// The session ended (logout).
pub fn session_ended() {
    emit("session_ended".to_string());
}

/// A chat message arrived from `from` (a contact's name, or a short token).
pub fn message_received(from: &str) {
    emit(format!("message\t{from}"));
}

#[cfg(not(target_os = "android"))]
fn emit(_event: String) {}

#[cfg(not(target_os = "android"))]
pub fn init(_app: &AppHandle) {}

#[cfg(not(target_os = "android"))]
pub fn on_run_event(_app: &AppHandle, _event: &RunEvent) {}

#[cfg(target_os = "android")]
use android::emit;
#[cfg(target_os = "android")]
pub use android::{init, on_run_event};

#[cfg(target_os = "android")]
mod android {
    use crate::state::AppState;
    use jni::{
        objects::JClass,
        sys::{jboolean, jstring},
        JNIEnv,
    };
    use std::sync::{atomic::Ordering, mpsc, Mutex, OnceLock};
    use tauri::{AppHandle, Manager, RunEvent, WebviewWindowBuilder};

    /// Set once Tauri's setup has run, which is after it built the first
    /// window. Until then there's no window to restore.
    static APP: OnceLock<AppHandle> = OnceLock::new();

    /// Held while `restore_window` checks for and builds the window, so two
    /// quick resumes can't both build one.
    static RESTORING: Mutex<()> = Mutex::new(());

    pub fn init(app: &AppHandle) {
        let _ = APP.set(app.clone());
    }

    /// Swiping the app away destroys its activity, and with it the only
    /// window. Tauri then exits the process (tao calls `process::exit`),
    /// which would also stop `MessageService` and all message delivery. So
    /// while someone's logged in, the exit is prevented and the relay
    /// connection carries on in the background.
    pub fn on_run_event(app: &AppHandle, event: &RunEvent) {
        // `code: None` is the last window closing; `Some` is an explicit
        // `exit()`, which is left alone.
        if let RunEvent::ExitRequested {
            code: None, api, ..
        } = event
        {
            // Busy means a command is using it, so someone's logging in or out.
            let logged_in = app
                .state::<AppState>()
                .pending_identity
                .try_lock()
                .map_or(true, |p| p.is_some());
            log::info!("Window closed (logged in: {logged_in})");
            if logged_in {
                api.prevent_exit();
            }
        }
    }

    /// Reopening the app after `on_run_event` kept it running gives it a
    /// new activity, but nothing creates a window for it, so this builds
    /// the main window again from tauri.conf.json. The frontend then picks
    /// the session back up (see the `current_session` command).
    fn restore_window(app: &AppHandle) {
        let _guard = RESTORING.lock().unwrap();
        let Some(config) = app.config().app.windows.first() else {
            return;
        };
        if app.get_webview_window(&config.label).is_some() {
            return;
        }
        log::info!("Rebuilding the window for the reopened app");
        match WebviewWindowBuilder::from_config(app, config).and_then(|b| b.build()) {
            Ok(_) => log::info!("Window rebuilt"),
            Err(e) => log::error!("Couldn't reopen the window: {e}"),
        }
    }

    struct Channel {
        tx: mpsc::Sender<String>,
        rx: Mutex<mpsc::Receiver<String>>,
    }

    fn channel() -> &'static Channel {
        static CHANNEL: OnceLock<Channel> = OnceLock::new();
        CHANNEL.get_or_init(|| {
            let (tx, rx) = mpsc::channel();
            Channel {
                tx,
                rx: Mutex::new(rx),
            }
        })
    }

    pub fn emit(event: String) {
        let _ = channel().tx.send(event);
    }

    /// `NativeBridge.nextEvent()`: blocks until the next event, then returns
    /// it as `"session_started"`, `"session_ended"` or `"message\t<from>"`.
    #[no_mangle]
    pub extern "system" fn Java_nz_ac_waikato_compx374_e2e_1messenger_NativeBridge_nextEvent(
        env: JNIEnv,
        _class: JClass,
    ) -> jstring {
        // `recv` can't fail: the sender lives in a static, so it's never dropped.
        let event = channel().rx.lock().unwrap().recv();
        match event.ok().and_then(|e| env.new_string(e).ok()) {
            Some(s) => s.into_raw(),
            None => std::ptr::null_mut(),
        }
    }

    /// `NativeBridge.appVisible(visible)`: the app came on screen or left it.
    #[no_mangle]
    pub extern "system" fn Java_nz_ac_waikato_compx374_e2e_1messenger_NativeBridge_appVisible(
        _env: JNIEnv,
        _class: JClass,
        visible: jboolean,
    ) {
        let visible = visible != 0;
        log::info!("App on screen: {visible} (presence pings follow)");
        super::ON_SCREEN.store(visible, Ordering::Relaxed);
        if visible {
            super::BACK_ON_SCREEN.notify_one();
        }
    }

    /// `NativeBridge.appResumed()`: the app is back in the foreground.
    #[no_mangle]
    pub extern "system" fn Java_nz_ac_waikato_compx374_e2e_1messenger_NativeBridge_appResumed(
        _env: JNIEnv,
        _class: JClass,
    ) {
        super::RESYNC.notify_one();
        if let Some(app) = APP.get() {
            let app = app.clone();
            // Not on this thread (Android's UI thread): `build` waits on
            // work that has to run here.
            tauri::async_runtime::spawn(async move { restore_window(&app) });
        }
    }
}
