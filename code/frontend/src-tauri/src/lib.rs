mod background;
mod commands;
mod state;

use state::AppState;
#[cfg(target_os = "linux")]
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // AppState starts empty (`ClientRuntime` is None) — populated once the
        // frontend calls the `bootstrap` command.
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::login,
            commands::logout,
            commands::create_identity,
            commands::delete_identity,
            commands::current_session,
            commands::list_pseudonyms,
            commands::bootstrap,
            commands::list_contacts,
            commands::connect_to_peer,
            commands::remove_contact,
            commands::repair_session,
            commands::connection_requests,
            commands::set_connection_requests_muted,
            commands::dismiss_connection_request,
            commands::notification_settings,
            commands::set_notify_with_names,
            commands::simulated_loss,
            commands::set_simulated_loss,
            commands::send_message,
            commands::network_stats,
            commands::sent_message_updates,
            commands::poll_inbox,
            commands::chat_history,
        ])
        .setup(|app| {
            background::init(app.handle());
            #[cfg(all(target_os = "android", debug_assertions))]
            forward_stdout_to_logcat();
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            #[cfg(target_os = "linux")]
            if let Some(window) = app.get_webview_window("main") {
                window.with_webview(enable_camera_for_qr_scanner)?;
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| background::on_run_event(app, &event));
}

/// Sends what's printed to stdout and stderr to logcat, tagged `E2E`, a
/// line at a time. The client crate reports what happens to each packet
/// with `println!` (sessions set up, PQ refreshes, messages it can't
/// decrypt yet), which Android otherwise throws away, so this is how to
/// watch it on a phone: `adb logcat -s E2E`. Debug builds only: it prints
/// messages as they arrive, which a release build mustn't put in the
/// system log.
#[cfg(all(target_os = "android", debug_assertions))]
fn forward_stdout_to_logcat() {
    use std::ffi::CString;
    use std::io::{BufRead, BufReader};
    use std::os::fd::FromRawFd;
    use std::os::raw::{c_char, c_int};

    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }
    const ANDROID_LOG_INFO: c_int = 4;

    let mut fds = [0 as c_int; 2];
    // SAFETY: `fds` has room for the two descriptors `pipe` writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return;
    }
    // SAFETY: plain descriptor calls on ones we own; stdout and stderr
    // become the pipe's write end.
    unsafe {
        libc::dup2(fds[1], libc::STDOUT_FILENO);
        libc::dup2(fds[1], libc::STDERR_FILENO);
        libc::close(fds[1]);
    }
    // SAFETY: the read end is ours alone, and the File takes it over.
    let reader = BufReader::new(unsafe { std::fs::File::from_raw_fd(fds[0]) });
    std::thread::spawn(move || {
        let tag = c"E2E";
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(text) = CString::new(line) {
                // SAFETY: both are valid NUL-terminated strings.
                unsafe { __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr()) };
            }
        }
    });
}

/// Lets the frontend's QR scanner (src/qr.rs) use the camera on Linux.
/// WebKitGTK has `getUserMedia` switched off by default and denies any
/// permission request nobody handles; the other platforms' webviews need
/// no code here (Android/iOS/macOS just need a camera permission in their
/// app manifests, Windows prompts the user itself). Only video-only
/// requests are allowed, since the app never asks for the microphone.
#[cfg(target_os = "linux")]
fn enable_camera_for_qr_scanner(webview: tauri::webview::PlatformWebview) {
    use webkit2gtk::glib::object::Cast;
    use webkit2gtk::{
        PermissionRequestExt, SettingsExt, UserMediaPermissionRequest,
        UserMediaPermissionRequestExt, WebViewExt,
    };

    let view = webview.inner();
    if let Some(settings) = WebViewExt::settings(&view) {
        settings.set_enable_media_stream(true);
    }
    view.connect_permission_request(|_, request| {
        match request.downcast_ref::<UserMediaPermissionRequest>() {
            Some(media) if media.is_for_video_device() && !media.is_for_audio_device() => {
                request.allow();
                true
            }
            // `false` = not handled here, so WebKit falls back to denying.
            _ => false,
        }
    });
}
