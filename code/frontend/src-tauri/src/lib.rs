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
            commands::connection_requests,
            commands::set_connection_requests_muted,
            commands::dismiss_connection_request,
            commands::notification_settings,
            commands::set_notify_with_names,
            commands::send_message,
            commands::sent_message_updates,
            commands::poll_inbox,
            commands::chat_history,
        ])
        .setup(|app| {
            background::init(app.handle());
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
