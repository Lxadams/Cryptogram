mod commands;
mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    // AppState starts empty (`ClientRuntime` is None) — populated once the
    // frontend calls the `bootstrap` command with the relay's pubkey.
    .manage(AppState::default())
    .invoke_handler(tauri::generate_handler![
      commands::bootstrap,
      commands::get_identity,
      commands::list_contacts,
      commands::connect_to_peer,
      commands::send_message,
      commands::poll_inbox,
    ])
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
