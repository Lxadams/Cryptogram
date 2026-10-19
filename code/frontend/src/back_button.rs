//! Android's back button. `MainActivity` (in gen/android) asks the page
//! what to do with each back press by calling `window.__cryptogramBack()`:
//! this closes whatever is open on top and says so, or says nothing was,
//! and the app then goes to the background as usual.
//!
//! Two simpler ways didn't hold up on a phone:
//! - **A history entry per layer** (an open chat, a QR code, the scanner),
//!   for Tauri to go back through. Chromium marks an entry for the back
//!   button to skip when the page adds the next one without a tap, as when
//!   our QR code popped up by itself after a scan, and the web view then
//!   says it can't go back: back left the app from an open chat.
//! - **Tauri's back-button listener.** Tauri attaches its back handling to
//!   the first activity only, so once the app had been closed and reopened
//!   while it kept running in the background (for `MessageService`), back
//!   left the app from anywhere until a force stop.

use leptos::prelude::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use wasm_bindgen::prelude::*;

/// A component's claim on the back button (see `while_active`).
struct Handler {
    id: u64,
    active: Rc<dyn Fn() -> bool>,
    on_back: Rc<dyn Fn()>,
}

thread_local! {
    static HANDLERS: RefCell<Vec<Handler>> = const { RefCell::new(Vec::new()) };
    static NEXT_ID: Cell<u64> = const { Cell::new(0) };
    static INSTALLED: Cell<bool> = const { Cell::new(false) };
}

/// For as long as the calling component lives: while `active` is true,
/// Android's back button calls `on_back` instead of leaving the app. Both
/// can run after the component's signals are gone, so they should use the
/// `try_` accessors.
pub fn while_active(active: impl Fn() -> bool + 'static, on_back: impl Fn() + 'static) {
    install();
    let id = NEXT_ID.replace(NEXT_ID.get() + 1);
    HANDLERS.with_borrow_mut(|handlers| {
        handlers.push(Handler {
            id,
            active: Rc::new(active),
            on_back: Rc::new(on_back),
        })
    });
    on_cleanup(move || HANDLERS.with_borrow_mut(|handlers| handlers.retain(|h| h.id != id)));
}

/// `window.__cryptogramBack`: runs the newest active handler, and says
/// whether there was one.
fn back() -> bool {
    let chosen = HANDLERS.with_borrow(|handlers| {
        handlers
            .iter()
            .rev()
            .find(|h| untrack(|| (h.active)()))
            .map(|h| h.on_back.clone())
    });
    // Outside the borrow: closing something may add or drop a handler.
    chosen.map(|on_back| on_back()).is_some()
}

fn install() {
    if INSTALLED.replace(true) {
        return;
    }
    let hook = Closure::<dyn Fn() -> bool>::new(back).into_js_value();
    let _ = js_sys::Reflect::set(&window(), &"__cryptogramBack".into(), &hook);
}
