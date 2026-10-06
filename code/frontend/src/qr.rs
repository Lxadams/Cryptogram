//! QR encode/decode plus the camera scanner component behind "Scan QR code".
//!
//! Everything here runs in the shared WASM UI, so it's the same code on
//! desktop and mobile: the camera comes from the webview's standard
//! `getUserMedia`, and frames are decoded in Rust (`rqrr`) and, where the
//! webview has one, by its own `BarcodeDetector` too (Android's copes far
//! better with blur and glare), with no native scanner plugin per
//! platform. The only per-platform piece is letting the
//! webview use the camera at all: Linux needs an opt-in (see
//! src-tauri/src/lib.rs), Android/iOS/macOS need a camera permission in
//! their app manifests, and Windows prompts the user on its own.

use leptos::prelude::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// How often a camera frame is grabbed and run through the decoder.
const SCAN_INTERVAL: Duration = Duration::from_millis(250);

/// Frames are downscaled to at most this width before `rqrr` decodes them:
/// enough to read a code from arm's length in a 1080p frame, while keeping
/// each decode quick.
const MAX_SCAN_WIDTH: u32 = 1280;

/// The QR code for `data`, at error correction level L. It's only ever
/// shown on a screen, where nothing tears or smudges it, and the lowest
/// level means fewer, bigger modules, which is what a camera further away
/// needs.
fn qr_code(data: &str) -> Result<qrcode::QrCode, String> {
    qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::L).map_err(|e| e.to_string())
}

/// Renders `data` as an SVG QR code. Always black-on-white with a quiet
/// zone, regardless of the app theme, since scanners read dark modules on
/// a light background most reliably.
pub fn svg_for(data: &str) -> Result<String, String> {
    use qrcode::render::svg;
    Ok(qr_code(data)?
        .render::<svg::Color<'_>>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

/// Finds and decodes the first readable QR code in a greyscale image
/// (`luma` is row-major, one byte per pixel).
pub fn decode_greyscale(width: usize, height: usize, luma: &[u8]) -> Option<String> {
    let mut img =
        rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| luma[y * width + x]);
    img.detect_grids()
        .into_iter()
        .find_map(|grid| grid.decode().ok().map(|(_meta, text)| text))
}

/// Live camera preview that decodes QR codes as they come into view.
///
/// `on_scan` gets each decoded string and decides whether it's the one we
/// wanted: `Ok(())` stops the camera, `Err(msg)` shows `msg` and keeps
/// scanning (so pointing at an unrelated QR code isn't a dead end). The
/// camera is also released whenever this component unmounts, e.g. when the
/// user closes the dialog it's in.
#[component]
pub fn QrScanner(on_scan: Callback<String, Result<(), String>>) -> impl IntoView {
    let video_ref = NodeRef::<leptos::html::Video>::new();
    let error = RwSignal::new(None::<String>);
    let camera_ready = RwSignal::new(false);

    let stream = StoredValue::new_local(None::<web_sys::MediaStream>);
    let interval = StoredValue::new(None::<IntervalHandle>);
    let stopped = StoredValue::new(false);

    // `try_*` throughout: this can run from the interval after the parent
    // has already closed us, by which point these values may be disposed.
    let stop = move || {
        let _ = stopped.try_set_value(true);
        if let Some(Some(handle)) = interval.try_get_value() {
            handle.clear();
        }
        let _ = stream.try_update_value(|s| {
            if let Some(s) = s.take() {
                stop_tracks(&s);
            }
        });
    };
    on_cleanup(stop);

    leptos::task::spawn_local(async move {
        let media = match start_camera().await {
            Ok(media) => media,
            Err(msg) => {
                error.try_set(Some(msg));
                return;
            }
        };
        // The dialog may have been closed while the permission prompt was
        // still up; don't leave the camera running for nobody.
        let Some(video) = video_ref
            .get_untracked()
            .filter(|_| stopped.try_get_value() == Some(false))
        else {
            stop_tracks(&media);
            return;
        };
        video.set_src_object(Some(&media));
        let _ = video.play();
        stream.set_value(Some(media));
        camera_ready.set(true);

        let canvas: web_sys::HtmlCanvasElement = document()
            .create_element("canvas")
            .expect("creating a <canvas> can't fail")
            .unchecked_into();
        // The last string `on_scan` rejected, so holding an unrelated QR
        // code in view doesn't re-run the callback four times a second.
        let last_rejected = Rc::new(RefCell::new(None::<String>));
        let found = Rc::new(move |text: String| {
            if stopped.try_get_value() != Some(false)
                || last_rejected.borrow().as_deref() == Some(text.as_str())
            {
                return;
            }
            match on_scan.run(text.clone()) {
                Ok(()) => stop(),
                Err(msg) => {
                    error.try_set(Some(msg));
                    *last_rejected.borrow_mut() = Some(text);
                }
            }
        });
        // The webview's own detector, if it has one (`None` once it has
        // failed). It works asynchronously, so `detecting` keeps one frame
        // in it at a time.
        let native = Rc::new(RefCell::new(native_detector().await));
        let detecting = Rc::new(Cell::new(false));

        let handle = set_interval_with_handle(
            move || {
                if stopped.try_get_value() != Some(false) || !has_frame(&video) {
                    return;
                }
                let detector = native.borrow().clone();
                if let Some(detector) = detector
                    && !detecting.replace(true)
                {
                    let (video, native, detecting, found) = (
                        video.clone(),
                        native.clone(),
                        detecting.clone(),
                        found.clone(),
                    );
                    leptos::task::spawn_local(async move {
                        match native_detect(&detector, &video).await {
                            Ok(Some(text)) => found(text),
                            Ok(None) => {}
                            Err(()) => *native.borrow_mut() = None,
                        }
                        detecting.set(false);
                    });
                }
                // `rqrr` on every frame regardless: a detector can exist and
                // still never find anything, without saying why (Android's
                // needs a Google Play services module that may not have
                // downloaded yet).
                if let Some(text) = grab_frame_and_decode(&video, &canvas) {
                    found(text);
                }
            },
            SCAN_INTERVAL,
        );
        match handle {
            Ok(handle) => interval.set_value(Some(handle)),
            Err(_) => error.set(Some("Couldn't start scanning.".into())),
        }
    });

    view! {
        <div class="qr-scanner">
            <video node_ref=video_ref autoplay=true playsinline=true prop:muted=true></video>
            {move || match error.get() {
                Some(e) => view! { <p class="error">{e}</p> }.into_any(),
                None if camera_ready.get() => view! {
                    <p class="hint">"Point the camera at your contact's QR code."</p>
                }.into_any(),
                None => view! { <p class="hint">"Starting camera..."</p> }.into_any(),
            }}
        </div>
    }
}

async fn start_camera() -> Result<web_sys::MediaStream, String> {
    // `navigator.mediaDevices` is simply absent (not an error) where the
    // webview doesn't allow camera access, e.g. a non-secure origin.
    let devices = js_sys::Reflect::get(&window().navigator(), &"mediaDevices".into())
        .ok()
        .filter(|v| !v.is_undefined() && !v.is_null())
        .ok_or("Camera access isn't available on this device.")?
        .unchecked_into::<web_sys::MediaDevices>();

    // Prefer the rear camera on phones; laptops just use whatever they have.
    // A sharp, detailed picture is what lets a code be read from further
    // away: up to 1080p (left alone, Android webviews tend to pick 640x480),
    // and continuous autofocus where the camera supports it (an advanced
    // constraint, so it's skipped where it doesn't).
    let ideal = |value: JsValue| {
        let constraint = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&constraint, &"ideal".into(), &value);
        constraint
    };
    let video = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&video, &"facingMode".into(), &ideal("environment".into()));
    let _ = js_sys::Reflect::set(&video, &"width".into(), &ideal(1920.into()));
    let _ = js_sys::Reflect::set(&video, &"height".into(), &ideal(1080.into()));
    let focus = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&focus, &"focusMode".into(), &"continuous".into());
    let _ = js_sys::Reflect::set(&video, &"advanced".into(), &js_sys::Array::of1(&focus));
    let constraints = web_sys::MediaStreamConstraints::new();
    constraints.set_video(&video);
    constraints.set_audio(&JsValue::FALSE);

    let promise = devices
        .get_user_media_with_constraints(&constraints)
        .map_err(camera_error)?;
    let stream = JsFuture::from(promise).await.map_err(camera_error)?;
    Ok(stream.unchecked_into())
}

/// Turns a `getUserMedia` rejection (a DOMException) into something a
/// user can act on.
fn camera_error(e: JsValue) -> String {
    let name = js_sys::Reflect::get(&e, &"name".into())
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    match name.as_str() {
        "NotAllowedError" | "SecurityError" => "Camera access was denied.".into(),
        "NotFoundError" | "OverconstrainedError" => "No camera found on this device.".into(),
        "NotReadableError" => "The camera is in use by another app.".into(),
        _ => format!("Couldn't start the camera ({name})."),
    }
}

/// The webview's built-in QR detector (the Shape Detection API's
/// `BarcodeDetector`), if it has one that reads QR codes. Android's uses
/// Google Play services; most desktop webviews have none.
async fn native_detector() -> Option<JsValue> {
    let ctor: js_sys::Function = js_sys::Reflect::get(&window(), &"BarcodeDetector".into())
        .ok()?
        .dyn_into()
        .ok()?;
    let supported: js_sys::Function = js_sys::Reflect::get(&ctor, &"getSupportedFormats".into())
        .ok()?
        .dyn_into()
        .ok()?;
    let supported = JsFuture::from(
        supported
            .call0(&ctor)
            .ok()?
            .dyn_into::<js_sys::Promise>()
            .ok()?,
    )
    .await
    .ok()?;
    if !js_sys::Array::from(&supported).includes(&"qr_code".into(), 0) {
        return None;
    }
    let options = js_sys::Object::new();
    js_sys::Reflect::set(
        &options,
        &"formats".into(),
        &js_sys::Array::of1(&"qr_code".into()),
    )
    .ok()?;
    js_sys::Reflect::construct(&ctor, &js_sys::Array::of1(&options)).ok()
}

/// Runs `detector` (from `native_detector`) on the video's current frame:
/// the first QR code it finds, if any, or `Err` if detection itself failed.
async fn native_detect(
    detector: &JsValue,
    video: &web_sys::HtmlVideoElement,
) -> Result<Option<String>, ()> {
    let detect: js_sys::Function = js_sys::Reflect::get(detector, &"detect".into())
        .map_err(|_| ())?
        .dyn_into()
        .map_err(|_| ())?;
    let promise: js_sys::Promise = detect
        .call1(detector, video)
        .map_err(|_| ())?
        .dyn_into()
        .map_err(|_| ())?;
    let codes = JsFuture::from(promise).await.map_err(|_| ())?;
    Ok(js_sys::Array::from(&codes).iter().find_map(|code| {
        js_sys::Reflect::get(&code, &"rawValue".into())
            .ok()?
            .as_string()
    }))
}

/// Whether the camera has delivered a frame to decode yet.
fn has_frame(video: &web_sys::HtmlVideoElement) -> bool {
    const HAVE_CURRENT_DATA: u16 = 2;
    video.ready_state() >= HAVE_CURRENT_DATA && video.video_width() > 0 && video.video_height() > 0
}

fn stop_tracks(stream: &web_sys::MediaStream) {
    for track in stream.get_tracks().iter() {
        track.unchecked_into::<web_sys::MediaStreamTrack>().stop();
    }
}

fn grab_frame_and_decode(
    video: &web_sys::HtmlVideoElement,
    canvas: &web_sys::HtmlCanvasElement,
) -> Option<String> {
    let (vw, vh) = (video.video_width(), video.video_height());
    let scale = (MAX_SCAN_WIDTH as f64 / vw as f64).min(1.0);
    let (w, h) = ((vw as f64 * scale) as u32, (vh as f64 * scale) as u32);
    if canvas.width() != w || canvas.height() != h {
        canvas.set_width(w);
        canvas.set_height(h);
    }

    let options = web_sys::ContextAttributes2d::new();
    options.set_will_read_frequently(true);
    let ctx: web_sys::CanvasRenderingContext2d = canvas
        .get_context_with_context_options("2d", &options)
        .ok()??
        .unchecked_into();
    ctx.draw_image_with_html_video_element_and_dw_and_dh(video, 0.0, 0.0, w as f64, h as f64)
        .ok()?;
    let rgba = ctx
        .get_image_data(0.0, 0.0, w as f64, h as f64)
        .ok()?
        .data();

    // Standard luma weights (ITU-R BT.601), in integer arithmetic.
    let luma: Vec<u8> = rgba
        .as_chunks::<4>()
        .0
        .iter()
        .map(|[r, g, b, _a]| ((*r as u32 * 77 + *g as u32 * 150 + *b as u32 * 29) >> 8) as u8)
        .collect();
    decode_greyscale(w as usize, h as usize, &luma)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact_code;

    fn contact_code() -> String {
        contact_code::encode(
            "00112233445566778899aabbccddeeff",
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        )
        .unwrap()
    }

    /// Rasterises `data` as a QR code the way a camera frame would present
    /// it (4px modules, white quiet zone), then checks the decoder reads
    /// the same string back — i.e. what "Present QR code" draws is what
    /// "Scan QR code" understands.
    #[test]
    fn decoder_reads_back_what_the_encoder_draws() {
        let data = contact_code();
        let code = qr_code(&data).unwrap();
        let modules = code.to_colors();
        let (n, scale, quiet) = (code.width(), 4, 4);
        let size = (n + 2 * quiet) * scale;
        let mut luma = vec![255u8; size * size];
        for (i, _) in modules
            .iter()
            .enumerate()
            .filter(|(_, c)| **c == qrcode::Color::Dark)
        {
            let (mx, my) = (i % n + quiet, i / n + quiet);
            for y in my * scale..(my + 1) * scale {
                luma[y * size + mx * scale..y * size + (mx + 1) * scale].fill(0);
            }
        }
        assert_eq!(decode_greyscale(size, size, &luma), Some(data));
    }

    /// The smaller the code, the further away a camera can read it, so
    /// pin it: a contact code fits QR version 3.
    #[test]
    fn contact_code_is_a_29_by_29_qr_code() {
        assert_eq!(qr_code(&contact_code()).unwrap().width(), 29);
    }

    #[test]
    fn svg_is_a_scalable_svg_element() {
        let svg = svg_for("hello").unwrap();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("viewBox"));
    }
}
