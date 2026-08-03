use leptos::prelude::*;

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    view! {
        <h1>"E2E-Messenger"</h1>
        <p>"Hello, world!"</p>
    }
}
