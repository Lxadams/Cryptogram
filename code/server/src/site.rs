//! The website anyone sees who connects without the app's access key.
//!
//! Every connection is served as HTTP/3, the app's included (it just never
//! asks for anything). A censor probing the relay's address finds a small
//! static site: the built-in page below, or the files in `SITE_DIR`.

use anyhow::Result;
use bytes::Bytes;
use h3::server::RequestResolver;
use http::{Method, Response, StatusCode};
use std::{collections::HashMap, path::Path, sync::Arc};
use tracing::debug;

const DEFAULT_INDEX: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Field Notes</title>
<style>
body { max-width: 38rem; margin: 3rem auto; padding: 0 1rem; font: 17px/1.6 Georgia, serif; color: #222; }
h1 { font-weight: normal; }
footer { margin-top: 3rem; color: #777; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>Field Notes</h1>
<p>Notes from walks, mostly. Tide tables, birds that turned up where they
shouldn't have, and the occasional photograph of a gate.</p>
<p>New entries are posted when there's something worth writing down.</p>
<footer>Nothing here is updated on a schedule.</footer>
</body>
</html>
"#;

const NOT_FOUND: &str = "<!doctype html>\n<title>404 Not Found</title>\n<h1>Not Found</h1>\n";

struct Page {
    content_type: &'static str,
    body: Bytes,
}

/// The site's pages, by path.
#[derive(Clone)]
pub struct Site(Arc<HashMap<String, Page>>);

impl Site {
    /// The files under `SITE_DIR` (`index.html` serves `/`), or the
    /// built-in page.
    pub fn load() -> Result<Self> {
        let mut pages = HashMap::new();
        match std::env::var("SITE_DIR") {
            Ok(dir) => add_dir(&mut pages, Path::new(&dir), "")?,
            Err(_) => {
                pages.insert(
                    "/".to_string(),
                    Page {
                        content_type: "text/html; charset=utf-8",
                        body: Bytes::from_static(DEFAULT_INDEX.as_bytes()),
                    },
                );
            }
        }
        Ok(Self(Arc::new(pages)))
    }

    fn get(&self, path: &str) -> Option<&Page> {
        self.0.get(path)
    }
}

fn add_dir(pages: &mut HashMap<String, Page>, dir: &Path, prefix: &str) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let url = format!("{prefix}/{name}");
        if entry.file_type()?.is_dir() {
            add_dir(pages, &entry.path(), &url)?;
            continue;
        }
        let body = Bytes::from(std::fs::read(entry.path())?);
        let content_type = content_type_for(&name);
        if name == "index.html" {
            let index = if prefix.is_empty() { "/" } else { prefix };
            pages.insert(
                index.to_string(),
                Page {
                    content_type,
                    body: body.clone(),
                },
            );
        }
        pages.insert(url, Page { content_type, body });
    }
    Ok(())
}

fn content_type_for(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" => "text/javascript",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Serve HTTP/3 requests on `connection` until it closes.
pub async fn serve(connection: quinn::Connection, site: Site) {
    let h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone()))
        .await;
    let mut h3 = match h3 {
        Ok(h3) => h3,
        Err(e) => {
            debug!("HTTP/3 setup failed: {e}");
            return;
        }
    };
    loop {
        match h3.accept().await {
            Ok(Some(request)) => {
                tokio::spawn(respond(request, site.clone()));
            }
            Ok(None) => break,
            Err(e) => {
                debug!("HTTP/3 connection error: {e}");
                break;
            }
        }
    }
    // Dropping `h3` closes the whole QUIC connection, and an app link (which
    // makes no HTTP requests) may outlive whatever made h3 give up, so it's
    // kept until the connection closes on its own.
    connection.closed().await;
    drop(h3);
}

async fn respond(request: RequestResolver<h3_quinn::Connection, Bytes>, site: Site) {
    let Ok((request, mut stream)) = request.resolve_request().await else {
        return;
    };
    let not_found = Page {
        content_type: "text/html; charset=utf-8",
        body: Bytes::from_static(NOT_FOUND.as_bytes()),
    };
    let (status, page) = match *request.method() {
        Method::GET | Method::HEAD => match site.get(request.uri().path()) {
            Some(page) => (StatusCode::OK, Some(page)),
            None => (StatusCode::NOT_FOUND, Some(&not_found)),
        },
        _ => (StatusCode::METHOD_NOT_ALLOWED, None),
    };
    let mut response = Response::builder().status(status);
    if let Some(page) = page {
        response = response
            .header("content-type", page.content_type)
            .header("content-length", page.body.len());
    }
    if let Ok(response) = response.body(())
        && stream.send_response(response).await.is_ok()
    {
        if let Some(page) = page
            && request.method() == Method::GET
        {
            let _ = stream.send_data(page.body.clone()).await;
        }
        let _ = stream.finish().await;
    }
}
