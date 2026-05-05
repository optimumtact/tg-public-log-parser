use std::{collections::HashMap, io::ErrorKind, path::PathBuf, sync::Arc};

use axum::{
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use crate::{app_state::AppState, parsers::get_file_sanitization_strategy};

pub const RUNTIME_CONDENSED_JSON: &str = "runtime.condensed.json";
pub const RUNTIME_CONDENSED_TXT: &str = "runtime.condensed.txt";

const NOT_FOUND: (StatusCode, &str) = (StatusCode::NOT_FOUND, "couldn't find that path");

#[derive(Serialize)]
struct TraversalItem {
    name: String,
    path: String,
    is_dir: bool,
}

#[tracing::instrument]
pub async fn get(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, axum::response::Response> {
    let decoded_path = percent_encoding::percent_decode_str(uri.path()).decode_utf8_lossy();
    tracing::debug!("path after percent decoding: {}", decoded_path);
    let requested_path = state
        .config
        .raw_logs_path
        .join(decoded_path.strip_prefix('/').unwrap_or(&decoded_path));


    if !requested_path.starts_with(&state.config.raw_logs_path) {
        tracing::warn!("attempted path traversal: {uri}");
        return Ok((StatusCode::FORBIDDEN, "attempted path traversal").into_response());
    }

    match state.path_is_ongoing_round(&requested_path).await {
        Ok(true) => {
            tracing::debug!("blocking access to ongoing round");
            return Ok(NOT_FOUND.into_response());
        }

        Ok(false) => {}

        Err(error) => {
            return Ok(error_to_response(
                error,
                StatusCode::INTERNAL_SERVER_ERROR,
                "error figuring out if that round is ongoing or not",
            ));
        }
    }

    // Pretend files
    match requested_path.file_name().and_then(std::ffi::OsStr::to_str) {
        name @ Some(RUNTIME_CONDENSED_TXT) | name @ Some(RUNTIME_CONDENSED_JSON) => {
            let runtimes_file = requested_path.with_file_name("runtime.log");
            let runtimes_contents = std::fs::read_to_string(runtimes_file).map_err(|error| {
                error_to_response(error, StatusCode::NOT_FOUND, "couldn't find runtime.log")
            })?;

            if name == Some(RUNTIME_CONDENSED_TXT) {
                return Ok((
                    StatusCode::OK,
                    headers("text/plain"),
                    crate::parsers::runtimes::condense_runtimes_to_string(&runtimes_contents),
                )
                    .into_response());
            } else if name == Some(RUNTIME_CONDENSED_JSON) {
                return Ok((
                    StatusCode::OK,
                    headers("application/json"),
                    crate::parsers::runtimes::condense_runtimes_to_json(&runtimes_contents)
                        .to_string(),
                )
                    .into_response());
            } else {
                unreachable!();
            }
        }

        _ => {}
    }

    let metadata = tokio::fs::metadata(&requested_path)
        .await
        .map_err(|error| {
            if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) {
                NOT_FOUND.into_response()
            } else {
                error_to_response(
                    error,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "couldn't get metadata of path",
                )
            }
        })?;

    if metadata.is_dir() {
        if params.get("format").map(|v| v == "json").unwrap_or(false) {
            let items = collect_traversal_items(&state, &requested_path)
                .await
                .map_err(|error| {
                    error_to_response(
                        error,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "error creating traversal JSON",
                    )
                })?;
            Ok((
                StatusCode::OK,
                headers("application/json"),
                serde_json::to_string(&items).unwrap(),
            )
                .into_response())
        } else {
            Ok((
                StatusCode::OK,
                headers("text/html"),
                traversal_page(&state, &requested_path)
                    .await
                    .map_err(|error| {
                        error_to_response(
                            error,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "error creating traversal page",
                        )
                    }),
            )
                .into_response())
        }
    } else if metadata.is_file() {
        let Some(strategy) = get_file_sanitization_strategy(&requested_path) else {
            return Ok(NOT_FOUND.into_response());
        };

        Ok((
            StatusCode::OK,
            headers(
                if requested_path.extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
                    "application/json"
                } else {
                    "text/plain"
                },
            ),
            strategy(std::fs::read_to_string(&requested_path).map_err(|error| {
                error_to_response(
                    error,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "couldn't read file",
                )
            })?),
        )
            .into_response())
    } else {
        Ok((StatusCode::BAD_REQUEST, "tried to access weird file").into_response())
    }
}

async fn collect_traversal_items(
    state: &AppState,
    path: &std::path::Path,
) -> eyre::Result<Vec<TraversalItem>> {
    let mut items = vec![];

    let read_dir = std::fs::read_dir(path)?;

    for entry in read_dir {
        let entry = entry?;
        let entry_path = entry.path();

        if state.path_is_ongoing_round(&entry_path).await? {
            continue;
        }

        let file_type = entry.file_type()?;
        let is_dir = file_type.is_dir();

        // build path relative to raw_logs_path
        let link_path = match entry_path.strip_prefix(&state.config.raw_logs_path) {
            Ok(link_path) => link_path,
            Err(_) => eyre::bail!("couldn't strip prefix with raw logs path"),
        };

        if is_dir || get_file_sanitization_strategy(&entry_path).is_some() {
            items.push(TraversalItem {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: format!("/{}", link_path.display()),
                is_dir,
            });

            // add fake runtime condensed links
            if !is_dir
                && entry_path
                    .file_stem()
                    .map(|s| s == "runtime")
                    .unwrap_or(false)
            {
                items.push(TraversalItem {
                    name: RUNTIME_CONDENSED_JSON.to_string(),
                    path: format!(
                        "/{}",
                        link_path.with_file_name(RUNTIME_CONDENSED_JSON).display()
                    ),
                    is_dir: false,
                });
                items.push(TraversalItem {
                    name: RUNTIME_CONDENSED_TXT.to_string(),
                    path: format!(
                        "/{}",
                        link_path.with_file_name(RUNTIME_CONDENSED_TXT).display()
                    ),
                    is_dir: false,
                });
            }
        }
    }

    items.sort_by(|a, b| (b.is_dir, &a.name).cmp(&(a.is_dir, &b.name)));

    Ok(items)
}

fn headers(content_type: &str) -> [(&'static str, &str); 2] {
    [
        ("cache-control", "public, max-age=31536000"),
        ("content-type", content_type),
    ]
}

fn error_to_response(
    error: impl std::fmt::Debug,
    status_code: StatusCode,
    message: &'static str,
) -> axum::response::Response {
    tracing::error!("{message}: {error:?}");
    (
        status_code,
        format!(
            "{message}\nplease report this error to mothblocks, ideally with the url you tried"
        ),
    )
        .into_response()
}

async fn traversal_page(state: &AppState, path: &std::path::Path) -> eyre::Result<String> {
    let items = collect_traversal_items(state, path).await?;

    let list_html: String = items
        .iter()
        .map(|item| {
            if item.is_dir {
                format!(
                    "<li><a href='{path}'>{name}/</a></li>",
                    path = item.path,
                    name = item.name
                )
            } else {
                format!(
                    "<li><a href='{path}'>{name}</a></li>",
                    path = item.path,
                    name = item.name
                )
            }
        })
        .collect();

    let relative_to_top = path.strip_prefix(&state.config.raw_logs_path)?;

    Ok(format!(
        "<html>
            <head>
                <title>{}</title>
            </head>
            <body>
                <p>{}</p>
                <hr />
                <ul>{}</ul>
            </body>
        </html>",
        relative_to_top.display(),
        link_segments(relative_to_top),
        list_html
    ))
}

fn link_segments(path: &std::path::Path) -> String {
    let mut pieces = Vec::new();

    let mut path_to_this_point = PathBuf::new();
    for component in path.components() {
        path_to_this_point = path_to_this_point.join(component);
        pieces.push(format!(
            "<a href='/{}'>{}</a>",
            path_to_this_point.display(),
            component.as_os_str().to_string_lossy()
        ));
    }

    pieces.join("/")
}
