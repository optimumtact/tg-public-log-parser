use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};

use eyre::Context;
use tokio::task::JoinHandle;

type OngoingRoundIds = Arc<parking_lot::Mutex<HashMap<String, u64>>>;

#[derive(Debug)]
pub struct OngoingRoundProtection {
    config: OngoingRoundProtectionConfig,

    last_known_round_ids: tokio::sync::OnceCell<OngoingRoundIds>,
    round_id_loop: OnceLock<JoinHandle<()>>,
}

impl OngoingRoundProtection {
    pub fn new(config: OngoingRoundProtectionConfig) -> Self {
        Self {
            config,
            last_known_round_ids: Default::default(),
            round_id_loop: OnceLock::new(),
        }
    }

    pub async fn path_is_ongoing_round(&self, path: &Path) -> eyre::Result<bool> {
        let last_known_round_ids = self.last_known_round_ids().await;

        for ancestor in path.ancestors() {
            let filename = match ancestor.file_name() {
                Some(filename) => filename,
                None => break,
            }
            .to_string_lossy();

            if let Some(round_id_text) = filename.strip_prefix("round-") {
                let last_known_round_ids = match &last_known_round_ids {
                    Ok(ids) => ids,
                    Err(_) => return Ok(true),
                };

                let last_known_round_ids = last_known_round_ids.lock();

                let round_id: u64 = round_id_text.parse().context("parsing round id")?;

                let server_identifier = match &self.config.paths_to_identifiers {
                    Some(paths_to_identifiers) => Some(paths_to_identifiers.get(&*filename)),
                    None => None,
                };

                match server_identifier {
                    Some(Some(server_identifier)) => {
                        if let Some(&ongoing_round_id) = last_known_round_ids.get(server_identifier)
                        {
                            return Ok(round_id >= ongoing_round_id);
                        }
                    }
                    None => {
                        for (_, ongoing_round_id) in last_known_round_ids.iter() {
                            if *ongoing_round_id == round_id {
                                return Ok(true);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(false)
    }

    async fn last_known_round_ids(&self) -> eyre::Result<OngoingRoundIds> {
        let last_known_round_ids = self
            .last_known_round_ids
            .get_or_try_init(|| async {
                let round_ids = fetch_ongoing_rounds(&self.config.serverinfo).await?;
                Ok(Arc::new(parking_lot::Mutex::new(round_ids))) as eyre::Result<OngoingRoundIds>
            })
            .await?
            .clone();

        self.round_id_loop.get_or_init({
            let last_known_round_ids: OngoingRoundIds = Arc::clone(&last_known_round_ids);
            let serverinfo = self.config.serverinfo.clone();

            move || {
                tokio::task::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        tracing::debug!("getting new round ids...");
                        let round_ids = match fetch_ongoing_rounds(&serverinfo).await {
                            Ok(round_ids) => round_ids,
                            Err(error) => {
                                tracing::error!("error getting ongoing rounds: {error}");
                                continue;
                            }
                        };

                        *last_known_round_ids.lock() = round_ids;
                    }
                })
            }
        });

        Ok(last_known_round_ids)
    }
}

impl Drop for OngoingRoundProtection {
    fn drop(&mut self) {
        if let Some(round_id_loop) = self.round_id_loop.get() {
            round_id_loop.abort();
        }
    }
}

async fn fetch_ongoing_rounds(serverinfo_url: &str) -> eyre::Result<HashMap<String, u64>> {
    let server_info_bytes = reqwest::get(serverinfo_url)
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let server_info: ServerInfo = match serde_json::from_slice(&server_info_bytes) {
        Ok(server_info) => server_info,
        Err(error) => {
            tracing::error!(
                "bad serverinfo.json, contents = {}",
                String::from_utf8_lossy(&server_info_bytes)
            );
            return Err(error.into());
        }
    };

    let round_ids = HashMap::from_iter(server_info.servers.into_iter().filter_map(|server| {
        server.data.and_then(|data| match data.round_id {
            Some(round_id) => {
                let round_id = round_id.parse().ok()?;
                Some((data.identifier, round_id))
            }
            None => None,
        })
    }));

    tracing::debug!("current round ids: {round_ids:?}");

    Ok(round_ids)
}

#[derive(Debug, serde::Deserialize)]
pub struct OngoingRoundProtectionConfig {
    serverinfo: String,
    paths_to_identifiers: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct ServerInfo {
    servers: Vec<Server>,
}

#[derive(serde::Deserialize)]
struct Server {
    data: Option<ServerData>,
}

#[derive(serde::Deserialize)]
struct ServerData {
    round_id: Option<String>,
    identifier: String,
}
