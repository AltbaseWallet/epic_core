use chrono::DateTime;
use epic_wallet_api::Owner;
use epic_wallet_config::{EpicboxConfig, TorConfig, WalletConfig};
use epic_wallet_impls::{
    DefaultLCProvider, DefaultWalletImpl, EpicboxChannel, EpicboxListenChannel, HTTPNodeClient,
};
use epic_wallet_libwallet::{
    InitTxArgs, OutputStatus, TxLogEntryType, WalletInitStatus, WalletInst,
};
use epic_wallet_util::epic_core::core::{amount_from_hr_string, amount_to_hr_string};
use epic_wallet_util::epic_core::global::{self, ChainTypes};
use epic_wallet_util::epic_keychain::ExtKeychain;
use epic_wallet_util::epic_util::{to_hex, Mutex as WalletMutex, ZeroingString};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

type EpicLc = DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>;
type EpicSecretKey = epic_wallet_util::epic_util::secp::key::SecretKey;
type EpicWallet =
    Arc<WalletMutex<Box<dyn WalletInst<'static, EpicLc, HTTPNodeClient, ExtKeychain>>>>;

static EPICBOX_LISTENERS: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();
static EPIC_UPDATERS: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();
static EPIC_BLOCK_TIME_CACHE: OnceLock<StdMutex<HashMap<u64, (i64, String)>>> = OnceLock::new();
const EPIC_ALTBASE_SUPPORT_START_HEIGHT: u64 = 3_540_000;
const EPIC_RECENT_RESCAN_BLOCKS: u64 = 30;
const EPICBOX_SEND_TIMEOUT_SECS: u64 = 25;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpicRequest {
    action: String,
    mnemonic: Option<String>,
    password: Option<String>,
    data_dir: Option<String>,
    node_url: Option<String>,
    restore_start_height: Option<u64>,
    to: Option<String>,
    amount: Option<String>,
    fee: Option<String>,
    send_max: Option<String>,
    memo: Option<String>,
}

fn ok(mut payload: Value) -> String {
    payload["ok"] = json!(true);
    payload.to_string()
}

fn err(code: &str, message: impl ToString) -> String {
    json!({
        "ok": false,
        "code": code,
        "error": message.to_string(),
    })
    .to_string()
}

fn c_string(text: String) -> *mut c_char {
    CString::new(text)
        .unwrap_or_else(|_| CString::new(err("epic-native-nul", "response contained NUL")).unwrap())
        .into_raw()
}

fn wallet_dir(req: &EpicRequest) -> PathBuf {
    req.data_dir
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("epic-light"))
}

fn node_url(req: &EpicRequest) -> String {
    req.node_url
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("https://api.altbase.io")
        .trim_end_matches('/')
        .to_string()
}

fn request_bool(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()),
        Some(v) if v == "true" || v == "1" || v == "yes"
    )
}

fn requested_or_default_fee(req: &EpicRequest) -> Result<u64, String> {
    if let Some(text) = req.fee.as_deref().filter(|v| !v.trim().is_empty()) {
        let fee = amount_from_hr_string(text).map_err(|e| format!("Epic fee: {e}"))?;
        if fee > 0 {
            return Ok(fee);
        }
    }
    amount_from_hr_string("0.01").map_err(|e| format!("Epic default fee: {e}"))
}

fn sanitize_epicbox_error(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("can't connect to the epicbox server")
        || lower.contains("native-tls")
        || lower.contains("os error 10060")
    {
        return "Epicbox server is not reachable. Please try again in a moment.".to_string();
    }
    text.to_string()
}

fn build_wallet(data_dir: &Path, node_url: &str) -> Result<(EpicWallet, WalletConfig), String> {
    let mut config = WalletConfig::default();
    config.chain_type = Some(ChainTypes::Mainnet);
    config.data_file_dir = data_dir
        .to_str()
        .ok_or_else(|| "Epic data directory is not valid UTF-8".to_string())?
        .to_string();
    config.check_node_api_http_addr = node_url.to_string();
    config.node_api_secret_path = None;

    let node_client = HTTPNodeClient::new(&config.check_node_api_http_addr, None)
        .map_err(|e| format!("Epic node client: {e}"))?;
    let mut wallet = Box::new(
        DefaultWalletImpl::<'static, HTTPNodeClient>::new(node_client.clone())
            .map_err(|e| format!("Epic wallet init: {e}"))?,
    ) as Box<dyn WalletInst<'static, EpicLc, HTTPNodeClient, ExtKeychain>>;
    wallet
        .lc_provider()
        .map_err(|e| format!("Epic lifecycle provider: {e}"))?
        .set_top_level_directory(&config.data_file_dir)
        .map_err(|e| format!("Epic data directory: {e}"))?;

    Ok((Arc::new(WalletMutex::new(wallet)), config))
}

fn start_epicbox_listener(scope: String, wallet: EpicWallet, mask: Option<EpicSecretKey>) {
    let listeners = EPICBOX_LISTENERS.get_or_init(|| StdMutex::new(HashSet::new()));
    {
        let mut guard = match listeners.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if !guard.insert(scope.clone()) {
            return;
        }
    }

    let _ = std::thread::Builder::new()
        .name("altbase-epicbox-listener".to_string())
        .spawn(move || {
            let mask = Arc::new(WalletMutex::new(mask));
            let mut reconnections = 0;
            let result = EpicboxListenChannel::new().and_then(|listener| {
                listener.listen(
                    wallet,
                    mask,
                    EpicboxConfig::default(),
                    &mut reconnections,
                    Arc::new(AtomicBool::new(true)),
                    TorConfig::default(),
                )
            });
            let _ = result;
            if let Some(listeners) = EPICBOX_LISTENERS.get() {
                if let Ok(mut guard) = listeners.lock() {
                    guard.remove(&scope);
                }
            }
        });
}

fn start_updater(
    scope: &str,
    owner: &Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    mask: Option<&EpicSecretKey>,
) {
    let updaters = EPIC_UPDATERS.get_or_init(|| StdMutex::new(HashSet::new()));
    {
        let mut guard = match updaters.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if !guard.insert(scope.to_string()) {
            return;
        }
    }
    if owner.start_updater(mask, Duration::from_secs(45)).is_err() {
        if let Ok(mut guard) = updaters.lock() {
            guard.remove(scope);
        }
    }
}

fn open_wallet(
    req: &EpicRequest,
) -> Result<
    (
        Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
        Option<EpicSecretKey>,
        EpicWallet,
        String,
    ),
    String,
> {
    global::set_mining_mode(ChainTypes::Mainnet);

    let mnemonic = req
        .mnemonic
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "Epic mnemonic is required".to_string())?;
    let password = req
        .password
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "Epic wallet password is required".to_string())?;

    let data_dir = wallet_dir(req);
    fs::create_dir_all(&data_dir).map_err(|e| format!("Epic data directory create: {e}"))?;
    let (wallet, config) = build_wallet(&data_dir, &node_url(req))?;
    let owner = Owner::new(wallet.clone(), None, Arc::new(AtomicBool::new(true)));

    let config_file = data_dir.join("epic-wallet.toml");
    if !config_file.exists() {
        owner
            .create_config(&ChainTypes::Mainnet, Some(config.clone()), None, None, None)
            .map_err(|e| format!("Epic config create: {e}"))?;
    }

    let seed_file = data_dir.join("wallet_data").join("wallet.seed");
    if !seed_file.exists() {
        owner
            .create_wallet(
                None,
                Some(ZeroingString::from(mnemonic)),
                0,
                ZeroingString::from(password),
            )
            .map_err(|e| format!("Epic wallet restore: {e}"))?;
    }

    let mask = owner
        .open_wallet(None, ZeroingString::from(password), true)
        .map_err(|e| format!("Epic wallet open: {e}"))?;

    let scope = data_dir.to_string_lossy().to_string();
    start_epicbox_listener(scope.clone(), wallet.clone(), mask.clone());

    Ok((owner, mask, wallet, scope))
}

fn address_for(
    owner: &Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    mask: Option<&EpicSecretKey>,
) -> Result<String, String> {
    owner
        .get_public_address(mask, 0)
        .map(|a| a.to_string())
        .map_err(|e| format!("Epic address: {e}"))
}

fn tx_direction(tx_type: &TxLogEntryType) -> &'static str {
    match tx_type {
        TxLogEntryType::TxReceived
        | TxLogEntryType::TxReceivedMempool
        | TxLogEntryType::ConfirmedCoinbase => "incoming",
        _ => "outgoing",
    }
}

fn tx_status(tx_type: &TxLogEntryType, confirmed: bool) -> &'static str {
    if confirmed {
        "confirmed"
    } else {
        match tx_type {
            TxLogEntryType::TxSentMempool | TxLogEntryType::TxReceivedMempool => "mempool",
            TxLogEntryType::TxSentCancelled | TxLogEntryType::TxReceivedCancelled => "cancelled",
            _ => "pending",
        }
    }
}

fn tx_amount(tx_type: &TxLogEntryType, credited: u64, debited: u64, fee: Option<u64>) -> String {
    let units = match tx_direction(tx_type) {
        "incoming" => credited.saturating_sub(debited),
        _ => debited
            .saturating_sub(credited)
            .saturating_sub(fee.unwrap_or(0)),
    };
    amount_to_hr_string(units, true)
}

fn confirmation_count(confirmed: bool, height: Option<u64>, tip_height: u64) -> u64 {
    if !confirmed {
        return 0;
    }
    height
        .filter(|h| *h > 0 && tip_height >= *h)
        .map(|h| tip_height.saturating_sub(h).saturating_add(1))
        .unwrap_or(1)
}

fn output_totals(
    owner: &Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    mask: Option<&EpicSecretKey>,
    current_height: u64,
) -> Option<(u64, u64)> {
    let outputs = owner
        .retrieve_outputs(
            mask,
            false,
            false,
            false,
            None,
            Some(1000),
            Some(0),
            Some("desc".to_string()),
        )
        .ok()?;
    let mut total = 0u64;
    let mut spendable = 0u64;
    for item in outputs.outputs {
        let output = item.output;
        match output.status {
            OutputStatus::Unspent => {
                total = total.saturating_add(output.value);
                if output.eligible_to_spend(current_height, 1) {
                    spendable = spendable.saturating_add(output.value);
                }
            }
            OutputStatus::Unconfirmed => {
                total = total.saturating_add(output.value);
            }
            OutputStatus::Locked => {}
            OutputStatus::Spent | OutputStatus::Deleted => {}
        }
    }
    Some((total, spendable))
}

fn spent_outputs_by_tx(
    owner: &Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    mask: Option<&EpicSecretKey>,
) -> (HashMap<u32, bool>, HashSet<String>) {
    let mut output_states: HashMap<u32, (bool, bool)> = HashMap::new();
    let mut spent_commits = HashSet::new();
    let outputs = match owner.retrieve_outputs(
        mask,
        true,
        false,
        false,
        None,
        Some(1000),
        Some(0),
        Some("desc".to_string()),
    ) {
        Ok(outputs) => outputs,
        Err(_) => return (HashMap::new(), spent_commits),
    };
    for item in outputs.outputs {
        if matches!(
            item.output.status,
            OutputStatus::Spent | OutputStatus::Deleted
        ) {
            spent_commits.insert(
                item.output
                    .commit
                    .clone()
                    .unwrap_or_else(|| to_hex(item.commit.as_ref().to_vec())),
            );
        }
        if let Some(tx_id) = item.output.tx_log_entry {
            let state = output_states.entry(tx_id).or_insert((false, false));
            if matches!(
                item.output.status,
                OutputStatus::Spent | OutputStatus::Deleted
            ) {
                state.0 = true;
            } else {
                state.1 = true;
            }
        }
    }
    let spent_by_tx = output_states
        .into_iter()
        .map(|(tx_id, (has_spent_output, has_live_output))| {
            (tx_id, has_spent_output && !has_live_output)
        })
        .collect();
    (spent_by_tx, spent_commits)
}

fn output_commits_and_heights_by_tx(
    owner: &Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    mask: Option<&EpicSecretKey>,
) -> (HashMap<u32, Vec<String>>, HashSet<u64>) {
    let mut commits: HashMap<u32, Vec<String>> = HashMap::new();
    let mut heights = HashSet::new();
    let outputs = match owner.retrieve_outputs(
        mask,
        true,
        false,
        true,
        None,
        Some(1000),
        Some(0),
        Some("desc".to_string()),
    ) {
        Ok(outputs) => outputs,
        Err(_) => return (commits, heights),
    };
    for item in outputs.outputs {
        if item.output.height > 0 {
            heights.insert(item.output.height);
        }
        if let Some(tx_id) = item.output.tx_log_entry {
            let commit = item
                .output
                .commit
                .clone()
                .unwrap_or_else(|| to_hex(item.commit.as_ref().to_vec()));
            commits.entry(tx_id).or_default().push(commit);
        }
    }
    (commits, heights)
}

fn epic_block_times_by_height(
    node_url: &str,
    heights: &HashSet<u64>,
) -> HashMap<u64, (i64, String)> {
    let mut timestamps = HashMap::new();
    if heights.is_empty() {
        return timestamps;
    }

    let cache = EPIC_BLOCK_TIME_CACHE.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut missing_heights = Vec::new();
    if let Ok(guard) = cache.lock() {
        for height in heights.iter().copied().filter(|height| *height > 0) {
            if let Some(value) = guard.get(&height) {
                timestamps.insert(height, value.clone());
            } else {
                missing_heights.push(height);
            }
        }
    } else {
        missing_heights.extend(heights.iter().copied().filter(|height| *height > 0));
    }
    if missing_heights.is_empty() {
        return timestamps;
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
    {
        Ok(client) => client,
        Err(_) => return timestamps,
    };
    let url = format!("{}/v2/foreign", node_url.trim_end_matches('/'));

    let requests = missing_heights
        .iter()
        .map(|height| {
            json!({
                "jsonrpc": "2.0",
                "method": "get_header",
                "params": [*height, null, null],
                "id": *height,
            })
        })
        .collect::<Vec<_>>();
    let response = client
        .post(&url)
        .json(&requests)
        .send()
        .and_then(|response| response.error_for_status());
    let Ok(response) = response else {
        return timestamps;
    };
    let Ok(payload) = response.json::<Value>() else {
        return timestamps;
    };
    let items = match payload {
        Value::Array(items) => items,
        item if item.is_object() => vec![item],
        _ => vec![],
    };

    let mut fetched = HashMap::new();
    for item in items {
        let height = item.get("id").and_then(Value::as_u64).or_else(|| {
            item.get("result")
                .and_then(|result| result.get("Ok"))
                .and_then(|header| header.get("height"))
                .and_then(Value::as_u64)
        });
        let Some(height) = height else {
            continue;
        };
        let Some(timestamp) = item
            .get("result")
            .and_then(|result| result.get("Ok"))
            .and_then(|header| header.get("timestamp"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Ok(parsed) = DateTime::parse_from_rfc3339(timestamp) else {
            continue;
        };
        fetched.insert(height, (parsed.timestamp_millis(), timestamp.to_string()));
    }

    if !fetched.is_empty() {
        if let Ok(mut guard) = cache.lock() {
            for (height, value) in &fetched {
                guard.insert(*height, value.clone());
            }
        }
        timestamps.extend(fetched);
    }

    timestamps
}

fn epic_time_for_height(
    block_times: &HashMap<u64, (i64, String)>,
    height: Option<u64>,
    fallback_timestamp: i64,
    fallback_date: String,
) -> (i64, String) {
    height
        .and_then(|value| block_times.get(&value))
        .map(|(timestamp, date)| (*timestamp, date.clone()))
        .unwrap_or((fallback_timestamp, fallback_date))
}

fn restored_output_transactions(
    owner: &Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    mask: Option<&EpicSecretKey>,
    address: &str,
    represented_tx_ids: &HashSet<u32>,
    tip_height: u64,
    block_times: &HashMap<u64, (i64, String)>,
) -> Vec<Value> {
    let outputs = match owner.retrieve_outputs(
        mask,
        true,
        false,
        true,
        None,
        Some(1000),
        Some(0),
        Some("desc".to_string()),
    ) {
        Ok(outputs) => outputs,
        Err(_) => return vec![],
    };

    outputs
        .outputs
        .into_iter()
        .filter(|item| {
            item.output
                .tx_log_entry
                .map(|id| !represented_tx_ids.contains(&id))
                .unwrap_or(true)
        })
        .map(|item| {
            let output_height = item.output.height;
            let (timestamp, date) =
                epic_time_for_height(block_times, Some(output_height), 0, String::new());
            let commit = item
                .output
                .commit
                .clone()
                .unwrap_or_else(|| to_hex(item.commit.as_ref().to_vec()));
            let txid = commit.clone();
            let spent = matches!(
                item.output.status,
                OutputStatus::Spent | OutputStatus::Deleted
            );
            json!({
                "id": txid,
                "txid": txid,
                "outputCommit": commit.clone(),
                "output_commit": commit,
                "type": "incoming",
                "direction": "incoming",
                "status": "confirmed",
                "confirmed": true,
                "confirmations": confirmation_count(true, Some(item.output.height), tip_height),
                "amount": amount_to_hr_string(item.output.value, true),
                "fee": null,
                "from": "Restore",
                "to": address,
                "timestamp": timestamp,
                "date": if date.is_empty() { Value::Null } else { json!(date) },
                "height": output_height,
                "spent": spent,
            })
        })
        .collect()
}

fn restore_scan_marker(scope: &str) -> PathBuf {
    PathBuf::from(scope).join("altbase.restore-scan.done")
}

fn marker_u64(marker: &Path, key: &str) -> Option<u64> {
    let text = fs::read_to_string(marker).ok()?;
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn marker_start_height(marker: &Path) -> Option<u64> {
    marker_u64(marker, "startHeight")
}

fn marker_scanned_height(marker: &Path) -> Option<u64> {
    marker_u64(marker, "scannedHeight")
}

fn write_restore_scan_marker(
    marker: &Path,
    start_height: u64,
    scanned_height: u64,
) -> Result<(), String> {
    fs::write(
        marker,
        format!("startHeight={start_height}\nscannedHeight={scanned_height}\n"),
    )
    .map_err(|e| format!("Epic restore scan marker: {e}"))
}

fn mark_init_complete(wallet: &EpicWallet, mask: Option<&EpicSecretKey>) -> Result<(), String> {
    let mut wallet_lock = wallet.lock();
    let wallet_inst = wallet_lock
        .lc_provider()
        .map_err(|e| format!("Epic lifecycle provider: {e}"))?
        .wallet_inst()
        .map_err(|e| format!("Epic wallet instance: {e}"))?;
    let mut batch = wallet_inst
        .batch(mask)
        .map_err(|e| format!("Epic wallet batch: {e}"))?;
    batch
        .save_init_status(WalletInitStatus::InitComplete)
        .map_err(|e| format!("Epic restore scan status: {e}"))?;
    batch
        .commit()
        .map_err(|e| format!("Epic restore scan status commit: {e}"))?;
    Ok(())
}

fn ensure_restore_scan(
    req: &EpicRequest,
    owner: &Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    mask: Option<&EpicSecretKey>,
    wallet: &EpicWallet,
    scope: &str,
) -> Result<(), String> {
    let marker = restore_scan_marker(scope);
    let start_height = req
        .restore_start_height
        .filter(|height| *height > 0)
        .unwrap_or(EPIC_ALTBASE_SUPPORT_START_HEIGHT);
    if marker.exists() {
        if let Some(height) = marker_start_height(&marker) {
            if height <= start_height {
                return mark_init_complete(wallet, mask);
            }
        } else {
            return mark_init_complete(wallet, mask);
        }
    }

    if marker.exists() {
        let _ = fs::remove_file(&marker);
    }

    owner
        .scan(mask, Some(start_height), false)
        .map_err(|e| format!("Epic restore scan: {e}"))?;
    mark_init_complete(wallet, mask)?;

    write_restore_scan_marker(&marker, start_height, start_height)?;
    Ok(())
}

fn ensure_recent_restore_scan(
    req: &EpicRequest,
    owner: &Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    mask: Option<&EpicSecretKey>,
    wallet: &EpicWallet,
    scope: &str,
    tip_height: u64,
) -> Result<bool, String> {
    if tip_height == 0 {
        return Ok(false);
    }

    let marker = restore_scan_marker(scope);
    let start_height = req
        .restore_start_height
        .filter(|height| *height > 0)
        .unwrap_or(EPIC_ALTBASE_SUPPORT_START_HEIGHT);
    let restore_start = marker_start_height(&marker)
        .filter(|height| *height <= start_height)
        .unwrap_or(start_height);
    let previous_scanned = marker_scanned_height(&marker);
    if previous_scanned
        .map(|height| height >= tip_height)
        .unwrap_or(false)
    {
        return Ok(false);
    }

    let scan_from = previous_scanned
        .filter(|height| *height > restore_start)
        .map(|height| height.saturating_sub(EPIC_RECENT_RESCAN_BLOCKS))
        .unwrap_or_else(|| tip_height.saturating_sub(EPIC_RECENT_RESCAN_BLOCKS))
        .max(restore_start)
        .min(tip_height);

    owner
        .scan(mask, Some(scan_from), false)
        .map_err(|e| format!("Epic recent scan: {e}"))?;
    mark_init_complete(wallet, mask)?;
    write_restore_scan_marker(&marker, restore_start, tip_height)?;
    Ok(true)
}

fn snapshot(req: &EpicRequest) -> Result<String, String> {
    let (owner, mask, wallet, scope) = open_wallet(req)?;
    let mask_ref = mask.as_ref();
    let address = address_for(&owner, mask_ref)?;
    ensure_restore_scan(req, &owner, mask_ref, &wallet, &scope)?;

    let (mut updated_from_node, mut info) = owner
        .retrieve_summary_info(mask_ref, true, 1)
        .map_err(|e| format!("Epic balance refresh: {e}"))?;
    if ensure_recent_restore_scan(
        req,
        &owner,
        mask_ref,
        &wallet,
        &scope,
        info.last_confirmed_height,
    )? {
        let refreshed = owner
            .retrieve_summary_info(mask_ref, true, 1)
            .map_err(|e| format!("Epic balance refresh: {e}"))?;
        updated_from_node = updated_from_node || refreshed.0;
        info = refreshed.1;
    }
    let txs = owner
        .retrieve_txs(
            mask_ref,
            false,
            None,
            None,
            Some(50),
            Some(0),
            Some("desc".to_string()),
        )
        .map_err(|e| format!("Epic transaction refresh: {e}"))?;
    start_updater(&scope, &owner, mask_ref);
    let (spent_by_tx, spent_commits) = spent_outputs_by_tx(&owner, mask_ref);
    let (output_commits_by_tx, mut block_time_heights) =
        output_commits_and_heights_by_tx(&owner, mask_ref);
    block_time_heights.extend(txs.txs.iter().filter_map(|tx| tx.confirmation_height));
    let effective_height = block_time_heights
        .iter()
        .copied()
        .filter(|height| *height > 0)
        .max()
        .map(|height| info.last_confirmed_height.max(height))
        .unwrap_or(info.last_confirmed_height);
    let (balance_total, balance_spendable) = output_totals(&owner, mask_ref, effective_height)
        .unwrap_or((
            info.total.saturating_sub(info.amount_locked),
            info.amount_currently_spendable,
        ));
    let block_times = epic_block_times_by_height(&node_url(req), &block_time_heights);
    let represented_tx_ids = txs.txs.iter().map(|tx| tx.id).collect::<HashSet<_>>();

    let mut transactions: Vec<Value> = txs
        .txs
        .into_iter()
        .map(|tx| {
            let direction = tx_direction(&tx.tx_type);
            let spent = direction == "incoming" && spent_by_tx.get(&tx.id).copied().unwrap_or(false);
            let tx_height = tx.confirmation_height;
            let kernel_excess = tx
                .kernel_excess
                .as_ref()
                .map(|commit| to_hex(commit.as_ref().to_vec()));
            let stored_kernel_excess = owner
                .get_stored_tx(mask_ref, &tx)
                .ok()
                .flatten()
                .and_then(|stored_tx| {
                    stored_tx
                        .kernels()
                        .first()
                        .map(|kernel| to_hex(kernel.excess.as_ref().to_vec()))
                });
            let output_commit = output_commits_by_tx
                .get(&tx.id)
                .and_then(|commits| commits.first().cloned());
            let output_commit_spent = output_commit
                .as_ref()
                .map(|commit| spent_commits.contains(commit))
                .unwrap_or(false);
            let slate_id = tx.tx_slate_id.map(|value| value.to_string());
            let (timestamp, date) = epic_time_for_height(
                &block_times,
                tx_height,
                tx.creation_ts.timestamp_millis(),
                tx.creation_ts.to_rfc3339(),
            );
            let searchable_id = kernel_excess
                .clone()
                .or_else(|| stored_kernel_excess.clone())
                .or_else(|| output_commit.clone());
            let chain_txid = searchable_id
                .or_else(|| slate_id.clone())
                .unwrap_or_else(|| {
                    let height = tx_height
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "pending".to_string());
                    format!("epic-local-{}-{}", height, tx.id)
                });
            let txid = slate_id.clone().unwrap_or_else(|| chain_txid.clone());
            json!({
                "id": txid,
                "txid": txid,
                "chainTxid": chain_txid.clone(),
                "chain_txid": chain_txid,
                "slateId": slate_id.clone(),
                "tx_slate_id": slate_id,
                "kernelExcess": kernel_excess.clone(),
                "kernel_excess": kernel_excess,
                "storedKernelExcess": stored_kernel_excess.clone(),
                "stored_kernel_excess": stored_kernel_excess,
                "outputCommit": output_commit.clone(),
                "output_commit": output_commit,
                "type": direction,
                "direction": direction,
                "status": tx_status(&tx.tx_type, tx.confirmed),
                "confirmed": tx.confirmed,
                "confirmations": confirmation_count(tx.confirmed, tx_height, info.last_confirmed_height),
                "amount": tx_amount(&tx.tx_type, tx.amount_credited, tx.amount_debited, tx.fee),
                "fee": tx.fee.map(|v| amount_to_hr_string(v, true)),
                "from": if direction == "incoming" { tx.public_addr.clone() } else { Some(address.clone()) },
                "to": if direction == "incoming" { Some(address.clone()) } else { tx.public_addr.clone() },
                "timestamp": timestamp,
                "date": date,
                "height": tx_height,
                "spent": spent || (direction == "incoming" && output_commit_spent),
            })
        })
        .collect();
    transactions.extend(restored_output_transactions(
        &owner,
        mask_ref,
        &address,
        &represented_tx_ids,
        info.last_confirmed_height,
        &block_times,
    ));

    Ok(ok(json!({
        "code": "epic-native-wallet",
        "updatedFromNode": updated_from_node,
        "updated_from_node": updated_from_node,
        "address": address,
        "balance": amount_to_hr_string(balance_total, true),
        "spendable": amount_to_hr_string(balance_spendable, true),
        "lastScannedHeight": info.last_confirmed_height,
        "last_scanned_height": info.last_confirmed_height,
        "transactions": transactions,
    })))
}

fn ensure(req: &EpicRequest) -> Result<String, String> {
    let (owner, mask, _wallet, _scope) = open_wallet(req)?;
    let address = address_for(&owner, mask.as_ref())?;
    Ok(ok(json!({
        "code": "epic-native-wallet",
        "address": address,
        "balance": "0",
        "spendable": "0",
        "transactions": [],
    })))
}

fn send(req: &EpicRequest) -> Result<String, String> {
    let (owner, mask, wallet, _scope) = open_wallet(req)?;
    let mask_ref = mask.as_ref();
    let to = req
        .to
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "Destination address is required".to_string())?;
    let send_max = request_bool(req.send_max.as_deref());
    let mut amount = if send_max {
        0
    } else {
        amount_from_hr_string(
            req.amount
                .as_deref()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| "Amount is required".to_string())?,
        )
        .map_err(|e| format!("Epic amount: {e}"))?
    };

    if send_max {
        let (_updated_from_node, info) = owner
            .retrieve_summary_info(mask_ref, true, 1)
            .map_err(|e| format!("Epic balance refresh: {e}"))?;
        let spendable = output_totals(&owner, mask_ref, info.last_confirmed_height)
            .map(|(_total, spendable)| spendable)
            .unwrap_or(info.amount_currently_spendable);
        let mut fee = requested_or_default_fee(req)?;
        for _ in 0..6 {
            if spendable <= fee {
                return Err(format!(
                    "Epic transaction create: Not enough funds. Required: {}, Available: {}",
                    amount_to_hr_string(fee, true),
                    amount_to_hr_string(spendable, true)
                ));
            }
            let candidate = spendable - fee;
            let estimate_args = InitTxArgs {
                src_acct_name: None,
                amount: candidate,
                minimum_confirmations: 1,
                max_outputs: 500,
                num_change_outputs: 1,
                selection_strategy_is_use_all: false,
                message: req.memo.clone(),
                estimate_only: Some(true),
                ..Default::default()
            };
            let estimate = owner
                .init_send_tx(mask_ref, estimate_args, Arc::new(AtomicBool::new(true)))
                .map_err(|e| format!("Epic max fee estimate: {e}"))?;
            if estimate.fee == fee {
                amount = candidate;
                break;
            }
            fee = estimate.fee;
            amount = spendable.saturating_sub(fee);
        }
        if amount == 0 {
            return Err("Epic transaction create: Not enough funds after fee".to_string());
        }
    }

    let args = InitTxArgs {
        src_acct_name: None,
        amount,
        minimum_confirmations: 1,
        max_outputs: 500,
        num_change_outputs: 1,
        selection_strategy_is_use_all: false,
        message: req.memo.clone(),
        ..Default::default()
    };

    let slate = owner
        .init_send_tx(mask_ref, args, Arc::new(AtomicBool::new(true)))
        .map_err(|e| format!("Epic transaction create: {e}"))?;
    let send_running = Arc::new(AtomicBool::new(true));
    let timeout_flag = send_running.clone();
    let _ = std::thread::Builder::new()
        .name("altbase-epicbox-send-timeout".to_string())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(EPICBOX_SEND_TIMEOUT_SECS));
            timeout_flag.store(false, Ordering::SeqCst);
        });

    let slate = EpicboxChannel::new(&to.to_string(), Some(EpicboxConfig::default()))
        .and_then(|channel| {
            channel.send(
                wallet,
                mask.clone(),
                &slate,
                send_running.clone(),
                TorConfig::default(),
            )
        })
        .map_err(|e| {
            if !send_running.load(Ordering::SeqCst) {
                format!("Epicbox send timeout after {EPICBOX_SEND_TIMEOUT_SECS}s")
            } else {
                format!("Epicbox send: {}", sanitize_epicbox_error(&e.to_string()))
            }
        })?;
    owner
        .tx_lock_outputs(mask_ref, &slate, 0, Some(to.to_string()))
        .map_err(|e| format!("Epic output lock: {e}"))?;

    Ok(ok(json!({
        "code": "epic-native-epicbox-sent",
        "address": address_for(&owner, mask_ref)?,
        "txid": slate.id.to_string(),
        "amount": amount_to_hr_string(amount, true),
        "fee": amount_to_hr_string(slate.fee, true),
        "balance": "0",
        "spendable": "0",
        "transactions": [],
    })))
}

fn handle(input: &str) -> String {
    let req: EpicRequest = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(e) => return err("epic-native-bad-request", e),
    };

    match req.action.as_str() {
        "ensure" => ensure(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        "snapshot" => snapshot(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        "send" => send(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        _ => err("epic-native-bad-action", "Unsupported Epic action"),
    }
}

#[no_mangle]
pub extern "C" fn altbase_epic_request(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return c_string(err("epic-native-null-request", "request pointer is null"));
    }
    let input = unsafe { CStr::from_ptr(input) };
    match input.to_str() {
        Ok(text) => c_string(handle(text)),
        Err(e) => c_string(err("epic-native-utf8-request", e)),
    }
}

#[no_mangle]
pub extern "C" fn altbase_epic_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}
