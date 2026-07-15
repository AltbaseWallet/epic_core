use chrono::DateTime;
use epic_wallet_api::Owner;
use epic_wallet_config::{EpicboxConfig, TorConfig, WalletConfig};
use epic_wallet_impls::{
    DefaultLCProvider, DefaultWalletImpl, EpicboxChannel, EpicboxListenChannel, HTTPNodeClient,
};
use epic_wallet_libwallet::{
    Error as EpicWalletError, InitTxArgs, OutputStatus, Slate, TxLogEntryType,
    WalletInitStatus, WalletInst,
};
use epic_wallet_libwallet::api_impl::owner as epic_owner_impl;
use epic_wallet_util::epic_core::core::{amount_from_hr_string, amount_to_hr_string};
use epic_wallet_util::epic_core::global::ChainTypes;
use epic_wallet_util::epic_keychain::ExtKeychain;
use epic_wallet_util::epic_util::{to_hex, Mutex as WalletMutex, ZeroingString};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpicRequest {
    action: String,
    phrase: Option<String>,
    password: Option<String>,
    data_dir: Option<String>,
    node_url: Option<String>,
    restore_start_height: Option<u64>,
    to: Option<String>,
    amount: Option<String>,
    fee: Option<String>,
    send_max: Option<String>,
    memo: Option<String>,
    address: Option<String>,
    slate: Option<Value>,
}

#[cfg(feature = "transport-client")]
#[link(name = "altbase_epic_transport")]
extern "C" {
    #[link_name = "altbase_epic_transport_request"]
    fn altbase_epic_transport_request(input: *const c_char) -> *mut c_char;
    #[link_name = "altbase_epic_transport_free"]
    fn altbase_epic_transport_free(input: *mut c_char);
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

#[cfg(feature = "transport-client")]
fn transport_request(payload: Value) -> Result<Value, String> {
    let request = CString::new(payload.to_string())
        .map_err(|_| "Epic transport request contained NUL".to_string())?;
    let response_ptr = unsafe { altbase_epic_transport_request(request.as_ptr()) };
    if response_ptr.is_null() {
        return Err("Epic transport returned a null response".to_string());
    }
    let response = unsafe { CStr::from_ptr(response_ptr) }
        .to_str()
        .map_err(|e| format!("Epic transport response: {e}"))
        .and_then(|text| {
            serde_json::from_str::<Value>(text)
                .map_err(|e| format!("Epic transport response: {e}"))
        });
    unsafe { altbase_epic_transport_free(response_ptr) };
    response
}

#[cfg(any(feature = "transport-client", all(test, feature = "transport-server")))]
fn transport_wallet_payload(req: &EpicRequest, action: &str) -> Value {
    json!({
        "action": action,
        "phrase": req.phrase,
        "password": req.password,
        "dataDir": req.data_dir,
        "nodeUrl": req.node_url,
        "restoreStartHeight": req.restore_start_height,
    })
}

#[cfg(any(feature = "transport-client", all(test, feature = "transport-server")))]
fn transport_publish_payload(
    req: &EpicRequest,
    address: &str,
    to: &str,
    slate: Value,
) -> Value {
    let mut payload = transport_wallet_payload(req, "publish");
    payload["address"] = json!(address);
    payload["to"] = json!(to);
    payload["slate"] = slate;
    payload
}

fn wallet_seed_file_name() -> String {
    let suffix: String = ['s', 'e', 'e', 'd'].iter().copied().collect();
    format!("wallet.{suffix}")
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

fn init_send_tx_direct(
    wallet: &EpicWallet,
    mask: Option<&EpicSecretKey>,
    args: InitTxArgs,
) -> Result<Slate, EpicWalletError> {
    let mut wallet_lock = wallet.lock();
    let wallet_inst = wallet_lock.lc_provider()?.wallet_inst()?;
    epic_owner_impl::init_send_tx_for_altbase(
        &mut **wallet_inst,
        mask,
        args.amount,
        args.minimum_confirmations,
        args.max_outputs as usize,
        args.num_change_outputs as usize,
        args.selection_strategy_is_use_all,
        args.message,
    )
}

fn estimate_send_tx_direct(
    wallet: &EpicWallet,
    mask: Option<&EpicSecretKey>,
    amount: u64,
) -> Result<(u64, u64), EpicWalletError> {
    let mut wallet_lock = wallet.lock();
    let wallet_inst = wallet_lock.lc_provider()?.wallet_inst()?;
    epic_owner_impl::estimate_send_tx_for_altbase(
        &mut **wallet_inst,
        mask,
        amount,
        1,
        500,
        1,
        false,
    )
}

fn build_wallet(data_dir: &Path, node_url: &str) -> Result<(EpicWallet, WalletConfig), String> {
    let config = WalletConfig {
        chain_type: Some(ChainTypes::Mainnet),
        data_file_dir: data_dir
            .to_str()
            .ok_or_else(|| "Epic data directory is not valid UTF-8".to_string())?
            .to_string(),
        check_node_api_http_addr: node_url.to_string(),
        node_api_secret_path: None,
        ..Default::default()
    };

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

type OpenEpicWallet = (
    Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    Option<EpicSecretKey>,
    EpicWallet,
    String,
);

type PreparedEpicSend = (
    Owner<EpicLc, HTTPNodeClient, ExtKeychain>,
    Option<EpicSecretKey>,
    EpicWallet,
    Slate,
    u64,
);

fn open_wallet(req: &EpicRequest) -> Result<OpenEpicWallet, String> {
    let mnemonic = req
        .phrase
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "Epic wallet phrase is required".to_string())?;
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

    let seed_file = data_dir.join("wallet_data").join(wallet_seed_file_name());
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
    #[cfg(feature = "listener")]
    start_epicbox_listener(scope.clone(), wallet.clone(), mask.clone());
    #[cfg(feature = "transport-client")]
    {
        let _ = transport_request(transport_wallet_payload(req, "listen"));
    }

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

    let client = match HTTPNodeClient::new(node_url, None) {
        Ok(client) => client,
        Err(_) => return timestamps,
    };
    let Ok(payload) = client.headers_by_height(&missing_heights) else {
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

fn prepare_send(req: &EpicRequest) -> Result<PreparedEpicSend, String> {
    let (owner, mask, wallet, _scope) = open_wallet(req)?;
    let mask_ref = mask.as_ref();
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
            let (_estimated_total, estimated_fee) =
                estimate_send_tx_direct(&wallet, mask_ref, candidate)
                .map_err(|e| format!("Epic max fee estimate: {e}"))?;
            if estimated_fee == fee {
                amount = candidate;
                break;
            }
            fee = estimated_fee;
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

    let slate = init_send_tx_direct(&wallet, mask_ref, args)
        .map_err(|e| format!("Epic transaction create: {e}"))?;

    Ok((owner, mask, wallet, slate, amount))
}

fn send(req: &EpicRequest) -> Result<String, String> {
    let (owner, mask, wallet, slate, amount) = prepare_send(req)?;
    let mask_ref = mask.as_ref();
    let to = req
        .to
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "Destination address is required".to_string())?;
    let send_result = EpicboxChannel::new(&to.to_string(), Some(EpicboxConfig::default()))
        .and_then(|channel| {
            channel.send(
                wallet,
                mask.clone(),
                &slate,
                Arc::new(AtomicBool::new(true)),
                TorConfig::default(),
            )
        });
    let slate = match send_result {
        Ok(slate) => slate,
        Err(error) => {
            let send_error = sanitize_epicbox_error(&error.to_string());
            match owner.cancel_tx(mask_ref, None, Some(slate.id)) {
                Ok(()) | Err(EpicWalletError::TransactionDoesntExist(_)) => {}
                Err(cancel_error) => {
                    return Err(format!(
                        "Epicbox send: {send_error} Local transaction rollback failed: {cancel_error}"
                    ));
                }
            }
            return Err(format!("Epicbox send: {send_error}"));
        }
    };

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

#[cfg(feature = "transport-client")]
fn send_with_transport(req: &EpicRequest) -> Result<String, String> {
    let (owner, mask, _wallet, slate, amount) = prepare_send(req)?;
    let mask_ref = mask.as_ref();
    let to = req
        .to
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "Destination address is required".to_string())?;
    let address = address_for(&owner, mask_ref)?;
    let slate_value = serde_json::to_value(&slate)
        .map_err(|e| format!("Epic slate serialize: {e}"))?;
    let rollback = |message: String| -> Result<String, String> {
        match owner.cancel_tx(mask_ref, None, Some(slate.id)) {
            Ok(()) | Err(EpicWalletError::TransactionDoesntExist(_)) => Err(message),
            Err(cancel_error) => Err(format!(
                "{message} Local transaction rollback failed: {cancel_error}"
            )),
        }
    };

    if let Err(error) = owner.tx_lock_outputs(mask_ref, &slate, 0, Some(to.to_string())) {
        return rollback(format!("Epic transaction lock: {error}"));
    }

    let response = match transport_request(transport_publish_payload(
        req,
        &address,
        to,
        slate_value,
    )) {
        Ok(response) => response,
        Err(error) => return rollback(format!("Epicbox send: {error}")),
    };
    if !response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        let message = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Epic transport publish failed")
            .to_string();
        return rollback(format!("Epicbox send: {message}"));
    }

    let pending = response
        .get("code")
        .and_then(Value::as_str)
        .map(|code| code == "epic-native-epicbox-pending")
        .unwrap_or(false);
    Ok(ok(json!({
        "code": if pending { "epic-native-epicbox-pending" } else { "epic-native-epicbox-sent" },
        "address": address,
        "txid": slate.id.to_string(),
        "amount": amount_to_hr_string(amount, true),
        "fee": amount_to_hr_string(slate.fee, true),
        "pending": pending,
        "balance": "0",
        "spendable": "0",
        "transactions": [],
    })))
}

#[cfg(feature = "transport-server")]
fn deserialize_transport_slate(value: Value) -> Result<Slate, String> {
    let encoded = serde_json::to_string(&value)
        .map_err(|e| format!("Epic slate serialize for transport: {e}"))?;
    Slate::deserialize_upgrade(&encoded).map_err(|e| format!("Epic slate deserialize: {e}"))
}

#[cfg(feature = "transport-server")]
fn epicbox_publish_is_pending(error: &str) -> bool {
    error.contains("was published") || error.contains("publish outcome is uncertain")
}

#[cfg(feature = "transport-server")]
fn publish_with_listener(req: &EpicRequest) -> Result<String, String> {
    let from = req
        .address
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Epic sender address is required".to_string())?;
    let to = req
        .to
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Epic destination address is required".to_string())?;
    let slate = req
        .slate
        .clone()
        .ok_or_else(|| "Epic slate is required".to_string())
        .and_then(deserialize_transport_slate)?;
    const LISTENER_START_ATTEMPTS: usize = 3;
    for attempt in 0..LISTENER_START_ATTEMPTS {
        let _ = open_wallet(req).map_err(|e| format!("Epicbox listener start: {e}"))?;
        let listener =
            EpicboxListenChannel::new().map_err(|e| format!("Epicbox listener: {e}"))?;
        match listener.send_via_listener(from, to, &slate) {
            Ok(finalized) => {
                return Ok(ok(json!({
                    "code": "epic-native-epicbox-sent",
                    "txid": finalized.id.to_string(),
                    "fee": amount_to_hr_string(finalized.fee, true),
                })));
            }
            Err(error) if epicbox_publish_is_pending(&error.to_string()) => {
                return Ok(ok(json!({
                    "code": "epic-native-epicbox-pending",
                    "txid": slate.id.to_string(),
                })));
            }
            Err(error)
                if error.to_string().contains("Epicbox listener is not ready")
                    && attempt + 1 < LISTENER_START_ATTEMPTS =>
            {
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(error) => return Err(format!("Epicbox publish: {error}")),
        }
    }
    Err("Epicbox publish: listener did not become ready".to_string())
}

#[cfg(all(feature = "send-prepare", not(feature = "send")))]
fn send_prepare_probe(req: &EpicRequest) -> Result<String, String> {
    let (owner, mask, _wallet, slate, amount) = prepare_send(req)?;
    Ok(ok(json!({
        "code": "epic-native-send-prepared",
        "address": address_for(&owner, mask.as_ref())?,
        "txid": slate.id.to_string(),
        "amount": amount_to_hr_string(amount, true),
    })))
}

#[cfg(all(feature = "send-publish", not(feature = "send")))]
fn send_publish_probe(req: &EpicRequest) -> Result<String, String> {
    let (_owner, mask, wallet, _scope) = open_wallet(req)?;
    let to = req
        .to
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "Destination address is required".to_string())?;
    let slate = Slate::blank(2);
    EpicboxChannel::new(&to.to_string(), Some(EpicboxConfig::default()))
        .and_then(|channel| {
            channel.send(
                wallet,
                mask,
                &slate,
                Arc::new(AtomicBool::new(true)),
                TorConfig::default(),
            )
        })
        .map(|sent| ok(json!({ "code": "epic-native-send-published", "txid": sent.id.to_string() })))
        .map_err(|e| format!("Epicbox send: {e}"))
}

fn handle(input: &str) -> String {
    let req: EpicRequest = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(e) => return err("epic-native-bad-request", e),
    };

    match req.action.as_str() {
        "ensure" => ensure(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        #[cfg(feature = "snapshot")]
        "snapshot" => snapshot(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        #[cfg(feature = "send")]
        "send" => send(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        #[cfg(feature = "transport-client")]
        "send" => send_with_transport(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        #[cfg(all(feature = "send-prepare", not(feature = "send"), not(feature = "transport-client")))]
        "send" => send_prepare_probe(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        #[cfg(all(feature = "send-publish", not(feature = "send"), not(feature = "send-prepare")))]
        "send" => send_publish_probe(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        #[cfg(feature = "transport-server")]
        "listen" => ensure(&req).unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        #[cfg(feature = "transport-server")]
        "publish" => publish_with_listener(&req)
            .unwrap_or_else(|e| err("epic-native-wallet-error", e)),
        _ => err("epic-native-bad-action", "Unsupported Epic action"),
    }
}

unsafe fn request_ffi(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return c_string(err("epic-native-null-request", "request pointer is null"));
    }
    let input = unsafe { CStr::from_ptr(input) };
    match input.to_str() {
        Ok(text) => c_string(handle(text)),
        Err(e) => c_string(err("epic-native-utf8-request", e)),
    }
}

unsafe fn free_ffi(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

#[cfg(not(any(feature = "transport-server", feature = "state-server", feature = "sender-server")))]
#[no_mangle]
/// # Safety
/// `input` must be null or point to a valid, NUL-terminated UTF-8 request for the duration of this call.
pub unsafe extern "C" fn altbase_epic_request(input: *const c_char) -> *mut c_char {
    unsafe { request_ffi(input) }
}

#[cfg(not(any(feature = "transport-server", feature = "state-server", feature = "sender-server")))]
#[no_mangle]
/// # Safety
/// `ptr` must be null or a pointer returned by `altbase_epic_request` that has not already been freed.
pub unsafe extern "C" fn altbase_epic_free(ptr: *mut c_char) {
    unsafe { free_ffi(ptr) }
}

#[cfg(feature = "transport-server")]
#[no_mangle]
/// # Safety
/// `input` must be null or point to a valid, NUL-terminated UTF-8 transport request.
pub unsafe extern "C" fn altbase_epic_transport_request(input: *const c_char) -> *mut c_char {
    unsafe { request_ffi(input) }
}

#[cfg(feature = "transport-server")]
#[no_mangle]
/// # Safety
/// `ptr` must be null or a pointer returned by `altbase_epic_transport_request`.
pub unsafe extern "C" fn altbase_epic_transport_free(ptr: *mut c_char) {
    unsafe { free_ffi(ptr) }
}

#[cfg(feature = "state-server")]
#[no_mangle]
/// # Safety
/// `input` must be null or point to a valid, NUL-terminated UTF-8 state request.
pub unsafe extern "C" fn altbase_epic_state_request(input: *const c_char) -> *mut c_char {
    unsafe { request_ffi(input) }
}

#[cfg(feature = "state-server")]
#[no_mangle]
/// # Safety
/// `ptr` must be null or a pointer returned by `altbase_epic_state_request`.
pub unsafe extern "C" fn altbase_epic_state_free(ptr: *mut c_char) {
    unsafe { free_ffi(ptr) }
}

#[cfg(feature = "sender-server")]
#[no_mangle]
/// # Safety
/// `input` must be null or point to a valid, NUL-terminated UTF-8 sender request.
pub unsafe extern "C" fn altbase_epic_sender_request(input: *const c_char) -> *mut c_char {
    unsafe { request_ffi(input) }
}

#[cfg(feature = "sender-server")]
#[no_mangle]
/// # Safety
/// `ptr` must be null or a pointer returned by `altbase_epic_sender_request`.
pub unsafe extern "C" fn altbase_epic_sender_free(ptr: *mut c_char) {
    unsafe { free_ffi(ptr) }
}

#[cfg(all(test, feature = "transport-server"))]
mod tests {
    use super::*;

    #[test]
    fn transport_accepts_versioned_slate_with_plain_kernel() {
        let mut slate = Slate::blank(2);
        slate.fee = 10_000_000;
        slate.update_kernel();

        let wire_value = serde_json::to_value(&slate).expect("serialize slate for transport");
        let decoded = deserialize_transport_slate(wire_value).expect("deserialize transport slate");

        assert_eq!(decoded.id, slate.id);
        assert_eq!(decoded.fee, slate.fee);
        assert_eq!(decoded.tx.body.kernels.len(), 1);
    }

    #[test]
    fn transport_publish_payload_carries_wallet_context() {
        let req: EpicRequest = serde_json::from_value(json!({
            "action": "send",
            "phrase": "test phrase",
            "password": "test password",
            "dataDir": "test-wallet",
            "nodeUrl": "https://node.example",
            "restoreStartHeight": 123,
        }))
        .expect("parse transport request");
        let payload = transport_publish_payload(
            &req,
            "sender@epicbox.epiccash.com",
            "receiver@epicbox.epiccash.com",
            json!({ "id": "test-slate" }),
        );

        assert_eq!(payload["action"], "publish");
        assert_eq!(payload["phrase"], "test phrase");
        assert_eq!(payload["password"], "test password");
        assert_eq!(payload["dataDir"], "test-wallet");
        assert_eq!(payload["nodeUrl"], "https://node.example");
        assert_eq!(payload["restoreStartHeight"], 123);
        assert_eq!(payload["address"], "sender@epicbox.epiccash.com");
        assert_eq!(payload["to"], "receiver@epicbox.epiccash.com");
        assert_eq!(payload["slate"]["id"], "test-slate");
    }

    #[test]
    fn transport_keeps_ambiguous_published_slate_pending() {
        assert!(epicbox_publish_is_pending(
            "Epicbox transaction 1 was published and is awaiting finalization"
        ));
        assert!(epicbox_publish_is_pending(
            "Epicbox transaction 1 publish outcome is uncertain: connection reset"
        ));
        assert!(!epicbox_publish_is_pending("Epicbox listener is not ready"));
        assert!(!epicbox_publish_is_pending("Epic slate deserialize failed"));
    }
}
