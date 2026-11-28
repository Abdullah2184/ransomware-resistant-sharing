mod car;
mod gateway_client;

use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use application::{
    AuthConfig, AuthService, DownloadConfig, DownloadService, ShareConfig, ShareError,
    ShareService, UploadConfig, UploadError, UploadService,
};
use crypto::DEFAULT_CHUNK_SIZE_BYTES;
use domain::{EvmAddress, FileId, FolderId, KeyVersion, MemberId, ProposalId, VersionNumber};
use gateway_client::{GatewayHttpClient, encode_hex, parse_hex_20, parse_hex_32};
use key_custody::{CustodyStartupPolicy, DevelopmentKeyCustody, verify_provider_policy};
use ports::{KeyCustodyProvider, LedgerPort, SystemClock};
use scanner::DisabledScanner;
use zeroize::Zeroizing;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

const DEFAULT_GATEWAY_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_CHAIN_ID: u64 = 1337;
const DEFAULT_AUDIENCE: &str = "rrds-local";
const DEFAULT_MIN_PIN_REPLICAS: usize = 2;
const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_OPERATION_TTL_SECONDS: u64 = 120;

#[tokio::main]
async fn main() -> ExitCode {
    match run(env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rrds: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        print_help();
        return Err("a command is required".into());
    };
    match command.as_str() {
        "--help" | "-h" | "help" => {
            print_help();
            Ok(())
        }
        "health" => cmd_health(rest).await,
        "login" => cmd_login(rest).await,
        "logout" => cmd_logout(rest).await,
        "whoami" => cmd_whoami(rest).await,
        "identity" => cmd_identity(rest).await,
        "ls" => cmd_ls(rest).await,
        "history" => cmd_history(rest).await,
        "upload" => cmd_upload(rest).await,
        "modify" => cmd_modify(rest).await,
        "download" => cmd_download(rest).await,
        "share" => cmd_share(rest).await,
        "restore" => cmd_restore(rest).await,
        "audit" => cmd_audit(rest).await,
        other => Err(format!("unknown command `{other}`; run `rrds --help`")),
    }
}

struct CliEnvConfig {
    gateway_url: String,
    allow_insecure_http: bool,
    chain_id: u64,
    access_governance: Option<EvmAddress>,
    file_registry: Option<EvmAddress>,
    audience: String,
    min_pin_replicas: usize,
    session_file: Option<PathBuf>,
}

impl CliEnvConfig {
    fn from_env() -> Result<Self, String> {
        let gateway_url =
            env::var("GATEWAY_URL").unwrap_or_else(|_| DEFAULT_GATEWAY_URL.to_owned());
        let allow_insecure_http = env::var("RRDS_ALLOW_INSECURE_HTTP")
            .map(|v| v == "true")
            .unwrap_or(false);
        let chain_id = env::var("BESU_CHAIN_ID")
            .ok()
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| "BESU_CHAIN_ID must be an integer".to_owned())
            })
            .transpose()?
            .unwrap_or(DEFAULT_CHAIN_ID);
        if chain_id == 0 {
            return Err("BESU_CHAIN_ID must be a positive integer".into());
        }
        let access_governance = env::var("CONTRACT_ACCESS_GOVERNANCE_ADDRESS")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| {
                parse_hex_20(&v)
                    .map(EvmAddress::from_bytes)
                    .map_err(|_| "CONTRACT_ACCESS_GOVERNANCE_ADDRESS is invalid".to_owned())
            })
            .transpose()?;
        let file_registry = env::var("CONTRACT_FILE_REGISTRY_ADDRESS")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| {
                parse_hex_20(&v)
                    .map(EvmAddress::from_bytes)
                    .map_err(|_| "CONTRACT_FILE_REGISTRY_ADDRESS is invalid".to_owned())
            })
            .transpose()?;
        let audience = env::var("GATEWAY_AUDIENCE").unwrap_or_else(|_| DEFAULT_AUDIENCE.to_owned());
        let min_pin_replicas = env::var("MIN_PIN_REPLICAS")
            .ok()
            .map(|v| {
                v.parse::<usize>()
                    .map_err(|_| "MIN_PIN_REPLICAS must be a positive integer".to_owned())
            })
            .transpose()?
            .unwrap_or(DEFAULT_MIN_PIN_REPLICAS);
        if min_pin_replicas == 0 {
            return Err("MIN_PIN_REPLICAS must be a positive integer".into());
        }
        let scanner_mode = env::var("RRDS_SCANNER_MODE").unwrap_or_else(|_| "disabled".to_owned());
        if !scanner_mode.eq_ignore_ascii_case("disabled") {
            return Err(format!(
                "RRDS_SCANNER_MODE `{scanner_mode}` requires an active scanner adapter (only `disabled` is available in the MVP)"
            ));
        }
        let session_file = env::var("RRDS_SESSION_FILE")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        Ok(Self {
            gateway_url,
            allow_insecure_http,
            chain_id,
            access_governance,
            file_registry,
            audience,
            min_pin_replicas,
            session_file,
        })
    }

    fn gateway_client(&self) -> Result<GatewayHttpClient, String> {
        GatewayHttpClient::new_with_insecure_http_opt_in(
            &self.gateway_url,
            self.allow_insecure_http,
        )
    }

    fn require_access_governance(&self) -> Result<EvmAddress, String> {
        self.access_governance
            .ok_or_else(|| "CONTRACT_ACCESS_GOVERNANCE_ADDRESS must be set".to_owned())
    }

    fn require_file_registry(&self) -> Result<EvmAddress, String> {
        self.file_registry
            .ok_or_else(|| "CONTRACT_FILE_REGISTRY_ADDRESS must be set".to_owned())
    }
}

async fn load_custody_from_env() -> Result<DevelopmentKeyCustody, String> {
    let allow_unsafe = env::var("RRDS_ALLOW_UNSAFE_DEV_CUSTODY")
        .map(|v| v == "true")
        .unwrap_or(false);
    let policy = if allow_unsafe {
        CustodyStartupPolicy::UnsafeDevelopment
    } else {
        CustodyStartupPolicy::Production
    };
    let member_raw = env::var("RRDS_DEV_MEMBER_ID")
        .map_err(|_| "no hardware key-custody provider configured (for local dev only, set RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true and RRDS_DEV_* keys)".to_owned())?;
    let sign_raw =
        Zeroizing::new(env::var("RRDS_DEV_SIGNING_KEY").map_err(|_| {
            "RRDS_DEV_SIGNING_KEY must be set in unsafe dev custody mode".to_owned()
        })?);
    let enc_raw = Zeroizing::new(env::var("RRDS_DEV_ENCRYPTION_SEED").map_err(|_| {
        "RRDS_DEV_ENCRYPTION_SEED must be set in unsafe dev custody mode".to_owned()
    })?);
    let sign_ver = env::var("RRDS_DEV_SIGNING_KEY_VERSION")
        .ok()
        .map(|v| v.parse::<u32>())
        .transpose()
        .map_err(|_| "RRDS_DEV_SIGNING_KEY_VERSION must be a positive integer".to_owned())?
        .unwrap_or(1);
    let enc_ver = env::var("RRDS_DEV_ENCRYPTION_KEY_VERSION")
        .ok()
        .map(|v| v.parse::<u32>())
        .transpose()
        .map_err(|_| "RRDS_DEV_ENCRYPTION_KEY_VERSION must be a positive integer".to_owned())?
        .unwrap_or(1);

    let member_id = MemberId::from_bytes(
        parse_hex_32(&member_raw).map_err(|_| "RRDS_DEV_MEMBER_ID must be 32-byte hex")?,
    );
    let signing_secret = Zeroizing::new(
        parse_hex_32(&sign_raw).map_err(|_| "RRDS_DEV_SIGNING_KEY must be 32-byte hex")?,
    );
    let encryption_seed = Zeroizing::new(
        parse_hex_32(&enc_raw).map_err(|_| "RRDS_DEV_ENCRYPTION_SEED must be 32-byte hex")?,
    );
    let provider = DevelopmentKeyCustody::from_dev_secrets(
        member_id,
        KeyVersion::new(sign_ver).map_err(|e| e.to_string())?,
        KeyVersion::new(enc_ver).map_err(|e| e.to_string())?,
        *signing_secret,
        *encryption_seed,
    )
    .map_err(|e| e.to_string())?;
    verify_provider_policy(&provider, policy)
        .await
        .map_err(|e| e.to_string())?;
    Ok(provider)
}

fn load_bearer_token(config: &CliEnvConfig) -> Result<String, String> {
    if let Ok(token) = env::var("RRDS_SESSION_TOKEN")
        && !token.is_empty()
    {
        return Ok(token);
    }
    if let Some(path) = &config.session_file {
        let content = fs::read_to_string(path)
            .map_err(|_| format!("could not read session file {}", path.display()))?;
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
    Err("not authenticated: run `rrds login` or set RRDS_SESSION_TOKEN / RRDS_SESSION_FILE".into())
}

fn write_session_file(path: &Path, token: &str) -> Result<(), String> {
    write_file_atomic_restricted(path, format!("{token}\n").as_bytes())
        .map_err(|_| format!("could not write session file {}", path.display()))
}

/// Validates that `path` is a regular file (rejecting symlinks, directories,
/// and special files) and reads at most `max_bytes` into a zeroizing buffer
/// (`TECHNICAL_SPECIFICATION.md` §9.2 #1).
fn read_regular_file_bounded(path: &Path, max_bytes: u64) -> Result<Zeroizing<Vec<u8>>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| format!("could not inspect input file `{}`", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!(
            "input path `{}` must be a regular file (symlinks and directories are rejected)",
            path.display()
        ));
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "input file `{}` exceeds maximum allowed size ({max_bytes} bytes)",
            path.display()
        ));
    }
    let file = fs::File::open(path)
        .map_err(|_| format!("could not open input file `{}`", path.display()))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(0),
    ));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| format!("could not read input file `{}`", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "input file `{}` exceeds maximum allowed size ({max_bytes} bytes)",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Writes `bytes` to a `0600` temporary file in the destination's directory,
/// calls `sync_all()` (`fsync`), and atomically renames it into `path`
/// (`TECHNICAL_SPECIFICATION.md` §9.3 #7).
fn write_file_atomic_restricted(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid output path `{}`", path.display()))?;
    let seq = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(
        ".{file_name}.rrds.tmp.{}.{seq}",
        std::process::id()
    ));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let write_result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result.map_err(|_| format!("could not atomically write `{}`", path.display()))
}

fn build_upload_service<K: KeyCustodyProvider>(
    custody: K,
    gateway: GatewayHttpClient,
    config: &CliEnvConfig,
    file_registry: EvmAddress,
) -> UploadService<K, GatewayHttpClient, GatewayHttpClient, SystemClock> {
    UploadService::new(
        custody,
        gateway.clone(),
        gateway,
        SystemClock,
        UploadConfig {
            chain_id: config.chain_id,
            file_registry,
            min_pin_replicas: config.min_pin_replicas,
            chunk_size_bytes: DEFAULT_CHUNK_SIZE_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            operation_ttl_seconds: DEFAULT_OPERATION_TTL_SECONDS,
        },
    )
    .with_scanner(Arc::new(DisabledScanner))
}

async fn cmd_logout(args: &[String]) -> Result<(), String> {
    let config = CliEnvConfig::from_env()?;
    let mut session_file = config.session_file.clone();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--session-file" => {
                let value = args
                    .get(index + 1)
                    .ok_or("usage: rrds logout [--session-file <path>]")?;
                session_file = Some(PathBuf::from(value));
                index += 2;
            }
            _ => return Err("usage: rrds logout [--session-file <path>]".into()),
        }
    }
    let effective_config = CliEnvConfig {
        session_file: session_file.clone(),
        ..config
    };
    let gateway = effective_config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&effective_config)?);
    gateway.logout().await.map_err(|e| e.to_string())?;
    if let Some(path) = &session_file
        && path.exists()
    {
        fs::remove_file(path)
            .map_err(|_| format!("session revoked, but could not remove {}", path.display()))?;
    }
    println!("session revoked");
    Ok(())
}

async fn cmd_health(args: &[String]) -> Result<(), String> {
    let allow_insecure_http = env::var("RRDS_ALLOW_INSECURE_HTTP")
        .map(|v| v == "true")
        .unwrap_or(false);
    let base_url = match args {
        [] => env::var("GATEWAY_URL").unwrap_or_else(|_| DEFAULT_GATEWAY_URL.into()),
        [url] => url.clone(),
        _ => return Err("usage: rrds health [gateway-url]".into()),
    };
    let client = GatewayHttpClient::new_with_insecure_http_opt_in(&base_url, allow_insecure_http)?;
    let status = client.check_health().await?;
    if status.is_success() {
        println!("gateway healthy ({status})");
        Ok(())
    } else {
        Err(format!("gateway health check returned {status}"))
    }
}

async fn cmd_login(args: &[String]) -> Result<(), String> {
    let config = CliEnvConfig::from_env()?;
    let mut session_file = config.session_file.clone();
    let mut print_token = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--session-file" => {
                let value = args
                    .get(index + 1)
                    .ok_or("usage: rrds login [--session-file <path>] [--print-token]")?;
                session_file = Some(PathBuf::from(value));
                index += 2;
            }
            "--print-token" => {
                print_token = true;
                index += 1;
            }
            _ => return Err("usage: rrds login [--session-file <path>] [--print-token]".into()),
        }
    }
    if session_file.is_none() && !print_token {
        return Err(
            "pass --session-file <path> (or set RRDS_SESSION_FILE) to save the session token with mode 0600, or pass --print-token to explicitly print it to stdout"
                .into(),
        );
    }
    let access_governance = config.require_access_governance()?;
    let custody = load_custody_from_env().await?;
    let gateway = config.gateway_client()?;
    let auth = AuthService::new(
        custody,
        gateway,
        SystemClock,
        AuthConfig {
            chain_id: config.chain_id,
            access_governance,
            expected_audience: config.audience,
            max_challenge_ttl_seconds: 300,
        },
    );
    let session = auth.login().await.map_err(|e| e.to_string())?;
    println!(
        "authenticated member={} expiresAt={}",
        session.member_id, session.expires_at
    );
    if let Some(path) = session_file {
        write_session_file(&path, session.bearer_token())?;
        println!("session saved to {} (mode 0600)", path.display());
    }
    if print_token {
        println!("sessionToken={}", session.bearer_token());
    }
    Ok(())
}

async fn cmd_whoami(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("usage: rrds whoami".into());
    }
    let config = CliEnvConfig::from_env()?;
    let gateway = config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&config)?);
    let member_id = gateway.whoami().await.map_err(|e| e.to_string())?;
    println!("memberId={member_id}");
    Ok(())
}

async fn cmd_identity(args: &[String]) -> Result<(), String> {
    let [raw_member_id] = args else {
        return Err("usage: rrds identity <member-id>".into());
    };
    let member_id = MemberId::from_bytes(
        parse_hex_32(raw_member_id).map_err(|_| "invalid member ID (expected 0x + 64 hex)")?,
    );
    let config = CliEnvConfig::from_env()?;
    let gateway = config.gateway_client()?;
    let Some(identity) = gateway
        .get_member(member_id)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Err("member not found".into());
    };
    println!("memberId: {}", identity.member_id);
    println!("organizationId: {}", identity.organization_id);
    println!("status: {:?}", identity.status);
    println!(
        "signingAddress: {} (v{})",
        identity.signing_address,
        identity.signing_key_version.get()
    );
    println!(
        "encryptionPublicKey: {} (v{})",
        encode_hex(&identity.encryption_public_key),
        identity.encryption_key_version.get()
    );
    println!("finalizedBlock: {}", identity.finalized_block);
    Ok(())
}

async fn cmd_ls(args: &[String]) -> Result<(), String> {
    let mut folder_id = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--folder" => {
                let raw = args
                    .get(index + 1)
                    .ok_or("usage: rrds ls [--folder <folder-id>]")?;
                folder_id = Some(FolderId::from_bytes(
                    parse_hex_32(raw).map_err(|_| "invalid folder ID")?,
                ));
                index += 2;
            }
            _ => return Err("usage: rrds ls [--folder <folder-id>]".into()),
        }
    }
    let config = CliEnvConfig::from_env()?;
    let gateway = config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&config)?);
    let listing = gateway
        .list_files(folder_id)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "folder={} finalizedBlock={} indexedBlock={:?} authoritative={}",
        listing.folder_id, listing.finalized_block, listing.indexed_block, listing.authoritative
    );
    for folder in listing.folders {
        println!(
            "  [DIR]  {}  {} (block {})",
            folder.folder_id, folder.display_name, folder.updated_block_number
        );
    }
    for file in listing.files {
        println!(
            "  [FILE] {}  {} v{} status={} head={}",
            file.file_id,
            file.display_name,
            file.current_version,
            file.file_status,
            file.current_head_manifest_hash
        );
    }
    Ok(())
}

async fn cmd_history(args: &[String]) -> Result<(), String> {
    let [raw_file_id] = args else {
        return Err("usage: rrds history <file-id>".into());
    };
    let file_id = FileId::from_bytes(parse_hex_32(raw_file_id).map_err(|_| "invalid file ID")?);
    let config = CliEnvConfig::from_env()?;
    let gateway = config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&config)?);
    let history = gateway
        .version_history(file_id)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "fileId={} currentVersion={} headManifest={} finalizedBlock={} indexedBlock={:?}",
        history.file_id,
        history.current_version,
        history.current_head_manifest_hash,
        history.finalized_block,
        history.indexed_block
    );
    for version in history.versions {
        println!(
            "  v{} block={} author={} manifest={} parent={} contentCid={} envCid={} (rev {}) historicalRead={}",
            version.version_number,
            version.block_number,
            version.author_member_id,
            version.manifest_hash,
            version.parent_manifest_hash,
            version.content_cid,
            version.current_envelope_set_cid,
            version.envelope_revision,
            version.historical_read_granted
        );
    }
    Ok(())
}

async fn cmd_upload(args: &[String]) -> Result<(), String> {
    let Some((file_path, rest)) = args.split_first() else {
        return Err(
            "usage: rrds upload <path> --name <display-name> [--folder <id>] [--file-id <id>] [--reader <member-id>]..."
                .into(),
        );
    };
    let mut display_name: Option<String> = None;
    let mut folder_id = FolderId::ROOT;
    let mut file_id: Option<FileId> = None;
    let mut readers: Vec<MemberId> = Vec::new();
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--name" => {
                display_name = Some(
                    rest.get(index + 1)
                        .ok_or("--name requires a value")?
                        .clone(),
                );
                index += 2;
            }
            "--folder" => {
                let raw = rest.get(index + 1).ok_or("--folder requires a value")?;
                folder_id =
                    FolderId::from_bytes(parse_hex_32(raw).map_err(|_| "invalid folder ID")?);
                index += 2;
            }
            "--file-id" => {
                let raw = rest.get(index + 1).ok_or("--file-id requires a value")?;
                file_id = Some(FileId::from_bytes(
                    parse_hex_32(raw).map_err(|_| "invalid file ID")?,
                ));
                index += 2;
            }
            "--reader" => {
                let raw = rest.get(index + 1).ok_or("--reader requires a member ID")?;
                readers.push(MemberId::from_bytes(
                    parse_hex_32(raw).map_err(|_| "invalid reader member ID")?,
                ));
                index += 2;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }
    let display_name = display_name.ok_or("--name <display-name> is required")?;
    let plaintext = read_regular_file_bounded(Path::new(file_path), DEFAULT_MAX_FILE_BYTES)?;
    let config = CliEnvConfig::from_env()?;
    let file_registry = config.require_file_registry()?;
    let custody = load_custody_from_env().await?;
    let gateway = config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&config)?);

    let uploader = build_upload_service(custody, gateway, &config, file_registry);
    let receipt = uploader
        .create_file(file_id, display_name, folder_id, &plaintext, None, &readers)
        .await
        .map_err(format_upload_error)?;
    print_upload_receipt("uploaded", &receipt);
    Ok(())
}

async fn cmd_modify(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: rrds modify <file-id> <path> [--reader <member-id>]...".into());
    }
    let file_id = FileId::from_bytes(parse_hex_32(&args[0]).map_err(|_| "invalid file ID")?);
    let file_path = &args[1];
    let readers = parse_reader_flags(&args[2..])?;
    let plaintext = read_regular_file_bounded(Path::new(file_path), DEFAULT_MAX_FILE_BYTES)?;

    let config = CliEnvConfig::from_env()?;
    let file_registry = config.require_file_registry()?;
    let custody = load_custody_from_env().await?;
    let gateway = config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&config)?);

    let uploader = build_upload_service(custody, gateway, &config, file_registry);
    let receipt = uploader
        .append_version(file_id, None, &plaintext, None, &readers)
        .await
        .map_err(format_upload_error)?;
    print_upload_receipt("modified", &receipt);
    Ok(())
}

async fn cmd_download(args: &[String]) -> Result<(), String> {
    let [raw_file_id, raw_version, output_path] = args else {
        return Err("usage: rrds download <file-id> <version> <output-path>".into());
    };
    let file_id = FileId::from_bytes(parse_hex_32(raw_file_id).map_err(|_| "invalid file ID")?);
    let version_num: u64 = raw_version
        .parse()
        .map_err(|_| "version must be a positive integer")?;
    let version = VersionNumber::new(version_num).map_err(|e| e.to_string())?;

    let config = CliEnvConfig::from_env()?;
    let access_governance = config.require_access_governance()?;
    let custody = load_custody_from_env().await?;
    let gateway = config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&config)?);

    let downloader = DownloadService::new(
        custody,
        gateway.clone(),
        gateway.clone(),
        SystemClock,
        DownloadConfig {
            chain_id: config.chain_id,
            access_governance,
            operation_ttl_seconds: DEFAULT_OPERATION_TTL_SECONDS,
        },
    );
    let access = downloader
        .authorize_version(file_id, version)
        .await
        .map_err(|e| e.to_string())?;
    let expected_manifest_hash = access.manifest_hash;
    let package = gateway
        .fetch_content_package(&access)
        .await
        .map_err(|e| e.to_string())?;
    let decrypted = downloader
        .decrypt_authorized_package(access, Some(expected_manifest_hash), &package)
        .await
        .map_err(|e| e.to_string())?;
    // Plaintext is written atomically via a 0600 fsync'd temp file only after
    // full manifest, CID, and AES-GCM tag verification (§9.3 #7).
    write_file_atomic_restricted(Path::new(output_path), decrypted.plaintext.as_slice())?;
    println!(
        "downloaded fileId={} version={} bytes={} manifestHash={} output={output_path}",
        decrypted.access.file_id,
        decrypted.access.version_number.get(),
        decrypted.plaintext.len(),
        decrypted.manifest_hash
    );
    Ok(())
}

async fn cmd_share(args: &[String]) -> Result<(), String> {
    if args.len() < 3 {
        return Err(
            "usage: rrds share <file-id> <version> <recipient-member-id> [--proposal-id <id>]"
                .into(),
        );
    }
    let file_id = FileId::from_bytes(parse_hex_32(&args[0]).map_err(|_| "invalid file ID")?);
    let version_num: u64 = args[1]
        .parse()
        .map_err(|_| "version must be a positive integer")?;
    let version = VersionNumber::new(version_num).map_err(|e| e.to_string())?;
    let recipient =
        MemberId::from_bytes(parse_hex_32(&args[2]).map_err(|_| "invalid recipient member ID")?);
    let mut proposal_id = ProposalId::from_bytes([0; 32]);
    let mut index = 3;
    while index < args.len() {
        match args[index].as_str() {
            "--proposal-id" => {
                let raw = args
                    .get(index + 1)
                    .ok_or("--proposal-id requires a 32-byte hex value")?;
                proposal_id =
                    ProposalId::from_bytes(parse_hex_32(raw).map_err(|_| "invalid proposal ID")?);
                index += 2;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }

    let config = CliEnvConfig::from_env()?;
    let access_governance = config.require_access_governance()?;
    let custody = Arc::new(load_custody_from_env().await?);
    let gateway = config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&config)?);

    let downloader = DownloadService::new(
        custody.clone(),
        gateway.clone(),
        gateway.clone(),
        SystemClock,
        DownloadConfig {
            chain_id: config.chain_id,
            access_governance,
            operation_ttl_seconds: DEFAULT_OPERATION_TTL_SECONDS,
        },
    );
    let access = downloader
        .authorize_version(file_id, version)
        .await
        .map_err(|e| e.to_string())?;
    let sharer = ShareService::new(
        custody,
        gateway.clone(),
        gateway,
        SystemClock,
        ShareConfig {
            chain_id: config.chain_id,
            access_governance,
            min_pin_replicas: config.min_pin_replicas,
            operation_ttl_seconds: DEFAULT_OPERATION_TTL_SECONDS,
        },
    );
    let receipt = sharer
        .share_version_envelope(&access, recipient, proposal_id)
        .await
        .map_err(format_share_error)?;
    println!(
        "shared fileId={} version={} recipient={} oldEnvelopeCid={} newEnvelopeCid={} revision={} tx={} block={}",
        file_id,
        version.get(),
        recipient,
        receipt.old_envelope_set_cid,
        receipt.new_envelope_set_cid,
        receipt.new_revision,
        encode_hex(&receipt.transaction.transaction_hash),
        receipt.transaction.block_number
    );
    Ok(())
}

async fn cmd_restore(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(
            "usage: rrds restore <file-id> <source-version> [--reader <member-id>]...".into(),
        );
    }
    let file_id = FileId::from_bytes(parse_hex_32(&args[0]).map_err(|_| "invalid file ID")?);
    let source_num: u64 = args[1]
        .parse()
        .map_err(|_| "source version must be a positive integer")?;
    let source_version = VersionNumber::new(source_num).map_err(|e| e.to_string())?;
    let readers = parse_reader_flags(&args[2..])?;

    let config = CliEnvConfig::from_env()?;
    let access_governance = config.require_access_governance()?;
    let file_registry = config.require_file_registry()?;
    let custody = Arc::new(load_custody_from_env().await?);
    let gateway = config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&config)?);

    let downloader = DownloadService::new(
        custody.clone(),
        gateway.clone(),
        gateway.clone(),
        SystemClock,
        DownloadConfig {
            chain_id: config.chain_id,
            access_governance,
            operation_ttl_seconds: DEFAULT_OPERATION_TTL_SECONDS,
        },
    );
    let access = downloader
        .authorize_version(file_id, source_version)
        .await
        .map_err(|e| e.to_string())?;
    let expected_manifest_hash = access.manifest_hash;
    let package = gateway
        .fetch_content_package(&access)
        .await
        .map_err(|e| e.to_string())?;
    let decrypted = downloader
        .decrypt_authorized_package(access, Some(expected_manifest_hash), &package)
        .await
        .map_err(|e| e.to_string())?;

    let uploader = build_upload_service(custody, gateway, &config, file_registry);
    let receipt = uploader
        .restore_version_from(
            file_id,
            source_version,
            None,
            decrypted.plaintext.as_slice(),
            decrypted.private_metadata.as_deref().map(Vec::as_slice),
            &readers,
        )
        .await
        .map_err(format_upload_error)?;
    println!(
        "restored sourceVersion={} -> newVersion={} fileId={} contentCid={} envelopeSetCid={} tx={} block={}",
        source_version.get(),
        receipt.version_number.get(),
        receipt.file_id,
        receipt.content_cid,
        receipt.envelope_set_cid,
        encode_hex(&receipt.transaction.transaction_hash),
        receipt.transaction.block_number
    );
    Ok(())
}

async fn cmd_audit(args: &[String]) -> Result<(), String> {
    let mut action: Option<String> = None;
    let mut limit: Option<u32> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--action" => {
                action = Some(
                    args.get(index + 1)
                        .ok_or("--action requires a value")?
                        .clone(),
                );
                index += 2;
            }
            "--limit" => {
                let raw = args.get(index + 1).ok_or("--limit requires a number")?;
                limit = Some(raw.parse::<u32>().map_err(|_| "--limit must be 1..100")?);
                index += 2;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }
    let config = CliEnvConfig::from_env()?;
    let gateway = config.gateway_client()?;
    gateway.set_bearer_token(load_bearer_token(&config)?);
    let audit = gateway
        .query_audit(action.as_deref(), limit)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "memberId={} finalizedBlock={} count={}",
        audit.member_id,
        audit.finalized_block,
        audit.events.len()
    );
    for event in audit.events {
        println!(
            "  seq={} hash={} record={}",
            event.sequence, event.record_hash, event.record
        );
    }
    Ok(())
}

fn parse_reader_flags(args: &[String]) -> Result<Vec<MemberId>, String> {
    let mut readers = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--reader" => {
                let raw = args.get(index + 1).ok_or("--reader requires a member ID")?;
                readers.push(MemberId::from_bytes(
                    parse_hex_32(raw).map_err(|_| "invalid reader member ID")?,
                ));
                index += 2;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }
    Ok(readers)
}

fn format_upload_error(error: UploadError) -> String {
    match error {
        UploadError::Domain(err) => err.to_string(),
        UploadError::BlockedByScanner { reason } => {
            format!("upload blocked by pre-upload scanner: {reason}")
        }
        UploadError::OrphanedUpload(details) => format!(
            "ledger commit failed ({}) after pinning contentCid={} envelopeSetCid={} (retained as orphan candidates)",
            details.cause, details.content_cid, details.envelope_set_cid
        ),
    }
}

fn format_share_error(error: ShareError) -> String {
    match error {
        ShareError::Domain(err) => err.to_string(),
        ShareError::OrphanedEnvelopeUpload(details) => format!(
            "ledger envelope update failed ({}) after pinning newEnvelopeSetCid={} (retained as orphan candidate)",
            details.cause, details.new_envelope_set_cid
        ),
    }
}

fn print_upload_receipt(verb: &str, receipt: &application::UploadReceipt) {
    println!(
        "{verb} fileId={} version={} manifestHash={} contentCid={} envelopeSetCid={} contentReplicas={} envelopeReplicas={} tx={} block={}",
        receipt.file_id,
        receipt.version_number.get(),
        receipt.manifest_hash,
        receipt.content_cid,
        receipt.envelope_set_cid,
        receipt.content_replication.pinned_peers.len(),
        receipt.envelope_replication.pinned_peers.len(),
        encode_hex(&receipt.transaction.transaction_hash),
        receipt.transaction.block_number
    );
    if let Some(warning) = &receipt.scan_warning {
        eprintln!("rrds: pre-upload scanner warning: {warning}");
    }
}

#[allow(dead_code)]
async fn _ensure_custody_trait_object(_: &dyn KeyCustodyProvider) {}

fn print_help() {
    println!(
        "Usage:
  rrds health [gateway-url]
  rrds login [--session-file <path>] [--print-token]
  rrds logout [--session-file <path>]
  rrds whoami
  rrds identity <member-id>
  rrds ls [--folder <folder-id>]
  rrds history <file-id>
  rrds upload <path> --name <display-name> [--folder <id>] [--file-id <id>] [--reader <member-id>]...
  rrds modify <file-id> <path> [--reader <member-id>]...
  rrds download <file-id> <version> <output-path>
  rrds share <file-id> <version> <recipient-member-id> [--proposal-id <id>]
  rrds restore <file-id> <source-version> [--reader <member-id>]...
  rrds audit [--action <action>] [--limit <1..100>]

Environment:
  GATEWAY_URL                          Gateway base URL (default: {DEFAULT_GATEWAY_URL})
  BESU_CHAIN_ID                        Chain ID (default: {DEFAULT_CHAIN_ID})
  CONTRACT_ACCESS_GOVERNANCE_ADDRESS   Deployed AccessGovernance address
  CONTRACT_FILE_REGISTRY_ADDRESS       Deployed FileRegistry address
  GATEWAY_AUDIENCE                     Expected login challenge audience (default: {DEFAULT_AUDIENCE})
  MIN_PIN_REPLICAS                     Minimum Cluster replicas (default: {DEFAULT_MIN_PIN_REPLICAS})
  RRDS_SESSION_TOKEN / RRDS_SESSION_FILE  Bearer session token or 0600 session file path

Note: Member registration and Read/Write ACL/revocation proposals are executed
through the configured Organization/Emergency/Consortium Safe governance flow."
    );
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use application::EncryptedPackageBytes;
    use crypto::raw_sha256_cid;
    use domain::{FileId, FolderId, KeyVersion, MemberId, ProposalId, VersionNumber};
    use key_custody::DevelopmentKeyCustody;
    use ports::{KeyCustodyProvider, decode_content_package_frame};
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::gateway_client::validate_base_url;

    #[test]
    fn builds_health_url_from_gateway_base_url() {
        let client = GatewayHttpClient::new("http://127.0.0.1:8080/").unwrap();
        assert_eq!(
            client.endpoint_url("/healthz"),
            "http://127.0.0.1:8080/healthz"
        );
    }

    #[test]
    fn rejects_gateway_urls_without_http_scheme_or_host() {
        assert!(validate_base_url("127.0.0.1:8080").is_err());
        assert!(validate_base_url("http://").is_err());
        assert!(validate_base_url("https://").is_err());
        assert!(validate_base_url("http://gateway/?secret=value").is_err());
        assert!(validate_base_url("http://user:password@gateway").is_err());
    }

    #[derive(Clone)]
    struct MockVersionEntry {
        manifest_hash: String,
        content_cid: String,
        envelope_set_cid: String,
        epoch_id: String,
        envelope_revision: u32,
    }

    #[derive(Default)]
    struct MockGatewayState {
        members: HashMap<String, Value>,
        blobs_content: HashMap<String, Vec<u8>>, // cid -> CARv1
        blobs_envelopes: HashMap<String, Vec<u8>>, // cid -> canonical JSON
        heads: HashMap<String, (u64, String)>,
        versions: HashMap<(String, u64), MockVersionEntry>,
        session_token: String,
        session_revoked: bool,
        block: u64,
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> (String, String, Vec<u8>) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let body_start;
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                body_start = pos + 4;
                break;
            }
        }
        let header_str = String::from_utf8_lossy(&buf[..body_start]).to_string();
        let first_line = header_str.lines().next().unwrap();
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap().to_owned();
        let path = parts.next().unwrap().to_owned();
        let content_length = header_str
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|v| v.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        while buf.len() < body_start + content_length {
            let n = stream.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
        }
        (
            method,
            path,
            buf[body_start..body_start + content_length].to_vec(),
        )
    }

    async fn write_http_response(
        stream: &mut tokio::net::TcpStream,
        status: &str,
        content_type: &str,
        body: &[u8],
    ) {
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    }

    #[tokio::test]
    async fn cli_gateway_client_runs_login_upload_download_share_modify_and_restore_end_to_end() {
        let alice_id = MemberId::from_bytes([0x11; 32]);
        let bob_id = MemberId::from_bytes([0x22; 32]);
        let alice_custody = DevelopmentKeyCustody::from_dev_secrets(
            alice_id,
            KeyVersion::new(1).unwrap(),
            KeyVersion::new(1).unwrap(),
            [0x11; 32],
            [0x21; 32],
        )
        .unwrap();
        let bob_custody = DevelopmentKeyCustody::from_dev_secrets(
            bob_id,
            KeyVersion::new(1).unwrap(),
            KeyVersion::new(1).unwrap(),
            [0x12; 32],
            [0x22; 32],
        )
        .unwrap();
        let alice_pub = alice_custody.public_identity().await.unwrap();
        let bob_pub = bob_custody.public_identity().await.unwrap();

        let state = Arc::new(Mutex::new(MockGatewayState {
            session_token: format!("0x{}", "77".repeat(32)),
            block: 10,
            ..Default::default()
        }));
        {
            let mut st = state.lock().unwrap();
            for (member_id, pub_id) in [(alice_id, &alice_pub), (bob_id, &bob_pub)] {
                st.members.insert(
                    member_id.to_string(),
                    json!({
                        "memberId": member_id.to_string(),
                        "organizationId": format!("0x{}", "01".repeat(32)),
                        "signingAddress": pub_id.signing_address.to_string(),
                        "signingKeyVersion": 1,
                        "encryptionKeyVersion": 1,
                        "encryptionPublicKey": encode_hex(&pub_id.encryption_public_key.to_bytes()),
                        "status": "active",
                        "finalizedBlock": 10,
                        "finalizedBlockHash": format!("0x{}", "ab".repeat(32)),
                    }),
                );
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let (method, path, body) = read_http_request(&mut stream).await;
                let (status, content_type, response_bytes): (&str, &str, Vec<u8>) =
                    match (method.as_str(), path.as_str()) {
                        ("GET", "/healthz") => ("200 OK", "text/plain", b"ok".to_vec()),
                        ("POST", "/v1/auth/challenge") => {
                            let req: Value = serde_json::from_slice(&body).unwrap();
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            let resp = json!({
                                "memberId": req["memberId"],
                                "nonce": format!("0x{}", "44".repeat(32)),
                                "issuedAt": now.saturating_sub(1),
                                "expiresAt": now + 120,
                                "audience": "rrds-local",
                                "protocolVersion": 1,
                            });
                            (
                                "200 OK",
                                "application/json",
                                serde_json::to_vec(&resp).unwrap(),
                            )
                        }
                        ("POST", "/v1/auth/session") => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            let mut st = server_state.lock().unwrap();
                            st.session_revoked = false;
                            let token = st.session_token.clone();
                            let resp = json!({
                                "token": token,
                                "tokenType": "Bearer",
                                "expiresAt": now + 900,
                            });
                            (
                                "200 OK",
                                "application/json",
                                serde_json::to_vec(&resp).unwrap(),
                            )
                        }
                        ("DELETE", "/v1/auth/session") => {
                            server_state.lock().unwrap().session_revoked = true;
                            ("204 No Content", "application/json", Vec::new())
                        }
                        ("GET", "/v1/auth/session") => {
                            if server_state.lock().unwrap().session_revoked {
                                (
                                    "401 Unauthorized",
                                    "application/json",
                                    b"{\"error\":\"unauthenticated\"}".to_vec(),
                                )
                            } else {
                                let resp = json!({ "memberId": alice_id.to_string() });
                                (
                                    "200 OK",
                                    "application/json",
                                    serde_json::to_vec(&resp).unwrap(),
                                )
                            }
                        }
                        ("GET", p) if p.starts_with("/v1/identities/") => {
                            let id = p.trim_start_matches("/v1/identities/");
                            let member = server_state.lock().unwrap().members.get(id).cloned();
                            match member {
                                Some(v) => (
                                    "200 OK",
                                    "application/json",
                                    serde_json::to_vec(&v).unwrap(),
                                ),
                                None => (
                                    "404 Not Found",
                                    "application/json",
                                    b"{\"error\":\"not_found\"}".to_vec(),
                                ),
                            }
                        }
                        ("POST", "/v1/blobs/content") => {
                            let pkg = decode_content_package_frame(&body).unwrap();
                            let (manifest, chunks) = pkg.into_parts();
                            let manifest_bytes = manifest.canonical_bytes().unwrap();
                            let mut extracted_chunks = Vec::new();
                            let mut total = manifest_bytes.len() as u64;
                            for chunk in chunks {
                                let idx = chunk.index();
                                let mut data = Vec::new();
                                chunk.into_reader().read_to_end(&mut data).await.unwrap();
                                total += data.len() as u64;
                                extracted_chunks.push((idx, data));
                            }
                            let (cid, car) =
                                crate::car::encode_unixfs_package_to_car(&EncryptedPackageBytes {
                                    manifest_bytes,
                                    chunks: extracted_chunks,
                                });
                            let cid = cid.to_string();
                            server_state
                                .lock()
                                .unwrap()
                                .blobs_content
                                .insert(cid.clone(), car);
                            let resp = json!({
                                "cid": cid,
                                "bytesWritten": total,
                                "requiredReplicas": 2,
                                "pinnedPeers": ["peer-1", "peer-2"],
                            });
                            (
                                "201 Created",
                                "application/json",
                                serde_json::to_vec(&resp).unwrap(),
                            )
                        }
                        ("POST", "/v1/blobs/envelopes") => {
                            let cid = raw_sha256_cid(&body).unwrap().to_string();
                            let len = body.len() as u64;
                            server_state
                                .lock()
                                .unwrap()
                                .blobs_envelopes
                                .insert(cid.clone(), body);
                            let resp = json!({
                                "cid": cid,
                                "bytesWritten": len,
                                "requiredReplicas": 2,
                                "pinnedPeers": ["peer-1", "peer-2"],
                            });
                            (
                                "201 Created",
                                "application/json",
                                serde_json::to_vec(&resp).unwrap(),
                            )
                        }
                        ("POST", "/v1/files") => {
                            let req: Value = serde_json::from_slice(&body).unwrap();
                            let mut st = server_state.lock().unwrap();
                            st.block += 1;
                            let fid = req["fileId"].as_str().unwrap().to_owned();
                            st.heads.insert(
                                fid.clone(),
                                (1, req["manifestHash"].as_str().unwrap().to_owned()),
                            );
                            st.versions.insert(
                                (fid.clone(), 1),
                                MockVersionEntry {
                                    manifest_hash: req["manifestHash"].as_str().unwrap().to_owned(),
                                    content_cid: req["contentCid"].as_str().unwrap().to_owned(),
                                    envelope_set_cid: req["envelopeSetCid"]
                                        .as_str()
                                        .unwrap()
                                        .to_owned(),
                                    epoch_id: req["epochId"].as_str().unwrap().to_owned(),
                                    envelope_revision: 1,
                                },
                            );
                            let resp = json!({
                                "fileId": fid,
                                "versionNumber": 1,
                                "transactionHash": format!("0x{}", "aa".repeat(32)),
                                "blockNumber": st.block,
                                "blockHash": format!("0x{}", "bb".repeat(32)),
                                "gasUsed": 100000,
                            });
                            (
                                "201 Created",
                                "application/json",
                                serde_json::to_vec(&resp).unwrap(),
                            )
                        }
                        ("GET", p) if p.starts_with("/v1/files/") && p.ends_with("/versions") => {
                            let fid = p
                                .trim_start_matches("/v1/files/")
                                .trim_end_matches("/versions");
                            let st = server_state.lock().unwrap();
                            let (ver, head_hash) = st.heads.get(fid).unwrap().clone();
                            let resp = json!({
                                "fileId": fid,
                                "fileStatus": 1,
                                "currentVersion": ver,
                                "currentHeadManifestHash": head_hash,
                                "finalizedBlock": st.block,
                                "finalizedBlockHash": format!("0x{}", "ab".repeat(32)),
                                "indexedBlock": st.block,
                                "indexedBlockHash": format!("0x{}", "ab".repeat(32)),
                                "versions": [],
                            });
                            (
                                "200 OK",
                                "application/json",
                                serde_json::to_vec(&resp).unwrap(),
                            )
                        }
                        ("POST", p) if p.starts_with("/v1/files/") && p.ends_with("/versions") => {
                            let fid = p
                                .trim_start_matches("/v1/files/")
                                .trim_end_matches("/versions")
                                .to_owned();
                            let req: Value = serde_json::from_slice(&body).unwrap();
                            let ver = req["versionNumber"].as_u64().unwrap();
                            let mut st = server_state.lock().unwrap();
                            st.block += 1;
                            st.heads.insert(
                                fid.clone(),
                                (ver, req["manifestHash"].as_str().unwrap().to_owned()),
                            );
                            st.versions.insert(
                                (fid.clone(), ver),
                                MockVersionEntry {
                                    manifest_hash: req["manifestHash"].as_str().unwrap().to_owned(),
                                    content_cid: req["contentCid"].as_str().unwrap().to_owned(),
                                    envelope_set_cid: req["envelopeSetCid"]
                                        .as_str()
                                        .unwrap()
                                        .to_owned(),
                                    epoch_id: req["epochId"].as_str().unwrap().to_owned(),
                                    envelope_revision: 1,
                                },
                            );
                            let resp = json!({
                                "fileId": fid,
                                "versionNumber": ver,
                                "transactionHash": format!("0x{}", "cc".repeat(32)),
                                "blockNumber": st.block,
                                "blockHash": format!("0x{}", "dd".repeat(32)),
                                "gasUsed": 110000,
                            });
                            (
                                "201 Created",
                                "application/json",
                                serde_json::to_vec(&resp).unwrap(),
                            )
                        }
                        ("POST", p) if p.starts_with("/v1/files/") && p.ends_with("/access") => {
                            let trimmed = p
                                .trim_start_matches("/v1/files/")
                                .trim_end_matches("/access");
                            let (fid, ver_str) = trimmed.split_once("/versions/").unwrap();
                            let ver: u64 = ver_str.parse().unwrap();
                            let st = server_state.lock().unwrap();
                            let entry = st.versions.get(&(fid.to_owned(), ver)).unwrap().clone();
                            let resp = json!({
                                "fileId": fid,
                                "versionNumber": ver,
                                "manifestHash": entry.manifest_hash,
                                "contentCid": entry.content_cid,
                                "envelopeSetCid": entry.envelope_set_cid,
                                "epochId": entry.epoch_id,
                                "envelopeRevision": entry.envelope_revision,
                                "finalizedBlock": st.block,
                            });
                            (
                                "200 OK",
                                "application/json",
                                serde_json::to_vec(&resp).unwrap(),
                            )
                        }
                        ("GET", p) if p.starts_with("/v1/files/") && p.ends_with("/content") => {
                            let trimmed = p
                                .trim_start_matches("/v1/files/")
                                .trim_end_matches("/content");
                            let (fid, ver_str) = trimmed.split_once("/versions/").unwrap();
                            let ver: u64 = ver_str.parse().unwrap();
                            let st = server_state.lock().unwrap();
                            let entry = st.versions.get(&(fid.to_owned(), ver)).unwrap();
                            let car = st.blobs_content.get(&entry.content_cid).unwrap().clone();
                            ("200 OK", "application/vnd.ipld.car", car)
                        }
                        ("GET", p) if p.starts_with("/v1/files/") && p.ends_with("/envelope") => {
                            let trimmed = p
                                .trim_start_matches("/v1/files/")
                                .trim_end_matches("/envelope");
                            let (fid, ver_str) = trimmed.split_once("/versions/").unwrap();
                            let ver: u64 = ver_str.parse().unwrap();
                            let st = server_state.lock().unwrap();
                            let entry = st.versions.get(&(fid.to_owned(), ver)).unwrap();
                            let env = st
                                .blobs_envelopes
                                .get(&entry.envelope_set_cid)
                                .unwrap()
                                .clone();
                            ("200 OK", "application/json", env)
                        }
                        ("POST", p) if p.starts_with("/v1/files/") && p.ends_with("/envelopes") => {
                            let trimmed = p
                                .trim_start_matches("/v1/files/")
                                .trim_end_matches("/envelopes");
                            let (fid, ver_str) = trimmed.split_once("/versions/").unwrap();
                            let ver: u64 = ver_str.parse().unwrap();
                            let req: Value = serde_json::from_slice(&body).unwrap();
                            let mut st = server_state.lock().unwrap();
                            st.block += 1;
                            let entry = st.versions.get_mut(&(fid.to_owned(), ver)).unwrap();
                            entry.envelope_set_cid =
                                req["newEnvelopeSetCid"].as_str().unwrap().to_owned();
                            entry.envelope_revision += 1;
                            let resp = json!({
                                "fileId": fid,
                                "versionNumber": ver,
                                "transactionHash": format!("0x{}", "ee".repeat(32)),
                                "blockNumber": st.block,
                                "blockHash": format!("0x{}", "ff".repeat(32)),
                                "gasUsed": 95000,
                            });
                            (
                                "200 OK",
                                "application/json",
                                serde_json::to_vec(&resp).unwrap(),
                            )
                        }
                        other => panic!("unexpected mock gateway request: {other:?}"),
                    };
                write_http_response(&mut stream, status, content_type, &response_bytes).await;
            }
        });

        let base_url = format!("http://{addr}");
        let alice_gw = GatewayHttpClient::new(&base_url).unwrap();
        let access_gov = EvmAddress::from_bytes([0x22; 20]);
        let file_reg = EvmAddress::from_bytes([0x11; 20]);

        // 1. Health + Login via AuthService
        assert!(alice_gw.check_health().await.unwrap().is_success());
        let auth = AuthService::new(
            DevelopmentKeyCustody::from_dev_secrets(
                alice_id,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(1).unwrap(),
                [0x11; 32],
                [0x21; 32],
            )
            .unwrap(),
            alice_gw.clone(),
            SystemClock,
            AuthConfig {
                chain_id: 1337,
                access_governance: access_gov,
                expected_audience: "rrds-local".to_owned(),
                max_challenge_ttl_seconds: 300,
            },
        );
        let session = auth.login().await.unwrap();
        assert_eq!(session.member_id, alice_id);

        // 2. Upload V1 via UploadService over HTTP gateway client
        let alice_upload = UploadService::new(
            DevelopmentKeyCustody::from_dev_secrets(
                alice_id,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(1).unwrap(),
                [0x11; 32],
                [0x21; 32],
            )
            .unwrap(),
            alice_gw.clone(),
            alice_gw.clone(),
            SystemClock,
            UploadConfig {
                chain_id: 1337,
                file_registry: file_reg,
                min_pin_replicas: 2,
                chunk_size_bytes: 64,
                max_file_bytes: 1024 * 1024,
                operation_ttl_seconds: 120,
            },
        );
        let v1_data = b"clean version 1 financial ledger bytes -- verified end to end over HTTP!";
        let file_id = FileId::from_bytes([0x99; 32]);
        let v1 = alice_upload
            .create_file(
                Some(file_id),
                "ledger.txt".to_owned(),
                FolderId::ROOT,
                v1_data,
                None,
                &[],
            )
            .await
            .unwrap();
        assert_eq!(v1.version_number, VersionNumber::ONE);

        // 3. Download & decrypt V1 via DownloadService + CARv1 extractor
        let alice_download = DownloadService::new(
            DevelopmentKeyCustody::from_dev_secrets(
                alice_id,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(1).unwrap(),
                [0x11; 32],
                [0x21; 32],
            )
            .unwrap(),
            alice_gw.clone(),
            alice_gw.clone(),
            SystemClock,
            DownloadConfig {
                chain_id: 1337,
                access_governance: access_gov,
                operation_ttl_seconds: 120,
            },
        );
        let v1_access = alice_download
            .authorize_version(file_id, VersionNumber::ONE)
            .await
            .unwrap();
        let v1_pkg = alice_gw.fetch_content_package(&v1_access).await.unwrap();
        let v1_decrypted = alice_download
            .decrypt_authorized_package(v1_access.clone(), Some(v1.manifest_hash), &v1_pkg)
            .await
            .unwrap();
        assert_eq!(v1_decrypted.plaintext.as_slice(), v1_data);

        // 4. Share V1 to Bob via ShareService (without re-encrypting ciphertext), then Bob decrypts V1!
        let alice_share = ShareService::new(
            DevelopmentKeyCustody::from_dev_secrets(
                alice_id,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(1).unwrap(),
                [0x11; 32],
                [0x21; 32],
            )
            .unwrap(),
            alice_gw.clone(),
            alice_gw.clone(),
            SystemClock,
            ShareConfig {
                chain_id: 1337,
                access_governance: access_gov,
                min_pin_replicas: 2,
                operation_ttl_seconds: 120,
            },
        );
        let share = alice_share
            .share_version_envelope(&v1_access, bob_id, ProposalId::from_bytes([0; 32]))
            .await
            .unwrap();
        assert_eq!(share.new_revision, 2);

        let bob_gw = GatewayHttpClient::new(&base_url).unwrap();
        bob_gw.set_bearer_token(session.bearer_token().to_owned());
        let bob_download = DownloadService::new(
            bob_custody,
            bob_gw.clone(),
            bob_gw.clone(),
            SystemClock,
            DownloadConfig {
                chain_id: 1337,
                access_governance: access_gov,
                operation_ttl_seconds: 120,
            },
        );
        let bob_access = bob_download
            .authorize_version(file_id, VersionNumber::ONE)
            .await
            .unwrap();
        let bob_pkg = bob_gw.fetch_content_package(&bob_access).await.unwrap();
        let bob_decrypted = bob_download
            .decrypt_authorized_package(bob_access, Some(v1.manifest_hash), &bob_pkg)
            .await
            .unwrap();
        assert_eq!(bob_decrypted.plaintext.as_slice(), v1_data);

        // 5. Modify V1 -> corrupted V2, then Restore V1 -> clean V3 (append-only recovery)!
        let v2 = alice_upload
            .append_version(file_id, None, b"RANSOMWARE_CORRUPTED_V2", None, &[bob_id])
            .await
            .unwrap();
        assert_eq!(v2.version_number.get(), 2);

        let v3 = alice_upload
            .restore_version(
                file_id,
                None,
                v1_decrypted.plaintext.as_slice(),
                None,
                &[bob_id],
            )
            .await
            .unwrap();
        assert_eq!(v3.version_number.get(), 3);
        assert_eq!(v3.parent_manifest_hash, v2.manifest_hash);
        let v3_access = alice_download
            .authorize_version(file_id, VersionNumber::new(3).unwrap())
            .await
            .unwrap();
        let v3_pkg = alice_gw.fetch_content_package(&v3_access).await.unwrap();
        let v3_decrypted = alice_download
            .decrypt_authorized_package(v3_access, Some(v3.manifest_hash), &v3_pkg)
            .await
            .unwrap();
        assert_eq!(v3_decrypted.plaintext.as_slice(), v1_data);

        // 6. Session revocation (DELETE /v1/auth/session) clears client token and rejects reuse.
        assert_eq!(alice_gw.whoami().await.unwrap(), alice_id.to_string());
        alice_gw.logout().await.unwrap();
        assert_eq!(
            alice_gw.whoami().await,
            Err(domain::DomainError::Unauthenticated)
        );
        alice_gw.set_bearer_token(session.bearer_token().to_owned());
        assert_eq!(
            alice_gw.whoami().await,
            Err(domain::DomainError::Unauthenticated)
        );

        server.abort();
    }

    #[test]
    fn bounded_regular_file_reader_enforces_size_and_rejects_non_regular_paths() {
        let dir = env::temp_dir().join(format!("rrds-cli-read-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let regular = dir.join("ok.bin");
        fs::write(&regular, b"hello-world").unwrap();

        assert_eq!(
            read_regular_file_bounded(&regular, 11).unwrap().as_slice(),
            b"hello-world"
        );
        assert!(read_regular_file_bounded(&regular, 10).is_err());
        assert!(read_regular_file_bounded(&dir, 1024).is_err());

        #[cfg(unix)]
        {
            let link = dir.join("sym.bin");
            let _ = fs::remove_file(&link);
            std::os::unix::fs::symlink(&regular, &link).unwrap();
            assert!(read_regular_file_bounded(&link, 1024).is_err());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_restricted_writer_sets_0600_and_leaves_no_temp_files() {
        let dir = env::temp_dir().join(format!("rrds-cli-write-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("decrypted.txt");

        write_file_atomic_restricted(&target, b"first-version").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first-version");
        write_file_atomic_restricted(&target, b"second-version").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second-version");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["decrypted.txt".to_owned()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enforces_https_for_non_loopback_gateways_unless_explicitly_opted_in() {
        assert!(validate_base_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_base_url("http://localhost:8080").is_ok());
        assert!(validate_base_url("http://[::1]:8080").is_ok());
        assert!(validate_base_url("https://gateway.consortium.example").is_ok());
        assert!(validate_base_url("http://gateway.consortium.example").is_err());
        assert!(
            gateway_client::validate_base_url_with_policy(
                "http://gateway.consortium.example",
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn maps_gateway_http_error_statuses_and_codes_accurately() {
        use gateway_client::map_http_error;
        use reqwest::StatusCode;

        assert_eq!(
            map_http_error(StatusCode::UNAUTHORIZED, Some("unauthenticated")),
            domain::DomainError::Unauthenticated
        );
        assert_eq!(
            map_http_error(StatusCode::UNAUTHORIZED, Some("member_suspended")),
            domain::DomainError::MemberSuspended
        );
        assert_eq!(
            map_http_error(StatusCode::FORBIDDEN, Some("unauthorized")),
            domain::DomainError::Unauthorized
        );
        assert_eq!(
            map_http_error(StatusCode::NOT_FOUND, None),
            domain::DomainError::ContractRejected
        );
        assert_eq!(
            map_http_error(StatusCode::CONFLICT, Some("stale_head")),
            domain::DomainError::StaleHead
        );
        assert_eq!(
            map_http_error(StatusCode::CONFLICT, Some("replay_detected")),
            domain::DomainError::ReplayDetected
        );
        assert_eq!(
            map_http_error(StatusCode::CONFLICT, Some("expired_request")),
            domain::DomainError::ExpiredRequest
        );
        assert_eq!(
            map_http_error(StatusCode::PAYLOAD_TOO_LARGE, None),
            domain::DomainError::InvalidManifest
        );
        assert_eq!(
            map_http_error(StatusCode::TOO_MANY_REQUESTS, None),
            domain::DomainError::RateLimited
        );
        assert_eq!(
            map_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                Some("replication_insufficient")
            ),
            domain::DomainError::ReplicationInsufficient
        );
        assert_eq!(
            map_http_error(StatusCode::SERVICE_UNAVAILABLE, Some("storage_unavailable")),
            domain::DomainError::StorageUnavailable
        );
        assert_eq!(
            map_http_error(StatusCode::BAD_REQUEST, Some("invalid_signature")),
            domain::DomainError::InvalidSignature
        );
    }

    #[tokio::test]
    async fn gateway_client_refuses_redirects_bounds_responses_and_maps_head_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let (method, path, _) = read_http_request(&mut stream).await;
                match (method.as_str(), path.as_str()) {
                    ("GET", "/v1/auth/session") => {
                        let resp = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        stream.write_all(resp.as_bytes()).await.unwrap();
                    }
                    ("GET", p) if p.contains("1111") && p.ends_with("/versions") => {
                        write_http_response(
                            &mut stream,
                            "404 Not Found",
                            "application/json",
                            br#"{"error":"not_found"}"#,
                        )
                        .await;
                    }
                    ("GET", p) if p.contains("2222") && p.ends_with("/versions") => {
                        let body = serde_json::to_vec(&json!({
                            "fileId": format!("0x{}", "22".repeat(32)),
                            "fileStatus": 2,
                            "currentVersion": 3,
                            "currentHeadManifestHash": format!("0x{}", "aa".repeat(32)),
                            "finalizedBlock": 42,
                            "indexedBlock": 42,
                            "versions": [],
                        }))
                        .unwrap();
                        write_http_response(&mut stream, "200 OK", "application/json", &body).await;
                    }
                    ("POST", p) if p.ends_with("/access") => {
                        let cid = raw_sha256_cid(b"env").unwrap().to_string();
                        let body = serde_json::to_vec(&json!({
                            "fileId": format!("0x{}", "33".repeat(32)),
                            "versionNumber": 1,
                            "manifestHash": format!("0x{}", "bb".repeat(32)),
                            "contentCid": cid,
                            "envelopeSetCid": cid,
                            "epochId": format!("0x{}", "cc".repeat(32)),
                            "envelopeRevision": 1,
                            "finalizedBlock": 10,
                        }))
                        .unwrap();
                        write_http_response(&mut stream, "200 OK", "application/json", &body).await;
                    }
                    ("GET", p) if p.ends_with("/envelope") => {
                        // Oversized > 512 KiB response must be rejected by bounded reader.
                        let huge = vec![b'x'; 600 * 1024];
                        write_http_response(&mut stream, "200 OK", "application/json", &huge).await;
                    }
                    _ => {
                        write_http_response(
                            &mut stream,
                            "404 Not Found",
                            "application/json",
                            br#"{"error":"not_found"}"#,
                        )
                        .await;
                    }
                }
            }
        });

        let client = GatewayHttpClient::new(&format!("http://{addr}")).unwrap();
        client.set_bearer_token("test-bearer-token".to_owned());

        // Redirects are refused (never followed).
        assert!(client.whoami().await.is_err());

        // 404 returns Ok(None) on get_file_head.
        assert_eq!(
            client
                .get_file_head(FileId::from_bytes([0x11; 32]))
                .await
                .unwrap(),
            None
        );

        // Archived fileStatus=2 is decoded faithfully as FileStatus::Archived.
        let head = client
            .get_file_head(FileId::from_bytes([0x22; 32]))
            .await
            .unwrap()
            .expect("archived head");
        assert_eq!(head.status, domain::FileStatus::Archived);
        assert_eq!(head.current_version.get(), 3);

        // Oversized envelope response fails closed with StorageError::SizeLimitExceeded.
        let access = client
            .authorize_read(&ports::SignedAccessLookupRequest {
                member_id: MemberId::from_bytes([1; 32]),
                file_id: FileId::from_bytes([0x33; 32]),
                version_number: VersionNumber::ONE,
                encryption_key_version: KeyVersion::new(1).unwrap(),
                operation_nonce: domain::OperationNonce::from_bytes([2; 32]),
                deadline: 1_900_000_000,
                signature: ports::EvmSignature::from_bytes([0; 65]),
            })
            .await
            .unwrap();
        let env_err = ports::BlobStore::get_envelope_set(&client, &access.envelope_set_cid)
            .await
            .err();
        assert_eq!(env_err, Some(ports::StorageError::SizeLimitExceeded));

        server.abort();
    }

    #[tokio::test]
    async fn cli_command_dispatcher_validates_arguments_and_requires_explicit_login_output() {
        assert!(run(vec![]).await.is_err());
        assert!(run(vec!["unknown-cmd".into()]).await.is_err());
        assert!(run(vec!["--help".into()]).await.is_ok());
        assert!(
            run(vec![
                "download".into(),
                "not-hex".into(),
                "1".into(),
                "out".into()
            ])
            .await
            .is_err()
        );
        assert!(run(vec!["history".into(), "not-hex".into()]).await.is_err());
        assert!(run(vec!["share".into(), "not-hex".into()]).await.is_err());
        // `login` with neither --session-file nor --print-token (and no RRDS_SESSION_FILE) fails closed.
        if env::var("RRDS_SESSION_FILE").is_err() {
            let err = run(vec!["login".into()]).await.unwrap_err();
            assert!(err.contains("--session-file"));
        }
    }
}
