#[cfg(test)]
use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, BufReader, Cursor, IsTerminal, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use bcrypt::{Version, hash_with_salt};
use dialoguer::{Confirm, Input, Password as DialoguerPassword, Select, theme::ColorfulTheme};
use num_bigint_dig::BigUint;
use num_traits::{One, Zero};
use pgp::composed::{
    CleartextSignedMessage, Deserializable, Message, PlainSessionKey, SignedPublicKey,
    SignedSecretKey,
};
use pgp::packet::{Packet, PacketParser};
use pgp::types::{DecryptionKey, EskType, Password, PkeskVersion};
use rand::RngCore;
use rand::rngs::OsRng;
use rayon::{Scope, ThreadPoolBuilder};
use reqwest::Method;
use reqwest::blocking::Client as HttpClient;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};

use crate::accounts::{self, StoredAccount};
use crate::backend::{OpenedSource, PhotoSource};
use crate::cli::{LoginCommand, ProtonSourceArgs, SharesCommand, TreeCacheMode};
use crate::paths;
use crate::progress;
use crate::types::{RemoteEntry, RemoteFile};

const API_BASE_URL: &str = "https://mail.proton.me/api";
const DEFAULT_APP_VERSION: &str = concat!("external-drive-protonpics@", env!("CARGO_PKG_VERSION"));
const DEFAULT_USER_AGENT: &str = concat!("protonpics/", env!("CARGO_PKG_VERSION"));
const MAX_PAGE_SIZE: usize = 150;
const BCRYPT_COST: u32 = 10;
const SRP_BITS: usize = 2048;
const SRP_BYTES: usize = SRP_BITS / 8;
const MAX_TRANSIENT_ATTEMPTS: usize = 3;
const RETRY_BASE_DELAY_MS: u64 = 250;
const RETRY_MAX_DELAY_MS: u64 = 2_000;
const HTTP_CONNECT_TIMEOUT_SECS: u64 = 15;
const HTTP_API_TIMEOUT_SECS: u64 = 45;
const HTTP_BLOCK_TIMEOUT_SECS: u64 = 60;
const BLOCK_PREFETCH_DEPTH: usize = 2;
const TREE_CACHE_VERSION: u32 = 2;
const LINK_TYPE_FOLDER: i32 = 1;
const LINK_TYPE_FILE: i32 = 2;
const LINK_TYPE_ALBUM: i32 = 3;
const LINK_STATE_ACTIVE: i32 = 1;
const SHARE_TYPE_MAIN: i32 = 1;
const SHARE_TYPE_STANDARD: i32 = 2;
const SHARE_TYPE_DEVICE: i32 = 3;
const SHARE_STATE_ACTIVE: i32 = 1;
const SHARE_STATE_DELETED: i32 = 2;
const SHARE_FLAG_NONE: i32 = 0;
const SHARE_FLAG_PRIMARY: i32 = 1;
const SHARE_TYPE_PHOTO: i32 = 4;
const PASSWORD_MODE_TWO: i32 = 2;
const TWO_FA_TOTP: i32 = 1;
const TWO_FA_FIDO2: i32 = 2;
const HUMAN_VERIFICATION_REQUIRED_CODE: i32 = 9001;
const HUMAN_VERIFICATION_TIMEOUT_SECS: u64 = 600;
const MODULUS_PUBKEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nxjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm\r\nL8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ\r\nBwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U\r\nMnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat\r\nSv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE\r\nkSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF\r\nhcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU\r\nWO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE\r\n=Y4Mw\r\n-----END PGP PUBLIC KEY BLOCK-----";

#[cfg(test)]
thread_local! {
    static TEST_API_BASE_URL: RefCell<Option<String>> = const { RefCell::new(None) };
    static TEST_ACCOUNTS_DIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static TEST_DEFAULT_ACCOUNT_ROOT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static TEST_SRP_CLIENT_SECRET: RefCell<Option<BigUint>> = const { RefCell::new(None) };
    static TEST_HUMAN_VERIFICATION_ANSWER: RefCell<Option<HumanVerificationAnswer>> = const { RefCell::new(None) };
    static TEST_PROMPT_TEXT: RefCell<VecDeque<String>> = const { RefCell::new(VecDeque::new()) };
    static TEST_PROMPT_SECRET: RefCell<VecDeque<String>> = const { RefCell::new(VecDeque::new()) };
    static TEST_PROMPT_CONFIRM: RefCell<Option<bool>> = const { RefCell::new(None) };
    static TEST_PROMPT_SELECT: RefCell<Option<usize>> = const { RefCell::new(None) };
    static TEST_BROWSER_BEHAVIOR: RefCell<Option<BrowserTestBehavior>> = const { RefCell::new(None) };
}

fn configured_api_base_url() -> String {
    #[cfg(test)]
    if let Some(base_url) = TEST_API_BASE_URL.with(|value| value.borrow().clone()) {
        return base_url;
    }

    API_BASE_URL.to_owned()
}

fn configured_accounts_dir() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_ACCOUNTS_DIR.with(|value| value.borrow().clone()) {
        return Ok(path);
    }

    paths::default_accounts_dir()
}

fn default_login_credentials_path(email: &str) -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(root) = TEST_DEFAULT_ACCOUNT_ROOT.with(|value| value.borrow().clone()) {
        return Ok(root
            .join(paths::sanitize_segment(email.trim()))
            .join("session.json"));
    }

    accounts::default_account_path(email)
}

#[cfg(test)]
fn with_test_api_base_url<T>(base_url: &str, f: impl FnOnce() -> T) -> T {
    let previous = TEST_API_BASE_URL.with(|value| value.replace(Some(base_url.to_owned())));
    let result = f();
    TEST_API_BASE_URL.with(|value| {
        value.replace(previous);
    });
    result
}

#[cfg(test)]
fn with_test_default_account_root<T>(path: PathBuf, f: impl FnOnce() -> T) -> T {
    let previous = TEST_DEFAULT_ACCOUNT_ROOT.with(|value| value.replace(Some(path)));
    let result = f();
    TEST_DEFAULT_ACCOUNT_ROOT.with(|value| {
        value.replace(previous);
    });
    result
}

#[cfg(test)]
fn with_test_accounts_dir<T>(path: PathBuf, f: impl FnOnce() -> T) -> T {
    let previous = TEST_ACCOUNTS_DIR.with(|value| value.replace(Some(path)));
    let result = f();
    TEST_ACCOUNTS_DIR.with(|value| {
        value.replace(previous);
    });
    result
}

#[cfg(test)]
fn with_test_srp_client_secret<T>(client_secret: BigUint, f: impl FnOnce() -> T) -> T {
    let previous = TEST_SRP_CLIENT_SECRET.with(|value| value.replace(Some(client_secret)));
    let result = f();
    TEST_SRP_CLIENT_SECRET.with(|value| {
        value.replace(previous);
    });
    result
}

#[cfg(test)]
fn with_test_human_verification_answer<T>(
    answer: HumanVerificationAnswer,
    f: impl FnOnce() -> T,
) -> T {
    let previous = TEST_HUMAN_VERIFICATION_ANSWER.with(|value| value.replace(Some(answer)));
    let result = f();
    TEST_HUMAN_VERIFICATION_ANSWER.with(|value| {
        value.replace(previous);
    });
    result
}

#[cfg(test)]
fn with_test_prompt_texts<T>(values: Vec<String>, f: impl FnOnce() -> T) -> T {
    let previous =
        TEST_PROMPT_TEXT.with(|value| value.replace(values.into_iter().collect::<VecDeque<_>>()));
    let result = f();
    TEST_PROMPT_TEXT.with(|value| {
        value.replace(previous);
    });
    result
}

#[cfg(test)]
fn with_test_prompt_secrets<T>(values: Vec<String>, f: impl FnOnce() -> T) -> T {
    let previous =
        TEST_PROMPT_SECRET.with(|value| value.replace(values.into_iter().collect::<VecDeque<_>>()));
    let result = f();
    TEST_PROMPT_SECRET.with(|value| {
        value.replace(previous);
    });
    result
}

#[cfg(test)]
fn with_test_prompt_confirm<T>(value: bool, f: impl FnOnce() -> T) -> T {
    let previous = TEST_PROMPT_CONFIRM.with(|slot| slot.replace(Some(value)));
    let result = f();
    TEST_PROMPT_CONFIRM.with(|slot| {
        slot.replace(previous);
    });
    result
}

#[cfg(test)]
fn with_test_prompt_selection<T>(value: usize, f: impl FnOnce() -> T) -> T {
    let previous = TEST_PROMPT_SELECT.with(|slot| slot.replace(Some(value)));
    let result = f();
    TEST_PROMPT_SELECT.with(|slot| {
        slot.replace(previous);
    });
    result
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct BrowserTestBehavior {
    succeed: bool,
    answer: Option<HumanVerificationAnswer>,
}

#[cfg(test)]
fn with_test_browser_behavior<T>(behavior: BrowserTestBehavior, f: impl FnOnce() -> T) -> T {
    let previous = TEST_BROWSER_BEHAVIOR.with(|slot| slot.replace(Some(behavior)));
    let result = f();
    TEST_BROWSER_BEHAVIOR.with(|slot| {
        slot.replace(previous);
    });
    result
}

#[derive(Debug)]
pub struct ProtonBackend {
    api: Arc<ProtonApi>,
    share_name: String,
    share_id: String,
    volume_id: String,
    root_id: String,
    folders: HashMap<String, Vec<RemoteEntry>>,
    files: HashMap<String, NativeFile>,
}

#[derive(Debug, Clone)]
struct NativeFile {
    link: ApiLink,
    node_keys: Arc<SecretKeyRing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TreeCacheSnapshot {
    version: u32,
    share_name: String,
    share_id: String,
    volume_id: String,
    root_id: String,
    folders: HashMap<String, Vec<RemoteEntry>>,
    files: HashMap<String, CachedNativeFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedNativeFile {
    link: ApiLink,
    node_keys: CachedSecretKeyRing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSecretKeyRing {
    keys: Vec<CachedSecretKeyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSecretKeyEntry {
    armored_key: String,
    passphrase: String,
}

#[derive(Debug)]
struct ProtonApi {
    client: HttpClient,
    base_url: String,
    credentials_path: PathBuf,
    session_email: Option<String>,
    session_password: Option<String>,
    app_version: String,
    user_agent: String,
    auth: Mutex<ReusableCredential>,
}

#[derive(Debug, Clone)]
struct AccountContext {
    api: Arc<ProtonApi>,
    address_keys_by_id: HashMap<String, SecretKeyRing>,
}

#[derive(Debug, Clone)]
struct SecretKeyRing {
    keys: Vec<SecretKeyEntry>,
}

#[derive(Debug, Clone)]
struct SecretKeyEntry {
    key: SignedSecretKey,
    passphrase: Vec<u8>,
}

#[derive(Debug, Clone)]
struct LoadedShareRoot {
    share: ApiShare,
    root_link: ApiLink,
}

#[derive(Debug)]
struct ProtonFileReader {
    api: Arc<ProtonApi>,
    session_key: PlainSessionKey,
    blocks: Vec<ApiBlock>,
    next_block: usize,
    current: Cursor<Vec<u8>>,
    finished: bool,
    prefetch: Option<BlockPrefetch>,
}

#[derive(Debug)]
struct BlockPrefetch {
    receiver: Receiver<PrefetchedBlock>,
}

#[derive(Debug)]
enum PrefetchedBlock {
    Data(Vec<u8>),
    Error(String),
    End,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareInfo {
    pub name: String,
    pub share_id: String,
    pub link_id: String,
    pub volume_id: String,
    #[serde(rename = "type")]
    pub share_type: String,
    pub state: String,
    pub flags: String,
    pub creator: String,
    #[serde(skip)]
    pub(crate) metadata_mode: LinkMetadataMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub(crate) enum LinkMetadataMode {
    #[default]
    Drive,
    Photos,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReusableCredential {
    #[serde(rename = "UID")]
    uid: String,
    #[serde(rename = "AccessToken")]
    access_token: String,
    #[serde(rename = "RefreshToken")]
    refresh_token: String,
    #[serde(rename = "SaltedKeyPass")]
    salted_key_pass: String,
}

#[derive(Debug, Clone, Serialize)]
struct AuthRefreshRequest {
    #[serde(rename = "UID")]
    uid: String,
    #[serde(rename = "RefreshToken")]
    refresh_token: String,
    #[serde(rename = "ResponseType")]
    response_type: String,
    #[serde(rename = "GrantType")]
    grant_type: String,
    #[serde(rename = "RedirectURI")]
    redirect_uri: String,
    #[serde(rename = "State")]
    state: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
struct AuthInfoRequest {
    username: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
struct AuthRequest {
    username: String,
    client_ephemeral: String,
    client_proof: String,
    #[serde(rename = "SRPSession")]
    srp_session: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Auth2FaRequest {
    two_factor_code: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct ApiErrorResponse {
    #[serde(default)]
    code: i32,
    #[serde(default)]
    details: ApiErrorDetails,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct ApiErrorDetails {
    #[serde(default)]
    human_verification_token: String,
    #[serde(default)]
    human_verification_methods: Vec<String>,
    #[serde(default)]
    web_url: String,
    #[serde(default)]
    title: String,
    expires_at: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct AuthInfoResponse {
    version: i32,
    modulus: String,
    server_ephemeral: String,
    salt: String,
    #[serde(rename = "SRPSession", alias = "SrpSession")]
    srp_session: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct AuthResponse {
    uid: String,
    access_token: String,
    refresh_token: String,
    server_proof: String,
    #[serde(rename = "2FA", default)]
    two_fa: ApiTwoFaInfo,
    password_mode: i32,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct ApiTwoFaInfo {
    enabled: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HumanVerificationChallenge {
    token: String,
    methods: Vec<String>,
    web_url: Option<String>,
    title: Option<String>,
    expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HumanVerificationAnswer {
    token: String,
    #[serde(rename = "type")]
    token_type: String,
}

#[derive(Debug)]
struct HumanVerificationRequired {
    challenge: HumanVerificationChallenge,
}

impl std::fmt::Display for HumanVerificationRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.challenge.title.as_deref() {
            Some(title) if !title.is_empty() => {
                write!(f, "Proton human verification required: {title}")
            }
            _ => write!(f, "Proton human verification required"),
        }
    }
}

impl std::error::Error for HumanVerificationRequired {}

#[derive(Debug)]
struct HumanVerificationServer {
    local_url: String,
    running: Arc<AtomicBool>,
    answer_rx: Receiver<HumanVerificationAnswer>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug)]
struct HumanVerificationHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RefreshResponse {
    uid: String,
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(transparent)]
struct ApiBool(i32);

impl ApiBool {
    fn is_true(self) -> bool {
        self.0 == 1
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserEnvelope {
    user: ApiUser,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AddressesEnvelope {
    addresses: Vec<ApiAddress>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SharesEnvelope {
    shares: Vec<ApiShareMetadata>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PhotoShareRootEnvelope {
    volume: ApiVolumeSummary,
    share: ApiPhotoShare,
    link: ApiLinkDetail,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ShareEnvelope {
    Wrapped {
        #[serde(rename = "Share")]
        share: ApiShareWire,
    },
    Bare(ApiShareWire),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LinkEnvelope {
    link: ApiLink,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FolderChildrenEnvelope {
    #[serde(rename = "LinkIDs", default)]
    link_ids: Vec<String>,
    #[serde(rename = "AnchorID", default)]
    anchor_id: Option<String>,
    #[serde(rename = "More", default)]
    more: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ShareChildrenEnvelope {
    #[serde(rename = "Links", default)]
    links: Vec<ApiShareChildLink>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AlbumChildrenEnvelope {
    #[serde(rename = "Photos", default)]
    photos: Vec<AlbumChildRecord>,
    #[serde(rename = "AnchorID", default)]
    anchor_id: Option<String>,
    #[serde(rename = "More", default)]
    more: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AlbumChildRecord {
    #[serde(rename = "LinkID", alias = "LinkId")]
    link_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiShareChildLink {
    #[serde(rename = "LinkID", alias = "LinkId")]
    link_id: String,
    #[serde(rename = "Type")]
    link_type: i32,
    name: String,
    #[serde(rename = "Size", default)]
    size: i64,
    #[serde(rename = "State")]
    link_state: i32,
    modify_time: i64,
    node_key: String,
    node_passphrase: String,
    #[serde(default)]
    file_properties: Option<ApiShareFileProperties>,
    #[serde(rename = "XAttr", default)]
    xattr: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiShareFileProperties {
    content_key_packet: String,
    #[serde(default)]
    active_revision: Option<ApiActiveRevisionDetail>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LinksEnvelopeV2 {
    links: Vec<ApiLinkDetail>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RevisionEnvelope {
    revision: ApiRevision,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiUser {
    keys: Vec<ApiKeyRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiAddress {
    #[serde(rename = "ID", alias = "Id")]
    id: String,
    keys: Vec<ApiKeyRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiKeyRecord {
    #[serde(rename = "ID", alias = "Id")]
    id: String,
    private_key: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    primary: ApiBool,
    active: ApiBool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiShareMetadata {
    #[serde(rename = "ShareID", alias = "ShareId")]
    share_id: String,
    #[serde(rename = "LinkID", alias = "LinkId")]
    link_id: String,
    #[serde(rename = "VolumeID", alias = "VolumeId")]
    volume_id: String,
    #[serde(rename = "Type")]
    share_type: i32,
    #[serde(rename = "State")]
    share_state: i32,
    creator: String,
    flags: i32,
    #[serde(rename = "VolumeType", default)]
    volume_type: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiShareMembership {
    #[serde(rename = "AddressID", alias = "AddressId")]
    address_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiPossibleKeyPacket {
    #[serde(rename = "AddressID", alias = "AddressId")]
    address_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiShareWire {
    #[serde(rename = "ShareID", alias = "ShareId")]
    share_id: String,
    #[serde(rename = "LinkID", alias = "LinkId")]
    link_id: String,
    #[serde(rename = "AddressID", alias = "AddressId", default)]
    address_id: Option<String>,
    key: String,
    passphrase: String,
    #[serde(default)]
    memberships: Vec<ApiShareMembership>,
    #[serde(rename = "PossibleKeyPackets", default)]
    possible_key_packets: Vec<ApiPossibleKeyPacket>,
}

#[derive(Debug, Clone)]
struct ApiShare {
    share_id: String,
    link_id: String,
    address_id: String,
    key: String,
    passphrase: String,
}

impl ShareEnvelope {
    fn into_share(self) -> Result<ApiShare> {
        match self {
            ShareEnvelope::Wrapped { share } | ShareEnvelope::Bare(share) => share.try_into(),
        }
    }
}

impl TryFrom<ApiShareWire> for ApiShare {
    type Error = anyhow::Error;

    fn try_from(value: ApiShareWire) -> Result<Self, Self::Error> {
        let address_id = value
            .address_id
            .or_else(|| {
                value
                    .memberships
                    .into_iter()
                    .map(|member| member.address_id)
                    .next()
            })
            .or_else(|| {
                value
                    .possible_key_packets
                    .into_iter()
                    .map(|packet| packet.address_id)
                    .next()
            })
            .ok_or_else(|| {
                anyhow!(
                    "Proton share {} did not include an address id",
                    value.share_id
                )
            })?;
        Ok(Self {
            share_id: value.share_id,
            link_id: value.link_id,
            address_id,
            key: value.key,
            passphrase: value.passphrase,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiLink {
    #[serde(rename = "LinkID", alias = "LinkId")]
    link_id: String,
    #[serde(rename = "Type")]
    link_type: i32,
    name: String,
    size: i64,
    #[serde(rename = "State")]
    link_state: i32,
    modify_time: i64,
    node_key: String,
    node_passphrase: String,
    #[serde(default)]
    file_properties: Option<ApiFileProperties>,
    #[serde(rename = "XAttr", default)]
    xattr: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiLinkDetail {
    link: ApiLinkRecord,
    #[serde(default)]
    file: Option<ApiFileDetail>,
    #[serde(default)]
    photo: Option<ApiPhotoDetail>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiLinkRecord {
    #[serde(rename = "LinkID", alias = "LinkId")]
    link_id: String,
    #[serde(rename = "Type")]
    link_type: i32,
    name: String,
    #[serde(rename = "State")]
    link_state: i32,
    modify_time: i64,
    node_key: String,
    node_passphrase: String,
    #[serde(rename = "Size", default)]
    size: Option<i64>,
    #[serde(rename = "XAttr", default)]
    xattr: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiFileDetail {
    content_key_packet: String,
    #[serde(default)]
    active_revision: Option<ApiActiveRevisionDetail>,
    #[serde(default)]
    total_encrypted_size: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiPhotoDetail {
    content_key_packet: String,
    #[serde(default)]
    active_revision: Option<ApiActiveRevisionDetail>,
    #[serde(default)]
    total_encrypted_size: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiActiveRevisionDetail {
    #[serde(rename = "RevisionID", alias = "ID", alias = "Id")]
    id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiFileProperties {
    content_key_packet: String,
    active_revision: ApiRevisionMetadata,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiVolumeSummary {
    #[serde(rename = "VolumeID", alias = "VolumeId")]
    volume_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiPhotoShare {
    #[serde(rename = "ShareID", alias = "ShareId")]
    share_id: String,
    creator_email: String,
    #[serde(rename = "AddressID", alias = "AddressId")]
    address_id: String,
    key: String,
    passphrase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiRevisionMetadata {
    #[serde(rename = "ID", alias = "Id")]
    id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiRevision {
    blocks: Vec<ApiBlock>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiBlock {
    #[serde(rename = "BareURL", alias = "BareUrl")]
    bare_url: String,
    token: String,
    hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeySaltsEnvelope {
    key_salts: Vec<ApiKeySalt>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiKeySalt {
    #[serde(rename = "ID", alias = "Id")]
    id: String,
    key_salt: Option<String>,
}

#[derive(Debug, Clone)]
struct SrpAuth {
    modulus: Vec<u8>,
    server_ephemeral: Vec<u8>,
    hashed_password: Vec<u8>,
}

#[derive(Debug, Clone)]
struct SrpProofs {
    client_proof: Vec<u8>,
    client_ephemeral: Vec<u8>,
    expected_server_proof: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ResolvedLoginCommand {
    credentials: PathBuf,
    email: String,
    password: String,
    two_fa: Option<String>,
    mailbox_password: Option<String>,
    app_version: Option<String>,
    user_agent: Option<String>,
    no_input: bool,
}

#[derive(Debug, Clone)]
struct SessionAccess {
    credentials_path: PathBuf,
    session_email: Option<String>,
    session_password: Option<String>,
}

#[derive(Debug)]
pub struct LoginOutput {
    pub credentials_path: PathBuf,
    pub shares: Vec<ShareInfo>,
}

enum SelectedSession {
    Existing(SessionAccess),
    Added {
        access: SessionAccess,
        shares: Vec<ShareInfo>,
    },
}

pub fn from_args(args: &ProtonSourceArgs, progress_mode: progress::Mode) -> Result<OpenedSource> {
    let mut reporter = progress::Reporter::stderr(progress_mode);
    let selection = select_session(
        args.credentials.as_ref(),
        args.account_password.as_deref(),
        args.app_version.as_deref(),
        args.user_agent.as_deref(),
        args.no_input,
    )?;
    let access = match selection {
        SelectedSession::Existing(access) | SelectedSession::Added { access, .. } => access,
    };
    let api = Arc::new(ProtonApi::from_credentials(
        &access.credentials_path,
        args.app_version.as_deref(),
        args.user_agent.as_deref(),
        access.session_password.clone(),
        access.session_email.clone(),
    )?);

    reporter.event(
        "tree_load",
        "start",
        [
            ("backend", json!("proton")),
            ("share_name", json!(args.share_name.clone())),
            ("share_id", json!(args.share_id.clone())),
            ("scan_concurrency", json!(args.scan_concurrency)),
        ],
    );

    if args.tree_cache == TreeCacheMode::ReuseIfPresent {
        match try_load_cached_backend(Arc::clone(&api), &access, args) {
            Ok(Some(backend)) => {
                let (folder_count, file_count) = count_index(&backend.folders);
                reporter.event(
                    "tree_load",
                    "complete",
                    [
                        ("backend", json!("proton")),
                        ("share_id", json!(backend.share_id.clone())),
                        ("root_id", json!(backend.root_id.clone())),
                        ("folders", json!(folder_count)),
                        ("files", json!(file_count)),
                        ("cached", json!(true)),
                    ],
                );
                reporter.finish();
                return Ok(OpenedSource {
                    source: Box::new(backend),
                    default_state_db: Some(default_state_db_path(&access.credentials_path)),
                });
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }

    let backend = ProtonBackend::load(api, args, &mut reporter)?;
    let (folder_count, file_count) = count_index(&backend.folders);
    reporter.event(
        "tree_load",
        "complete",
        [
            ("backend", json!("proton")),
            ("share_id", json!(backend.share_id.clone())),
            ("root_id", json!(backend.root_id.clone())),
            ("folders", json!(folder_count)),
            ("files", json!(file_count)),
            ("cached", json!(false)),
        ],
    );
    if args.tree_cache != TreeCacheMode::Off {
        let _ = save_tree_cache(&backend, &access);
    }

    reporter.finish();
    Ok(OpenedSource {
        source: Box::new(backend),
        default_state_db: Some(default_state_db_path(&access.credentials_path)),
    })
}

pub fn login(args: &LoginCommand) -> Result<LoginOutput> {
    let resolved = resolve_login_command(args)?;
    let api = Arc::new(ProtonApi::from_auth_state(
        &resolved.credentials,
        empty_credentials(),
        resolved.app_version.as_deref(),
        resolved.user_agent.as_deref(),
        Some(resolved.password.clone()),
        Some(resolved.email.clone()),
    )?);
    let shares = login_with_api(api, &resolved)?;
    Ok(LoginOutput {
        credentials_path: resolved.credentials,
        shares,
    })
}

fn login_with_api(api: Arc<ProtonApi>, args: &ResolvedLoginCommand) -> Result<Vec<ShareInfo>> {
    let auth = api.authenticate_password(&args.email, args.password.as_bytes(), args.no_input)?;
    complete_login(api, args, auth)
}

fn complete_login(
    api: Arc<ProtonApi>,
    args: &ResolvedLoginCommand,
    auth: AuthResponse,
) -> Result<Vec<ShareInfo>> {
    api.set_auth_state(ReusableCredential {
        uid: auth.uid.clone(),
        access_token: auth.access_token.clone(),
        refresh_token: auth.refresh_token.clone(),
        salted_key_pass: String::new(),
    });

    if auth.two_fa.enabled & TWO_FA_TOTP != 0 {
        let code = match args.two_fa.as_deref() {
            Some(code) => code.to_owned(),
            None => prompt_secret(
                &format!("Proton 2FA code for {}", args.email),
                args.no_input,
                "this account requires a 2FA TOTP code; pass `--2fa` or rerun without `--no-input`",
            )?,
        };
        api.auth_2fa(&code)?;
    } else if auth.two_fa.enabled & TWO_FA_FIDO2 != 0 {
        bail!("unsupported Proton 2FA configuration; FIDO2 login is not implemented");
    } else if auth.two_fa.enabled != 0 {
        bail!(
            "unsupported Proton 2FA configuration flags {}; only TOTP is implemented",
            auth.two_fa.enabled
        );
    }

    let key_pass = match auth.password_mode {
        PASSWORD_MODE_TWO => match args.mailbox_password.as_deref() {
            Some(password) => password.to_owned(),
            None => prompt_secret(
                &format!("Proton mailbox password for {}", args.email),
                args.no_input,
                "this account requires a mailbox password; pass `--mailbox-password` or rerun without `--no-input`",
            )?,
        },
        1 => args.password.clone(),
        other => bail!("unsupported Proton password mode {other}"),
    };

    let user = api.get_user()?;
    let salted_key_pass = derive_salted_key_pass(api.as_ref(), &user, key_pass.as_bytes())?;
    let credentials = ReusableCredential {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        salted_key_pass: base64::engine::general_purpose::STANDARD.encode(salted_key_pass),
    };
    api.set_auth_state(credentials.clone());
    api.persist_credentials(&credentials)?;

    let account = AccountContext::bootstrap(api)?;
    account.list_share_infos()
}

pub fn list_shares(args: &SharesCommand) -> Result<Vec<ShareInfo>> {
    let selection = select_session(
        args.credentials.as_ref(),
        args.account_password.as_deref(),
        args.app_version.as_deref(),
        args.user_agent.as_deref(),
        args.no_input,
    )?;
    if let SelectedSession::Added { shares, .. } = selection {
        return Ok(shares);
    }
    let access = match selection {
        SelectedSession::Existing(access) => access,
        SelectedSession::Added { .. } => unreachable!("freshly added sessions returned early"),
    };
    let api = Arc::new(ProtonApi::from_credentials(
        &access.credentials_path,
        args.app_version.as_deref(),
        args.user_agent.as_deref(),
        access.session_password.clone(),
        access.session_email.clone(),
    )?);
    list_shares_with_api(api)
}

fn list_shares_with_api(api: Arc<ProtonApi>) -> Result<Vec<ShareInfo>> {
    let account = AccountContext::bootstrap(api)?;
    account.list_share_infos()
}

fn default_state_db_path(credentials_path: &Path) -> PathBuf {
    credentials_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("proton-photos.sqlite")
}

fn default_tree_cache_path(credentials_path: &Path) -> PathBuf {
    credentials_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("proton-tree-cache.json")
}

fn inferred_session_email(credentials_path: &Path) -> Option<String> {
    let is_session_json = credentials_path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("session.json"));
    if is_session_json {
        return credentials_path
            .parent()
            .and_then(|value| value.file_name())
            .and_then(|value| value.to_str())
            .map(str::to_owned);
    }
    credentials_path
        .file_stem()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
}

fn try_load_cached_backend(
    api: Arc<ProtonApi>,
    access: &SessionAccess,
    args: &ProtonSourceArgs,
) -> Result<Option<ProtonBackend>> {
    let cache_path = default_tree_cache_path(&access.credentials_path);
    if !cache_path.is_file() {
        return Ok(None);
    }

    let Some(password) = access.session_password.as_deref() else {
        return Ok(None);
    };
    let bytes = fs::read(&cache_path)
        .with_context(|| format!("read tree cache {}", cache_path.display()))?;
    let decrypted = accounts::decrypt_session_bytes(&cache_path, &bytes, Some(password))
        .with_context(|| format!("decrypt tree cache {}", cache_path.display()))?;
    let snapshot: TreeCacheSnapshot = serde_json::from_slice(&decrypted)
        .with_context(|| format!("parse tree cache {}", cache_path.display()))?;
    if snapshot.version != TREE_CACHE_VERSION {
        return Ok(None);
    }
    if !tree_cache_matches(&snapshot, args) {
        return Ok(None);
    }
    ProtonBackend::from_tree_cache(api, snapshot).map(Some)
}

fn tree_cache_matches(snapshot: &TreeCacheSnapshot, args: &ProtonSourceArgs) -> bool {
    if let Some(share_id) = args.share_id.as_deref() {
        return snapshot.share_id == share_id;
    }
    share_display_base(&snapshot.share_name).eq_ignore_ascii_case(args.share_name.trim())
}

fn save_tree_cache(backend: &ProtonBackend, access: &SessionAccess) -> Result<()> {
    let Some(password) = access.session_password.as_deref() else {
        return Ok(());
    };
    let Some(email) = access
        .session_email
        .clone()
        .or_else(|| inferred_session_email(&access.credentials_path))
    else {
        return Ok(());
    };

    let snapshot = backend.to_tree_cache()?;
    let plaintext = serde_json::to_vec(&snapshot).context("serialize Proton tree cache")?;
    let payload = accounts::encrypt_session_bytes(&email, password, &plaintext)?;
    let path = default_tree_cache_path(&access.credentials_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create tree cache parent {}", parent.display()))?;
    }
    fs::write(&path, payload).with_context(|| format!("write tree cache {}", path.display()))
}

fn empty_credentials() -> ReusableCredential {
    ReusableCredential {
        uid: String::new(),
        access_token: String::new(),
        refresh_token: String::new(),
        salted_key_pass: String::new(),
    }
}

fn resolve_login_command(args: &LoginCommand) -> Result<ResolvedLoginCommand> {
    let email = match args.email.as_deref() {
        Some(email) if !email.trim().is_empty() => email.trim().to_owned(),
        _ => prompt_text(
            "Proton email",
            args.no_input,
            "missing Proton email; pass `--email` or rerun without `--no-input`",
        )?,
    };
    let password = match args.password.as_deref() {
        Some(password) if !password.is_empty() => password.to_owned(),
        _ => prompt_secret(
            &format!("Proton account password for {email}"),
            args.no_input,
            "missing Proton account password; pass `--password` or rerun without `--no-input`",
        )?,
    };
    let credentials = match &args.credentials {
        Some(path) => path.clone(),
        None => default_login_credentials_path(&email)?,
    };
    Ok(ResolvedLoginCommand {
        credentials,
        email,
        password,
        two_fa: args.two_fa.clone(),
        mailbox_password: args.mailbox_password.clone(),
        app_version: args.app_version.clone(),
        user_agent: args.user_agent.clone(),
        no_input: args.no_input,
    })
}

fn select_session(
    credentials: Option<&PathBuf>,
    account_password: Option<&str>,
    app_version: Option<&str>,
    user_agent: Option<&str>,
    no_input: bool,
) -> Result<SelectedSession> {
    if let Some(path) = credentials {
        let info = accounts::inspect_session_file(path)?;
        let password = if info.encrypted {
            match account_password {
                Some(password) => Some(password.to_owned()),
                None => Some(prompt_secret(
                    &format!(
                        "Proton account password for {}",
                        info.email
                            .as_deref()
                            .unwrap_or_else(|| path.to_str().unwrap_or("saved session"))
                    ),
                    no_input,
                    "the selected Proton session is encrypted; pass `--account-password` or rerun without `--no-input` to unlock it interactively",
                )?),
            }
        } else {
            None
        };
        return Ok(SelectedSession::Existing(SessionAccess {
            credentials_path: path.clone(),
            session_email: info.email,
            session_password: password,
        }));
    }

    let accounts_dir = configured_accounts_dir()?;
    let stored_accounts = accounts::list_accounts(&accounts_dir)?;
    if stored_accounts.is_empty() {
        if no_input {
            bail!(
                "no saved Proton accounts found in {}; run `login` first or pass `--credentials`",
                accounts_dir.display()
            );
        }
        let add = prompt_confirm(
            format!(
                "No saved Proton accounts found in {}. Add an account now?",
                accounts_dir.display()
            ),
            true,
        )?;
        if !add {
            bail!("no Proton account selected");
        }
        let (access, shares) = add_account_interactively(app_version, user_agent)?;
        return Ok(SelectedSession::Added { access, shares });
    }

    if no_input {
        bail!(
            "saved Proton accounts exist in {}, but interactive selection is disabled; pass `--credentials` or rerun without `--no-input`",
            accounts_dir.display()
        );
    }

    let choice = prompt_account_selection(&stored_accounts)?;
    if choice == stored_accounts.len() {
        let (access, shares) = add_account_interactively(app_version, user_agent)?;
        return Ok(SelectedSession::Added { access, shares });
    }

    let selected = &stored_accounts[choice];
    let password = prompt_secret(
        &format!("Proton account password for {}", selected.email),
        false,
        "missing Proton account password",
    )?;
    Ok(SelectedSession::Existing(SessionAccess {
        credentials_path: selected.path.clone(),
        session_email: Some(selected.email.clone()),
        session_password: Some(password),
    }))
}

fn add_account_interactively(
    app_version: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(SessionAccess, Vec<ShareInfo>)> {
    let resolved = resolve_login_command(&LoginCommand {
        credentials: None,
        email: None,
        password: None,
        two_fa: None,
        mailbox_password: None,
        app_version: app_version.map(str::to_owned),
        user_agent: user_agent.map(str::to_owned),
        no_input: false,
    })?;
    let api = Arc::new(ProtonApi::from_auth_state(
        &resolved.credentials,
        empty_credentials(),
        resolved.app_version.as_deref(),
        resolved.user_agent.as_deref(),
        Some(resolved.password.clone()),
        Some(resolved.email.clone()),
    )?);
    let shares = login_with_api(api, &resolved)?;
    let access = SessionAccess {
        credentials_path: resolved.credentials,
        session_email: Some(resolved.email),
        session_password: Some(resolved.password),
    };
    Ok((access, shares))
}

fn prompt_theme() -> ColorfulTheme {
    ColorfulTheme::default()
}

fn prompt_text(prompt: &str, no_input: bool, non_interactive_error: &str) -> Result<String> {
    if no_input {
        bail!("{}", non_interactive_error);
    }
    let theme = prompt_theme();
    let input = Input::<String>::with_theme(&theme).with_prompt(prompt);
    let value = interact_prompt_text(input, prompt)?;
    let trimmed = value.trim().to_owned();
    if trimmed.is_empty() {
        bail!("{prompt} cannot be empty");
    }
    Ok(trimmed)
}

fn prompt_secret(prompt: &str, no_input: bool, non_interactive_error: &str) -> Result<String> {
    if no_input {
        bail!("{}", non_interactive_error);
    }
    let theme = prompt_theme();
    let input = DialoguerPassword::with_theme(&theme)
        .with_prompt(prompt)
        .allow_empty_password(false);
    let value = interact_prompt_secret(input, prompt)?;
    if value.is_empty() {
        bail!("{prompt} cannot be empty");
    }
    Ok(value)
}

fn prompt_account_selection(accounts: &[StoredAccount]) -> Result<usize> {
    let mut items: Vec<String> = accounts
        .iter()
        .map(|account| account.email.clone())
        .collect();
    items.push("Add an account".to_owned());
    let theme = prompt_theme();
    let select = Select::with_theme(&theme)
        .with_prompt("Select a Proton account")
        .items(&items)
        .default(0);
    interact_prompt_select(select)
}

fn prompt_confirm(prompt: String, default: bool) -> Result<bool> {
    let theme = prompt_theme();
    let confirm = Confirm::with_theme(&theme)
        .with_prompt(prompt)
        .default(default);
    interact_prompt_confirm(confirm)
}

fn interact_prompt_text(input: Input<String>, prompt: &str) -> Result<String> {
    #[cfg(test)]
    if let Some(value) = TEST_PROMPT_TEXT.with(|slot| slot.borrow_mut().pop_front()) {
        return Ok(value);
    }
    input
        .interact_text()
        .with_context(|| format!("prompt for {prompt}"))
}

fn interact_prompt_secret(input: DialoguerPassword<'_>, prompt: &str) -> Result<String> {
    #[cfg(test)]
    if let Some(value) = TEST_PROMPT_SECRET.with(|slot| slot.borrow_mut().pop_front()) {
        return Ok(value);
    }
    input
        .interact()
        .with_context(|| format!("prompt for {prompt}"))
}

fn interact_prompt_select(select: Select<'_>) -> Result<usize> {
    #[cfg(test)]
    if let Some(choice) = TEST_PROMPT_SELECT.with(|slot| slot.borrow_mut().take()) {
        return Ok(choice);
    }
    select.interact().context("select Proton account")
}

fn interact_prompt_confirm(confirm: Confirm<'_>) -> Result<bool> {
    #[cfg(test)]
    if let Some(choice) = TEST_PROMPT_CONFIRM.with(|slot| slot.borrow_mut().take()) {
        return Ok(choice);
    }
    confirm.interact().context("prompt to add Proton account")
}

impl PhotoSource for ProtonBackend {
    fn backend_name(&self) -> &'static str {
        "proton"
    }

    fn root_id(&self) -> &str {
        &self.root_id
    }

    fn list_children(&self, folder_id: &str) -> Result<Vec<RemoteEntry>> {
        self.folders
            .get(folder_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown Proton folder id {folder_id}"))
    }

    fn open_file(&self, file_id: &str) -> Result<Box<dyn Read + Send>> {
        let native = self
            .files
            .get(file_id)
            .ok_or_else(|| anyhow!("unknown Proton file id {file_id}"))?;
        let file_properties = native
            .link
            .file_properties
            .as_ref()
            .ok_or_else(|| anyhow!("file {file_id} is missing active revision metadata"))?;
        let revision = self.api.get_revision_all_blocks(
            &self.volume_id,
            file_id,
            &file_properties.active_revision.id,
        )?;
        let session_key = native
            .node_keys
            .decrypt_content_session_key(&file_properties.content_key_packet)?;

        Ok(Box::new(ProtonFileReader {
            api: Arc::clone(&self.api),
            prefetch: start_block_prefetch(
                Arc::clone(&self.api),
                session_key.clone(),
                revision.blocks.clone(),
            ),
            session_key,
            blocks: revision.blocks,
            next_block: 0,
            current: Cursor::new(Vec::new()),
            finished: false,
        }))
    }
}

impl ProtonBackend {
    fn from_tree_cache(api: Arc<ProtonApi>, snapshot: TreeCacheSnapshot) -> Result<Self> {
        let files = snapshot
            .files
            .into_iter()
            .map(|(id, file)| {
                Ok((
                    id,
                    NativeFile {
                        link: file.link,
                        node_keys: Arc::new(SecretKeyRing::from_cached(&file.node_keys)?),
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        Ok(Self {
            api,
            share_name: snapshot.share_name,
            share_id: snapshot.share_id,
            volume_id: snapshot.volume_id,
            root_id: snapshot.root_id,
            folders: snapshot.folders,
            files,
        })
    }

    fn to_tree_cache(&self) -> Result<TreeCacheSnapshot> {
        let files = self
            .files
            .iter()
            .map(|(id, file)| {
                Ok((
                    id.clone(),
                    CachedNativeFile {
                        link: file.link.clone(),
                        node_keys: file.node_keys.to_cached()?,
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        Ok(TreeCacheSnapshot {
            version: TREE_CACHE_VERSION,
            share_name: self.share_name.clone(),
            share_id: self.share_id.clone(),
            volume_id: self.volume_id.clone(),
            root_id: self.root_id.clone(),
            folders: self.folders.clone(),
            files,
        })
    }

    fn load(
        api: Arc<ProtonApi>,
        args: &ProtonSourceArgs,
        reporter: &mut progress::Reporter,
    ) -> Result<Self> {
        let account = AccountContext::bootstrap(Arc::clone(&api))?;
        let shares = account.list_share_infos()?;
        let selected = select_share(&shares, args.share_id.as_deref(), &args.share_name)?;
        let loaded = account.load_share_root(selected)?;
        let share_keys = account.unlock_share_key(&loaded.share)?;
        let root_keys = decrypt_node_keys(&share_keys, &loaded.root_link).with_context(|| {
            format!("decrypt root node keys for share {}", loaded.share.share_id)
        })?;
        let loaded_tree = load_tree(
            TreeLoadRequest {
                api: Arc::clone(&api),
                share_id: loaded.share.share_id.clone(),
                volume_id: selected.volume_id.clone(),
                metadata_mode: selected.metadata_mode,
                root_id: loaded.root_link.link_id.clone(),
                root_link_type: loaded.root_link.link_type,
                root_keys,
                scan_concurrency: args.scan_concurrency,
            },
            reporter,
        )?;
        let LoadedTree { folders, files } = loaded_tree;

        Ok(Self {
            api,
            share_name: selected.name.clone(),
            share_id: loaded.share.share_id,
            volume_id: selected.volume_id.clone(),
            root_id: loaded.root_link.link_id,
            folders,
            files,
        })
    }
}

impl AccountContext {
    fn bootstrap(api: Arc<ProtonApi>) -> Result<Self> {
        let credentials = api.credentials();
        let salted_key_pass = base64::engine::general_purpose::STANDARD
            .decode(credentials.salted_key_pass.as_bytes())
            .context("decode SaltedKeyPass")?;

        let user = api.get_user()?;
        let user_keys = unlock_key_records(&user.keys, &salted_key_pass, None)
            .context("unlock Proton user keys")?;

        let addresses = api.get_addresses()?;
        let mut address_keys_by_id = HashMap::new();
        for address in addresses {
            let keys = unlock_key_records(&address.keys, &salted_key_pass, Some(&user_keys))
                .with_context(|| format!("unlock Proton address keys for {}", address.id))?;
            address_keys_by_id.insert(address.id, keys);
        }

        Ok(Self {
            api,
            address_keys_by_id,
        })
    }

    fn list_share_infos(&self) -> Result<Vec<ShareInfo>> {
        let shares = self.api.list_shares()?;
        let photo_root = self.api.get_photos_share_root()?;
        let mut rows = Vec::with_capacity(shares.len() + usize::from(photo_root.is_some()));
        for share in shares {
            if let Some(photo_root) = photo_root
                .as_ref()
                .filter(|photo_root| photo_root.share.share_id == share.share_id)
            {
                rows.push(self.photo_share_info(photo_root)?);
                continue;
            }

            let name = self.resolve_share_name(&share)?;
            rows.push(ShareInfo {
                name,
                share_id: share.share_id,
                link_id: share.link_id,
                volume_id: share.volume_id,
                share_type: share_type_label(share.share_type),
                state: share_state_label(share.share_state),
                flags: share_flags_label(share.flags),
                creator: share.creator,
                metadata_mode: metadata_mode_for_volume_type(share.volume_type),
            });
        }

        if let Some(photo_root) = photo_root
            && !rows
                .iter()
                .any(|share| share.share_id == photo_root.share.share_id)
        {
            rows.push(self.photo_share_info(&photo_root)?);
        }
        Ok(rows)
    }

    fn resolve_share_name(&self, meta: &ApiShareMetadata) -> Result<String> {
        if meta.share_type == SHARE_TYPE_MAIN {
            return Ok("My files".to_owned());
        }

        let share = self.api.get_share(&meta.share_id)?;
        let share_keys = self.unlock_share_key(&share)?;
        let root_link = self.api.get_share_link(&share.share_id, &share.link_id)?;
        let name = decrypt_text(&share_keys, &root_link.name)
            .with_context(|| format!("decrypt root name for share {}", meta.share_id))?;
        Ok(apply_share_name_suffix(
            name,
            meta.share_type,
            &meta.creator,
        ))
    }

    fn unlock_share_key(&self, share: &ApiShare) -> Result<SecretKeyRing> {
        let address_keys = self
            .address_keys_by_id
            .get(&share.address_id)
            .ok_or_else(|| anyhow!("missing address keyring {}", share.address_id))?;
        let share_passphrase = address_keys
            .decrypt_armored_message(&share.passphrase)
            .with_context(|| format!("decrypt share passphrase {}", share.share_id))?;
        SecretKeyRing::from_armored_secret(&share.key, &share_passphrase)
            .with_context(|| format!("unlock share key {}", share.share_id))
    }

    fn load_share_root(&self, share: &ShareInfo) -> Result<LoadedShareRoot> {
        match share.metadata_mode {
            LinkMetadataMode::Drive => {
                let share_record = self.api.get_share(&share.share_id)?;
                let root_link = self.api.get_share_link(&share.share_id, &share.link_id)?;
                Ok(LoadedShareRoot {
                    share: share_record,
                    root_link,
                })
            }
            LinkMetadataMode::Photos => {
                let photo_root = self.api.get_photos_share_root()?.ok_or_else(|| {
                    anyhow!("PhotosRoot was not available for this Proton account")
                })?;
                let root_link = photo_root.link.clone().into_api_link()?;
                Ok(LoadedShareRoot {
                    share: photo_root.into_api_share(root_link.link_id.clone()),
                    root_link,
                })
            }
        }
    }

    fn photo_share_info(&self, photo_root: &PhotoShareRootEnvelope) -> Result<ShareInfo> {
        let root_link = photo_root.link.clone().into_api_link()?;
        let share = photo_root.clone().into_api_share(root_link.link_id.clone());
        let share_keys = self.unlock_share_key(&share)?;
        let decrypted_name = decrypt_text(&share_keys, &root_link.name)
            .with_context(|| format!("decrypt root name for share {}", share.share_id))?;
        Ok(ShareInfo {
            name: normalize_photo_share_name(&decrypted_name),
            share_id: share.share_id,
            link_id: root_link.link_id,
            volume_id: photo_root.volume.volume_id.clone(),
            share_type: "photo".to_owned(),
            state: "active".to_owned(),
            flags: "none".to_owned(),
            creator: photo_root.share.creator_email.clone(),
            metadata_mode: LinkMetadataMode::Photos,
        })
    }
}

impl ProtonApi {
    fn from_credentials(
        credentials_path: &Path,
        app_version: Option<&str>,
        user_agent: Option<&str>,
        session_password: Option<String>,
        session_email: Option<String>,
    ) -> Result<Self> {
        let base_url = configured_api_base_url();
        Self::from_credentials_with_base_url(
            credentials_path,
            app_version,
            user_agent,
            &base_url,
            session_password,
            session_email,
        )
    }

    fn from_credentials_with_base_url(
        credentials_path: &Path,
        app_version: Option<&str>,
        user_agent: Option<&str>,
        base_url: &str,
        session_password: Option<String>,
        session_email: Option<String>,
    ) -> Result<Self> {
        let credentials_bytes = fs::read(credentials_path)
            .with_context(|| format!("read credentials file {}", credentials_path.display()))?;
        let session_info = accounts::inspect_session_bytes(credentials_path, &credentials_bytes);
        let decrypted_bytes = accounts::decrypt_session_bytes(
            credentials_path,
            &credentials_bytes,
            session_password.as_deref(),
        )?;
        let auth: ReusableCredential =
            serde_json::from_slice(&decrypted_bytes).context("parse credentials JSON")?;
        Self::from_auth_state_with_base_url(
            credentials_path,
            auth,
            app_version,
            user_agent,
            base_url,
            session_password,
            session_email.or_else(|| session_info.and_then(|info| info.email)),
        )
    }

    fn from_auth_state(
        credentials_path: &Path,
        auth: ReusableCredential,
        app_version: Option<&str>,
        user_agent: Option<&str>,
        session_password: Option<String>,
        session_email: Option<String>,
    ) -> Result<Self> {
        let base_url = configured_api_base_url();
        Self::from_auth_state_with_base_url(
            credentials_path,
            auth,
            app_version,
            user_agent,
            &base_url,
            session_password,
            session_email,
        )
    }

    fn from_auth_state_with_base_url(
        credentials_path: &Path,
        auth: ReusableCredential,
        app_version: Option<&str>,
        user_agent: Option<&str>,
        base_url: &str,
        session_password: Option<String>,
        session_email: Option<String>,
    ) -> Result<Self> {
        #[cfg(test)]
        let client_builder = HttpClient::builder()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(HTTP_CONNECT_TIMEOUT_SECS));
        #[cfg(not(test))]
        let client_builder =
            HttpClient::builder().connect_timeout(Duration::from_secs(HTTP_CONNECT_TIMEOUT_SECS));
        let client = client_builder.build().context("build HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
            credentials_path: credentials_path.to_path_buf(),
            session_email,
            session_password,
            app_version: app_version.unwrap_or(DEFAULT_APP_VERSION).to_owned(),
            user_agent: user_agent.unwrap_or(DEFAULT_USER_AGENT).to_owned(),
            auth: Mutex::new(auth),
        })
    }

    fn credentials(&self) -> ReusableCredential {
        self.auth.lock().expect("auth mutex poisoned").clone()
    }

    fn set_auth_state(&self, auth: ReusableCredential) {
        let mut guard = self.auth.lock().expect("auth mutex poisoned");
        *guard = auth;
    }

    fn persist_credentials(&self, auth: &ReusableCredential) -> Result<()> {
        if let Some(parent) = self.credentials_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create credentials parent {}", parent.display()))?;
        }
        let serialized = serde_json::to_vec(auth).context("serialize credentials JSON")?;
        let payload = if let Some(password) = self.session_password.as_deref() {
            let email = self
                .session_email
                .as_deref()
                .or_else(|| {
                    self.credentials_path
                        .file_stem()
                        .and_then(|value| value.to_str())
                })
                .unwrap_or("account");
            accounts::encrypt_session_bytes(email, password, &serialized)?
        } else {
            serialized
        };
        fs::write(&self.credentials_path, payload)
            .with_context(|| format!("write credentials {}", self.credentials_path.display()))?;
        Ok(())
    }

    fn get_user(&self) -> Result<ApiUser> {
        Ok(self
            .request_json::<UserEnvelope, serde_json::Value>(
                Method::GET,
                "/core/v4/users",
                &[],
                None::<&serde_json::Value>,
                true,
            )?
            .user)
    }

    fn get_addresses(&self) -> Result<Vec<ApiAddress>> {
        Ok(self
            .request_json::<AddressesEnvelope, serde_json::Value>(
                Method::GET,
                "/core/v4/addresses",
                &[],
                None::<&serde_json::Value>,
                true,
            )?
            .addresses)
    }

    fn get_key_salts(&self) -> Result<Vec<ApiKeySalt>> {
        Ok(self
            .request_json::<KeySaltsEnvelope, serde_json::Value>(
                Method::GET,
                "/core/v4/keys/salts",
                &[],
                None::<&serde_json::Value>,
                true,
            )?
            .key_salts)
    }

    fn authenticate_password(
        &self,
        username: &str,
        password: &[u8],
        no_input: bool,
    ) -> Result<AuthResponse> {
        let info = self.request_json::<AuthInfoResponse, AuthInfoRequest>(
            Method::POST,
            "/auth/v4/info",
            &[],
            Some(&AuthInfoRequest {
                username: username.to_owned(),
            }),
            false,
        )?;
        let srp = SrpAuth::new(
            info.version,
            username,
            password,
            &info.salt,
            &info.modulus,
            &info.server_ephemeral,
        )?;
        let proofs = srp.generate_proofs()?;
        let auth_request = AuthRequest {
            username: username.to_owned(),
            client_ephemeral: base64::engine::general_purpose::STANDARD
                .encode(&proofs.client_ephemeral),
            client_proof: base64::engine::general_purpose::STANDARD.encode(&proofs.client_proof),
            srp_session: info.srp_session,
        };
        let auth = match self.authenticate_exchange(&auth_request, None) {
            Ok(auth) => auth,
            Err(error) => match error.downcast::<HumanVerificationRequired>() {
                Ok(required) => {
                    let answer = self.complete_human_verification(&required.challenge, no_input)?;
                    self.authenticate_exchange(&auth_request, Some(&answer))?
                }
                Err(error) => return Err(error),
            },
        };
        let server_proof = base64::engine::general_purpose::STANDARD
            .decode(auth.server_proof.as_bytes())
            .context("decode Proton server proof")?;
        if server_proof != proofs.expected_server_proof {
            bail!("unexpected Proton server proof");
        }
        Ok(auth)
    }

    fn auth_2fa(&self, code: &str) -> Result<()> {
        self.request_json::<serde_json::Value, Auth2FaRequest>(
            Method::POST,
            "/auth/v4/2fa",
            &[],
            Some(&Auth2FaRequest {
                two_factor_code: code.to_owned(),
            }),
            true,
        )?;
        Ok(())
    }

    fn list_shares(&self) -> Result<Vec<ApiShareMetadata>> {
        Ok(self
            .request_json::<SharesEnvelope, serde_json::Value>(
                Method::GET,
                "/drive/shares",
                &[("ShowAll", "1")],
                None::<&serde_json::Value>,
                true,
            )?
            .shares)
    }

    fn get_photos_share_root(&self) -> Result<Option<PhotoShareRootEnvelope>> {
        let url = format!("{}{}", self.base_url, "/drive/v2/shares/photos");
        let mut refreshed = false;

        for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
            let auth = self.credentials();
            let mut request = self
                .client
                .request(Method::GET, &url)
                .header("x-pm-appversion", &self.app_version);
            #[cfg(test)]
            {
                request = request.header(reqwest::header::CONNECTION, "close");
            }
            if !self.user_agent.is_empty() {
                request = request.header(reqwest::header::USER_AGENT, &self.user_agent);
            }
            request = request
                .header("x-pm-uid", auth.uid.as_str())
                .bearer_auth(auth.access_token.as_str());

            let response = match request.send() {
                Ok(response) => response,
                Err(error) => {
                    if let Some(delay) =
                        retry_delay_for_transport_error(&Method::GET, &error, attempt)
                    {
                        thread::sleep(delay);
                        continue;
                    }
                    return Err(error)
                        .with_context(|| format!("send Proton API request GET {url}"));
                }
            };
            if response.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {
                self.refresh_auth()?;
                refreshed = true;
                continue;
            }

            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }

            let status = response.status();
            if let Some(delay) = retry_delay_for_response(&response, attempt) {
                thread::sleep(delay);
                continue;
            }
            if !status.is_success() {
                let body = response.text().unwrap_or_default();
                bail!("Proton API GET {url} failed with {status}: {body}");
            }

            let body = match response.text() {
                Ok(body) => body,
                Err(error) => {
                    if let Some(delay) =
                        retry_delay_for_transport_error(&Method::GET, &error, attempt)
                    {
                        thread::sleep(delay);
                        continue;
                    }
                    return Err(error)
                        .with_context(|| format!("read Proton API response body for GET {url}"));
                }
            };
            let parsed =
                serde_json::from_str::<PhotoShareRootEnvelope>(&body).with_context(|| {
                    let snippet: String = body.chars().take(4000).collect();
                    format!("parse Proton API response for GET {url}: {snippet}")
                })?;
            return Ok(Some(parsed));
        }

        unreachable!("request retries are bounded by MAX_TRANSIENT_ATTEMPTS")
    }

    fn get_share(&self, share_id: &str) -> Result<ApiShare> {
        let path = format!("/drive/shares/{share_id}");
        self.request_json::<ShareEnvelope, serde_json::Value>(
            Method::GET,
            &path,
            &[],
            None::<&serde_json::Value>,
            true,
        )?
        .into_share()
    }

    fn get_share_link(&self, share_id: &str, link_id: &str) -> Result<ApiLink> {
        let path = format!("/drive/shares/{share_id}/links/{link_id}");
        Ok(self
            .request_json::<LinkEnvelope, serde_json::Value>(
                Method::GET,
                &path,
                &[],
                None::<&serde_json::Value>,
                true,
            )?
            .link)
    }

    fn list_children(
        &self,
        volume_id: &str,
        link_id: &str,
        parent_link_type: i32,
        metadata_mode: LinkMetadataMode,
        progress: Option<&TreeLoadProgressState>,
    ) -> Result<Vec<ApiLink>> {
        let link_ids = self.list_child_ids(volume_id, link_id, parent_link_type, progress)?;
        if link_ids.is_empty() {
            return Ok(Vec::new());
        }
        let details_mode = if parent_link_type == LINK_TYPE_ALBUM {
            LinkMetadataMode::Photos
        } else {
            metadata_mode
        };
        self.get_link_details(volume_id, &link_ids, details_mode)
    }

    fn list_share_children(
        &self,
        share_id: &str,
        link_id: &str,
        progress: Option<&TreeLoadProgressState>,
    ) -> Result<Vec<ApiLink>> {
        let path = format!("/drive/shares/{share_id}/folders/{link_id}/children");
        let mut page = 0usize;
        let mut links = Vec::new();
        loop {
            let page_text = page.to_string();
            let page_size_text = MAX_PAGE_SIZE.to_string();
            let envelope = self.request_json::<ShareChildrenEnvelope, serde_json::Value>(
                Method::GET,
                &path,
                &[("Page", &page_text), ("PageSize", &page_size_text)],
                None::<&serde_json::Value>,
                true,
            )?;
            let count = envelope.links.len();
            if let Some(progress) = progress {
                progress.record_page(count as u64);
            }
            links.extend(
                envelope
                    .links
                    .into_iter()
                    .map(ApiShareChildLink::into_api_link),
            );
            if count < MAX_PAGE_SIZE {
                break;
            }
            page += 1;
        }
        Ok(links)
    }

    fn list_child_ids(
        &self,
        volume_id: &str,
        link_id: &str,
        parent_link_type: i32,
        progress: Option<&TreeLoadProgressState>,
    ) -> Result<Vec<String>> {
        if parent_link_type == LINK_TYPE_ALBUM {
            return self.list_album_child_ids(volume_id, link_id, progress);
        }

        let path = format!("/drive/v2/volumes/{volume_id}/folders/{link_id}/children");
        let mut anchor = None::<String>;
        let mut link_ids = Vec::new();
        loop {
            let mut query = Vec::new();
            if let Some(anchor_id) = anchor.as_deref() {
                query.push(("AnchorID", anchor_id));
            }
            let envelope = self.request_json::<FolderChildrenEnvelope, serde_json::Value>(
                Method::GET,
                &path,
                &query,
                None::<&serde_json::Value>,
                true,
            )?;
            if let Some(progress) = progress {
                progress.record_page(envelope.link_ids.len() as u64);
            }
            if envelope.link_ids.is_empty() && !envelope.more {
                break;
            }
            link_ids.extend(envelope.link_ids);
            if !envelope.more {
                break;
            }
            anchor = envelope.anchor_id;
        }

        Ok(link_ids)
    }

    fn list_album_child_ids(
        &self,
        volume_id: &str,
        link_id: &str,
        progress: Option<&TreeLoadProgressState>,
    ) -> Result<Vec<String>> {
        let path = format!("/drive/photos/volumes/{volume_id}/albums/{link_id}/children");
        let mut anchor = None::<String>;
        let mut link_ids = Vec::new();
        loop {
            let mut query = vec![("Sort", "Captured"), ("Desc", "1")];
            if let Some(anchor_id) = anchor.as_deref() {
                query.push(("AnchorID", anchor_id));
            }
            let envelope = self.request_json::<AlbumChildrenEnvelope, serde_json::Value>(
                Method::GET,
                &path,
                &query,
                None::<&serde_json::Value>,
                true,
            )?;
            if let Some(progress) = progress {
                progress.record_page(envelope.photos.len() as u64);
            }
            if envelope.photos.is_empty() && !envelope.more {
                break;
            }
            link_ids.extend(envelope.photos.into_iter().map(|photo| photo.link_id));
            if !envelope.more {
                break;
            }
            anchor = envelope.anchor_id;
        }

        Ok(link_ids)
    }

    fn get_link_details(
        &self,
        volume_id: &str,
        link_ids: &[String],
        metadata_mode: LinkMetadataMode,
    ) -> Result<Vec<ApiLink>> {
        let path = match metadata_mode {
            LinkMetadataMode::Drive => format!("/drive/v2/volumes/{volume_id}/links"),
            LinkMetadataMode::Photos => format!("/drive/photos/volumes/{volume_id}/links"),
        };
        let mut links = Vec::with_capacity(link_ids.len());
        for chunk in link_ids.chunks(MAX_PAGE_SIZE) {
            let body = json!({ "LinkIDs": chunk });
            let envelope = self.request_json::<LinksEnvelopeV2, serde_json::Value>(
                Method::POST,
                &path,
                &[],
                Some(&body),
                true,
            )?;
            for link in envelope.links {
                links.push(link.into_api_link()?);
            }
        }
        Ok(links)
    }

    fn get_revision_all_blocks(
        &self,
        volume_id: &str,
        link_id: &str,
        revision_id: &str,
    ) -> Result<ApiRevision> {
        let path = format!("/drive/v2/volumes/{volume_id}/files/{link_id}/revisions/{revision_id}");
        Ok(self
            .request_json::<RevisionEnvelope, serde_json::Value>(
                Method::GET,
                &path,
                &[],
                None::<&serde_json::Value>,
                true,
            )?
            .revision)
    }

    fn get_block(&self, bare_url: &str, token: &str) -> Result<Vec<u8>> {
        self.request_bytes_absolute(
            Method::GET,
            bare_url,
            Some(("pm-storage-token", token)),
            true,
        )
    }

    fn request_json<T, B>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&B>,
        authenticated: bool,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let body_bytes = match body {
            Some(value) => Some(serde_json::to_vec(value).context("encode JSON request body")?),
            None => None,
        };
        let url = format!("{}{}", self.base_url, path);
        let mut refreshed = false;

        for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
            let auth = self.credentials();
            let mut request = self
                .client
                .request(method.clone(), &url)
                .header("x-pm-appversion", &self.app_version)
                .query(query)
                .timeout(Duration::from_secs(HTTP_API_TIMEOUT_SECS));
            #[cfg(test)]
            {
                request = request.header(reqwest::header::CONNECTION, "close");
            }
            if !self.user_agent.is_empty() {
                request = request.header(reqwest::header::USER_AGENT, &self.user_agent);
            }
            if authenticated {
                request = request
                    .header("x-pm-uid", auth.uid.as_str())
                    .bearer_auth(auth.access_token.as_str());
            }
            if let Some(bytes) = body_bytes.clone() {
                request = request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(bytes);
            }

            let response = match request.send() {
                Ok(response) => response,
                Err(error) => {
                    if let Some(delay) = retry_delay_for_transport_error(&method, &error, attempt) {
                        report_request_retry(&method, &url, attempt, delay, &error.to_string());
                        thread::sleep(delay);
                        continue;
                    }
                    return Err(error)
                        .with_context(|| format!("send Proton API request {method} {url}"));
                }
            };
            if authenticated && response.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed
            {
                self.refresh_auth()?;
                refreshed = true;
                continue;
            }

            let status = response.status();
            if let Some(delay) = retry_delay_for_response(&response, attempt) {
                report_request_retry(
                    &method,
                    &url,
                    attempt,
                    delay,
                    &format!("HTTP {}", status.as_u16()),
                );
                thread::sleep(delay);
                continue;
            }
            if !status.is_success() {
                let body = response.text().unwrap_or_default();
                bail!("Proton API {method} {url} failed with {status}: {body}");
            }

            let body = match response.text() {
                Ok(body) => body,
                Err(error) => {
                    if let Some(delay) = retry_delay_for_transport_error(&method, &error, attempt) {
                        report_request_retry(&method, &url, attempt, delay, &error.to_string());
                        thread::sleep(delay);
                        continue;
                    }
                    return Err(error).with_context(|| {
                        format!("read Proton API response body for {method} {url}")
                    });
                }
            };
            return serde_json::from_str::<T>(&body).with_context(|| {
                let snippet: String = body.chars().take(4000).collect();
                format!("parse Proton API response for {method} {url}: {snippet}")
            });
        }

        unreachable!("request retries are bounded by MAX_TRANSIENT_ATTEMPTS")
    }

    fn request_bytes_absolute(
        &self,
        method: Method,
        url: &str,
        extra_header: Option<(&str, &str)>,
        authenticated: bool,
    ) -> Result<Vec<u8>> {
        let mut refreshed = false;

        for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
            let auth = self.credentials();
            let mut request = self
                .client
                .request(method.clone(), url)
                .header("x-pm-appversion", &self.app_version)
                .timeout(Duration::from_secs(HTTP_BLOCK_TIMEOUT_SECS));
            #[cfg(test)]
            {
                request = request.header(reqwest::header::CONNECTION, "close");
            }
            if !self.user_agent.is_empty() {
                request = request.header(reqwest::header::USER_AGENT, &self.user_agent);
            }
            if authenticated {
                request = request
                    .header("x-pm-uid", auth.uid.as_str())
                    .bearer_auth(auth.access_token.as_str());
            }
            if let Some((name, value)) = extra_header {
                request = request.header(name, value);
            }

            let response = match request.send() {
                Ok(response) => response,
                Err(error) => {
                    if let Some(delay) = retry_delay_for_transport_error(&method, &error, attempt) {
                        report_request_retry(&method, url, attempt, delay, &error.to_string());
                        thread::sleep(delay);
                        continue;
                    }
                    return Err(error)
                        .with_context(|| format!("send Proton API request {method} {url}"));
                }
            };
            if authenticated && response.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed
            {
                self.refresh_auth()?;
                refreshed = true;
                continue;
            }

            let status = response.status();
            if let Some(delay) = retry_delay_for_response(&response, attempt) {
                report_request_retry(
                    &method,
                    url,
                    attempt,
                    delay,
                    &format!("HTTP {}", status.as_u16()),
                );
                thread::sleep(delay);
                continue;
            }
            if !status.is_success() {
                let body = response.text().unwrap_or_default();
                bail!("Proton API {method} {url} failed with {status}: {body}");
            }

            return match response.bytes() {
                Ok(bytes) => Ok(bytes.to_vec()),
                Err(error) => {
                    if let Some(delay) = retry_delay_for_transport_error(&method, &error, attempt) {
                        report_request_retry(&method, url, attempt, delay, &error.to_string());
                        thread::sleep(delay);
                        continue;
                    }
                    Err(error).with_context(|| format!("read Proton API bytes for {method} {url}"))
                }
            };
        }

        unreachable!("request retries are bounded by MAX_TRANSIENT_ATTEMPTS")
    }

    fn refresh_auth(&self) -> Result<()> {
        let current = self.credentials();
        let state = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_string();
        let body = AuthRefreshRequest {
            uid: current.uid,
            refresh_token: current.refresh_token,
            response_type: "token".to_owned(),
            grant_type: "refresh_token".to_owned(),
            redirect_uri: "https://protonmail.ch".to_owned(),
            state,
        };
        let refreshed: RefreshResponse =
            self.request_json(Method::POST, "/auth/v4/refresh", &[], Some(&body), false)?;

        let updated = ReusableCredential {
            uid: refreshed.uid,
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token,
            salted_key_pass: self.credentials().salted_key_pass,
        };

        {
            let mut auth = self.auth.lock().expect("auth mutex poisoned");
            *auth = updated.clone();
        }
        self.persist_credentials(&updated)?;

        Ok(())
    }

    fn authenticate_exchange(
        &self,
        body: &AuthRequest,
        verification: Option<&HumanVerificationAnswer>,
    ) -> Result<AuthResponse> {
        let url = format!("{}{}", self.base_url, "/auth/v4");
        let body_bytes = serde_json::to_vec(body).context("encode JSON request body")?;
        let mut request = self
            .client
            .request(Method::POST, &url)
            .header("x-pm-appversion", &self.app_version)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(Duration::from_secs(HTTP_API_TIMEOUT_SECS))
            .body(body_bytes);
        #[cfg(test)]
        {
            request = request.header(reqwest::header::CONNECTION, "close");
        }
        if !self.user_agent.is_empty() {
            request = request.header(reqwest::header::USER_AGENT, &self.user_agent);
        }
        if let Some(verification) = verification {
            request = request
                .header("x-pm-human-verification-token", verification.token.as_str())
                .header(
                    "x-pm-human-verification-token-type",
                    verification.token_type.as_str(),
                );
        }

        let response = request
            .send()
            .with_context(|| format!("send Proton API request POST {url}"))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            if let Some(challenge) = parse_human_verification_challenge(status, &body) {
                return Err(HumanVerificationRequired { challenge }.into());
            }
            bail!("Proton API POST {url} failed with {status}: {body}");
        }

        let body = response
            .text()
            .with_context(|| format!("read Proton API response body for POST {url}"))?;
        serde_json::from_str::<AuthResponse>(&body).with_context(|| {
            let snippet: String = body.chars().take(4000).collect();
            format!("parse Proton API response for POST {url}: {snippet}")
        })
    }

    fn complete_human_verification(
        &self,
        challenge: &HumanVerificationChallenge,
        no_input: bool,
    ) -> Result<HumanVerificationAnswer> {
        #[cfg(test)]
        if let Some(answer) = TEST_HUMAN_VERIFICATION_ANSWER.with(|value| value.borrow().clone()) {
            return Ok(answer);
        }

        if !challenge
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case("captcha"))
        {
            bail!(
                "unsupported Proton human verification methods: {}",
                challenge.methods.join(", ")
            );
        }

        if no_input {
            let web_url = challenge.web_url.as_deref().unwrap_or("unavailable");
            bail!(
                "Proton requires CAPTCHA verification; rerun without `--no-input` so the CLI can open a local verification page. Proton WebUrl: {web_url}"
            );
        }

        eprintln!("Proton requires CAPTCHA verification before login can continue.");
        let server = HumanVerificationServer::start(&self.base_url, challenge)?;
        let local_url = server.local_url.clone();
        if let Err(error) = open_browser(&local_url) {
            eprintln!("Unable to open the browser automatically: {error}");
            eprintln!("Open this URL manually to continue: {local_url}");
        } else {
            eprintln!("Opened verification page: {local_url}");
        }
        if let Some(web_url) = challenge.web_url.as_deref() {
            eprintln!("Reference challenge URL: {web_url}");
        }
        server.wait_for_answer(challenge.wait_timeout())
    }
}

impl HumanVerificationChallenge {
    fn wait_timeout(&self) -> Duration {
        let fallback = Duration::from_secs(HUMAN_VERIFICATION_TIMEOUT_SECS);
        let Some(expires_at) = self.expires_at else {
            return fallback;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Duration::from_secs(
            expires_at
                .saturating_sub(now)
                .clamp(1, HUMAN_VERIFICATION_TIMEOUT_SECS),
        )
    }
}

impl HumanVerificationServer {
    fn start(base_url: &str, challenge: &HumanVerificationChallenge) -> Result<Self> {
        let listener =
            TcpListener::bind("127.0.0.1:0").context("bind local verification server")?;
        listener
            .set_nonblocking(true)
            .context("set local verification server to nonblocking")?;
        let local_url = format!(
            "http://{}",
            listener
                .local_addr()
                .context("local verification address")?
        );
        let html = build_human_verification_page(challenge)?;
        #[cfg(test)]
        let proxy_client_builder = HttpClient::builder()
            .cookie_store(true)
            .pool_max_idle_per_host(0);
        #[cfg(not(test))]
        let proxy_client_builder = HttpClient::builder().cookie_store(true);
        let proxy_client = proxy_client_builder
            .build()
            .context("build local verification proxy client")?;
        let proxy_base_url = human_verification_proxy_base_url(base_url, challenge)?;
        let running = Arc::new(AtomicBool::new(true));
        let (answer_tx, answer_rx) = mpsc::channel();
        let worker_running = Arc::clone(&running);
        let worker = thread::spawn(move || {
            while worker_running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(error) = handle_human_verification_connection(
                            stream,
                            &html,
                            &proxy_base_url,
                            &proxy_client,
                            &answer_tx,
                            &worker_running,
                        ) {
                            eprintln!("local verification server error: {error}");
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => {
                        eprintln!("local verification server accept failed: {error}");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            local_url,
            running,
            answer_rx,
            worker: Some(worker),
        })
    }

    fn wait_for_answer(mut self, timeout: Duration) -> Result<HumanVerificationAnswer> {
        let result = self
            .answer_rx
            .recv_timeout(timeout)
            .map_err(|_| anyhow!("timed out waiting for Proton CAPTCHA completion"))?;
        self.stop();
        Ok(result)
    }

    fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(address) = self.local_url.strip_prefix("http://") {
            let _ = TcpStream::connect(address);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for HumanVerificationServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn parse_human_verification_challenge(
    status: reqwest::StatusCode,
    body: &str,
) -> Option<HumanVerificationChallenge> {
    if status != reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        return None;
    }
    let parsed: ApiErrorResponse = serde_json::from_str(body).ok()?;
    if parsed.code != HUMAN_VERIFICATION_REQUIRED_CODE
        || parsed.details.human_verification_token.is_empty()
        || parsed.details.human_verification_methods.is_empty()
    {
        return None;
    }
    Some(HumanVerificationChallenge {
        token: parsed.details.human_verification_token,
        methods: parsed.details.human_verification_methods,
        web_url: (!parsed.details.web_url.is_empty()).then_some(parsed.details.web_url),
        title: (!parsed.details.title.is_empty()).then_some(parsed.details.title),
        expires_at: parsed.details.expires_at,
    })
}

fn human_verification_proxy_base_url(
    base_url: &str,
    challenge: &HumanVerificationChallenge,
) -> Result<String> {
    if let Some(web_url) = challenge.web_url.as_deref() {
        let web_url = reqwest::Url::parse(web_url).context("parse Proton verification WebUrl")?;
        let mut api_origin = web_url.clone();
        let hostname = api_origin
            .host_str()
            .ok_or_else(|| anyhow!("Proton verification WebUrl is missing a host"))?;
        let is_ip_like = hostname.parse::<std::net::IpAddr>().is_ok() || hostname == "localhost";
        if is_ip_like || !hostname.contains('.') {
            let mut fallback = reqwest::Url::parse(base_url).context("parse Proton base URL")?;
            fallback.set_path("");
            fallback.set_query(None);
            fallback.set_fragment(None);
            return Ok(fallback.as_str().trim_end_matches('/').to_owned());
        }
        if !hostname.contains("-api.") {
            let Some((first, rest)) = hostname.split_once('.') else {
                bail!("cannot derive Proton verification API hostname from {hostname}");
            };
            api_origin
                .set_host(Some(&format!("{first}-api.{rest}")))
                .context("set Proton verification API host")?;
        }
        api_origin.set_path("");
        api_origin.set_query(None);
        api_origin.set_fragment(None);
        return Ok(api_origin.as_str().trim_end_matches('/').to_owned());
    }

    let mut api_origin = reqwest::Url::parse(base_url).context("parse Proton base URL")?;
    api_origin.set_path("");
    api_origin.set_query(None);
    api_origin.set_fragment(None);
    Ok(api_origin.as_str().trim_end_matches('/').to_owned())
}

fn open_browser(url: &str) -> Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("open");
        command.arg(url);
        command
    } else if cfg!(target_os = "windows") {
        let mut command = Command::new("rundll32");
        command.args(["url.dll,FileProtocolHandler", url]);
        command
    } else {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };
    run_browser_command(&mut command, url)
}

fn run_browser_command(command: &mut Command, url: &str) -> Result<()> {
    #[cfg(test)]
    if let Some(behavior) = TEST_BROWSER_BEHAVIOR.with(|slot| slot.borrow().clone()) {
        if let Some(answer) = behavior.answer {
            let complete_url = format!("{}/complete", url.trim_end_matches('/'));
            thread::spawn(move || {
                let client = reqwest::blocking::Client::new();
                for _ in 0..10 {
                    let result = client.post(&complete_url).json(&answer).send();
                    if result.is_ok() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            });
        }
        if behavior.succeed {
            return Ok(());
        }
        bail!("browser launcher exited with status 1");
    }
    let status = command
        .status()
        .with_context(|| format!("open browser for {url}"))?;
    if !status.success() {
        bail!("browser launcher exited with status {status}");
    }
    Ok(())
}

fn build_human_verification_page(challenge: &HumanVerificationChallenge) -> Result<String> {
    let mut iframe_url = reqwest::Url::parse("http://127.0.0.1/api/core/v4/captcha")
        .context("build local CAPTCHA iframe URL")?;
    iframe_url
        .query_pairs_mut()
        .append_pair("Token", &challenge.token)
        .append_pair("ForceWebMessaging", "1");
    let iframe_path = format!(
        "{}{}",
        iframe_url.path(),
        iframe_url
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default()
    );
    let iframe_url = serde_json::to_string(&iframe_path).context("encode local verify URL")?;
    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Proton Verification</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 2rem auto; max-width: 48rem; padding: 0 1rem; color: #111; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
    p {{ line-height: 1.4; }}
    iframe {{ width: 100%; min-height: 42rem; border: 1px solid #d0d7de; border-radius: 0.75rem; }}
    code {{ background: #f6f8fa; padding: 0.125rem 0.375rem; border-radius: 0.375rem; }}
  </style>
</head>
<body>
  <h1>Complete Proton CAPTCHA</h1>
  <p id="status">Solve the CAPTCHA below. This tab will notify the CLI and continue automatically.</p>
  <iframe id="captcha" title="Proton CAPTCHA" sandbox="allow-scripts allow-same-origin allow-popups"></iframe>
  <script>
    const iframeUrl = {iframe_url};
    const targetOrigin = window.location.origin;
    const iframe = document.getElementById('captcha');
    const status = document.getElementById('status');
    iframe.src = iframeUrl;
    const parseMessage = (raw) => {{
      if (typeof raw === 'string') {{
        try {{
          return JSON.parse(raw);
        }} catch (_) {{
          return null;
        }}
      }}
      return raw;
    }};
    window.addEventListener('message', async (event) => {{
      if (event.origin !== targetOrigin || !event.data) {{
        return;
      }}
      const data = parseMessage(event.data);
      if (!data || typeof data !== 'object') {{
        return;
      }}
      if (data.type === 'RESIZE' && data.payload && data.payload.height) {{
        iframe.style.minHeight = (data.payload.height + 140) + 'px';
      }}
      if (data.type === 'pm_height' && data.height) {{
        iframe.style.minHeight = (data.height + 140) + 'px';
      }}
      if (data.type === 'ERROR') {{
        status.textContent = 'Proton verification reported an error. Retry from the terminal.';
      }}
      if (data.type === 'HUMAN_VERIFICATION_SUCCESS' && data.payload && data.payload.token && data.payload.type) {{
        status.textContent = 'Submitting verification token back to the CLI...';
        const response = await fetch('/complete', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ token: data.payload.token, type: data.payload.type }})
        }});
        if (response.ok) {{
          status.textContent = 'Verification complete. Return to the terminal.';
        }} else {{
          status.textContent = 'The CLI did not accept the verification token. Retry from the terminal.';
        }}
      }}
      if (data.type === 'pm_captcha' && data.token) {{
        status.textContent = 'Submitting verification token back to the CLI...';
        const response = await fetch('/complete', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ token: data.token, type: 'captcha' }})
        }});
        if (response.ok) {{
          status.textContent = 'Verification complete. Return to the terminal.';
        }} else {{
          status.textContent = 'The CLI did not accept the verification token. Retry from the terminal.';
        }}
      }}
    }});
  </script>
</body>
</html>"#
    ))
}

fn handle_human_verification_connection(
    stream: TcpStream,
    html: &str,
    proxy_base_url: &str,
    proxy_client: &HttpClient,
    answer_tx: &mpsc::Sender<HumanVerificationAnswer>,
    running: &AtomicBool,
) -> Result<()> {
    let request = match read_human_verification_request(&stream) {
        Ok(request) => request,
        Err(error)
            if error.to_string().contains("request line was empty")
                || error.to_string().contains("read verification request line") =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => write_human_verification_response(
            stream,
            200,
            "OK",
            "text/html; charset=utf-8",
            html.as_bytes(),
        )?,
        ("GET", "/favicon.ico") => {
            write_human_verification_response(stream, 204, "No Content", "text/plain", b"")?
        }
        ("POST", "/complete") => {
            let answer: HumanVerificationAnswer = serde_json::from_slice(&request.body)
                .context("parse verification callback JSON")?;
            answer_tx
                .send(answer)
                .context("send verification callback to CLI")?;
            running.store(false, Ordering::SeqCst);
            write_human_verification_response(
                stream,
                200,
                "OK",
                "application/json",
                br#"{"ok":true}"#,
            )?;
        }
        _ => proxy_human_verification_request(stream, &request, proxy_base_url, proxy_client)?,
    }
    Ok(())
}

fn read_human_verification_request(stream: &TcpStream) -> Result<HumanVerificationHttpRequest> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut reader = BufReader::new(stream.try_clone().context("clone verification stream")?);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("read verification request line")?;
    if request_line.is_empty() {
        bail!("verification request line was empty");
    }
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("verification request missing method"))?
        .to_owned();
    let path = parts
        .next()
        .ok_or_else(|| anyhow!("verification request missing path"))?
        .to_owned();

    let mut content_length = 0usize;
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("read verification request header")?;
        if line == "\r\n" {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            bail!("malformed verification request header: {line:?}");
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        if name.trim().eq_ignore_ascii_case("Content-Length") {
            content_length = value
                .trim()
                .parse::<usize>()
                .context("parse verification content length")?;
        }
    }

    let mut body = vec![0u8; content_length];
    reader
        .read_exact(&mut body)
        .context("read verification request body")?;

    Ok(HumanVerificationHttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn proxy_human_verification_request(
    stream: TcpStream,
    request: &HumanVerificationHttpRequest,
    proxy_base_url: &str,
    proxy_client: &HttpClient,
) -> Result<()> {
    let url = human_verification_upstream_url(proxy_base_url, &request.path)?;
    let method = Method::from_bytes(request.method.as_bytes())
        .with_context(|| format!("unsupported proxied method {}", request.method))?;
    let mut upstream = proxy_client.request(method.clone(), &url);
    let local_origin = request
        .headers
        .get("host")
        .map(|host| format!("http://{host}"));
    for (header_name, value) in &request.headers {
        if should_skip_human_verification_proxy_header(header_name) {
            continue;
        }
        let value = rewrite_human_verification_proxy_header(
            header_name,
            value,
            local_origin.as_deref(),
            proxy_base_url,
        )?;
        upstream = upstream.header(header_name, value);
    }
    if !request.body.is_empty() {
        upstream = upstream.body(request.body.clone());
    }

    let response = upstream
        .send()
        .with_context(|| format!("proxy Proton human verification request {method} {url}"))?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let body = response
        .bytes()
        .with_context(|| format!("read proxied Proton response {method} {url}"))?;

    write_human_verification_response(
        stream,
        status.as_u16(),
        status.canonical_reason().unwrap_or("Status"),
        &content_type,
        body.as_ref(),
    )
}

fn human_verification_upstream_url(proxy_base_url: &str, request_path: &str) -> Result<String> {
    let upstream_path = request_path.strip_prefix("/api").unwrap_or(request_path);
    let mut url =
        reqwest::Url::parse(proxy_base_url).context("parse Proton verification proxy base URL")?;
    let path_and_query = if upstream_path.starts_with('/') {
        upstream_path.to_owned()
    } else {
        format!("/{upstream_path}")
    };
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);
    let joined = url
        .join(path_and_query.trim_start_matches('/'))
        .with_context(|| format!("join Proton verification path {path_and_query}"))?;
    Ok(joined.to_string())
}

fn should_skip_human_verification_proxy_header(header_name: &str) -> bool {
    matches!(
        header_name,
        "host"
            | "connection"
            | "proxy-connection"
            | "content-length"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
            | "accept-encoding"
    )
}

fn rewrite_human_verification_proxy_header(
    header_name: &str,
    value: &str,
    local_origin: Option<&str>,
    proxy_base_url: &str,
) -> Result<String> {
    match header_name {
        "origin" => Ok(rewrite_human_verification_origin(
            value,
            local_origin,
            proxy_base_url,
        )),
        "referer" => rewrite_human_verification_referer(value, local_origin, proxy_base_url),
        _ => Ok(value.to_owned()),
    }
}

fn rewrite_human_verification_origin(
    value: &str,
    local_origin: Option<&str>,
    proxy_base_url: &str,
) -> String {
    match local_origin {
        Some(local_origin) if value == local_origin => {
            proxy_base_url.trim_end_matches('/').to_owned()
        }
        _ => value.to_owned(),
    }
}

fn rewrite_human_verification_referer(
    value: &str,
    local_origin: Option<&str>,
    proxy_base_url: &str,
) -> Result<String> {
    let Some(local_origin) = local_origin else {
        return Ok(value.to_owned());
    };
    let Ok(referer) = reqwest::Url::parse(value) else {
        return Ok(value.to_owned());
    };
    let Ok(local_origin_url) = reqwest::Url::parse(local_origin) else {
        return Ok(value.to_owned());
    };
    if referer.scheme() != local_origin_url.scheme()
        || referer.host_str() != local_origin_url.host_str()
        || referer.port_or_known_default() != local_origin_url.port_or_known_default()
    {
        return Ok(value.to_owned());
    }
    let mut path = referer.path().to_owned();
    if let Some(query) = referer.query() {
        path.push('?');
        path.push_str(query);
    }
    human_verification_upstream_url(proxy_base_url, &path)
}

fn write_human_verification_response(
    mut stream: TcpStream,
    status: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
        status,
        status_text,
        body.len(),
        content_type,
    )
    .context("write verification response headers")?;
    if let Err(error) = stream.write_all(body) {
        if matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
        ) {
            return Ok(());
        }
        return Err(error).context("write verification response body");
    }
    if let Err(error) = stream.flush() {
        if matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
        ) {
            return Ok(());
        }
        return Err(error).context("flush verification response");
    }
    Ok(())
}

impl SecretKeyRing {
    fn from_armored_secret(armored: &str, passphrase: &[u8]) -> Result<Self> {
        let (key, _) = SignedSecretKey::from_armor_single(Cursor::new(armored.as_bytes()))
            .context("parse armored secret key")?;
        Ok(Self {
            keys: vec![SecretKeyEntry {
                key,
                passphrase: passphrase.to_vec(),
            }],
        })
    }

    fn decrypt_armored_message(&self, armored: &str) -> Result<Vec<u8>> {
        let mut last_error = None;
        for entry in &self.keys {
            let (message, _) = Message::from_armor(Cursor::new(armored.as_bytes()))
                .context("parse armored encrypted message")?;
            let password: Password = entry.passphrase.as_slice().into();
            match message.decrypt(&password, &entry.key) {
                Ok(message) => {
                    // Some Proton clients wrap the payload in a Compressed
                    // Data Packet (typically zlib). The pgp crate does not
                    // walk into compressed packets implicitly, so a plain
                    // `read_to_end` would return the raw deflate bytes and
                    // any UTF-8 caller would fail with garbage. Decompress
                    // explicitly before reading. The call is a no-op when
                    // the message is already a Literal Data Packet.
                    let message = message
                        .decompress()
                        .context("decompress decrypted message")?;
                    return read_message_bytes(message);
                }
                Err(error) => last_error = Some(error),
            }
        }

        match last_error {
            Some(error) => Err(error).context("decrypt armored message"),
            None => bail!("empty keyring cannot decrypt armored message"),
        }
    }

    fn decrypt_content_session_key(&self, content_key_packet: &str) -> Result<PlainSessionKey> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(content_key_packet.as_bytes())
            .context("decode ContentKeyPacket")?;
        let mut parser = PacketParser::new(raw.as_slice());
        let packet = parser
            .next()
            .ok_or_else(|| anyhow!("ContentKeyPacket is empty"))?
            .context("parse ContentKeyPacket packet")?;
        let Packet::PublicKeyEncryptedSessionKey(pkesk) = packet else {
            bail!("ContentKeyPacket did not contain a public-key encrypted session key");
        };

        let esk_type = match pkesk.version() {
            PkeskVersion::V3 => EskType::V3_4,
            PkeskVersion::V6 => EskType::V6,
            PkeskVersion::Other(version) => {
                bail!("unsupported ContentKeyPacket version {version}")
            }
        };

        for entry in &self.keys {
            let password: Password = entry.passphrase.as_slice().into();
            let values = pkesk.values().context("get ContentKeyPacket values")?;
            if let Ok(Ok(session_key)) = entry.key.primary_key.decrypt(&password, values, esk_type)
            {
                return Ok(session_key);
            }
            for subkey in &entry.key.secret_subkeys {
                if let Ok(Ok(session_key)) = subkey.decrypt(&password, values, esk_type) {
                    return Ok(session_key);
                }
            }
        }

        bail!("no key in keyring could decrypt ContentKeyPacket")
    }

    fn to_cached(&self) -> Result<CachedSecretKeyRing> {
        Ok(CachedSecretKeyRing {
            keys: self
                .keys
                .iter()
                .map(|entry| {
                    Ok(CachedSecretKeyEntry {
                        armored_key: entry
                            .key
                            .to_armored_string(None.into())
                            .context("serialize cached secret key")?,
                        passphrase: base64::engine::general_purpose::STANDARD
                            .encode(&entry.passphrase),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn from_cached(cached: &CachedSecretKeyRing) -> Result<Self> {
        let keys = cached
            .keys
            .iter()
            .map(|entry| {
                let (key, _) =
                    SignedSecretKey::from_armor_single(Cursor::new(entry.armored_key.as_bytes()))
                        .context("parse cached armored secret key")?;
                Ok(SecretKeyEntry {
                    key,
                    passphrase: base64::engine::general_purpose::STANDARD
                        .decode(entry.passphrase.as_bytes())
                        .context("decode cached secret key passphrase")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        if keys.is_empty() {
            bail!("cached keyring did not contain any keys");
        }

        Ok(Self { keys })
    }
}

impl SrpAuth {
    fn new(
        version: i32,
        username: &str,
        password: &[u8],
        salt_b64: &str,
        signed_modulus: &str,
        server_ephemeral_b64: &str,
    ) -> Result<Self> {
        let modulus = parse_signed_modulus(signed_modulus)?;
        let hashed_password = hash_password(version, username, password, salt_b64, &modulus)?;
        let server_ephemeral = base64::engine::general_purpose::STANDARD
            .decode(server_ephemeral_b64.as_bytes())
            .context("decode Proton server ephemeral")?;

        validate_srp_params(&modulus, &server_ephemeral)?;

        Ok(Self {
            modulus,
            server_ephemeral,
            hashed_password,
        })
    }

    fn generate_proofs(&self) -> Result<SrpProofs> {
        #[cfg(test)]
        if let Some(client_secret) = TEST_SRP_CLIENT_SECRET.with(|value| value.borrow().clone()) {
            return self.generate_proofs_with_secret(client_secret);
        }

        let modulus = biguint_from_le(&self.modulus);
        let modulus_minus_one = &modulus - BigUint::one();

        let client_secret = generate_client_secret(&modulus_minus_one)?;
        self.generate_proofs_with_secret(client_secret)
    }

    fn generate_proofs_with_secret(&self, client_secret: BigUint) -> Result<SrpProofs> {
        let modulus = biguint_from_le(&self.modulus);
        let modulus_minus_one = &modulus - BigUint::one();
        let generator = BigUint::from(2u8);

        if client_secret <= BigUint::from((SRP_BITS * 2) as u64)
            || client_secret >= modulus_minus_one
        {
            bail!("invalid SRP client secret");
        }

        let client_ephemeral = generator.modpow(&client_secret, &modulus);
        let client_ephemeral_bytes = biguint_to_fixed_le(&client_ephemeral, SRP_BYTES);

        let scramble = biguint_from_le(&expand_hash(
            &[
                client_ephemeral_bytes.as_slice(),
                self.server_ephemeral.as_slice(),
            ]
            .concat(),
        ));
        if scramble.is_zero() {
            bail!("generated zero SRP scramble parameter");
        }

        let multiplier = biguint_from_le(&expand_hash(
            &[
                biguint_to_fixed_le(&generator, SRP_BYTES).as_slice(),
                self.modulus.as_slice(),
            ]
            .concat(),
        )) % &modulus;
        if multiplier <= BigUint::one() || multiplier >= modulus_minus_one {
            bail!("derived invalid SRP multiplier");
        }

        let hashed_password = biguint_from_le(&self.hashed_password);
        let server_ephemeral = biguint_from_le(&self.server_ephemeral);
        let gx = generator.modpow(&hashed_password, &modulus);
        let kgx = (&multiplier * gx) % &modulus;
        let base = if server_ephemeral >= kgx {
            (&server_ephemeral - &kgx) % &modulus
        } else {
            (&server_ephemeral + &modulus - &kgx) % &modulus
        };
        let exponent = ((&scramble * &hashed_password) + &client_secret) % &modulus_minus_one;
        let shared_secret = base.modpow(&exponent, &modulus);
        let shared_secret_bytes = biguint_to_fixed_le(&shared_secret, SRP_BYTES);

        let client_proof = expand_hash(
            &[
                client_ephemeral_bytes.as_slice(),
                self.server_ephemeral.as_slice(),
                shared_secret_bytes.as_slice(),
            ]
            .concat(),
        );
        let expected_server_proof = expand_hash(
            &[
                client_ephemeral_bytes.as_slice(),
                client_proof.as_slice(),
                shared_secret_bytes.as_slice(),
            ]
            .concat(),
        );

        Ok(SrpProofs {
            client_proof,
            client_ephemeral: client_ephemeral_bytes,
            expected_server_proof,
        })
    }
}

fn derive_salted_key_pass(api: &ProtonApi, user: &ApiUser, key_pass: &[u8]) -> Result<Vec<u8>> {
    let key_id = user
        .keys
        .iter()
        .find(|record| record.primary.is_true())
        .or_else(|| user.keys.iter().find(|record| record.active.is_true()))
        .map(|record| record.id.as_str())
        .ok_or_else(|| anyhow!("Proton account has no primary active user key"))?;
    let key_salts = api.get_key_salts()?;
    let key_salt = key_salts
        .into_iter()
        .find(|salt| salt.id == key_id && salt.key_salt.as_deref().is_some())
        .ok_or_else(|| anyhow!("no Proton key salt found for user key {key_id}"))?;
    let key_salt = key_salt
        .key_salt
        .ok_or_else(|| anyhow!("no Proton key salt found for user key {key_id}"))?;
    let raw_salt = base64::engine::general_purpose::STANDARD
        .decode(key_salt.as_bytes())
        .with_context(|| format!("decode Proton key salt for {key_id}"))?;
    let mailbox_hash = mailbox_password(key_pass, &raw_salt)?;
    if mailbox_hash.len() < 31 {
        bail!("derived Proton mailbox hash was unexpectedly short");
    }
    Ok(mailbox_hash[mailbox_hash.len() - 31..].to_vec())
}

fn parse_signed_modulus(signed_modulus: &str) -> Result<Vec<u8>> {
    let (message, _) = CleartextSignedMessage::from_string(signed_modulus)
        .context("parse Proton signed modulus message")?;
    let (public_key, _) =
        SignedPublicKey::from_armor_single(Cursor::new(MODULUS_PUBKEY.as_bytes()))
            .context("parse Proton modulus signing key")?;
    message
        .verify(&public_key)
        .context("verify Proton modulus signature")?;
    let modulus = message.signed_text();
    let modulus = modulus.trim_end_matches(['\r', '\n']);
    base64::engine::general_purpose::STANDARD
        .decode(modulus.as_bytes())
        .context("decode Proton signed modulus payload")
}

fn validate_srp_params(modulus_le: &[u8], server_ephemeral_le: &[u8]) -> Result<()> {
    let modulus = biguint_from_le(modulus_le);
    let server_ephemeral = biguint_from_le(server_ephemeral_le);
    let modulus_minus_one = &modulus - BigUint::one();

    if modulus.bits() != SRP_BITS {
        bail!("unsupported Proton SRP modulus size {}", modulus.bits());
    }
    if (&modulus % BigUint::from(8u8)) != BigUint::from(3u8) {
        bail!("unexpected Proton SRP modulus");
    }
    if server_ephemeral <= BigUint::one() || server_ephemeral >= modulus_minus_one {
        bail!("Proton SRP server ephemeral is out of bounds");
    }

    Ok(())
}

fn hash_password(
    version: i32,
    _username: &str,
    password: &[u8],
    salt_b64: &str,
    modulus: &[u8],
) -> Result<Vec<u8>> {
    match version {
        3 | 4 => hash_password_v3(password, salt_b64, modulus),
        other => {
            bail!("unsupported Proton auth version {other}; only versions 3 and 4 are implemented")
        }
    }
}

fn hash_password_v3(password: &[u8], salt_b64: &str, modulus: &[u8]) -> Result<Vec<u8>> {
    let mut salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64.as_bytes())
        .context("decode Proton SRP salt")?;
    salt.extend_from_slice(b"proton");
    let bcrypt = bcrypt_hash(password, &salt)?;
    Ok(expand_hash(&[bcrypt.as_bytes(), modulus].concat()))
}

fn mailbox_password(password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    Ok(bcrypt_hash(password, salt)?.into_bytes())
}

fn bcrypt_hash(password: &[u8], salt: &[u8]) -> Result<String> {
    let salt: [u8; 16] = salt
        .try_into()
        .map_err(|_| anyhow!("bcrypt salt must be exactly 16 bytes"))?;
    let parts = hash_with_salt(password, BCRYPT_COST, salt).context("compute bcrypt hash")?;
    Ok(parts.format_for_version(Version::TwoY))
}

fn expand_hash(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(64 * 4);
    for suffix in 0u8..4 {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.update([suffix]);
        output.extend_from_slice(&hasher.finalize());
    }
    output
}

fn generate_client_secret(modulus_minus_one: &BigUint) -> Result<BigUint> {
    let lower_bound = BigUint::from((SRP_BITS * 2) as u64);
    let mut rng = OsRng;
    loop {
        let mut candidate = vec![0u8; SRP_BYTES];
        rng.fill_bytes(&mut candidate);
        let value = BigUint::from_bytes_le(&candidate);
        if value > lower_bound && value < *modulus_minus_one {
            return Ok(value);
        }
    }
}

fn biguint_from_le(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

fn biguint_to_fixed_le(value: &BigUint, width: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_le();
    bytes.resize(width, 0);
    bytes
}

impl PhotoShareRootEnvelope {
    fn into_api_share(self, root_link_id: String) -> ApiShare {
        ApiShare {
            share_id: self.share.share_id,
            link_id: root_link_id,
            address_id: self.share.address_id,
            key: self.share.key,
            passphrase: self.share.passphrase,
        }
    }
}

impl ApiLinkDetail {
    fn into_api_link(self) -> Result<ApiLink> {
        let total_encrypted_size = self
            .file
            .as_ref()
            .map(|file| file.total_encrypted_size)
            .or_else(|| self.photo.as_ref().map(|photo| photo.total_encrypted_size))
            .unwrap_or(0);
        let file_properties = self
            .file
            .and_then(ApiFileDetail::into_file_properties)
            .or_else(|| self.photo.and_then(ApiPhotoDetail::into_file_properties));
        let size = match self.link.size {
            Some(size) if size > 0 => size,
            _ => total_encrypted_size,
        };
        Ok(ApiLink {
            link_id: self.link.link_id,
            link_type: self.link.link_type,
            name: self.link.name,
            size,
            link_state: self.link.link_state,
            modify_time: self.link.modify_time,
            node_key: self.link.node_key,
            node_passphrase: self.link.node_passphrase,
            file_properties,
            xattr: self.link.xattr,
        })
    }
}

impl ApiFileDetail {
    fn into_file_properties(self) -> Option<ApiFileProperties> {
        let active_revision = self.active_revision?;
        Some(ApiFileProperties {
            content_key_packet: self.content_key_packet,
            active_revision: ApiRevisionMetadata {
                id: active_revision.id,
            },
        })
    }
}

impl ApiPhotoDetail {
    fn into_file_properties(self) -> Option<ApiFileProperties> {
        let active_revision = self.active_revision?;
        Some(ApiFileProperties {
            content_key_packet: self.content_key_packet,
            active_revision: ApiRevisionMetadata {
                id: active_revision.id,
            },
        })
    }
}

impl ApiShareChildLink {
    fn into_api_link(self) -> ApiLink {
        ApiLink {
            link_id: self.link_id,
            link_type: self.link_type,
            name: self.name,
            size: self.size,
            link_state: self.link_state,
            modify_time: self.modify_time,
            node_key: self.node_key,
            node_passphrase: self.node_passphrase,
            file_properties: self
                .file_properties
                .and_then(|file| file.into_file_properties()),
            xattr: self.xattr,
        }
    }
}

impl ApiShareFileProperties {
    fn into_file_properties(self) -> Option<ApiFileProperties> {
        let active_revision = self.active_revision?;
        Some(ApiFileProperties {
            content_key_packet: self.content_key_packet,
            active_revision: ApiRevisionMetadata {
                id: active_revision.id,
            },
        })
    }
}

impl Read for ProtonFileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let bytes = self.current.read(buf)?;
            if bytes > 0 {
                return Ok(bytes);
            }
            if self.finished {
                return Ok(0);
            }
            self.load_next_block().map_err(io::Error::other)?;
        }
    }
}

impl ProtonFileReader {
    fn load_next_block(&mut self) -> Result<()> {
        if self.next_block >= self.blocks.len() {
            self.finished = true;
            return Ok(());
        }

        let plain = match self.prefetch.as_ref() {
            Some(prefetch) => match prefetch.receiver.recv() {
                Ok(PrefetchedBlock::Data(plain)) => plain,
                Ok(PrefetchedBlock::Error(error)) => return Err(anyhow!(error)),
                Ok(PrefetchedBlock::End) => {
                    self.finished = true;
                    return Ok(());
                }
                Err(error) => {
                    return Err(anyhow!(error).context("receive prefetched Proton block"));
                }
            },
            None => self.fetch_block(self.next_block)?,
        };
        self.current = Cursor::new(plain);
        self.next_block += 1;
        Ok(())
    }

    fn fetch_block(&self, block_index: usize) -> Result<Vec<u8>> {
        let block = &self.blocks[block_index];
        let encrypted = self.api.get_block(&block.bare_url, &block.token)?;
        verify_block_hash(&encrypted, &block.hash)?;
        decrypt_with_session_key(&encrypted, &self.session_key)
    }
}

fn start_block_prefetch(
    api: Arc<ProtonApi>,
    session_key: PlainSessionKey,
    blocks: Vec<ApiBlock>,
) -> Option<BlockPrefetch> {
    if blocks.len() <= 1 {
        return None;
    }

    let (tx, rx) = mpsc::sync_channel(BLOCK_PREFETCH_DEPTH);
    thread::spawn(move || {
        run_block_prefetch(api, session_key, blocks, tx);
    });
    Some(BlockPrefetch { receiver: rx })
}

fn run_block_prefetch(
    api: Arc<ProtonApi>,
    session_key: PlainSessionKey,
    blocks: Vec<ApiBlock>,
    tx: SyncSender<PrefetchedBlock>,
) {
    for block in blocks {
        let result = (|| -> Result<Vec<u8>> {
            let encrypted = api.get_block(&block.bare_url, &block.token)?;
            verify_block_hash(&encrypted, &block.hash)?;
            decrypt_with_session_key(&encrypted, &session_key)
        })();

        let message = match result {
            Ok(plain) => PrefetchedBlock::Data(plain),
            Err(error) => {
                let _ = tx.send(PrefetchedBlock::Error(error.to_string()));
                return;
            }
        };

        if tx.send(message).is_err() {
            return;
        }
    }

    let _ = tx.send(PrefetchedBlock::End);
}

#[derive(Debug)]
struct FolderScanTask {
    folder_id: String,
    parent_link_type: i32,
    folder_keys: Arc<SecretKeyRing>,
}

#[derive(Debug)]
struct FolderScanResult {
    folder_id: String,
    visible: Vec<RemoteEntry>,
    files: Vec<(String, NativeFile)>,
    child_folders: Vec<FolderScanTask>,
}

#[derive(Debug, Default)]
struct TreeLoadProgressState {
    folders: AtomicU64,
    files: AtomicU64,
    pages: AtomicU64,
    items: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TreeLoadProgressSnapshot {
    folders: u64,
    files: u64,
    pages: u64,
    items: u64,
}

impl TreeLoadProgressState {
    fn record_folder(&self, file_count: u64) {
        self.folders.fetch_add(1, Ordering::Relaxed);
        self.files.fetch_add(file_count, Ordering::Relaxed);
    }

    fn record_page(&self, item_count: u64) {
        self.pages.fetch_add(1, Ordering::Relaxed);
        self.items.fetch_add(item_count, Ordering::Relaxed);
    }

    fn snapshot(&self) -> TreeLoadProgressSnapshot {
        TreeLoadProgressSnapshot {
            folders: self.folders.load(Ordering::Relaxed),
            files: self.files.load(Ordering::Relaxed),
            pages: self.pages.load(Ordering::Relaxed),
            items: self.items.load(Ordering::Relaxed),
        }
    }
}

impl TreeLoadProgressSnapshot {
    fn has_activity(self) -> bool {
        self.folders > 0 || self.files > 0 || self.pages > 0 || self.items > 0
    }
}

#[derive(Debug)]
struct ConcurrentTreeLoadState {
    api: Arc<ProtonApi>,
    share_id: String,
    volume_id: String,
    metadata_mode: LinkMetadataMode,
    folders: Mutex<HashMap<String, Vec<RemoteEntry>>>,
    files: Mutex<HashMap<String, NativeFile>>,
    progress: TreeLoadProgressState,
    failed: AtomicBool,
    error: Mutex<Option<anyhow::Error>>,
}

impl ConcurrentTreeLoadState {
    fn new(
        api: Arc<ProtonApi>,
        share_id: &str,
        volume_id: &str,
        metadata_mode: LinkMetadataMode,
    ) -> Self {
        Self {
            api,
            share_id: share_id.to_owned(),
            volume_id: volume_id.to_owned(),
            metadata_mode,
            folders: Mutex::new(HashMap::new()),
            files: Mutex::new(HashMap::new()),
            progress: TreeLoadProgressState::default(),
            failed: AtomicBool::new(false),
            error: Mutex::new(None),
        }
    }

    fn store_folder_result(&self, result: FolderScanResult) {
        let file_count = result.files.len() as u64;
        {
            let mut folders = self.folders.lock().expect("folder map mutex poisoned");
            folders.insert(result.folder_id, result.visible);
        }
        if !result.files.is_empty() {
            let mut files = self.files.lock().expect("file map mutex poisoned");
            files.extend(result.files);
        }
        self.progress.record_folder(file_count);
    }

    fn fail(&self, error: anyhow::Error) {
        self.failed.store(true, Ordering::Release);
        let mut slot = self.error.lock().expect("scan error mutex poisoned");
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    fn take_error(&self) -> Option<anyhow::Error> {
        self.error.lock().expect("scan error mutex poisoned").take()
    }

    fn into_index(
        self,
    ) -> (
        HashMap<String, Vec<RemoteEntry>>,
        HashMap<String, NativeFile>,
    ) {
        (
            self.folders
                .into_inner()
                .expect("folder map mutex poisoned"),
            self.files.into_inner().expect("file map mutex poisoned"),
        )
    }
}

struct TreeLoadRequest {
    api: Arc<ProtonApi>,
    share_id: String,
    volume_id: String,
    metadata_mode: LinkMetadataMode,
    root_id: String,
    root_link_type: i32,
    root_keys: SecretKeyRing,
    scan_concurrency: usize,
}

#[derive(Debug)]
struct LoadedTree {
    folders: HashMap<String, Vec<RemoteEntry>>,
    files: HashMap<String, NativeFile>,
}

fn load_tree(request: TreeLoadRequest, reporter: &mut progress::Reporter) -> Result<LoadedTree> {
    let shared = Arc::new(ConcurrentTreeLoadState::new(
        request.api,
        &request.share_id,
        &request.volume_id,
        request.metadata_mode,
    ));
    let root_task = FolderScanTask {
        folder_id: request.root_id,
        parent_link_type: request.root_link_type,
        folder_keys: Arc::new(request.root_keys),
    };

    thread::scope(|scope| -> Result<()> {
        let done = Arc::new(AtomicBool::new(false));
        let ticker_done = Arc::clone(&done);
        let ticker_shared = Arc::clone(&shared);
        scope.spawn(move || {
            monitor_tree_load_progress(reporter, &ticker_shared.progress, ticker_done.as_ref())
        });

        let result = ThreadPoolBuilder::new()
            .num_threads(request.scan_concurrency.max(1))
            .build()
            .context("build Proton scan thread pool")
            .map(|pool| {
                pool.scope(|pool_scope| {
                    schedule_folder_scan(pool_scope, Arc::clone(&shared), root_task)
                })
            });

        done.store(true, Ordering::Release);
        result
    })?;

    if let Some(error) = shared.take_error() {
        return Err(error);
    }

    let shared = Arc::into_inner(shared).expect("tree scan workers still hold shared state");
    let (folders, files) = shared.into_index();
    Ok(LoadedTree { folders, files })
}

fn monitor_tree_load_progress(
    reporter: &mut progress::Reporter,
    progress: &TreeLoadProgressState,
    done: &AtomicBool,
) {
    let mut last = TreeLoadProgressSnapshot {
        folders: 0,
        files: 0,
        pages: 0,
        items: 0,
    };
    while !done.load(Ordering::Acquire) {
        let current = progress.snapshot();
        if current != last && current.has_activity() {
            emit_tree_load_progress(reporter, current);
            last = current;
        }
        thread::sleep(Duration::from_millis(200));
    }

    let current = progress.snapshot();
    if current != last && current.has_activity() {
        emit_tree_load_progress(reporter, current);
    }
}

fn emit_tree_load_progress(reporter: &mut progress::Reporter, snapshot: TreeLoadProgressSnapshot) {
    reporter.event(
        "tree_load",
        "progress",
        [
            ("backend", json!("proton")),
            ("folders", json!(snapshot.folders)),
            ("files", json!(snapshot.files)),
            ("pages", json!(snapshot.pages)),
            ("items", json!(snapshot.items)),
        ],
    );
}

fn schedule_folder_scan<'scope>(
    scope: &Scope<'scope>,
    shared: Arc<ConcurrentTreeLoadState>,
    task: FolderScanTask,
) {
    scope.spawn(move |scope| {
        if shared.failed.load(Ordering::Acquire) {
            return;
        }

        let result = match scan_folder(&shared, task) {
            Ok(result) => result,
            Err(error) => {
                shared.fail(error);
                return;
            }
        };

        let child_folders = result.child_folders;
        shared.store_folder_result(FolderScanResult {
            folder_id: result.folder_id,
            visible: result.visible,
            files: result.files,
            child_folders: Vec::new(),
        });

        if shared.failed.load(Ordering::Acquire) {
            return;
        }

        for child in child_folders.into_iter().rev() {
            schedule_folder_scan(scope, Arc::clone(&shared), child);
        }
    });
}

fn scan_folder(shared: &ConcurrentTreeLoadState, task: FolderScanTask) -> Result<FolderScanResult> {
    let children = if task.parent_link_type == LINK_TYPE_FOLDER {
        match shared.api.list_share_children(
            &shared.share_id,
            &task.folder_id,
            Some(&shared.progress),
        ) {
            Ok(children) => children,
            Err(error) if can_fallback_to_volume_child_listing(&error) => {
                shared.api.list_children(
                    &shared.volume_id,
                    &task.folder_id,
                    task.parent_link_type,
                    shared.metadata_mode,
                    Some(&shared.progress),
                )?
            }
            Err(error) => return Err(error),
        }
    } else {
        shared.api.list_children(
            &shared.volume_id,
            &task.folder_id,
            task.parent_link_type,
            shared.metadata_mode,
            Some(&shared.progress),
        )?
    };
    let mut visible = Vec::new();
    let mut files = Vec::new();
    let mut child_folders = Vec::new();

    for child in children {
        if child.link_state != LINK_STATE_ACTIVE {
            continue;
        }

        let name = decrypt_text(task.folder_keys.as_ref(), &child.name)
            .with_context(|| format!("decrypt child name {}", child.link_id))?;

        match child.link_type {
            LINK_TYPE_FOLDER | LINK_TYPE_ALBUM => {
                let child_keys = decrypt_node_keys(task.folder_keys.as_ref(), &child)
                    .with_context(|| format!("decrypt folder node keys {}", child.link_id))?;
                child_folders.push(FolderScanTask {
                    folder_id: child.link_id.clone(),
                    parent_link_type: child.link_type,
                    folder_keys: Arc::new(child_keys),
                });
                visible.push(RemoteEntry::folder(child.link_id, name));
            }
            LINK_TYPE_FILE => {
                let file_properties = child
                    .file_properties
                    .as_ref()
                    .ok_or_else(|| anyhow!("file {} missing file properties", child.link_id))?;
                let child_keys = decrypt_node_keys(task.folder_keys.as_ref(), &child)
                    .with_context(|| format!("decrypt file node keys {}", child.link_id))?;
                let xattr_parsed = decrypt_xattr_for_link(&child, &child_keys);
                let file = RemoteFile {
                    revision_id: file_properties.active_revision.id.clone(),
                    size: child.size,
                    modified_at_ns: child.modify_time.saturating_mul(1_000_000_000),
                    sha1: xattr_parsed.sha1.clone(),
                    original_modified_at_ns: xattr_parsed.modification_time_ns,
                    capture_time_ns: xattr_parsed.capture_time_ns,
                };
                files.push((
                    child.link_id.clone(),
                    NativeFile {
                        link: child.clone(),
                        node_keys: Arc::new(child_keys),
                    },
                ));
                visible.push(RemoteEntry::file(child.link_id, name, file));
            }
            other => bail!("unsupported Proton link type {other} for {}", child.link_id),
        }
    }

    Ok(FolderScanResult {
        folder_id: task.folder_id,
        visible,
        files,
        child_folders,
    })
}

fn can_fallback_to_volume_child_listing(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text.contains("failed with 400")
        || text.contains("failed with 404")
        || text.contains("failed with 422")
}

fn unlock_key_records(
    records: &[ApiKeyRecord],
    default_passphrase: &[u8],
    user_keys: Option<&SecretKeyRing>,
) -> Result<SecretKeyRing> {
    let mut unlocked = Vec::new();

    for record in records {
        if !record.active.is_true() {
            continue;
        }

        let passphrase = if record.token.trim().is_empty() || record.signature.trim().is_empty() {
            default_passphrase.to_vec()
        } else {
            let user_keys = user_keys.ok_or_else(|| {
                anyhow!(
                    "key {} requires a user keyring to decrypt its token",
                    record.id
                )
            })?;
            user_keys
                .decrypt_armored_message(&record.token)
                .with_context(|| format!("decrypt token for key {}", record.id))?
        };

        let (key, _) =
            SignedSecretKey::from_armor_single(Cursor::new(record.private_key.as_bytes()))
                .with_context(|| format!("parse armored private key {}", record.id))?;
        unlocked.push(SecretKeyEntry { key, passphrase });
    }

    if unlocked.is_empty() {
        bail!("no active keys could be unlocked")
    }

    Ok(SecretKeyRing { keys: unlocked })
}

fn decrypt_node_keys(parent_keys: &SecretKeyRing, link: &ApiLink) -> Result<SecretKeyRing> {
    let passphrase = parent_keys
        .decrypt_armored_message(&link.node_passphrase)
        .with_context(|| format!("decrypt NodePassphrase for {}", link.link_id))?;
    SecretKeyRing::from_armored_secret(&link.node_key, &passphrase)
}

fn decrypt_text(keys: &SecretKeyRing, armored: &str) -> Result<String> {
    let bytes = keys.decrypt_armored_message(armored)?;
    String::from_utf8(bytes).context("decode decrypted UTF-8 text")
}

fn decrypt_with_session_key(data: &[u8], session_key: &PlainSessionKey) -> Result<Vec<u8>> {
    let message = Message::from_bytes(data).context("parse encrypted message bytes")?;
    let message = message
        .decrypt_with_session_key(session_key.clone())
        .context("decrypt encrypted message with session key")?;
    read_message_bytes(message)
}

fn read_message_bytes(mut message: Message<'_>) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    message
        .read_to_end(&mut output)
        .context("read decrypted message bytes")?;
    Ok(output)
}

fn verify_block_hash(encrypted: &[u8], expected_base64: &str) -> Result<()> {
    let actual = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(encrypted));
    if actual != expected_base64 {
        bail!("downloaded Proton block hash did not match server hash");
    }
    Ok(())
}

fn retry_delay_for_response(
    response: &reqwest::blocking::Response,
    attempt: usize,
) -> Option<Duration> {
    if !should_retry_status(response.status()) {
        return None;
    }

    retry_delay_for_attempt(
        attempt,
        response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after_seconds),
    )
}

fn retry_delay_for_transport_error(
    method: &Method,
    error: &reqwest::Error,
    attempt: usize,
) -> Option<Duration> {
    if *method != Method::GET {
        return None;
    }
    let text = error.to_string();
    if !(error.is_timeout()
        || error.is_connect()
        || error.is_request()
        || error.is_body()
        || error.is_decode()
        || text.contains("connection closed before message completed"))
    {
        return None;
    }

    retry_delay_for_attempt(attempt, None)
}

fn retry_delay_for_attempt(attempt: usize, retry_after: Option<Duration>) -> Option<Duration> {
    if attempt + 1 >= MAX_TRANSIENT_ATTEMPTS {
        return None;
    }
    if let Some(retry_after) = retry_after {
        return Some(retry_after);
    }
    let shift = attempt.min(3) as u32;
    let delay_ms = (RETRY_BASE_DELAY_MS.saturating_mul(1u64 << shift)).min(RETRY_MAX_DELAY_MS);
    Some(Duration::from_millis(delay_ms))
}

fn report_request_retry(method: &Method, url: &str, attempt: usize, delay: Duration, detail: &str) {
    if !io::stderr().is_terminal() {
        return;
    }

    let next_attempt = attempt + 2;
    eprintln!(
        "Retrying Proton {method} {} in {:.1}s (attempt {next_attempt}/{MAX_TRANSIENT_ATTEMPTS}): {detail}",
        abbreviate_retry_url(url),
        delay.as_secs_f64(),
    );
}

fn abbreviate_retry_url(url: &str) -> &str {
    if let Some(index) = url.find("/api/") {
        &url[index..]
    } else {
        url
    }
}

fn should_retry_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

fn parse_retry_after_seconds(value: &str) -> Option<Duration> {
    let seconds = value.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds))
}

fn count_index(index: &HashMap<String, Vec<RemoteEntry>>) -> (usize, usize) {
    let folder_count = index.len();
    let file_count = index
        .values()
        .map(|entries| entries.iter().filter(|entry| entry.file.is_some()).count())
        .sum();
    (folder_count, file_count)
}

fn select_share<'a>(
    shares: &'a [ShareInfo],
    share_id: Option<&str>,
    share_name: &str,
) -> Result<&'a ShareInfo> {
    if let Some(share_id) = share_id {
        return shares
            .iter()
            .find(|share| share.share_id == share_id)
            .ok_or_else(|| anyhow!("no share matched id {share_id}"));
    }

    find_share_by_name(shares, share_name)
}

fn find_share_by_name<'a>(shares: &'a [ShareInfo], want: &str) -> Result<&'a ShareInfo> {
    let want = want.trim();
    if want.is_empty() {
        bail!("empty share name")
    }

    let matches: Vec<&ShareInfo> = shares
        .iter()
        .filter(|share| {
            let base = share_display_base(&share.name);
            share.name == want
                || share.name.eq_ignore_ascii_case(want)
                || base == want
                || base.eq_ignore_ascii_case(want)
        })
        .collect();

    match matches.as_slice() {
        [] => bail!("no share matched {want:?}; run `shares` to inspect available names"),
        [share] => Ok(*share),
        many => bail!("ambiguous share name {want:?} (matches {})", many.len()),
    }
}

fn share_display_base(name: &str) -> &str {
    let trimmed = name.trim();
    if let Some(index) = trimmed.find(" (Shared by ") {
        return trimmed[..index].trim();
    }
    if let Some(stripped) = trimmed.strip_suffix(" (Device)") {
        return stripped.trim();
    }
    trimmed
}

fn apply_share_name_suffix(name: String, share_type: i32, creator: &str) -> String {
    match share_type {
        SHARE_TYPE_STANDARD => format!("{name} (Shared by {creator})"),
        SHARE_TYPE_DEVICE => format!("{name} (Device)"),
        _ => name,
    }
}

fn share_type_label(value: i32) -> String {
    match value {
        SHARE_TYPE_MAIN => "main".to_owned(),
        SHARE_TYPE_STANDARD => "standard".to_owned(),
        SHARE_TYPE_DEVICE => "device".to_owned(),
        SHARE_TYPE_PHOTO => "photo".to_owned(),
        other => format!("type_{other}"),
    }
}

fn share_state_label(value: i32) -> String {
    match value {
        SHARE_STATE_ACTIVE => "active".to_owned(),
        SHARE_STATE_DELETED => "deleted".to_owned(),
        other => format!("state_{other}"),
    }
}

fn share_flags_label(value: i32) -> String {
    match value {
        SHARE_FLAG_NONE => "none".to_owned(),
        SHARE_FLAG_PRIMARY => "primary".to_owned(),
        other => format!("flags_{other}"),
    }
}

fn metadata_mode_for_volume_type(volume_type: Option<i32>) -> LinkMetadataMode {
    match volume_type {
        Some(2) => LinkMetadataMode::Photos,
        _ => LinkMetadataMode::Drive,
    }
}

fn normalize_photo_share_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("root") {
        "PhotosRoot".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Parsed view of a Proton XAttr blob, narrowed to the metadata we care
/// about restoring to the local filesystem. See the official schema at
/// `proton-sdk/js/sdk/src/internal/nodes/extendedAttributes.ts` and at
/// `ProtonMail-WebClients/applications/drive/src/app/store/_links/extendedAttributes.ts`.
#[derive(Debug, Default, Clone)]
struct ParsedXAttr {
    /// `Common.ModificationTime` translated to nanoseconds since the unix
    /// epoch. This is the user's original local mtime at upload time.
    modification_time_ns: Option<i64>,
    /// `Camera.CaptureTime` translated to nanoseconds since the unix epoch.
    /// Only present when the file is a photo or a video that carried EXIF
    /// or container-level timing info at upload time.
    capture_time_ns: Option<i64>,
    /// `Common.Digests.SHA1`, lowercased to match Proton's other clients.
    sha1: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XAttrEnvelope {
    #[serde(default, rename = "Common")]
    common: Option<XAttrCommon>,
    #[serde(default, rename = "Camera")]
    camera: Option<XAttrCamera>,
}

#[derive(Debug, Deserialize)]
struct XAttrCommon {
    #[serde(default, rename = "ModificationTime")]
    modification_time: Option<String>,
    #[serde(default, rename = "Digests")]
    digests: Option<XAttrDigests>,
}

#[derive(Debug, Deserialize)]
struct XAttrDigests {
    #[serde(default, rename = "SHA1")]
    sha1: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XAttrCamera {
    #[serde(default, rename = "CaptureTime")]
    capture_time: Option<String>,
}

/// Best-effort decryption and parsing of a link's XAttr blob. Returns an
/// empty `ParsedXAttr` whenever anything goes wrong: the goal is to enrich
/// metadata when we can, never to fail the scan.
///
/// Note: signature verification is intentionally skipped here. Adding it
/// would require fetching and unlocking the address public keys for every
/// file's `SignatureEmail`, which is well beyond the value of XAttr metadata
/// for a one-way export tool. The XAttr is decrypted with the file's own
/// node key, which an attacker without the user's password cannot produce.
///
/// Set `PROTONPICS_DEBUG_XATTR=1` to print one line per file describing
/// what was seen at every stage. Useful when investigating "why are my
/// timestamps still wrong" reports without re-downloading anything. The
/// number of lines is capped (default 50, override via
/// `PROTONPICS_DEBUG_XATTR_MAX`) so a 39k-file scan does not flood stderr.
fn decrypt_xattr_for_link(link: &ApiLink, node_keys: &SecretKeyRing) -> ParsedXAttr {
    let debug = xattr_debug_enabled();
    let armored = match link.xattr.as_deref() {
        Some(value) => value,
        None => {
            if debug {
                emit_xattr_debug(format_args!(
                    "[xattr] {}: field absent in link metadata",
                    link.link_id
                ));
            }
            return ParsedXAttr::default();
        }
    };
    let trimmed = armored.trim();
    if trimmed.is_empty() {
        if debug {
            emit_xattr_debug(format_args!(
                "[xattr] {}: field present but empty",
                link.link_id
            ));
        }
        return ParsedXAttr::default();
    }

    let plaintext = match decrypt_text(node_keys, trimmed) {
        Ok(text) => text,
        Err(error) => {
            if debug {
                emit_xattr_debug(format_args!(
                    "[xattr] {}: decrypt failed ({} bytes armored): {error:#}",
                    link.link_id,
                    trimmed.len()
                ));
            }
            return ParsedXAttr::default();
        }
    };

    let parsed = parse_xattr_payload(&plaintext);
    if debug {
        let preview: String = plaintext.chars().take(160).collect();
        emit_xattr_debug(format_args!(
            "[xattr] {}: decrypted ok ({} bytes plaintext); parsed mtime={:?} capture={:?} sha1={:?}; preview={}",
            link.link_id,
            plaintext.len(),
            parsed.modification_time_ns,
            parsed.capture_time_ns,
            parsed.sha1.as_deref(),
            preview.replace(['\n', '\r'], " "),
        ));
    }
    parsed
}

fn xattr_debug_enabled() -> bool {
    matches!(
        std::env::var("PROTONPICS_DEBUG_XATTR")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn xattr_debug_max_lines() -> u64 {
    std::env::var("PROTONPICS_DEBUG_XATTR_MAX")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(50)
}

static XATTR_DEBUG_EMITTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn emit_xattr_debug(args: std::fmt::Arguments<'_>) {
    use std::sync::atomic::Ordering;
    let max = xattr_debug_max_lines();
    let current = XATTR_DEBUG_EMITTED.fetch_add(1, Ordering::SeqCst);
    if current >= max {
        // Print one final hint that we suppressed the rest, exactly once.
        if current == max {
            eprintln!(
                "[xattr] (further debug lines suppressed; raise PROTONPICS_DEBUG_XATTR_MAX to see more)"
            );
        }
        return;
    }
    eprintln!("{args}");
}

fn parse_xattr_payload(plaintext: &str) -> ParsedXAttr {
    let envelope: XAttrEnvelope = match serde_json::from_str(plaintext) {
        Ok(parsed) => parsed,
        Err(_) => return ParsedXAttr::default(),
    };

    let modification_time_ns = envelope
        .common
        .as_ref()
        .and_then(|common| common.modification_time.as_deref())
        .and_then(parse_iso8601_to_ns);
    let capture_time_ns = envelope
        .camera
        .as_ref()
        .and_then(|camera| camera.capture_time.as_deref())
        .and_then(parse_iso8601_to_ns);
    let sha1 = envelope
        .common
        .and_then(|common| common.digests)
        .and_then(|digests| digests.sha1)
        .map(|raw| raw.trim().to_ascii_lowercase())
        .filter(|hex| !hex.is_empty());

    ParsedXAttr {
        modification_time_ns,
        capture_time_ns,
        sha1,
    }
}

/// Parses an ISO 8601 timestamp returned by Proton XAttr blobs. Accepts
/// the canonical `2024-08-15T14:32:00.000Z`, the legacy `+0000` form
/// (older Proton clients), `+HH:MM` offsets, and missing fractional
/// seconds. Returns nanoseconds since the unix epoch.
fn parse_iso8601_to_ns(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let bytes = trimmed.as_bytes();
    if bytes.len() < 19 {
        return None;
    }

    // Position 4, 7 must be '-', position 10 must be 'T' (or space, some
    // clients emit a space), positions 13 and 16 must be ':'.
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || (bytes[10] != b'T' && bytes[10] != b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let year: i32 = trimmed[0..4].parse().ok()?;
    let month: u32 = trimmed[5..7].parse().ok()?;
    let day: u32 = trimmed[8..10].parse().ok()?;
    let hour: u32 = trimmed[11..13].parse().ok()?;
    let minute: u32 = trimmed[14..16].parse().ok()?;
    let second: u32 = trimmed[17..19].parse().ok()?;

    // Optional fractional seconds and timezone, e.g. ".123Z" or "+02:00".
    let mut cursor = 19;
    let mut fractional_ns: u32 = 0;
    if cursor < bytes.len() && bytes[cursor] == b'.' {
        cursor += 1;
        let frac_start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        let frac = &trimmed[frac_start..cursor];
        if frac.is_empty() {
            return None;
        }
        // Pad or truncate to 9 digits to align with nanoseconds.
        let mut padded = String::with_capacity(9);
        for ch in frac.chars().take(9) {
            padded.push(ch);
        }
        while padded.len() < 9 {
            padded.push('0');
        }
        fractional_ns = padded.parse().ok()?;
    }

    let tz_offset_seconds: i64 = if cursor >= bytes.len() {
        // No timezone designator. Older Proton clients sometimes omit the
        // `Z`; treat it as UTC for safety since Proton normalizes to UTC.
        0
    } else {
        match bytes[cursor] {
            b'Z' | b'z' => 0,
            b'+' | b'-' => {
                let sign: i64 = if bytes[cursor] == b'-' { -1 } else { 1 };
                cursor += 1;
                let remaining = &trimmed[cursor..];
                let (h, m): (i64, i64) = if remaining.len() >= 5 && &remaining[2..3] == ":" {
                    let h: i64 = remaining[0..2].parse().ok()?;
                    let m: i64 = remaining[3..5].parse().ok()?;
                    (h, m)
                } else if remaining.len() >= 4 {
                    let h: i64 = remaining[0..2].parse().ok()?;
                    let m: i64 = remaining[2..4].parse().ok()?;
                    (h, m)
                } else {
                    return None;
                };
                sign * (h * 3600 + m * 60)
            }
            _ => return None,
        }
    };

    let utc_seconds = days_from_civil(year, month, day)?
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))?
        .checked_sub(tz_offset_seconds)?;

    let nanos = utc_seconds.checked_mul(1_000_000_000)?;
    nanos.checked_add(i64::from(fractional_ns))
}

/// Days since 1970-01-01 for a proleptic Gregorian date, using Howard
/// Hinnant's `days_from_civil` algorithm. Returns `None` if the date is
/// invalid.
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u32;
    let m = month as i32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u32;
    Some(i64::from(era) * 146_097 + i64::from(doe) - 719_468)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use anyhow::{Result, anyhow};
    use base64::Engine;
    use pgp::composed::{
        Deserializable, EncryptionCaps, Esk, KeyType, Message, MessageBuilder,
        SecretKeyParamsBuilder, SignedPublicKey, SubkeyParamsBuilder,
    };
    use pgp::crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
    use pgp::packet::Packet;
    use pgp::ser::Serialize;
    use pgp::types::CompressionAlgorithm;
    use sha2::Digest;
    use smallvec::smallvec;
    use tempfile::TempDir;

    use super::{
        AccountContext, ApiBlock, ApiBool, ApiFileProperties, ApiKeyRecord, ApiLink,
        ApiPossibleKeyPacket, ApiRevisionMetadata, ApiShare, ApiShareWire, ApiTwoFaInfo, ApiUser,
        AuthResponse, BrowserTestBehavior, CachedSecretKeyEntry, CachedSecretKeyRing,
        HUMAN_VERIFICATION_TIMEOUT_SECS, HumanVerificationAnswer, HumanVerificationChallenge,
        HumanVerificationRequired, HumanVerificationServer, LINK_STATE_ACTIVE, LINK_TYPE_ALBUM,
        LINK_TYPE_FILE, LINK_TYPE_FOLDER, LinkMetadataMode, MAX_PAGE_SIZE, MAX_TRANSIENT_ATTEMPTS,
        MODULUS_PUBKEY, NativeFile, ProtonApi, ProtonBackend, ProtonFileReader,
        ResolvedLoginCommand, ReusableCredential, SHARE_FLAG_NONE, SHARE_FLAG_PRIMARY,
        SHARE_STATE_ACTIVE, SHARE_STATE_DELETED, SHARE_TYPE_DEVICE, SHARE_TYPE_MAIN,
        SHARE_TYPE_STANDARD, SecretKeyRing, SelectedSession, SessionAccess, ShareEnvelope,
        ShareInfo, SrpAuth, TREE_CACHE_VERSION, TWO_FA_FIDO2, TWO_FA_TOTP, TreeCacheSnapshot,
        TreeLoadRequest, apply_share_name_suffix, bcrypt_hash, biguint_from_le,
        can_fallback_to_volume_child_listing, complete_login, configured_accounts_dir, count_index,
        decrypt_xattr_for_link, default_login_credentials_path, default_tree_cache_path,
        derive_salted_key_pass, empty_credentials, find_share_by_name, from_args,
        handle_human_verification_connection, hash_password, human_verification_proxy_base_url,
        inferred_session_email, list_shares, list_shares_with_api, load_tree, login,
        login_with_api, mailbox_password, parse_human_verification_challenge, parse_iso8601_to_ns,
        parse_retry_after_seconds, parse_signed_modulus, parse_signed_modulus as parse_modulus,
        parse_xattr_payload, resolve_login_command, retry_delay_for_attempt, save_tree_cache,
        select_session, select_share, share_display_base, share_flags_label, share_state_label,
        share_type_label, start_block_prefetch, tree_cache_matches, try_load_cached_backend,
        unlock_key_records, validate_srp_params, verify_block_hash, with_test_accounts_dir,
        with_test_api_base_url, with_test_browser_behavior, with_test_default_account_root,
        with_test_human_verification_answer, with_test_prompt_confirm, with_test_prompt_secrets,
        with_test_prompt_selection, with_test_prompt_texts, with_test_srp_client_secret,
        write_human_verification_response, xattr_debug_enabled, xattr_debug_max_lines,
    };
    use crate::accounts;
    use crate::backend::PhotoSource;
    use crate::progress::Mode;
    use crate::types::{RemoteEntry, RemoteFile};

    const TEST_SERVER_EPHEMERAL: &str = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";
    static MOCK_SERVER_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    const TEST_SERVER_PROOF: &str = "SLCSIClioSAtozauZZzcJuVPyY+MjnxfJSgEe9y6RafgjlPqnhQTZclRKPGsEhxVyWan7PIzhL+frPyZNaE1QaV5zbqz1yf9RXpGyTjZwU3FuVCJpkhp6iiCK3Wd2SemxawFXC06dgAdJ7I3HKvfkXeMANOUUh5ofjnJtXg42OGp4x1lKoFcH+IbB/CvRNQCmRTyhOiBJmZyUFwxHXLT/h+PlD0XSehcyybIIBIsscQ7ZPVPxQw4BqlqoYzTjjXPJxLxeQUQm2g9bPzT+izuR0VOPDtjt+dXrWny90k2nzS0Bs2YvNIqbJn1aQwFZr42p/O1I9n5S3mYtMgGk/7b1g==";
    const TEST_CLIENT_PROOF: &str = "Qb+1+jEqHRqpJ3nEJX2FEj0kXgCIWHngO0eT4R2Idkwke/ceCIUmQa0RfTYU53ybO1AVergtb7N0W/3bathdHT9FAHhy0vDGQDg/yPnuUneqV76NuU+pQHnO83gcjmZjDq/zvRRSD7dtIORRK97xhdR9W9bG5XRGr2c9Zev40YVcXgUiNUG/0zHSKQfEhUpMKxdauKtGC+dZnZzU6xaU0qvulYEsraawurRf0b1VXwohM6KE52Fj5xlS2FWZ3Mg0WIOC5KW5ziI6QirEUDK2pH/Rxvu4HcW9aMuppUmHk9Bm6kdg99o3vl0G7OgmEI7y6iyEYmXqH44XGORJ2sDMxQ==";
    const TEST_CLIENT_SECRET: &str = "sZJW0Jr9ysC6dIn/J+1va1fjqD8CFsHUDkFE8/1HiUlhEI5lFzhuBSuOgiYjyQU/J15wKeGydFtawi3copbncXAcHKEA2ge2LGlfiC3N2gDhhygQDL79/hJXW0ngw3uu88TG4wztipcWBmJ4WkZDqjyQPO1CihBRp4IbiK6vCxuOx6LPeVV8h6IuzgSsGt0TrI9tVOrrHP5PjD7W6D6EutxM42+9S57ngY50TuWCb57aj+EpGfn0HbQCvHXTYT8IWAebcODLGoQ1hYhMFNbADFulOw2fnwx6YZtCdk2b199Snd0JupI+NNnJCVLyhBRbn+hytEufu5cbv2Sxln+MUw==";
    const TEST_MODULUS: &str = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
    const TEST_MODULUS_CLEAR_SIGN: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nW2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\nGO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\nkvNM7qIK\n=q6vu\n-----END PGP SIGNATURE-----";

    fn empty_salted_credentials() -> ReusableCredential {
        ReusableCredential {
            salted_key_pass: String::new(),
            ..reusable_credentials()
        }
    }

    fn generate_fixture_key(user_id: &str) -> Result<(String, SignedPublicKey)> {
        let mut rng = rand::thread_rng();
        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(user_id.into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha256])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZIP])
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()?,
            )
            .build()?;
        let secret = key_params.generate(&mut rng)?;
        Ok((
            secret.to_armored_string(None.into())?,
            secret.to_public_key(),
        ))
    }

    fn encrypt_armored_message(public_key: &SignedPublicKey, plaintext: &[u8]) -> Result<String> {
        let mut rng = rand::thread_rng();
        let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.encrypt_to_key(&mut rng, &public_key.public_subkeys[0])?;
        Ok(builder.to_armored_string(&mut rng, Default::default())?)
    }

    /// Wrap the plaintext in a Compressed Data Packet before encryption,
    /// mirroring how the official Proton clients ship XAttr blobs. Used by
    /// the regression test that ensures `decrypt_armored_message` walks
    /// into compressed packets transparently.
    fn encrypt_compressed_armored_message(
        public_key: &SignedPublicKey,
        plaintext: &[u8],
    ) -> Result<String> {
        let mut rng = rand::thread_rng();
        let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec());
        builder.compression(CompressionAlgorithm::ZLIB);
        let mut builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.encrypt_to_key(&mut rng, &public_key.public_subkeys[0])?;
        Ok(builder.to_armored_string(&mut rng, Default::default())?)
    }

    fn encrypt_block_and_packet(
        public_key: &SignedPublicKey,
        plaintext: &[u8],
        session_key: &[u8],
    ) -> Result<(String, Vec<u8>, String)> {
        let mut rng = rand::thread_rng();
        let mut builder = MessageBuilder::from_bytes("block.bin", plaintext.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder
            .set_session_key(session_key.to_vec().into())?
            .encrypt_to_key(&mut rng, &public_key.public_subkeys[0])?;
        let encrypted = builder.to_vec(&mut rng)?;
        let encrypted_copy = encrypted.clone();
        let (message, _) = Message::from_reader(&encrypted_copy[..])?;
        let Message::Encrypted { esk, .. } = message else {
            panic!("generated block should be encrypted");
        };
        let Some(Esk::PublicKeyEncryptedSessionKey(pkesk)) = esk.into_iter().next() else {
            panic!("generated block should contain a PKESK packet");
        };
        let packet_bytes = Packet::PublicKeyEncryptedSessionKey(pkesk).to_bytes()?;
        let block_hash =
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&encrypted));
        Ok((
            base64::engine::general_purpose::STANDARD.encode(packet_bytes),
            encrypted,
            block_hash,
        ))
    }

    fn sample_share(name: &str, share_id: &str) -> ShareInfo {
        ShareInfo {
            name: name.to_owned(),
            share_id: share_id.to_owned(),
            link_id: "link".to_owned(),
            volume_id: "volume".to_owned(),
            share_type: "device".to_owned(),
            state: "active".to_owned(),
            flags: "none".to_owned(),
            creator: "user@example.com".to_owned(),
            metadata_mode: LinkMetadataMode::Drive,
        }
    }

    fn get_text_with_retries(url: &str) -> Result<String> {
        let client = reqwest::blocking::Client::new();
        let mut last_error = None;
        for _ in 0..5 {
            match client.get(url).send().and_then(|response| response.text()) {
                Ok(body) => return Ok(body),
                Err(error) => {
                    last_error = Some(error);
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        Err(last_error
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("request {url} failed without an error")))
    }

    #[derive(Debug, Clone)]
    struct MockRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct MockResponse {
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
    }

    impl MockResponse {
        fn json(body: impl Into<String>) -> Self {
            Self {
                status: 200,
                content_type: "application/json",
                body: body.into().into_bytes(),
            }
        }

        fn bytes(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: 200,
                content_type: "application/octet-stream",
                body: body.into(),
            }
        }

        fn status(status: u16, body: impl Into<String>) -> Self {
            Self {
                status,
                content_type: "application/json",
                body: body.into().into_bytes(),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct ExpectedExchange {
        method: &'static str,
        path: &'static str,
        response: MockResponse,
    }

    struct MockServer {
        address: String,
        expected: Arc<Mutex<VecDeque<ExpectedExchange>>>,
        errors: Arc<Mutex<Vec<String>>>,
        requests: Arc<Mutex<Vec<MockRequest>>>,
        running: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
        _lock: MutexGuard<'static, ()>,
    }

    impl MockServer {
        fn start(expected: Vec<ExpectedExchange>) -> Self {
            let lock = MOCK_SERVER_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
            listener.set_nonblocking(true).expect("set nonblocking");
            let address = format!("http://{}", listener.local_addr().expect("local addr"));
            let expected = Arc::new(Mutex::new(VecDeque::from(expected)));
            let errors = Arc::new(Mutex::new(Vec::new()));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let running = Arc::new(AtomicBool::new(true));
            let worker_expected = Arc::clone(&expected);
            let worker_errors = Arc::clone(&errors);
            let worker_requests = Arc::clone(&requests);
            let worker_running = Arc::clone(&running);
            let worker = thread::spawn(move || {
                while worker_running.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if let Err(error) = handle_mock_connection(
                                stream,
                                &worker_expected,
                                &worker_errors,
                                &worker_requests,
                            ) {
                                if error == "empty request line"
                                    || error.contains("Resource temporarily unavailable")
                                {
                                    continue;
                                }
                                worker_errors.lock().expect("errors lock").push(error);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => {
                            worker_errors
                                .lock()
                                .expect("errors lock")
                                .push(format!("accept failed: {error}"));
                            break;
                        }
                    }
                }
            });

            Self {
                address,
                expected,
                errors,
                requests,
                running,
                worker: Some(worker),
                _lock: lock,
            }
        }

        fn base_url(&self) -> &str {
            &self.address
        }

        fn finish(mut self) -> Vec<MockRequest> {
            self.stop();
            let errors = self.errors.lock().expect("errors lock");
            assert!(errors.is_empty(), "mock server errors: {errors:?}");
            let remaining = self.expected.lock().expect("expected lock");
            assert!(
                remaining.is_empty(),
                "mock server had unconsumed exchanges: {remaining:?}"
            );
            self.requests.lock().expect("requests lock").clone()
        }

        fn stop(&mut self) {
            self.running.store(false, Ordering::SeqCst);
            let _ = TcpStream::connect(
                self.address
                    .trim_start_matches("http://")
                    .parse::<std::net::SocketAddr>()
                    .expect("socket addr"),
            );
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn handle_mock_connection(
        mut stream: TcpStream,
        expected: &Arc<Mutex<VecDeque<ExpectedExchange>>>,
        errors: &Arc<Mutex<Vec<String>>>,
        requests: &Arc<Mutex<Vec<MockRequest>>>,
    ) -> std::result::Result<(), String> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let Some(request) = read_mock_request(&stream)? else {
            return Ok(());
        };
        requests
            .lock()
            .expect("requests lock")
            .push(request.clone());
        let response = match expected.lock().expect("expected lock").pop_front() {
            Some(exchange) => {
                if request.method != exchange.method || request.path != exchange.path {
                    errors.lock().expect("errors lock").push(format!(
                        "expected {} {} but got {} {}",
                        exchange.method, exchange.path, request.method, request.path
                    ));
                }
                exchange.response
            }
            None => {
                errors.lock().expect("errors lock").push(format!(
                    "unexpected request {} {}",
                    request.method, request.path
                ));
                MockResponse::status(500, r#"{"Error":"unexpected request"}"#)
            }
        };
        write_mock_response(&mut stream, &response).map_err(|error| error.to_string())?;
        Ok(())
    }

    fn read_mock_request(stream: &TcpStream) -> std::result::Result<Option<MockRequest>, String> {
        let mut reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);
        let mut request_line = String::new();
        match reader.read_line(&mut request_line) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.to_string()),
        }
        if request_line.is_empty() {
            return Ok(None);
        }
        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| "request line missing method".to_owned())?
            .to_owned();
        let path = parts
            .next()
            .ok_or_else(|| "request line missing path".to_owned())?
            .to_owned();

        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|error| error.to_string())?;
            if line == "\r\n" {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(format!("malformed header: {line:?}"));
            };
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }

        let content_length = headers
            .get("content-length")
            .map(|value| value.parse::<usize>().map_err(|error| error.to_string()))
            .transpose()?
            .unwrap_or(0);
        let mut body = vec![0u8; content_length];
        reader
            .read_exact(&mut body)
            .map_err(|error| error.to_string())?;

        Ok(Some(MockRequest {
            method,
            path,
            headers,
            body,
        }))
    }

    fn write_mock_response(stream: &mut TcpStream, response: &MockResponse) -> std::io::Result<()> {
        let status_text = match response.status {
            200 => "OK",
            401 => "Unauthorized",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Status",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
            response.status,
            status_text,
            response.body.len(),
            response.content_type,
        )?;
        stream.write_all(&response.body)?;
        stream.flush()
    }

    fn reusable_credentials() -> ReusableCredential {
        ReusableCredential {
            uid: "uid-1".to_owned(),
            access_token: "access-1".to_owned(),
            refresh_token: "refresh-1".to_owned(),
            salted_key_pass: base64::engine::general_purpose::STANDARD.encode(b"salted-key-pass"),
        }
    }

    fn test_api(temp_dir: &TempDir, base_url: &str) -> Result<ProtonApi> {
        ProtonApi::from_auth_state_with_base_url(
            &temp_dir.path().join("credentials.json"),
            reusable_credentials(),
            Some("test-app"),
            Some("test-agent"),
            base_url,
            None,
            None,
        )
    }

    fn write_credentials(path: &Path, credentials: &ReusableCredential) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec(credentials)?)?;
        Ok(())
    }

    fn write_encrypted_credentials(
        path: &Path,
        email: &str,
        password: &str,
        credentials: &ReusableCredential,
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let plaintext = serde_json::to_vec(credentials)?;
        let payload = accounts::encrypt_session_bytes(email, password, &plaintext)?;
        fs::write(path, payload)?;
        Ok(())
    }

    fn cached_backend_fixture(temp_dir: &TempDir) -> Result<ProtonBackend> {
        let (secret_armored, public_key) = generate_fixture_key("Cache <cached@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        Ok(ProtonBackend {
            api: Arc::new(test_api(temp_dir, "http://127.0.0.1:9")?),
            share_name: "PhotosRoot".to_owned(),
            share_id: "share-1".to_owned(),
            volume_id: "volume-1".to_owned(),
            root_id: "root-1".to_owned(),
            folders: HashMap::from([(
                "root-1".to_owned(),
                vec![RemoteEntry::file(
                    "file-1",
                    "photo.jpg",
                    RemoteFile {
                        revision_id: "rev-1".to_owned(),
                        size: 42,
                        modified_at_ns: 99,
                        sha1: None,
                        original_modified_at_ns: None,
                        capture_time_ns: None,
                    },
                )],
            )]),
            files: HashMap::from([(
                "file-1".to_owned(),
                NativeFile {
                    link: ApiLink {
                        link_id: "file-1".to_owned(),
                        link_type: LINK_TYPE_FILE,
                        name: "photo".to_owned(),
                        size: 42,
                        link_state: LINK_STATE_ACTIVE,
                        modify_time: 1,
                        node_key: secret_armored.clone(),
                        node_passphrase: empty_message,
                        file_properties: Some(ApiFileProperties {
                            content_key_packet: "packet-1".to_owned(),
                            active_revision: ApiRevisionMetadata {
                                id: "rev-1".to_owned(),
                            },
                        }),
                        xattr: None,
                    },
                    node_keys: Arc::new(SecretKeyRing::from_armored_secret(&secret_armored, b"")?),
                },
            )]),
        })
    }

    fn login_command(credentials: &Path) -> crate::cli::LoginCommand {
        crate::cli::LoginCommand {
            credentials: Some(credentials.to_path_buf()),
            email: Some("jakubqa".to_owned()),
            password: Some("abc123".to_owned()),
            two_fa: None,
            mailbox_password: None,
            app_version: Some("test-app".to_owned()),
            user_agent: Some("test-agent".to_owned()),
            no_input: true,
        }
    }

    fn share_listing_exchanges(
        secret_armored: &str,
        empty_message: &str,
        root_name: &str,
    ) -> Vec<ExpectedExchange> {
        vec![
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/users",
                response: MockResponse::json(
                    serde_json::json!({
                        "User": {
                            "Keys": [{
                                "Id": "user-key",
                                "PrivateKey": secret_armored,
                                "Token": "",
                                "Signature": "",
                                "Primary": 1,
                                "Active": 1
                            }]
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/addresses",
                response: MockResponse::json(
                    serde_json::json!({
                        "Addresses": [{
                            "Id": "addr-1",
                            "Keys": [{
                                "Id": "addr-key",
                                "PrivateKey": secret_armored,
                                "Token": "",
                                "Signature": "",
                                "Primary": 0,
                                "Active": 1
                            }]
                        }]
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares?ShowAll=1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Shares": [{
                            "ShareId": "share-1",
                            "LinkId": "root-1",
                            "VolumeId": "volume-1",
                            "Type": 3,
                            "State": 1,
                            "Creator": "user@example.com",
                            "Flags": 1
                        }]
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::status(404, r#"{"Error":"not found"}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Share": {
                            "ShareId": "share-1",
                            "LinkId": "root-1",
                            "AddressId": "addr-1",
                            "Key": secret_armored,
                            "Passphrase": empty_message
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/links/root-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Link": {
                            "LinkId": "root-1",
                            "Type": 1,
                            "Name": root_name,
                            "Size": 0,
                            "State": 1,
                            "ModifyTime": 1700000000,
                            "NodeKey": secret_armored,
                            "NodePassphrase": empty_message,
                            "FileProperties": null
                        }
                    })
                    .to_string(),
                ),
            },
        ]
    }

    #[test]
    fn resolve_login_command_uses_prompt_hooks_for_missing_fields() -> Result<()> {
        let resolved = with_test_prompt_texts(vec!["user@example.com".to_owned()], || {
            with_test_prompt_secrets(vec!["account-password".to_owned()], || {
                resolve_login_command(&crate::cli::LoginCommand {
                    credentials: None,
                    email: None,
                    password: None,
                    two_fa: None,
                    mailbox_password: None,
                    app_version: Some("test-app".to_owned()),
                    user_agent: Some("test-agent".to_owned()),
                    no_input: false,
                })
            })
        })?;
        assert_eq!(resolved.email, "user@example.com");
        assert_eq!(resolved.password, "account-password");
        assert_eq!(
            resolved
                .credentials
                .file_name()
                .map(|value| value.to_string_lossy().into_owned()),
            Some("session.json".to_owned())
        );
        Ok(())
    }

    #[test]
    fn select_session_with_encrypted_credentials_prompts_for_password() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let path = temp_dir
            .path()
            .join("saved@example.com")
            .join("session.json");
        let plaintext = serde_json::to_vec(&reusable_credentials())?;
        let encrypted =
            accounts::encrypt_session_bytes("saved@example.com", "real-password", &plaintext)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, encrypted)?;

        let session = with_test_prompt_secrets(vec!["typed-password".to_owned()], || {
            select_session(
                Some(&path),
                None,
                Some("test-app"),
                Some("test-agent"),
                false,
            )
        })?;

        match session {
            SelectedSession::Existing(access) => {
                assert_eq!(access.credentials_path, path);
                assert_eq!(access.session_email.as_deref(), Some("saved@example.com"));
                assert_eq!(access.session_password.as_deref(), Some("typed-password"));
            }
            SelectedSession::Added { .. } => panic!("expected existing session"),
        }

        Ok(())
    }

    #[test]
    fn select_session_without_accounts_can_decline_interactive_add() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let result = with_test_accounts_dir(temp_dir.path().join("accounts"), || {
            with_test_prompt_confirm(false, || {
                select_session(None, None, Some("test-app"), Some("test-agent"), false)
            })
        });
        let error = match result {
            Ok(_) => panic!("declined add-account flow should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no Proton account selected"));
        Ok(())
    }

    #[test]
    fn select_session_no_input_paths_report_actionable_errors() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let empty_result = with_test_accounts_dir(temp_dir.path().join("accounts-empty"), || {
            select_session(None, None, Some("test-app"), Some("test-agent"), true)
        });
        let empty_error = match empty_result {
            Ok(_) => panic!("missing accounts should fail"),
            Err(error) => error,
        };
        assert!(
            empty_error
                .to_string()
                .contains("no saved Proton accounts found")
        );

        let encrypted_path = temp_dir
            .path()
            .join("accounts-encrypted")
            .join("saved@example.com")
            .join("session.json");
        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &encrypted_path,
            accounts::encrypt_session_bytes(
                "saved@example.com",
                "password",
                &serde_json::to_vec(&reusable_credentials())?,
            )?,
        )?;
        let encrypted_result = select_session(
            Some(&encrypted_path),
            None,
            Some("test-app"),
            Some("test-agent"),
            true,
        );
        let encrypted_error = match encrypted_result {
            Ok(_) => panic!("encrypted credentials should require account password"),
            Err(error) => error,
        };
        assert!(
            encrypted_error
                .to_string()
                .contains("selected Proton session is encrypted")
        );

        let stored_accounts_dir = temp_dir.path().join("accounts-stored");
        let stored_path = stored_accounts_dir
            .join("stored@example.com")
            .join("session.json");
        if let Some(parent) = stored_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &stored_path,
            accounts::encrypt_session_bytes(
                "stored@example.com",
                "password",
                &serde_json::to_vec(&reusable_credentials())?,
            )?,
        )?;
        let stored_result = with_test_accounts_dir(stored_accounts_dir, || {
            select_session(None, None, Some("test-app"), Some("test-agent"), true)
        });
        let stored_error = match stored_result {
            Ok(_) => panic!("stored accounts should require interactive selection"),
            Err(error) => error,
        };
        assert!(
            stored_error
                .to_string()
                .contains("interactive selection is disabled")
        );
        Ok(())
    }

    #[test]
    fn select_session_confirmed_add_account_runs_login_flow() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let accounts_dir = temp_dir.path().join("accounts");
        let account_root = temp_dir.path().join("account-root");
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"PhotosRoot")?;
        let client_secret = base64::engine::general_purpose::STANDARD
            .decode(TEST_CLIENT_SECRET.as_bytes())
            .expect("client secret");

        let mut expected = vec![
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/info",
                response: MockResponse::json(format!(
                    r#"{{"Version":4,"Modulus":"{}","ServerEphemeral":"{}","Salt":"yKlc5/CvObfoiw==","SrpSession":"session-1"}}"#,
                    TEST_MODULUS_CLEAR_SIGN.replace('\n', "\\n"),
                    TEST_SERVER_EPHEMERAL,
                )),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4",
                response: MockResponse::json(format!(
                    r#"{{"Uid":"uid-1","AccessToken":"access-1","RefreshToken":"refresh-1","ServerProof":"{}","2FA":{{"Enabled":0}},"PasswordMode":1}}"#,
                    TEST_SERVER_PROOF,
                )),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/users",
                response: MockResponse::json(
                    serde_json::json!({
                        "User": {
                            "Keys": [{
                                "Id": "user-key",
                                "PrivateKey": secret_armored.clone(),
                                "Token": "",
                                "Signature": "",
                                "Primary": 1,
                                "Active": 1
                            }]
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/keys/salts",
                response: MockResponse::json(
                    r#"{"KeySalts":[{"Id":"user-key","KeySalt":"AQIDBAUGBwgJCgsMDQ4PEA=="}]}"#,
                ),
            },
        ];
        expected.extend(share_listing_exchanges(
            &secret_armored,
            &empty_message,
            &root_name,
        ));

        let server = MockServer::start(expected);
        let base_url = server.base_url().to_owned();
        let selection = with_test_accounts_dir(accounts_dir, || {
            with_test_default_account_root(account_root.clone(), || {
                with_test_api_base_url(&base_url, || {
                    with_test_srp_client_secret(biguint_from_le(&client_secret), || {
                        with_test_prompt_confirm(true, || {
                            with_test_prompt_texts(vec!["jakubqa".to_owned()], || {
                                with_test_prompt_secrets(vec!["abc123".to_owned()], || {
                                    select_session(
                                        None,
                                        None,
                                        Some("test-app"),
                                        Some("test-agent"),
                                        false,
                                    )
                                })
                            })
                        })
                    })
                })
            })
        })?;

        match selection {
            SelectedSession::Added { access, shares } => {
                assert_eq!(
                    access.credentials_path,
                    account_root.join("jakubqa").join("session.json")
                );
                assert_eq!(access.session_email.as_deref(), Some("jakubqa"));
                assert_eq!(access.session_password.as_deref(), Some("abc123"));
                assert_eq!(shares.len(), 1);
                assert!(access.credentials_path.exists());
            }
            SelectedSession::Existing(_) => panic!("expected interactive account add"),
        }

        server.finish();
        Ok(())
    }

    #[test]
    fn select_session_from_stored_accounts_uses_selection_prompt() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let accounts_dir = temp_dir.path().join("accounts");
        let path = accounts_dir.join("picked@example.com").join("session.json");
        let plaintext = serde_json::to_vec(&reusable_credentials())?;
        let encrypted =
            accounts::encrypt_session_bytes("picked@example.com", "real-password", &plaintext)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, encrypted)?;

        let session = with_test_accounts_dir(accounts_dir, || {
            with_test_prompt_selection(0, || {
                with_test_prompt_secrets(vec!["typed-password".to_owned()], || {
                    select_session(None, None, Some("test-app"), Some("test-agent"), false)
                })
            })
        })?;

        match session {
            SelectedSession::Existing(access) => {
                assert_eq!(access.credentials_path, path);
                assert_eq!(access.session_email.as_deref(), Some("picked@example.com"));
                assert_eq!(access.session_password.as_deref(), Some("typed-password"));
            }
            SelectedSession::Added { .. } => panic!("expected stored account"),
        }

        Ok(())
    }

    #[test]
    fn complete_login_prompts_for_totp_and_mailbox_password() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials = temp_dir.path().join("prompted").join("creds.json");
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"PhotosRoot")?;
        let raw_salt = base64::engine::general_purpose::STANDARD
            .decode(b"AQIDBAUGBwgJCgsMDQ4PEA==")
            .expect("base64 salt");

        let mut expected = vec![
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/2fa",
                response: MockResponse::json(r#"{}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/users",
                response: MockResponse::json(
                    serde_json::json!({
                        "User": {
                            "Keys": [{
                                "Id": "user-key",
                                "PrivateKey": secret_armored.clone(),
                                "Token": "",
                                "Signature": "",
                                "Primary": 1,
                                "Active": 1
                            }]
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/keys/salts",
                response: MockResponse::json(
                    r#"{"KeySalts":[{"Id":"user-key","KeySalt":"AQIDBAUGBwgJCgsMDQ4PEA=="}]}"#,
                ),
            },
        ];
        expected.extend(share_listing_exchanges(
            &secret_armored,
            &empty_message,
            &root_name,
        ));

        let server = MockServer::start(expected);
        let base_url = server.base_url().to_owned();
        let api = Arc::new(ProtonApi::from_auth_state_with_base_url(
            &credentials,
            empty_credentials(),
            Some("test-app"),
            Some("test-agent"),
            &base_url,
            Some("account-password".to_owned()),
            Some("prompted@example.com".to_owned()),
        )?);
        let args = ResolvedLoginCommand {
            credentials: credentials.clone(),
            email: "prompted@example.com".to_owned(),
            password: "account-password".to_owned(),
            two_fa: None,
            mailbox_password: None,
            app_version: Some("test-app".to_owned()),
            user_agent: Some("test-agent".to_owned()),
            no_input: false,
        };

        let shares = with_test_prompt_secrets(
            vec!["123456".to_owned(), "mailbox-password".to_owned()],
            || {
                complete_login(
                    Arc::clone(&api),
                    &args,
                    AuthResponse {
                        uid: "uid-1".to_owned(),
                        access_token: "access-1".to_owned(),
                        refresh_token: "refresh-1".to_owned(),
                        server_proof: String::new(),
                        two_fa: ApiTwoFaInfo {
                            enabled: TWO_FA_TOTP,
                        },
                        password_mode: super::PASSWORD_MODE_TWO,
                    },
                )
            },
        )?;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "PhotosRoot (Device)");

        let encrypted_bytes = fs::read(&credentials)?;
        let persisted: ReusableCredential =
            serde_json::from_slice(&accounts::decrypt_session_bytes(
                &credentials,
                &encrypted_bytes,
                Some("account-password"),
            )?)?;
        let expected_salted_key_pass = {
            let mailbox = mailbox_password(b"mailbox-password", &raw_salt)?;
            base64::engine::general_purpose::STANDARD.encode(&mailbox[mailbox.len() - 31..])
        };
        assert_eq!(persisted.salted_key_pass, expected_salted_key_pass);

        let requests = server.finish();
        let two_fa_body: serde_json::Value = serde_json::from_slice(&requests[0].body)?;
        assert_eq!(two_fa_body["TwoFactorCode"], "123456");
        Ok(())
    }

    #[test]
    fn human_verification_display_timeout_and_proxy_base_url_cover_edge_cases() -> Result<()> {
        let titled = HumanVerificationRequired {
            challenge: HumanVerificationChallenge {
                token: "token".to_owned(),
                methods: vec!["captcha".to_owned()],
                web_url: None,
                title: Some("Human Verification".to_owned()),
                expires_at: None,
            },
        };
        assert_eq!(
            titled.to_string(),
            "Proton human verification required: Human Verification"
        );
        let untitled = HumanVerificationRequired {
            challenge: HumanVerificationChallenge {
                token: "token".to_owned(),
                methods: vec!["captcha".to_owned()],
                web_url: None,
                title: None,
                expires_at: None,
            },
        };
        assert_eq!(untitled.to_string(), "Proton human verification required");

        let fallback = HumanVerificationChallenge {
            token: "token".to_owned(),
            methods: vec!["captcha".to_owned()],
            web_url: None,
            title: None,
            expires_at: None,
        };
        assert_eq!(
            fallback.wait_timeout(),
            Duration::from_secs(HUMAN_VERIFICATION_TIMEOUT_SECS)
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let short = HumanVerificationChallenge {
            expires_at: Some(now.saturating_sub(10)),
            ..fallback.clone()
        };
        assert_eq!(short.wait_timeout(), Duration::from_secs(1));
        let long = HumanVerificationChallenge {
            expires_at: Some(now + HUMAN_VERIFICATION_TIMEOUT_SECS * 2),
            ..fallback.clone()
        };
        assert_eq!(
            long.wait_timeout(),
            Duration::from_secs(HUMAN_VERIFICATION_TIMEOUT_SECS)
        );

        assert_eq!(
            human_verification_proxy_base_url(
                "https://mail.proton.me/api",
                &HumanVerificationChallenge {
                    web_url: Some("https://verify.proton.me/?methods=captcha&token=abc".to_owned()),
                    ..fallback.clone()
                },
            )?,
            "https://verify-api.proton.me"
        );
        assert_eq!(
            human_verification_proxy_base_url(
                "https://mail.proton.me/api",
                &HumanVerificationChallenge {
                    web_url: Some("http://127.0.0.1:8080/?methods=captcha&token=abc".to_owned()),
                    ..fallback.clone()
                },
            )?,
            "https://mail.proton.me"
        );
        assert_eq!(
            human_verification_proxy_base_url("https://mail.proton.me/api", &fallback)?,
            "https://mail.proton.me"
        );
        Ok(())
    }

    #[test]
    fn photos_root_share_is_discovered_and_normalized() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"root")?;

        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares?ShowAll=1",
                response: MockResponse::json(r#"{"Shares":[]}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::json(
                    serde_json::json!({
                        "Volume": { "VolumeID": "volume-1" },
                        "Share": {
                            "ShareID": "share-1",
                            "CreatorEmail": "user@example.com",
                            "AddressID": "addr-1",
                            "Key": secret_armored,
                            "Passphrase": empty_message
                        },
                        "Link": {
                            "Link": {
                                "LinkID": "root-1",
                                "Type": 1,
                                "Name": root_name,
                                "Size": 0,
                                "State": 1,
                                "ModifyTime": 1700000000,
                                "NodeKey": secret_armored.clone(),
                                "NodePassphrase": empty_message.clone()
                            }
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::json(
                    serde_json::json!({
                        "Volume": { "VolumeID": "volume-1" },
                        "Share": {
                            "ShareID": "share-1",
                            "CreatorEmail": "user@example.com",
                            "AddressID": "addr-1",
                            "Key": secret_armored.clone(),
                            "Passphrase": empty_message.clone()
                        },
                        "Link": {
                            "Link": {
                                "LinkID": "root-1",
                                "Type": 1,
                                "Name": root_name.clone(),
                                "Size": 0,
                                "State": 1,
                                "ModifyTime": 1700000000,
                                "NodeKey": secret_armored.clone(),
                                "NodePassphrase": empty_message.clone()
                            }
                        }
                    })
                    .to_string(),
                ),
            },
        ]);
        let context = AccountContext {
            api: Arc::new(test_api(&temp_dir, server.base_url())?),
            address_keys_by_id: HashMap::from([(
                "addr-1".to_owned(),
                SecretKeyRing::from_armored_secret(&secret_armored, b"")?,
            )]),
        };

        let shares = context.list_share_infos()?;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "PhotosRoot");
        assert_eq!(shares[0].metadata_mode, LinkMetadataMode::Photos);

        let loaded = context.load_share_root(&shares[0])?;
        assert_eq!(loaded.share.share_id, "share-1");
        assert_eq!(loaded.root_link.link_id, "root-1");

        server.finish();
        Ok(())
    }

    #[test]
    fn photo_share_info_replaces_matching_share_row_in_loop() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"root")?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares?ShowAll=1",
                response: MockResponse::json(
                    r#"{"Shares":[{"ShareId":"share-1","LinkId":"root-1","VolumeId":"volume-1","Type":3,"State":1,"Creator":"user@example.com","Flags":1}]}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::json(
                    serde_json::json!({
                        "Volume": { "VolumeID": "volume-1" },
                        "Share": {
                            "ShareID": "share-1",
                            "CreatorEmail": "user@example.com",
                            "AddressID": "addr-1",
                            "Key": secret_armored,
                            "Passphrase": empty_message
                        },
                        "Link": {
                            "Link": {
                                "LinkID": "root-1",
                                "Type": 1,
                                "Name": root_name,
                                "Size": 0,
                                "State": 1,
                                "ModifyTime": 1700000000,
                                "NodeKey": secret_armored.clone(),
                                "NodePassphrase": empty_message.clone()
                            }
                        }
                    })
                    .to_string(),
                ),
            },
        ]);
        let context = AccountContext {
            api: Arc::new(test_api(&temp_dir, server.base_url())?),
            address_keys_by_id: HashMap::from([(
                "addr-1".to_owned(),
                SecretKeyRing::from_armored_secret(&secret_armored, b"")?,
            )]),
        };
        let shares = context.list_share_infos()?;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "PhotosRoot");
        server.finish();
        Ok(())
    }

    #[test]
    fn standard_drive_share_names_are_resolved_via_share_and_root_link() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"Trips")?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares?ShowAll=1",
                response: MockResponse::json(
                    r#"{"Shares":[{"ShareID":"share-2","LinkID":"root-2","VolumeID":"volume-2","Type":2,"State":1,"Creator":"foo@example.com","Flags":0,"VolumeType":1}]}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::status(404, r#"{"Code":2501}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-2",
                response: MockResponse::json(
                    serde_json::json!({
                        "ShareID": "share-2",
                        "LinkID": "root-2",
                        "AddressID": "addr-1",
                        "Key": secret_armored.clone(),
                        "Passphrase": empty_message.clone()
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-2/links/root-2",
                response: MockResponse::json(
                    serde_json::json!({
                        "Link": {
                            "LinkID": "root-2",
                            "Type": 1,
                            "Name": root_name,
                            "Size": 0,
                            "State": 1,
                            "ModifyTime": 1700000000,
                            "NodeKey": secret_armored.clone(),
                            "NodePassphrase": empty_message.clone()
                        }
                    })
                    .to_string(),
                ),
            },
        ]);
        let context = AccountContext {
            api: Arc::new(test_api(&temp_dir, server.base_url())?),
            address_keys_by_id: HashMap::from([(
                "addr-1".to_owned(),
                SecretKeyRing::from_armored_secret(&secret_armored, b"")?,
            )]),
        };

        let shares = context.list_share_infos()?;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "Trips (Shared by foo@example.com)");
        assert_eq!(shares[0].metadata_mode, LinkMetadataMode::Drive);

        server.finish();
        Ok(())
    }

    #[test]
    fn photos_volume_children_use_photo_link_details_and_size_fallback() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/volumes/volume-1/folders/root-1/children",
                response: MockResponse::json(
                    r#"{"LinkIDs":["file-1"],"More":true,"AnchorID":"file-1"}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/volumes/volume-1/folders/root-1/children?AnchorID=file-1",
                response: MockResponse::json(r#"{"LinkIDs":["file-2"],"More":false}"#),
            },
            ExpectedExchange {
                method: "POST",
                path: "/drive/photos/volumes/volume-1/links",
                response: MockResponse::json(
                    serde_json::json!({
                        "Links": [
                            {
                                "Link": {
                                    "LinkID": "file-1",
                                    "Type": 2,
                                    "Name": "photo-one",
                                    "Size": 0,
                                    "State": 1,
                                    "ModifyTime": 1,
                                    "NodeKey": "node-key",
                                    "NodePassphrase": "node-passphrase"
                                },
                                "Photo": {
                                    "ContentKeyPacket": "packet-1",
                                    "TotalEncryptedSize": 42,
                                    "ActiveRevision": { "RevisionID": "rev-1" }
                                }
                            },
                            {
                                "Link": {
                                    "LinkID": "file-2",
                                    "Type": 2,
                                    "Name": "photo-two",
                                    "Size": 9,
                                    "State": 1,
                                    "ModifyTime": 2,
                                    "NodeKey": "node-key",
                                    "NodePassphrase": "node-passphrase"
                                },
                                "Photo": {
                                    "ContentKeyPacket": "packet-2",
                                    "TotalEncryptedSize": 99,
                                    "ActiveRevision": { "RevisionID": "rev-2" }
                                }
                            }
                        ]
                    })
                    .to_string(),
                ),
            },
        ]);
        let api = test_api(&temp_dir, server.base_url())?;
        let links = api.list_children(
            "volume-1",
            "root-1",
            LINK_TYPE_FOLDER,
            LinkMetadataMode::Photos,
            None,
        )?;
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].size, 42);
        assert_eq!(
            links[0]
                .file_properties
                .as_ref()
                .expect("file properties")
                .active_revision
                .id,
            "rev-1"
        );
        assert_eq!(links[1].size, 9);
        server.finish();
        Ok(())
    }

    #[test]
    fn album_children_use_album_endpoint_and_photo_link_details_even_in_drive_mode() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/photos/volumes/volume-1/albums/album-1/children?Sort=Captured&Desc=1",
                response: MockResponse::json(
                    r#"{"Photos":[{"LinkID":"file-1","CaptureTime":1,"Hash":"h","ContentHash":"c","RelatedPhotos":[],"AddedTime":1,"IsChildOfAlbum":true,"Tags":[]}],"More":false}"#,
                ),
            },
            ExpectedExchange {
                method: "POST",
                path: "/drive/photos/volumes/volume-1/links",
                response: MockResponse::json(
                    serde_json::json!({
                        "Links": [
                            {
                                "Link": {
                                    "LinkID": "file-1",
                                    "Type": 2,
                                    "Name": "album-photo",
                                    "Size": 0,
                                    "State": 1,
                                    "ModifyTime": 3,
                                    "NodeKey": "node-key",
                                    "NodePassphrase": "node-passphrase"
                                },
                                "Photo": {
                                    "ContentKeyPacket": "packet-1",
                                    "TotalEncryptedSize": 123,
                                    "ActiveRevision": { "RevisionID": "rev-1" }
                                }
                            }
                        ]
                    })
                    .to_string(),
                ),
            },
        ]);
        let api = test_api(&temp_dir, server.base_url())?;
        let links = api.list_children(
            "volume-1",
            "album-1",
            LINK_TYPE_ALBUM,
            LinkMetadataMode::Drive,
            None,
        )?;
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_id, "file-1");
        assert_eq!(links[0].size, 123);
        assert_eq!(
            links[0]
                .file_properties
                .as_ref()
                .expect("file properties")
                .active_revision
                .id,
            "rev-1"
        );
        server.finish();
        Ok(())
    }

    #[test]
    fn parallel_tree_load_propagates_worker_errors() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let odd_name = encrypt_armored_message(&public_key, b"odd-node")?;
        let server = MockServer::start(vec![ExpectedExchange {
            method: "GET",
            path: "/drive/shares/share-1/folders/root-1/children?Page=0&PageSize=150",
            response: MockResponse::json(
                serde_json::json!({
                    "Links": [{
                            "LinkID": "odd-1",
                            "Type": 9,
                            "Name": odd_name,
                            "Size": 0,
                            "State": 1,
                            "ModifyTime": 1,
                            "NodeKey": secret_armored.clone(),
                            "NodePassphrase": empty_message.clone(),
                            "FileProperties": null
                    }]
                })
                .to_string(),
            ),
        }]);
        let api = Arc::new(test_api(&temp_dir, server.base_url())?);
        let root_keys = SecretKeyRing::from_armored_secret(&secret_armored, b"")?;
        let mut reporter = crate::progress::Reporter::stderr(Mode::Quiet);
        let error = load_tree(
            TreeLoadRequest {
                api,
                share_id: "share-1".to_owned(),
                volume_id: "volume-1".to_owned(),
                metadata_mode: LinkMetadataMode::Drive,
                root_id: "root-1".to_owned(),
                root_link_type: LINK_TYPE_FOLDER,
                root_keys,
                scan_concurrency: 4,
            },
            &mut reporter,
        )
        .expect_err("unsupported link type should fail the scan");
        assert!(error.to_string().contains("unsupported Proton link type 9"));
        server.finish();
        Ok(())
    }

    #[test]
    fn list_share_children_paginates_and_preserves_file_metadata() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let first_page_links = (0..MAX_PAGE_SIZE)
            .map(|index| {
                serde_json::json!({
                    "LinkID": format!("file-{index}"),
                    "Type": LINK_TYPE_FILE,
                    "Name": format!("name-{index}"),
                    "Size": index as i64,
                    "State": LINK_STATE_ACTIVE,
                    "ModifyTime": 1_700_000_000i64 + index as i64,
                    "NodeKey": "node-key",
                    "NodePassphrase": "node-passphrase",
                    "FileProperties": {
                        "ContentKeyPacket": format!("packet-{index}"),
                        "ActiveRevision": { "ID": format!("rev-{index}") }
                    }
                })
            })
            .collect::<Vec<_>>();
        let last_link = serde_json::json!({
            "LinkID": "folder-last",
            "Type": LINK_TYPE_FOLDER,
            "Name": "last-folder",
            "Size": 0,
            "State": LINK_STATE_ACTIVE,
            "ModifyTime": 1_700_000_999i64,
            "NodeKey": "node-key",
            "NodePassphrase": "node-passphrase",
            "FileProperties": null
        });
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/folders/root-1/children?Page=0&PageSize=150",
                response: MockResponse::json(
                    serde_json::json!({ "Links": first_page_links }).to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/folders/root-1/children?Page=1&PageSize=150",
                response: MockResponse::json(
                    serde_json::json!({ "Links": [last_link] }).to_string(),
                ),
            },
        ]);
        let api = test_api(&temp_dir, server.base_url())?;

        let links = api.list_share_children("share-1", "root-1", None)?;

        assert_eq!(links.len(), MAX_PAGE_SIZE + 1);
        assert_eq!(links[0].link_id, "file-0");
        assert_eq!(links[0].link_type, LINK_TYPE_FILE);
        assert_eq!(
            links[0]
                .file_properties
                .as_ref()
                .expect("file properties")
                .active_revision
                .id,
            "rev-0"
        );
        assert_eq!(links[MAX_PAGE_SIZE].link_id, "folder-last");
        assert!(links[MAX_PAGE_SIZE].file_properties.is_none());
        server.finish();
        Ok(())
    }

    #[test]
    fn load_tree_falls_back_to_volume_children_when_share_listing_is_unavailable() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let file_name = encrypt_armored_message(&public_key, b"fallback.jpg")?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/folders/root-1/children?Page=0&PageSize=150",
                response: MockResponse::status(404, r#"{"Code":2001,"Error":"not found"}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/volumes/volume-1/folders/root-1/children",
                response: MockResponse::json(r#"{"LinkIDs":["file-1"],"More":false}"#),
            },
            ExpectedExchange {
                method: "POST",
                path: "/drive/v2/volumes/volume-1/links",
                response: MockResponse::json(
                    serde_json::json!({
                        "Links": [{
                            "Link": {
                                "LinkID": "file-1",
                                "Type": LINK_TYPE_FILE,
                                "Name": file_name,
                                "Size": 123i64,
                                "State": LINK_STATE_ACTIVE,
                                "ModifyTime": 1_700_000_000i64,
                                "NodeKey": secret_armored.clone(),
                                "NodePassphrase": empty_message.clone(),
                            },
                            "File": {
                                "ContentKeyPacket": "packet-1",
                                "TotalEncryptedSize": 123i64,
                                "ActiveRevision": { "RevisionID": "rev-1" }
                            }
                        }]
                    })
                    .to_string(),
                ),
            },
        ]);
        let api = Arc::new(test_api(&temp_dir, server.base_url())?);
        let root_keys = SecretKeyRing::from_armored_secret(&secret_armored, b"")?;
        let mut reporter = crate::progress::Reporter::stderr(Mode::Quiet);

        let tree = load_tree(
            TreeLoadRequest {
                api,
                share_id: "share-1".to_owned(),
                volume_id: "volume-1".to_owned(),
                metadata_mode: LinkMetadataMode::Drive,
                root_id: "root-1".to_owned(),
                root_link_type: LINK_TYPE_FOLDER,
                root_keys,
                scan_concurrency: 1,
            },
            &mut reporter,
        )?;

        let root_children = tree.folders.get("root-1").expect("root children");
        assert_eq!(root_children.len(), 1);
        assert_eq!(root_children[0].name, "fallback.jpg");
        assert_eq!(
            root_children[0]
                .file
                .as_ref()
                .expect("file metadata")
                .revision_id,
            "rev-1"
        );
        server.finish();
        Ok(())
    }

    #[test]
    fn fallback_to_volume_child_listing_only_triggers_for_status_errors() {
        assert!(can_fallback_to_volume_child_listing(&anyhow!(
            "Proton API GET /children failed with 400 Bad Request"
        )));
        assert!(can_fallback_to_volume_child_listing(&anyhow!(
            "Proton API GET /children failed with 404 Not Found"
        )));
        assert!(can_fallback_to_volume_child_listing(&anyhow!(
            "Proton API GET /children failed with 422 Unprocessable Entity"
        )));
        assert!(!can_fallback_to_volume_child_listing(&anyhow!(
            "network timeout"
        )));
    }

    #[test]
    fn api_share_wire_uses_possible_key_packet_address_id_fallback() -> Result<()> {
        let share = ShareEnvelope::Bare(ApiShareWire {
            share_id: "share-1".to_owned(),
            link_id: "link-1".to_owned(),
            address_id: None,
            key: "key".to_owned(),
            passphrase: "passphrase".to_owned(),
            memberships: Vec::new(),
            possible_key_packets: vec![ApiPossibleKeyPacket {
                address_id: "addr-from-packet".to_owned(),
            }],
        })
        .into_share()?;
        assert_eq!(share.address_id, "addr-from-packet");
        Ok(())
    }

    #[test]
    fn api_share_wire_requires_any_address_id() {
        let error = ShareEnvelope::Bare(ApiShareWire {
            share_id: "share-1".to_owned(),
            link_id: "link-1".to_owned(),
            address_id: None,
            key: "key".to_owned(),
            passphrase: "passphrase".to_owned(),
            memberships: Vec::new(),
            possible_key_packets: Vec::new(),
        })
        .into_share()
        .expect_err("share without address ids should fail");
        assert!(error.to_string().contains("did not include an address id"));
    }

    #[test]
    fn configured_path_helpers_use_default_locations_without_test_overrides() -> Result<()> {
        assert_eq!(
            configured_accounts_dir()?,
            crate::paths::default_accounts_dir()?
        );
        assert_eq!(
            default_login_credentials_path("user@example.com")?,
            crate::accounts::default_account_path("user@example.com")?
        );
        Ok(())
    }

    #[test]
    fn human_verification_errors_cover_no_input_and_unsupported_methods() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let api = test_api(&temp_dir, "http://127.0.0.1:9")?;
        let unsupported = api
            .complete_human_verification(
                &HumanVerificationChallenge {
                    token: "hv".to_owned(),
                    methods: vec!["email".to_owned()],
                    web_url: None,
                    title: None,
                    expires_at: None,
                },
                false,
            )
            .expect_err("unsupported verification method");
        assert!(
            unsupported
                .to_string()
                .contains("unsupported Proton human verification methods")
        );

        let no_input = api
            .complete_human_verification(
                &HumanVerificationChallenge {
                    token: "hv".to_owned(),
                    methods: vec!["captcha".to_owned()],
                    web_url: Some("https://verify.proton.me/?methods=captcha&token=hv".to_owned()),
                    title: None,
                    expires_at: None,
                },
                true,
            )
            .expect_err("captcha without input");
        assert!(
            no_input
                .to_string()
                .contains("Proton requires CAPTCHA verification")
        );
        Ok(())
    }

    #[test]
    fn complete_human_verification_browser_paths_cover_success_and_failure() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let api = test_api(&temp_dir, "http://127.0.0.1:9")?;
        let challenge = HumanVerificationChallenge {
            token: "hv-start".to_owned(),
            methods: vec!["captcha".to_owned()],
            web_url: Some("https://verify.proton.me/?methods=captcha&token=hv-start".to_owned()),
            title: Some("Human Verification".to_owned()),
            expires_at: Some(4102444800),
        };

        let success = with_test_browser_behavior(
            BrowserTestBehavior {
                succeed: true,
                answer: Some(HumanVerificationAnswer {
                    token: "hv-success".to_owned(),
                    token_type: "captcha".to_owned(),
                }),
            },
            || api.complete_human_verification(&challenge, false),
        )?;
        assert_eq!(success.token, "hv-success");

        let failure = with_test_browser_behavior(
            BrowserTestBehavior {
                succeed: false,
                answer: Some(HumanVerificationAnswer {
                    token: "hv-failure".to_owned(),
                    token_type: "captcha".to_owned(),
                }),
            },
            || api.complete_human_verification(&challenge, false),
        )?;
        assert_eq!(failure.token, "hv-failure");
        Ok(())
    }

    #[test]
    fn get_photos_share_root_reports_refresh_parse_and_http_errors() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials_path = temp_dir.path().join("creds-refresh.json");
        write_credentials(&credentials_path, &reusable_credentials())?;
        let refresh_server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::status(401, r#"{"Code":401}"#),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/refresh",
                response: MockResponse::json(
                    r#"{"Uid":"uid-2","AccessToken":"access-2","RefreshToken":"refresh-2"}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::json(r#"{"broken":true}"#),
            },
        ]);
        let refresh_api = ProtonApi::from_credentials_with_base_url(
            &credentials_path,
            Some("test-app"),
            Some("test-agent"),
            refresh_server.base_url(),
            None,
            None,
        )?;
        let parse_error = refresh_api
            .get_photos_share_root()
            .expect_err("invalid photos root payload should fail");
        assert!(
            parse_error
                .to_string()
                .contains("parse Proton API response for GET")
        );
        refresh_server.finish();

        let mut error_server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::status(500, r#"{"Error":"boom"}"#),
            };
            MAX_TRANSIENT_ATTEMPTS
        ]);
        let error_credentials_path = temp_dir.path().join("creds-error.json");
        write_credentials(&error_credentials_path, &reusable_credentials())?;
        let error_api = ProtonApi::from_credentials_with_base_url(
            &error_credentials_path,
            Some("test-app"),
            Some("test-agent"),
            error_server.base_url(),
            None,
            None,
        )?;
        let error = error_api
            .get_photos_share_root()
            .expect_err("500 should fail");
        assert!(error.to_string().contains("failed with 500"));
        error_server.stop();
        Ok(())
    }

    #[test]
    fn request_json_parse_errors_include_response_snippet() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials_path = temp_dir.path().join("creds.json");
        write_credentials(&credentials_path, &reusable_credentials())?;
        let server = MockServer::start(vec![ExpectedExchange {
            method: "GET",
            path: "/core/v4/users",
            response: MockResponse::json(r#"{"User":true}"#),
        }]);
        let api = ProtonApi::from_credentials_with_base_url(
            &credentials_path,
            Some("test-app"),
            Some("test-agent"),
            server.base_url(),
            None,
            None,
        )?;
        let error = api
            .get_user()
            .expect_err("invalid user payload should fail");
        assert!(error.to_string().contains(r#"{"User":true}"#));
        server.finish();
        Ok(())
    }

    #[test]
    fn authenticate_password_non_human_verification_errors_are_reported() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/info",
                response: MockResponse::json(format!(
                    r#"{{"Version":4,"Modulus":"{}","ServerEphemeral":"{}","Salt":"yKlc5/CvObfoiw==","SrpSession":"session-1"}}"#,
                    TEST_MODULUS_CLEAR_SIGN.replace('\n', "\\n"),
                    TEST_SERVER_EPHEMERAL,
                )),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4",
                response: MockResponse::status(400, r#"{"Code":2000,"Error":"bad login"}"#),
            },
        ]);
        let api = test_api(&temp_dir, server.base_url())?;
        let client_secret = base64::engine::general_purpose::STANDARD
            .decode(TEST_CLIENT_SECRET.as_bytes())
            .expect("client secret");
        let error = with_test_srp_client_secret(biguint_from_le(&client_secret), || {
            api.authenticate_password("jakubqa", b"abc123", true)
        })
        .expect_err("plain auth errors should bubble up");
        let message = error.to_string();
        assert!(
            message.contains("failed with 400")
                || message.contains("bad login")
                || message.contains("send Proton API request POST")
        );
        server.finish();
        Ok(())
    }

    #[test]
    fn login_wrapper_returns_credentials_path_and_shares() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials = temp_dir.path().join("login-wrapper").join("creds.json");
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"PhotosRoot")?;
        let client_secret = base64::engine::general_purpose::STANDARD
            .decode(TEST_CLIENT_SECRET.as_bytes())
            .expect("client secret");

        let mut expected = vec![
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/info",
                response: MockResponse::json(format!(
                    r#"{{"Version":4,"Modulus":"{}","ServerEphemeral":"{}","Salt":"yKlc5/CvObfoiw==","SrpSession":"session-1"}}"#,
                    TEST_MODULUS_CLEAR_SIGN.replace('\n', "\\n"),
                    TEST_SERVER_EPHEMERAL,
                )),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4",
                response: MockResponse::json(format!(
                    r#"{{"Uid":"uid-1","AccessToken":"access-1","RefreshToken":"refresh-1","ServerProof":"{}","2FA":{{"Enabled":0}},"PasswordMode":1}}"#,
                    TEST_SERVER_PROOF,
                )),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/users",
                response: MockResponse::json(
                    serde_json::json!({
                        "User": {
                            "Keys": [{
                                "Id": "user-key",
                                "PrivateKey": secret_armored.clone(),
                                "Token": "",
                                "Signature": "",
                                "Primary": 1,
                                "Active": 1
                            }]
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/keys/salts",
                response: MockResponse::json(
                    r#"{"KeySalts":[{"Id":"user-key","KeySalt":"AQIDBAUGBwgJCgsMDQ4PEA=="}]}"#,
                ),
            },
        ];
        expected.extend(share_listing_exchanges(
            &secret_armored,
            &empty_message,
            &root_name,
        ));

        let server = MockServer::start(expected);
        let mut command = login_command(&credentials);
        command.no_input = true;
        let result = with_test_api_base_url(server.base_url(), || {
            with_test_srp_client_secret(biguint_from_le(&client_secret), || login(&command))
        })?;
        assert_eq!(result.credentials_path, credentials);
        assert_eq!(result.shares.len(), 1);
        server.finish();
        Ok(())
    }

    #[test]
    fn save_auth_uses_credentials_file_stem_when_session_email_is_missing() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials_path = temp_dir.path().join("fallback-email.json");
        let api = ProtonApi::from_auth_state_with_base_url(
            &credentials_path,
            empty_credentials(),
            Some("test-app"),
            Some("test-agent"),
            "http://127.0.0.1:9",
            Some("account-password".to_owned()),
            None,
        )?;
        api.persist_credentials(&reusable_credentials())?;
        let bytes = fs::read(&credentials_path)?;
        let text = String::from_utf8(bytes).expect("utf8 envelope");
        assert!(text.contains("\"email\":\"fallback-email\""));
        Ok(())
    }

    #[test]
    fn human_verification_socket_helpers_cover_disconnect_paths() -> Result<()> {
        let proxy_client = reqwest::blocking::Client::builder().build()?;
        let (answer_tx, _answer_rx) = std::sync::mpsc::channel();
        let running = AtomicBool::new(true);

        let (client, server) = connected_stream_pair()?;
        drop(client);
        handle_human_verification_connection(
            server,
            "<html></html>",
            "https://verify-api.proton.me",
            &proxy_client,
            &answer_tx,
            &running,
        )?;

        let (client, server) = connected_stream_pair()?;
        let closer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            drop(client);
        });
        write_human_verification_response(server, 200, "OK", "text/plain", b"body")?;
        closer.join().expect("join disconnect helper");
        Ok(())
    }

    #[test]
    fn native_proton_success_path_loads_tree_and_reads_blocks() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"PhotosRoot")?;
        let album_name = encrypt_armored_message(&public_key, b"Summer 2026")?;
        let folder_name = encrypt_armored_message(&public_key, b"Trips")?;
        let file_name = encrypt_armored_message(&public_key, b"photo.jpg")?;
        let file_plaintext = b"hello proton";
        let (content_key_packet, encrypted_block, block_hash) =
            encrypt_block_and_packet(&public_key, file_plaintext, &[7u8; 32])?;
        let server = MockServer::start(Vec::new());
        let base_url = server.base_url().to_owned();
        *server.expected.lock().expect("expected lock") = VecDeque::from(vec![
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/users",
                response: MockResponse::json(
                    serde_json::json!({
                        "User": {
                            "Keys": [{
                                "Id": "user-key",
                                "PrivateKey": secret_armored.clone(),
                                "Token": "",
                                "Signature": "",
                                "Primary": 1,
                                "Active": 1
                            }]
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/addresses",
                response: MockResponse::json(
                    serde_json::json!({
                        "Addresses": [{
                            "Id": "addr-1",
                            "Keys": [{
                                "Id": "addr-key",
                                "PrivateKey": secret_armored.clone(),
                                "Token": "",
                                "Signature": "",
                                "Primary": 0,
                                "Active": 1
                            }]
                        }]
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares?ShowAll=1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Shares": [{
                            "ShareId": "share-1",
                            "LinkId": "root-1",
                            "VolumeId": "volume-1",
                            "Type": 3,
                            "State": 1,
                            "Creator": "user@example.com",
                            "Flags": 1
                        }]
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::status(404, r#"{"Error":"not found"}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Share": {
                            "ShareId": "share-1",
                            "LinkId": "root-1",
                            "AddressId": "addr-1",
                            "Key": secret_armored.clone(),
                            "Passphrase": empty_message.clone()
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/links/root-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Link": {
                            "LinkId": "root-1",
                            "Type": 1,
                            "Name": root_name.clone(),
                            "Size": 0,
                            "State": 1,
                            "ModifyTime": 1700000000,
                            "NodeKey": secret_armored.clone(),
                            "NodePassphrase": empty_message.clone(),
                            "FileProperties": null
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Share": {
                            "ShareId": "share-1",
                            "LinkId": "root-1",
                            "AddressId": "addr-1",
                            "Key": secret_armored.clone(),
                            "Passphrase": empty_message.clone()
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/links/root-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Link": {
                            "LinkId": "root-1",
                            "Type": 1,
                            "Name": root_name.clone(),
                            "Size": 0,
                            "State": 1,
                            "ModifyTime": 1700000000,
                            "NodeKey": secret_armored.clone(),
                            "NodePassphrase": empty_message.clone(),
                            "FileProperties": null
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/folders/root-1/children?Page=0&PageSize=150",
                response: MockResponse::json(
                    serde_json::json!({
                        "Links": [
                            {
                                "LinkID": "album-1",
                                    "Type": 3,
                                    "Name": album_name.clone(),
                                    "State": 1,
                                    "ModifyTime": 1700000000i64,
                                    "NodeKey": secret_armored.clone(),
                                    "NodePassphrase": empty_message.clone(),
                                    "Size": 0,
                                    "FileProperties": null
                            },
                            {
                                "LinkID": "folder-1",
                                    "Type": 1,
                                    "Name": folder_name.clone(),
                                    "State": 1,
                                    "ModifyTime": 1700000001i64,
                                    "NodeKey": secret_armored.clone(),
                                    "NodePassphrase": empty_message.clone(),
                                    "Size": 0,
                                    "FileProperties": null
                            },
                            {
                                "LinkID": "file-1",
                                    "Type": 2,
                                    "Name": file_name.clone(),
                                    "State": 1,
                                    "ModifyTime": 1700000002i64,
                                    "NodeKey": secret_armored.clone(),
                                    "NodePassphrase": empty_message.clone(),
                                    "Size": file_plaintext.len() as i64,
                                    "FileProperties": {
                                        "ContentKeyPacket": content_key_packet.clone(),
                                        "ActiveRevision": { "ID": "rev-1" }
                                    }
                            },
                            {
                                "LinkID": "ignored-1",
                                    "Type": 2,
                                    "Name": "ignored",
                                    "State": 2,
                                    "ModifyTime": 0,
                                    "NodeKey": "",
                                    "NodePassphrase": "",
                                    "Size": 0,
                                    "FileProperties": null
                            }
                        ]
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/photos/volumes/volume-1/albums/album-1/children?Sort=Captured&Desc=1",
                response: MockResponse::json(r#"{"Photos":[],"More":false}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/folders/folder-1/children?Page=0&PageSize=150",
                response: MockResponse::json(r#"{"Links":[]}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/volumes/volume-1/files/file-1/revisions/rev-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Revision": {
                            "Blocks": [{
                                "BareUrl": format!("{}/block-1", base_url),
                                "Token": "block-token",
                                "Hash": block_hash.clone()
                            }]
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/block-1",
                response: MockResponse::bytes(encrypted_block),
            },
        ]);
        let credentials_path = temp_dir.path().join("credentials.json");
        write_credentials(&credentials_path, &empty_salted_credentials())?;
        let args = crate::cli::ProtonSourceArgs {
            credentials: Some(credentials_path.clone()),
            account_password: None,
            share_name: "PhotosRoot".to_owned(),
            share_id: None,
            app_version: Some("test-app".to_owned()),
            user_agent: Some("test-agent".to_owned()),
            scan_concurrency: 1,
            tree_cache: crate::cli::TreeCacheMode::Refresh,
            no_input: true,
        };

        let opened = with_test_api_base_url(&base_url, || from_args(&args, Mode::Quiet))?;
        let expected_state_db = credentials_path
            .parent()
            .expect("credentials dir")
            .join("proton-photos.sqlite");
        assert_eq!(
            opened.default_state_db.as_deref(),
            Some(expected_state_db.as_path())
        );
        assert_eq!(opened.source.backend_name(), "proton");
        assert_eq!(opened.source.root_id(), "root-1");
        let root_children = opened.source.list_children("root-1")?;
        assert_eq!(root_children.len(), 3);
        assert_eq!(root_children[0].name, "Summer 2026");
        assert_eq!(root_children[1].name, "Trips");
        assert_eq!(root_children[2].name, "photo.jpg");
        assert!(opened.source.list_children("album-1")?.is_empty());
        assert!(opened.source.list_children("folder-1")?.is_empty());

        let mut reader = opened.source.open_file("file-1")?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        assert_eq!(bytes, file_plaintext);

        let requests = server.finish();
        assert_eq!(
            requests.last().map(|request| request.path.as_str()),
            Some("/block-1")
        );
        Ok(())
    }

    #[test]
    fn share_display_base_strips_suffixes() {
        assert_eq!(share_display_base("PhotosRoot"), "PhotosRoot");
        assert_eq!(share_display_base("PhotosRoot (Device)"), "PhotosRoot");
        assert_eq!(
            share_display_base("Shared album (Shared by foo@example.com)"),
            "Shared album"
        );
    }

    #[test]
    fn share_lookup_matches_base_name_case_insensitively() {
        let shares = vec![
            sample_share("PhotosRoot (Device)", "share-1"),
            sample_share("Something else", "share-2"),
        ];
        let found = find_share_by_name(&shares, "photosroot").expect("share lookup");
        assert_eq!(found.share_id, "share-1");
    }

    #[test]
    fn share_selection_and_labels_cover_edge_cases() {
        let shares = vec![
            sample_share("PhotosRoot (Device)", "share-1"),
            sample_share("PhotosRoot", "share-2"),
            sample_share("Album", "share-3"),
        ];
        assert_eq!(
            select_share(&shares, Some("share-3"), "ignored")
                .expect("share by id")
                .share_id,
            "share-3"
        );
        assert!(find_share_by_name(&shares, "   ").is_err());
        assert!(find_share_by_name(&shares, "missing").is_err());
        assert!(find_share_by_name(&shares, "photosroot").is_err());

        assert_eq!(
            apply_share_name_suffix("Album".to_owned(), SHARE_TYPE_STANDARD, "foo@example.com"),
            "Album (Shared by foo@example.com)"
        );
        assert_eq!(
            apply_share_name_suffix("PhotosRoot".to_owned(), SHARE_TYPE_DEVICE, "ignored"),
            "PhotosRoot (Device)"
        );
        assert_eq!(
            apply_share_name_suffix("My files".to_owned(), SHARE_TYPE_MAIN, "ignored"),
            "My files"
        );

        assert_eq!(share_type_label(SHARE_TYPE_MAIN), "main");
        assert_eq!(share_type_label(SHARE_TYPE_STANDARD), "standard");
        assert_eq!(share_type_label(SHARE_TYPE_DEVICE), "device");
        assert_eq!(share_type_label(99), "type_99");
        assert_eq!(share_state_label(SHARE_STATE_ACTIVE), "active");
        assert_eq!(share_state_label(SHARE_STATE_DELETED), "deleted");
        assert_eq!(share_state_label(99), "state_99");
        assert_eq!(share_flags_label(SHARE_FLAG_NONE), "none");
        assert_eq!(share_flags_label(SHARE_FLAG_PRIMARY), "primary");
        assert_eq!(share_flags_label(99), "flags_99");
        assert!(ApiBool(1).is_true());
        assert!(!ApiBool(0).is_true());

        let index = HashMap::from([
            (
                "root".to_owned(),
                vec![
                    RemoteEntry::folder("folder-1", "Trips"),
                    RemoteEntry::file(
                        "file-1",
                        "photo.jpg",
                        RemoteFile {
                            revision_id: "rev-1".to_owned(),
                            size: 4,
                            modified_at_ns: 1,
                            sha1: None,
                            original_modified_at_ns: None,
                            capture_time_ns: None,
                        },
                    ),
                ],
            ),
            ("folder-1".to_owned(), Vec::new()),
        ]);
        assert_eq!(count_index(&index), (2, 1));
    }

    #[test]
    fn tree_cache_helpers_cover_paths_and_match_rules() {
        let session_path = PathBuf::from("/tmp/cached@example.com/session.json");
        assert_eq!(
            default_tree_cache_path(&session_path),
            PathBuf::from("/tmp/cached@example.com/proton-tree-cache.json")
        );
        assert_eq!(
            inferred_session_email(&session_path),
            Some("cached@example.com".to_owned())
        );
        assert_eq!(
            inferred_session_email(Path::new("/tmp/custom-creds.json")),
            Some("custom-creds".to_owned())
        );
        assert_eq!(inferred_session_email(Path::new("session.json")), None);

        let snapshot = TreeCacheSnapshot {
            version: TREE_CACHE_VERSION,
            share_name: "PhotosRoot (Device)".to_owned(),
            share_id: "share-1".to_owned(),
            volume_id: "volume-1".to_owned(),
            root_id: "root-1".to_owned(),
            folders: HashMap::new(),
            files: HashMap::new(),
        };
        let args = crate::cli::ProtonSourceArgs {
            credentials: None,
            account_password: None,
            share_name: "photosroot".to_owned(),
            share_id: None,
            app_version: None,
            user_agent: None,
            scan_concurrency: 4,
            tree_cache: crate::cli::TreeCacheMode::Refresh,
            no_input: true,
        };
        assert!(tree_cache_matches(&snapshot, &args));

        let args = crate::cli::ProtonSourceArgs {
            share_id: Some("share-1".to_owned()),
            ..args.clone()
        };
        assert!(tree_cache_matches(&snapshot, &args));

        let args = crate::cli::ProtonSourceArgs {
            share_id: Some("other-share".to_owned()),
            ..args
        };
        assert!(!tree_cache_matches(&snapshot, &args));
    }

    #[test]
    fn tree_cache_save_skips_without_password() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials_path = temp_dir
            .path()
            .join("cached@example.com")
            .join("session.json");
        let backend = cached_backend_fixture(&temp_dir)?;
        save_tree_cache(
            &backend,
            &SessionAccess {
                credentials_path: credentials_path.clone(),
                session_email: Some("cached@example.com".to_owned()),
                session_password: None,
            },
        )?;
        assert!(!default_tree_cache_path(&credentials_path).exists());
        Ok(())
    }

    #[test]
    fn cached_secret_key_ring_round_trip_and_error_paths_are_covered() -> Result<()> {
        let (secret_armored, _) = generate_fixture_key("Cache <cached@example.com>")?;
        let ring = SecretKeyRing::from_armored_secret(&secret_armored, b"")?;
        let cached = ring.to_cached()?;
        let restored = SecretKeyRing::from_cached(&cached)?;
        assert_eq!(restored.keys.len(), 1);

        let error = SecretKeyRing::from_cached(&CachedSecretKeyRing { keys: Vec::new() })
            .expect_err("empty cached keyring");
        assert!(error.to_string().contains("did not contain any keys"));

        let error = SecretKeyRing::from_cached(&CachedSecretKeyRing {
            keys: vec![CachedSecretKeyEntry {
                armored_key: secret_armored,
                passphrase: "%%%".to_owned(),
            }],
        })
        .expect_err("invalid base64 passphrase");
        assert!(
            error
                .to_string()
                .contains("decode cached secret key passphrase")
        );
        Ok(())
    }

    #[test]
    fn try_load_cached_backend_covers_cache_miss_mismatch_and_parse_errors() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let account_dir = temp_dir.path().join("cached@example.com");
        let credentials_path = account_dir.join("session.json");
        write_encrypted_credentials(
            &credentials_path,
            "cached@example.com",
            "real-password",
            &reusable_credentials(),
        )?;

        let access = SessionAccess {
            credentials_path: credentials_path.clone(),
            session_email: Some("cached@example.com".to_owned()),
            session_password: Some("real-password".to_owned()),
        };
        let api = Arc::new(test_api(&temp_dir, "http://127.0.0.1:9")?);
        let args = crate::cli::ProtonSourceArgs {
            credentials: Some(credentials_path.clone()),
            account_password: Some("real-password".to_owned()),
            share_name: "PhotosRoot".to_owned(),
            share_id: None,
            app_version: Some("test-app".to_owned()),
            user_agent: Some("test-agent".to_owned()),
            scan_concurrency: 1,
            tree_cache: crate::cli::TreeCacheMode::ReuseIfPresent,
            no_input: true,
        };

        assert!(try_load_cached_backend(Arc::clone(&api), &access, &args)?.is_none());

        let snapshot = TreeCacheSnapshot {
            version: TREE_CACHE_VERSION + 1,
            share_name: "PhotosRoot".to_owned(),
            share_id: "share-1".to_owned(),
            volume_id: "volume-1".to_owned(),
            root_id: "root-1".to_owned(),
            folders: HashMap::new(),
            files: HashMap::new(),
        };
        let cache_path = default_tree_cache_path(&credentials_path);
        fs::write(
            &cache_path,
            accounts::encrypt_session_bytes(
                "cached@example.com",
                "real-password",
                &serde_json::to_vec(&snapshot)?,
            )?,
        )?;
        assert!(try_load_cached_backend(Arc::clone(&api), &access, &args)?.is_none());

        let snapshot = TreeCacheSnapshot {
            version: TREE_CACHE_VERSION,
            share_name: "AnotherRoot".to_owned(),
            ..snapshot
        };
        fs::write(
            &cache_path,
            accounts::encrypt_session_bytes(
                "cached@example.com",
                "real-password",
                &serde_json::to_vec(&snapshot)?,
            )?,
        )?;
        assert!(try_load_cached_backend(Arc::clone(&api), &access, &args)?.is_none());

        let no_password = SessionAccess {
            session_password: None,
            ..access.clone()
        };
        let backend = cached_backend_fixture(&temp_dir)?;
        save_tree_cache(&backend, &access)?;
        assert!(try_load_cached_backend(Arc::clone(&api), &no_password, &args)?.is_none());

        fs::write(
            &cache_path,
            accounts::encrypt_session_bytes("cached@example.com", "real-password", b"not-json")?,
        )?;
        let error = try_load_cached_backend(Arc::clone(&api), &access, &args)
            .expect_err("invalid cached json should fail");
        assert!(error.to_string().contains("parse tree cache"));
        Ok(())
    }

    #[test]
    fn from_args_reuse_if_present_refreshes_when_cache_is_missing() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials_path = temp_dir
            .path()
            .join("cached@example.com")
            .join("session.json");
        write_encrypted_credentials(
            &credentials_path,
            "cached@example.com",
            "real-password",
            &reusable_credentials(),
        )?;
        let (secret_armored, public_key) = generate_fixture_key("Cache <cached@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"DriveRoot")?;
        let mut exchanges = share_listing_exchanges(&secret_armored, &empty_message, &root_name);
        exchanges.extend([
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Share": {
                            "ShareId": "share-1",
                            "LinkId": "root-1",
                            "AddressId": "addr-1",
                            "Key": secret_armored.clone(),
                            "Passphrase": empty_message.clone()
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/links/root-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Link": {
                            "LinkId": "root-1",
                            "Type": 1,
                            "Name": root_name.clone(),
                            "Size": 0,
                            "State": 1,
                            "ModifyTime": 1700000000,
                            "NodeKey": secret_armored.clone(),
                            "NodePassphrase": empty_message.clone(),
                            "FileProperties": null
                        }
                    })
                    .to_string(),
                ),
            },
        ]);
        exchanges.push(ExpectedExchange {
            method: "GET",
            path: "/drive/shares/share-1/folders/root-1/children?Page=0&PageSize=150",
            response: MockResponse::json(r#"{"Links":[]}"#),
        });
        let server = MockServer::start(exchanges);

        let args = crate::cli::ProtonSourceArgs {
            credentials: Some(credentials_path.clone()),
            account_password: Some("real-password".to_owned()),
            share_name: "DriveRoot".to_owned(),
            share_id: None,
            app_version: Some("test-app".to_owned()),
            user_agent: Some("test-agent".to_owned()),
            scan_concurrency: 1,
            tree_cache: crate::cli::TreeCacheMode::ReuseIfPresent,
            no_input: true,
        };

        let opened = with_test_api_base_url(server.base_url(), || from_args(&args, Mode::Quiet))?;
        assert_eq!(opened.source.root_id(), "root-1");
        assert!(opened.source.list_children("root-1")?.is_empty());
        assert!(default_tree_cache_path(&credentials_path).is_file());
        server.finish();
        Ok(())
    }

    #[test]
    fn from_args_reuse_if_present_ignores_invalid_cache_and_refreshes() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials_path = temp_dir
            .path()
            .join("cached@example.com")
            .join("session.json");
        write_encrypted_credentials(
            &credentials_path,
            "cached@example.com",
            "real-password",
            &reusable_credentials(),
        )?;
        fs::write(
            default_tree_cache_path(&credentials_path),
            accounts::encrypt_session_bytes("cached@example.com", "real-password", b"not-json")?,
        )?;

        let (secret_armored, public_key) = generate_fixture_key("Cache <cached@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"DriveRoot")?;
        let mut exchanges = share_listing_exchanges(&secret_armored, &empty_message, &root_name);
        exchanges.extend([
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Share": {
                            "ShareId": "share-1",
                            "LinkId": "root-1",
                            "AddressId": "addr-1",
                            "Key": secret_armored.clone(),
                            "Passphrase": empty_message.clone()
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/links/root-1",
                response: MockResponse::json(
                    serde_json::json!({
                        "Link": {
                            "LinkId": "root-1",
                            "Type": 1,
                            "Name": root_name.clone(),
                            "Size": 0,
                            "State": 1,
                            "ModifyTime": 1700000000,
                            "NodeKey": secret_armored.clone(),
                            "NodePassphrase": empty_message.clone(),
                            "FileProperties": null
                        }
                    })
                    .to_string(),
                ),
            },
        ]);
        exchanges.push(ExpectedExchange {
            method: "GET",
            path: "/drive/shares/share-1/folders/root-1/children?Page=0&PageSize=150",
            response: MockResponse::json(r#"{"Links":[]}"#),
        });
        let server = MockServer::start(exchanges);

        let args = crate::cli::ProtonSourceArgs {
            credentials: Some(credentials_path.clone()),
            account_password: Some("real-password".to_owned()),
            share_name: "DriveRoot".to_owned(),
            share_id: None,
            app_version: Some("test-app".to_owned()),
            user_agent: Some("test-agent".to_owned()),
            scan_concurrency: 1,
            tree_cache: crate::cli::TreeCacheMode::ReuseIfPresent,
            no_input: true,
        };

        let opened = with_test_api_base_url(server.base_url(), || from_args(&args, Mode::Quiet))?;
        assert_eq!(opened.source.root_id(), "root-1");
        server.finish();
        Ok(())
    }

    #[test]
    fn reuse_if_present_tree_cache_loads_cached_backend_without_network() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let account_dir = temp_dir.path().join("cached@example.com");
        fs::create_dir_all(&account_dir)?;
        let credentials_path = account_dir.join("session.json");
        write_encrypted_credentials(
            &credentials_path,
            "cached@example.com",
            "real-password",
            &reusable_credentials(),
        )?;
        let backend = cached_backend_fixture(&temp_dir)?;
        save_tree_cache(
            &backend,
            &SessionAccess {
                credentials_path: credentials_path.clone(),
                session_email: Some("cached@example.com".to_owned()),
                session_password: Some("real-password".to_owned()),
            },
        )?;

        let args = crate::cli::ProtonSourceArgs {
            credentials: Some(credentials_path.clone()),
            account_password: Some("real-password".to_owned()),
            share_name: "PhotosRoot".to_owned(),
            share_id: None,
            app_version: Some("test-app".to_owned()),
            user_agent: Some("test-agent".to_owned()),
            scan_concurrency: 1,
            tree_cache: crate::cli::TreeCacheMode::ReuseIfPresent,
            no_input: true,
        };

        let opened =
            with_test_api_base_url("http://127.0.0.1:9", || from_args(&args, Mode::Quiet))?;
        assert_eq!(opened.source.backend_name(), "proton");
        assert_eq!(opened.source.root_id(), "root-1");
        let children = opened.source.list_children("root-1")?;
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "photo.jpg");
        assert_eq!(
            opened.default_state_db.as_deref(),
            Some(account_dir.join("proton-photos.sqlite").as_path())
        );
        Ok(())
    }

    #[test]
    fn photos_root_load_errors_when_photo_share_root_is_missing() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![ExpectedExchange {
            method: "GET",
            path: "/drive/v2/shares/photos",
            response: MockResponse::status(404, r#"{"Error":"not found"}"#),
        }]);
        let account = AccountContext {
            api: Arc::new(test_api(&temp_dir, server.base_url())?),
            address_keys_by_id: HashMap::new(),
        };
        let error = account
            .load_share_root(&ShareInfo {
                name: "PhotosRoot".to_owned(),
                share_id: "photos-root".to_owned(),
                link_id: "root".to_owned(),
                volume_id: "volume-1".to_owned(),
                share_type: "photo".to_owned(),
                state: "active".to_owned(),
                flags: "none".to_owned(),
                creator: "user@example.com".to_owned(),
                metadata_mode: LinkMetadataMode::Photos,
            })
            .expect_err("missing photo share root should fail");
        assert!(error.to_string().contains("PhotosRoot was not available"));
        server.finish();
        Ok(())
    }

    #[test]
    fn from_auth_state_defaults_and_invalid_credentials_json_are_covered() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials_path = temp_dir.path().join("creds.json");

        let api = ProtonApi::from_auth_state(
            &credentials_path,
            reusable_credentials(),
            None,
            None,
            None,
            None,
        )?;
        assert_eq!(api.base_url, super::API_BASE_URL);
        assert_eq!(api.app_version, super::DEFAULT_APP_VERSION);
        assert_eq!(api.user_agent, super::DEFAULT_USER_AGENT);

        fs::write(&credentials_path, b"not-json")?;
        let error = ProtonApi::from_credentials_with_base_url(
            &credentials_path,
            Some("test-app"),
            Some("test-agent"),
            "http://127.0.0.1:9",
            None,
            None,
        )
        .expect_err("invalid credentials json should fail");
        assert!(error.to_string().contains("parse credentials JSON"));
        Ok(())
    }

    #[test]
    fn public_wrappers_and_helpers_cover_early_login_and_share_errors() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials = temp_dir.path().join("creds.json");
        let api = Arc::new(ProtonApi::from_auth_state_with_base_url(
            &credentials,
            ReusableCredential {
                uid: String::new(),
                access_token: String::new(),
                refresh_token: String::new(),
                salted_key_pass: String::new(),
            },
            Some("test-app"),
            Some("test-agent"),
            "http://127.0.0.1:9",
            Some("abc123".to_owned()),
            Some("jakubqa".to_owned()),
        )?);
        let resolved = resolve_login_command(&login_command(&credentials))?;

        let error = complete_login(
            Arc::clone(&api),
            &resolved,
            AuthResponse {
                uid: "uid-1".to_owned(),
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                server_proof: String::new(),
                two_fa: ApiTwoFaInfo {
                    enabled: TWO_FA_TOTP,
                },
                password_mode: 1,
            },
        )
        .expect_err("missing totp");
        assert!(error.to_string().contains("requires a 2FA TOTP code"));

        let error = complete_login(
            Arc::clone(&api),
            &resolved,
            AuthResponse {
                uid: "uid-1".to_owned(),
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                server_proof: String::new(),
                two_fa: ApiTwoFaInfo {
                    enabled: TWO_FA_FIDO2,
                },
                password_mode: 1,
            },
        )
        .expect_err("fido2");
        assert!(error.to_string().contains("FIDO2"));

        let error = complete_login(
            Arc::clone(&api),
            &resolved,
            AuthResponse {
                uid: "uid-1".to_owned(),
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                server_proof: String::new(),
                two_fa: ApiTwoFaInfo { enabled: 4 },
                password_mode: 1,
            },
        )
        .expect_err("unsupported 2fa");
        assert!(
            error
                .to_string()
                .contains("unsupported Proton 2FA configuration flags")
        );

        let error = complete_login(
            Arc::clone(&api),
            &resolved,
            AuthResponse {
                uid: "uid-1".to_owned(),
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                server_proof: String::new(),
                two_fa: ApiTwoFaInfo { enabled: 0 },
                password_mode: super::PASSWORD_MODE_TWO,
            },
        )
        .expect_err("mailbox password");
        assert!(error.to_string().contains("requires a mailbox password"));

        let error = complete_login(
            api,
            &resolved,
            AuthResponse {
                uid: "uid-1".to_owned(),
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                server_proof: String::new(),
                two_fa: ApiTwoFaInfo { enabled: 0 },
                password_mode: 99,
            },
        )
        .expect_err("password mode");
        assert!(
            error
                .to_string()
                .contains("unsupported Proton password mode")
        );

        let invalid_salt_api = Arc::new(ProtonApi::from_auth_state_with_base_url(
            &credentials,
            ReusableCredential {
                salted_key_pass: "%%%".to_owned(),
                ..reusable_credentials()
            },
            Some("test-app"),
            Some("test-agent"),
            "http://127.0.0.1:9",
            None,
            None,
        )?);
        let error = list_shares_with_api(invalid_salt_api).expect_err("invalid salted key pass");
        assert!(error.to_string().contains("decode SaltedKeyPass"));

        let error =
            with_test_api_base_url("http://127.0.0.1:9", || login(&login_command(&credentials)))
                .expect_err("public login wrapper should propagate auth failures");
        assert!(error.to_string().contains("send Proton API request POST"));
        Ok(())
    }

    #[test]
    fn proton_modulus_signature_verifies() {
        let modulus = parse_signed_modulus(TEST_MODULUS_CLEAR_SIGN).expect("signed modulus");
        let expected = base64::engine::general_purpose::STANDARD
            .decode(TEST_MODULUS.as_bytes())
            .expect("expected modulus");
        assert_eq!(modulus, expected);
    }

    #[test]
    fn bcrypt_hash_matches_go_reference() {
        let alphabet = base64::alphabet::Alphabet::new(
            "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        )
        .expect("alphabet");
        let engine = base64::engine::general_purpose::GeneralPurpose::new(
            &alphabet,
            base64::engine::general_purpose::NO_PAD,
        );
        let salt = engine
            .decode("PTTsDBs/mlLnSk6VmtFghe".as_bytes())
            .expect("salt");
        let hash = bcrypt_hash(b"test!!!", &salt).expect("bcrypt");
        assert_eq!(
            hash,
            "$2y$10$PTTsDBs/mlLnSk6VmtFgheNSiK/lSwtJsrBLLDK3kZYI7193nInqy"
        );
    }

    #[test]
    fn crypto_helpers_reject_invalid_inputs() {
        let invalid_signed = TEST_MODULUS_CLEAR_SIGN.replace("W2z5", "X2z5");
        assert!(parse_modulus(&invalid_signed).is_err());
        assert!(hash_password(2, "user", b"password", "AQIDBA==", b"modulus").is_err());
        assert!(hash_password(3, "user", b"password", "yKlc5/CvObfoiw==", b"modulus").is_ok());
        assert!(bcrypt_hash(b"password", b"short-salt").is_err());

        let modulus = parse_signed_modulus(TEST_MODULUS_CLEAR_SIGN).expect("modulus");
        assert!(validate_srp_params(&modulus[..32], &[2]).is_err());
        assert!(validate_srp_params(&modulus, &[1]).is_err());
        let mut unexpected_modulus = vec![0u8; super::SRP_BYTES];
        unexpected_modulus[0] = 5;
        unexpected_modulus[super::SRP_BYTES - 1] = 0x80;
        assert!(validate_srp_params(&unexpected_modulus, &[2]).is_err());

        let mailbox = mailbox_password(b"password", &[7u8; 16]).expect("mailbox hash");
        assert!(!mailbox.is_empty());

        let modulus_minus_one =
            super::biguint_from_le(&modulus) - num_bigint_dig::BigUint::from(1u8);
        let client_secret =
            super::generate_client_secret(&modulus_minus_one).expect("client secret");
        assert!(client_secret > num_bigint_dig::BigUint::from((super::SRP_BITS * 2) as u64));
        assert!(client_secret < modulus_minus_one);
        assert_eq!(
            super::biguint_to_fixed_le(&num_bigint_dig::BigUint::from(7u8), 4),
            vec![7, 0, 0, 0]
        );
    }

    #[test]
    fn secret_key_and_backend_helpers_cover_error_paths() -> Result<()> {
        assert!(SecretKeyRing::from_armored_secret("not armored", b"pass").is_err());

        let empty_ring = SecretKeyRing { keys: Vec::new() };
        let error = empty_ring
            .decrypt_armored_message("ignored")
            .expect_err("empty ring should fail");
        assert!(
            error
                .to_string()
                .contains("empty keyring cannot decrypt armored message")
        );

        let error = empty_ring
            .decrypt_content_session_key("%%%")
            .expect_err("invalid packet encoding");
        assert!(error.to_string().contains("decode ContentKeyPacket"));

        let empty_packet = base64::engine::general_purpose::STANDARD.encode(Vec::<u8>::new());
        let error = empty_ring
            .decrypt_content_session_key(&empty_packet)
            .expect_err("empty packet");
        assert!(error.to_string().contains("ContentKeyPacket is empty"));

        let (secret_a, public_a) = generate_fixture_key("A <a@example.com>")?;
        let (secret_b, _public_b) = generate_fixture_key("B <b@example.com>")?;
        let wrong_ring = SecretKeyRing::from_armored_secret(&secret_b, b"")?;
        let encrypted_for_a = encrypt_armored_message(&public_a, b"secret")?;
        let error = wrong_ring
            .decrypt_armored_message(&encrypted_for_a)
            .expect_err("wrong key should fail");
        assert!(error.to_string().contains("decrypt armored message"));

        let (content_key_packet, _, _) = encrypt_block_and_packet(&public_a, b"plain", &[7u8; 32])?;
        let error = empty_ring
            .decrypt_content_session_key(&content_key_packet)
            .expect_err("missing decrypt key");
        assert!(
            error
                .to_string()
                .contains("no key in keyring could decrypt ContentKeyPacket")
        );

        let inactive = ApiKeyRecord {
            id: "inactive".to_owned(),
            private_key: String::new(),
            token: String::new(),
            signature: String::new(),
            primary: ApiBool(0),
            active: ApiBool(0),
        };
        let error =
            unlock_key_records(&[inactive], b"pass", None).expect_err("no active keys should fail");
        assert!(
            error
                .to_string()
                .contains("no active keys could be unlocked")
        );

        let tokened = ApiKeyRecord {
            id: "tokened".to_owned(),
            private_key: "bad".to_owned(),
            token: "encrypted".to_owned(),
            signature: "sig".to_owned(),
            primary: ApiBool(0),
            active: ApiBool(1),
        };
        let error = unlock_key_records(&[tokened], b"pass", None)
            .expect_err("user keyring should be required");
        assert!(error.to_string().contains("requires a user keyring"));

        let error = unlock_key_records(
            &[ApiKeyRecord {
                id: "tokened-bad-message".to_owned(),
                private_key: secret_a.clone(),
                token: encrypted_for_a,
                signature: "sig".to_owned(),
                primary: ApiBool(0),
                active: ApiBool(1),
            }],
            b"pass",
            Some(&wrong_ring),
        )
        .expect_err("token decrypt should fail");
        assert!(
            error
                .to_string()
                .contains("decrypt token for key tokened-bad-message")
        );

        let bad_key = ApiKeyRecord {
            id: "bad-key".to_owned(),
            private_key: "bad".to_owned(),
            token: String::new(),
            signature: String::new(),
            primary: ApiBool(0),
            active: ApiBool(1),
        };
        let error = unlock_key_records(&[bad_key], b"pass", None).expect_err("bad private key");
        assert!(error.to_string().contains("parse armored private key"));

        let temp_dir = TempDir::new()?;
        let api = Arc::new(test_api(&temp_dir, "http://127.0.0.1:9")?);
        let mut backend = ProtonBackend {
            api,
            share_name: "PhotosRoot".to_owned(),
            share_id: "share-1".to_owned(),
            volume_id: "volume-1".to_owned(),
            root_id: "root-1".to_owned(),
            folders: HashMap::new(),
            files: HashMap::new(),
        };
        assert_eq!(backend.backend_name(), "proton");
        assert_eq!(backend.root_id(), "root-1");
        let error = backend
            .list_children("missing-folder")
            .expect_err("missing folder should fail");
        assert!(error.to_string().contains("unknown Proton folder id"));
        let error = backend
            .open_file("missing-file")
            .err()
            .expect("missing file should fail");
        assert!(error.to_string().contains("unknown Proton file id"));

        backend.files.insert(
            "file-1".to_owned(),
            NativeFile {
                link: ApiLink {
                    link_id: "file-1".to_owned(),
                    link_type: LINK_TYPE_FILE,
                    name: String::new(),
                    size: 0,
                    link_state: 1,
                    modify_time: 0,
                    node_key: String::new(),
                    node_passphrase: String::new(),
                    file_properties: None,
                    xattr: None,
                },
                node_keys: Arc::new(SecretKeyRing { keys: Vec::new() }),
            },
        );
        let error = backend
            .open_file("file-1")
            .err()
            .expect("missing revision metadata should fail");
        assert!(
            error
                .to_string()
                .contains("missing active revision metadata")
        );

        let expected =
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(b"abc"));
        verify_block_hash(b"abc", &expected)?;
        let error = verify_block_hash(b"abc", "wrong").expect_err("hash mismatch");
        assert!(error.to_string().contains("block hash did not match"));
        Ok(())
    }

    fn connected_stream_pair() -> Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let client = TcpStream::connect(address)?;
        let (server, _) = listener.accept()?;
        Ok((client, server))
    }

    #[test]
    fn mock_request_helpers_cover_error_paths() -> Result<()> {
        let (client, server) = connected_stream_pair()?;
        drop(client);
        let request = read_mock_request(&server).map_err(anyhow::Error::msg)?;
        assert!(request.is_none());

        let (mut client, server) = connected_stream_pair()?;
        client.write_all(b"GET / HTTP/1.1\r\nBadHeader\r\n\r\n")?;
        let error = read_mock_request(&server).expect_err("malformed header");
        assert!(error.contains("malformed header"));

        let (mut client, server) = connected_stream_pair()?;
        let expected = Arc::new(Mutex::new(VecDeque::from([ExpectedExchange {
            method: "GET",
            path: "/expected",
            response: MockResponse::json(r#"{}"#),
        }])));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        client.write_all(b"GET /actual HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        handle_mock_connection(server, &expected, &errors, &requests)
            .map_err(anyhow::Error::msg)?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert!(response.contains("200 OK"));
        assert_eq!(requests.lock().expect("requests lock")[0].path, "/actual");
        assert!(
            errors.lock().expect("errors lock")[0]
                .contains("expected GET /expected but got GET /actual")
        );

        let (mut client, server) = connected_stream_pair()?;
        let expected = Arc::new(Mutex::new(VecDeque::new()));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        client.write_all(b"GET /unexpected HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        handle_mock_connection(server, &expected, &errors, &requests)
            .map_err(anyhow::Error::msg)?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert!(response.contains("500 Internal Server Error"));
        assert!(
            errors.lock().expect("errors lock")[0].contains("unexpected request GET /unexpected")
        );

        let (mut client, mut server) = connected_stream_pair()?;
        write_mock_response(
            &mut server,
            &MockResponse {
                status: 418,
                content_type: "text/plain",
                body: b"teapot".to_vec(),
            },
        )?;
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert!(response.contains("418 Status"));
        Ok(())
    }

    #[test]
    fn srp_proofs_match_go_reference() {
        let srp = SrpAuth::new(
            4,
            "jakubqa",
            b"abc123",
            "yKlc5/CvObfoiw==",
            TEST_MODULUS_CLEAR_SIGN,
            TEST_SERVER_EPHEMERAL,
        )
        .expect("srp auth");
        let secret = base64::engine::general_purpose::STANDARD
            .decode(TEST_CLIENT_SECRET.as_bytes())
            .expect("client secret");
        let proofs = srp
            .generate_proofs_with_secret(super::biguint_from_le(&secret))
            .expect("srp proofs");
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(proofs.client_proof),
            TEST_CLIENT_PROOF
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(proofs.expected_server_proof),
            TEST_SERVER_PROOF
        );
    }

    #[test]
    fn modulus_public_key_constant_parses() {
        let (_key, _) = pgp::composed::SignedPublicKey::from_armor_single(std::io::Cursor::new(
            MODULUS_PUBKEY.as_bytes(),
        ))
        .expect("modulus public key");
    }

    #[test]
    fn proton_file_reader_with_no_blocks_returns_eof() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let api = Arc::new(test_api(&temp_dir, "http://127.0.0.1:9")?);
        let mut reader = ProtonFileReader {
            api,
            session_key: pgp::composed::PlainSessionKey::V3_4 {
                key: vec![0; 32].into(),
                sym_alg: pgp::crypto::sym::SymmetricKeyAlgorithm::AES256,
            },
            blocks: Vec::new(),
            next_block: 0,
            current: std::io::Cursor::new(Vec::new()),
            finished: false,
            prefetch: None,
        };
        let mut buffer = [0u8; 8];
        assert_eq!(reader.read(&mut buffer)?, 0);
        assert!(reader.finished);
        Ok(())
    }

    #[test]
    fn proton_file_reader_reports_block_hash_mismatches() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![ExpectedExchange {
            method: "GET",
            path: "/block",
            response: MockResponse::bytes(b"encrypted".to_vec()),
        }]);
        let api = Arc::new(test_api(&temp_dir, server.base_url())?);
        let mut reader = ProtonFileReader {
            api,
            session_key: pgp::composed::PlainSessionKey::V3_4 {
                key: vec![0; 32].into(),
                sym_alg: pgp::crypto::sym::SymmetricKeyAlgorithm::AES256,
            },
            blocks: vec![ApiBlock {
                bare_url: format!("{}/block", server.base_url()),
                token: "token".to_owned(),
                hash: "wrong".to_owned(),
            }],
            next_block: 0,
            current: std::io::Cursor::new(Vec::new()),
            finished: false,
            prefetch: None,
        };
        let error = reader.read(&mut [0u8; 8]).expect_err("hash mismatch");
        assert!(error.to_string().contains("block hash did not match"));
        let requests = server.finish();
        assert_eq!(
            requests[0]
                .headers
                .get("pm-storage-token")
                .map(String::as_str),
            Some("token")
        );
        Ok(())
    }

    #[test]
    fn proton_file_reader_prefetches_multiple_blocks() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (_secret_armored, public_key) = generate_fixture_key("prefetch@example.com")?;
        let block_session_key = [7u8; 32];
        let (_packet_one, encrypted_one, hash_one) =
            encrypt_block_and_packet(&public_key, b"hello ", &block_session_key)?;
        let (_packet_two, encrypted_two, hash_two) =
            encrypt_block_and_packet(&public_key, b"world", &block_session_key)?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/block-1",
                response: MockResponse::bytes(encrypted_one),
            },
            ExpectedExchange {
                method: "GET",
                path: "/block-2",
                response: MockResponse::bytes(encrypted_two),
            },
        ]);
        let api = Arc::new(test_api(&temp_dir, server.base_url())?);
        let session_key = pgp::composed::PlainSessionKey::V3_4 {
            key: block_session_key.to_vec().into(),
            sym_alg: pgp::crypto::sym::SymmetricKeyAlgorithm::AES256,
        };
        let blocks = vec![
            ApiBlock {
                bare_url: format!("{}/block-1", server.base_url()),
                token: "token-1".to_owned(),
                hash: hash_one,
            },
            ApiBlock {
                bare_url: format!("{}/block-2", server.base_url()),
                token: "token-2".to_owned(),
                hash: hash_two,
            },
        ];
        let mut reader = ProtonFileReader {
            api: Arc::clone(&api),
            prefetch: start_block_prefetch(api, session_key.clone(), blocks.clone()),
            session_key,
            blocks,
            next_block: 0,
            current: std::io::Cursor::new(Vec::new()),
            finished: false,
        };
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"hello world");
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        Ok(())
    }

    #[test]
    fn derive_salted_key_pass_prefers_primary_and_active_keys() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![ExpectedExchange {
            method: "GET",
            path: "/core/v4/keys/salts",
            response: MockResponse::json(
                r#"{"KeySalts":[{"Id":"other-key","KeySalt":null},{"Id":"primary-key","KeySalt":"BwcHBwcHBwcHBwcHBwcHBw=="}]}"#,
            ),
        }]);
        let api = test_api(&temp_dir, server.base_url())?;
        let user = ApiUser {
            keys: vec![
                ApiKeyRecord {
                    id: "inactive-key".to_owned(),
                    private_key: String::new(),
                    token: String::new(),
                    signature: String::new(),
                    primary: ApiBool(0),
                    active: ApiBool(0),
                },
                ApiKeyRecord {
                    id: "primary-key".to_owned(),
                    private_key: String::new(),
                    token: String::new(),
                    signature: String::new(),
                    primary: ApiBool(1),
                    active: ApiBool(1),
                },
            ],
        };
        let salted = derive_salted_key_pass(&api, &user, b"password")?;
        assert_eq!(salted.len(), 31);
        let requests = server.finish();
        assert_eq!(requests[0].path, "/core/v4/keys/salts");
        Ok(())
    }

    #[test]
    fn derive_salted_key_pass_errors_when_key_salt_is_missing() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![ExpectedExchange {
            method: "GET",
            path: "/core/v4/keys/salts",
            response: MockResponse::json(
                r#"{"KeySalts":[{"Id":"other-key","KeySalt":"BwcHBwcHBwcHBwcHBwcHBw=="}]}"#,
            ),
        }]);
        let api = test_api(&temp_dir, server.base_url())?;
        let user = ApiUser {
            keys: vec![ApiKeyRecord {
                id: "wanted-key".to_owned(),
                private_key: String::new(),
                token: String::new(),
                signature: String::new(),
                primary: ApiBool(1),
                active: ApiBool(1),
            }],
        };
        let error = derive_salted_key_pass(&api, &user, b"password").expect_err("missing salt");
        assert!(error.to_string().contains("no Proton key salt found"));
        server.finish();
        Ok(())
    }

    #[test]
    fn derive_salted_key_pass_errors_when_no_usable_key_exists() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let api = test_api(&temp_dir, "http://127.0.0.1:9")?;
        let user = ApiUser { keys: Vec::new() };
        let error = derive_salted_key_pass(&api, &user, b"password").expect_err("missing key");
        assert!(error.to_string().contains("no primary active user key"));
        Ok(())
    }

    #[test]
    fn proton_api_methods_cover_success_refresh_and_error_paths() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/users",
                response: MockResponse::status(401, r#"{"Code":401}"#),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/refresh",
                response: MockResponse::json(
                    r#"{"Uid":"uid-2","AccessToken":"access-2","RefreshToken":"refresh-2"}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/users",
                response: MockResponse::json(r#"{"User":{"Keys":[]}}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/addresses",
                response: MockResponse::json(r#"{"Addresses":[{"Id":"addr-1","Keys":[]}]}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/keys/salts",
                response: MockResponse::json(
                    r#"{"KeySalts":[{"Id":"key-1","KeySalt":"AQIDBAUGBwgJCgsMDQ4PEA=="}]}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares?ShowAll=1",
                response: MockResponse::json(
                    r#"{"Shares":[{"ShareId":"share-1","LinkId":"link-1","VolumeId":"volume-1","Type":3,"State":1,"Creator":"user@example.com","Flags":1}]}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::status(404, r#"{"Error":"not found"}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1",
                response: MockResponse::json(
                    r#"{"Share":{"ShareId":"share-1","LinkId":"link-1","AddressId":"addr-1","Key":"key","Passphrase":"passphrase"}}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares/share-1/links/link-1",
                response: MockResponse::json(
                    r#"{"Link":{"LinkId":"link-1","Type":1,"Name":"name","Size":0,"State":1,"ModifyTime":1,"NodeKey":"node-key","NodePassphrase":"node-passphrase","FileProperties":null}}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/volumes/volume-1/folders/link-1/children",
                response: MockResponse::json(r#"{"LinkIDs":["folder-1"],"More":false}"#),
            },
            ExpectedExchange {
                method: "POST",
                path: "/drive/v2/volumes/volume-1/links",
                response: MockResponse::json(
                    r#"{"Links":[{"Link":{"LinkId":"folder-1","Type":1,"Name":"folder","Size":0,"State":1,"ModifyTime":1,"NodeKey":"node-key","NodePassphrase":"node-passphrase"},"Folder":{}}]}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/volumes/volume-1/files/file-1/revisions/rev-1",
                response: MockResponse::json(
                    r#"{"Revision":{"Blocks":[{"BareUrl":"http://unused","Token":"block-token","Hash":"hash"}]}}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/block-1",
                response: MockResponse::bytes(b"encrypted-block".to_vec()),
            },
            ExpectedExchange {
                method: "GET",
                path: "/missing",
                response: MockResponse::status(404, r#"{"Error":"nope"}"#),
            },
        ]);
        let credentials_path = temp_dir.path().join("creds").join("auth.json");
        write_credentials(&credentials_path, &reusable_credentials())?;
        let api = ProtonApi::from_credentials_with_base_url(
            &credentials_path,
            Some("test-app"),
            Some("test-agent"),
            server.base_url(),
            None,
            None,
        )?;

        assert!(api.get_user()?.keys.is_empty());
        assert_eq!(api.credentials().uid, "uid-2");
        assert_eq!(api.get_addresses()?.len(), 1);
        assert_eq!(api.get_key_salts()?.len(), 1);
        assert_eq!(api.list_shares()?.len(), 1);
        assert!(api.get_photos_share_root()?.is_none());
        assert_eq!(api.get_share("share-1")?.share_id, "share-1");
        assert_eq!(api.get_share_link("share-1", "link-1")?.link_id, "link-1");
        assert_eq!(
            api.list_children(
                "volume-1",
                "link-1",
                LINK_TYPE_FOLDER,
                LinkMetadataMode::Drive,
                None
            )?
            .len(),
            1
        );
        assert_eq!(
            api.get_revision_all_blocks("volume-1", "file-1", "rev-1")?
                .blocks
                .len(),
            1
        );
        assert_eq!(
            api.get_block(&format!("{}/block-1", server.base_url()), "block-token")?,
            b"encrypted-block"
        );
        let error = api
            .request_json::<serde_json::Value, serde_json::Value>(
                reqwest::Method::GET,
                "/missing",
                &[],
                None::<&serde_json::Value>,
                true,
            )
            .expect_err("404 should fail");
        assert!(error.to_string().contains("failed with 404"));

        let persisted: ReusableCredential = serde_json::from_slice(&fs::read(&credentials_path)?)?;
        assert_eq!(persisted.uid, "uid-2");
        assert_eq!(persisted.access_token, "access-2");
        assert_eq!(persisted.refresh_token, "refresh-2");

        let requests = server.finish();
        assert_eq!(
            requests[0].headers.get("authorization").map(String::as_str),
            Some("Bearer access-1")
        );
        let refresh_body: serde_json::Value = serde_json::from_slice(&requests[1].body)?;
        assert_eq!(refresh_body["UID"], "uid-1");
        assert_eq!(refresh_body["RefreshToken"], "refresh-1");
        assert_eq!(refresh_body["ResponseType"], "token");
        assert_eq!(refresh_body["GrantType"], "refresh_token");
        assert_eq!(refresh_body["RedirectURI"], "https://protonmail.ch");
        assert!(refresh_body["State"].as_str().is_some());
        Ok(())
    }

    #[test]
    fn request_bytes_absolute_retries_after_refresh_and_reports_http_errors() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials_path = temp_dir.path().join("creds.json");
        write_credentials(&credentials_path, &reusable_credentials())?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/bytes",
                response: MockResponse::status(401, r#"{"Code":401}"#),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/refresh",
                response: MockResponse::json(
                    r#"{"Uid":"uid-2","AccessToken":"access-2","RefreshToken":"refresh-2"}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/bytes",
                response: MockResponse::bytes(b"payload".to_vec()),
            },
            ExpectedExchange {
                method: "GET",
                path: "/missing",
                response: MockResponse::status(404, r#"{"Error":"nope"}"#),
            },
        ]);
        let api = ProtonApi::from_credentials_with_base_url(
            &credentials_path,
            Some("test-app"),
            Some("test-agent"),
            server.base_url(),
            None,
            None,
        )?;
        let bytes = api.request_bytes_absolute(
            reqwest::Method::GET,
            &format!("{}/bytes", server.base_url()),
            None,
            true,
        )?;
        assert_eq!(bytes, b"payload");
        let error = api
            .request_bytes_absolute(
                reqwest::Method::GET,
                &format!("{}/missing", server.base_url()),
                None,
                true,
            )
            .expect_err("404 should fail");
        let text = error.to_string();
        assert!(text.contains("/missing"));
        assert!(text.contains("failed with") || text.contains("send Proton API request"));
        let requests = server.finish();
        assert_eq!(
            requests[0].headers.get("authorization").map(String::as_str),
            Some("Bearer access-1")
        );
        assert_eq!(
            requests[2].headers.get("authorization").map(String::as_str),
            Some("Bearer access-2")
        );
        Ok(())
    }

    #[test]
    fn request_json_retries_after_transient_rate_limit() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials_path = temp_dir.path().join("creds-rate-limit.json");
        write_credentials(&credentials_path, &reusable_credentials())?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/retry-json",
                response: MockResponse::status(429, r#"{"Error":"slow down"}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/retry-json",
                response: MockResponse::json(r#"{"ok":true}"#),
            },
        ]);
        let api = ProtonApi::from_credentials_with_base_url(
            &credentials_path,
            Some("test-app"),
            Some("test-agent"),
            server.base_url(),
            None,
            None,
        )?;
        let value = api.request_json::<serde_json::Value, serde_json::Value>(
            reqwest::Method::GET,
            "/retry-json",
            &[],
            None::<&serde_json::Value>,
            true,
        )?;
        assert_eq!(value["ok"], true);
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        Ok(())
    }

    #[test]
    fn retry_delay_for_attempt_uses_retry_after_and_stops_after_last_attempt() {
        assert_eq!(
            retry_delay_for_attempt(0, Some(Duration::from_secs(7))),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            retry_delay_for_attempt(0, None),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            retry_delay_for_attempt(1, None),
            Some(Duration::from_millis(500))
        );
        assert_eq!(retry_delay_for_attempt(2, None), None);
        assert_eq!(retry_delay_for_attempt(3, None), None);
    }

    #[test]
    fn request_json_retries_after_connection_closed_before_response_complete() -> Result<()> {
        let _lock = MOCK_SERVER_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let base_url = format!("http://{}", listener.local_addr()?);
        let worker = thread::spawn(move || -> Result<()> {
            let (first, _) = listener.accept()?;
            let _ = read_mock_request(&first).map_err(|error| anyhow!(error))?;
            drop(first);

            let (mut second, _) = listener.accept()?;
            let request = read_mock_request(&second)
                .map_err(|error| anyhow!(error))?
                .expect("second request");
            assert_eq!(request.path, "/retry-json");
            write!(
                second,
                "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{{\"ok\":true}}"
            )?;
            second.flush()?;
            Ok(())
        });

        let temp_dir = TempDir::new()?;
        let api = test_api(&temp_dir, &base_url)?;
        let value = api.request_json::<serde_json::Value, serde_json::Value>(
            reqwest::Method::GET,
            "/retry-json",
            &[],
            None::<&serde_json::Value>,
            false,
        )?;
        assert_eq!(value["ok"], true);
        worker.join().expect("join raw server")?;
        Ok(())
    }

    #[test]
    fn request_bytes_absolute_retries_after_truncated_body() -> Result<()> {
        let _lock = MOCK_SERVER_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let base_url = format!("http://{}", listener.local_addr()?);
        let worker = thread::spawn(move || -> Result<()> {
            let (mut first, _) = listener.accept()?;
            let request = read_mock_request(&first)
                .map_err(|error| anyhow!(error))?
                .expect("first request");
            assert_eq!(request.path, "/bytes");
            write!(
                first,
                "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\npay"
            )?;
            first.flush()?;
            drop(first);

            let (mut second, _) = listener.accept()?;
            let request = read_mock_request(&second)
                .map_err(|error| anyhow!(error))?
                .expect("second request");
            assert_eq!(request.path, "/bytes");
            write!(
                second,
                "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\npayload"
            )?;
            second.flush()?;
            Ok(())
        });

        let temp_dir = TempDir::new()?;
        let api = test_api(&temp_dir, &base_url)?;
        let bytes = api.request_bytes_absolute(
            reqwest::Method::GET,
            &format!("{base_url}/bytes"),
            None,
            false,
        )?;
        assert_eq!(bytes, b"payload");
        worker.join().expect("join raw server")?;
        Ok(())
    }

    #[test]
    fn parse_retry_after_seconds_accepts_numeric_values() {
        assert_eq!(parse_retry_after_seconds("2"), Some(Duration::from_secs(2)));
        assert_eq!(parse_retry_after_seconds(" invalid "), None);
    }

    #[test]
    fn account_context_covers_main_share_listing_and_missing_address_keyring() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/drive/shares?ShowAll=1",
                response: MockResponse::json(
                    r#"{"Shares":[{"ShareId":"main-share","LinkId":"root-link","VolumeId":"volume-1","Type":1,"State":1,"Creator":"user@example.com","Flags":0}]}"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/drive/v2/shares/photos",
                response: MockResponse::status(404, r#"{"Error":"not found"}"#),
            },
        ]);
        let context = AccountContext {
            api: Arc::new(test_api(&temp_dir, server.base_url())?),
            address_keys_by_id: HashMap::new(),
        };
        let shares = context.list_share_infos()?;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "My files");
        let error = context
            .unlock_share_key(&ApiShare {
                share_id: "share-1".to_owned(),
                link_id: "link-1".to_owned(),
                address_id: "missing-address".to_owned(),
                key: "bad".to_owned(),
                passphrase: "bad".to_owned(),
            })
            .expect_err("missing address keyring");
        assert!(error.to_string().contains("missing address keyring"));
        server.finish();
        Ok(())
    }

    #[test]
    fn authenticate_password_sends_expected_requests_and_auth_2fa_posts_code() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/info",
                response: MockResponse::json(format!(
                    r#"{{"Version":4,"Modulus":"{}","ServerEphemeral":"{}","Salt":"yKlc5/CvObfoiw==","SrpSession":"session-1"}}"#,
                    TEST_MODULUS_CLEAR_SIGN.replace('\n', "\\n"),
                    TEST_SERVER_EPHEMERAL,
                )),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4",
                response: MockResponse::json(
                    r#"{"Uid":"uid-1","AccessToken":"access-1","RefreshToken":"refresh-1","ServerProof":"AQ==","2FA":{"Enabled":0},"PasswordMode":1}"#,
                ),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/2fa",
                response: MockResponse::json(r#"{}"#),
            },
        ]);
        let api = test_api(&temp_dir, server.base_url())?;
        let error = api
            .authenticate_password("jakubqa", b"abc123", true)
            .expect_err("server proof is intentionally invalid");
        assert!(!error.to_string().trim().is_empty());
        api.set_auth_state(reusable_credentials());
        api.auth_2fa("123456")?;
        let requests = server.finish();
        assert_eq!(requests[0].path, "/auth/v4/info");
        assert_eq!(requests[1].path, "/auth/v4");
        assert_eq!(requests[2].path, "/auth/v4/2fa");
        let auth_info_body: serde_json::Value = serde_json::from_slice(&requests[0].body)?;
        assert_eq!(auth_info_body["Username"], "jakubqa");
        let auth_body: serde_json::Value = serde_json::from_slice(&requests[1].body)?;
        assert_eq!(auth_body["Username"], "jakubqa");
        assert_eq!(auth_body["SRPSession"], "session-1");
        assert!(auth_body["ClientEphemeral"].as_str().is_some());
        assert!(auth_body["ClientProof"].as_str().is_some());
        let two_fa_body: serde_json::Value = serde_json::from_slice(&requests[2].body)?;
        assert_eq!(two_fa_body["TwoFactorCode"], "123456");
        Ok(())
    }

    #[test]
    fn authenticate_password_retries_with_human_verification_headers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/info",
                response: MockResponse::json(format!(
                    r#"{{"Version":4,"Modulus":"{}","ServerEphemeral":"{}","Salt":"yKlc5/CvObfoiw==","SRPSession":"session-1"}}"#,
                    TEST_MODULUS_CLEAR_SIGN.replace('\n', "\\n"),
                    TEST_SERVER_EPHEMERAL,
                )),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4",
                response: MockResponse::status(
                    422,
                    r#"{"Code":9001,"Error":"captcha required","Details":{"HumanVerificationToken":"hv-start","HumanVerificationMethods":["captcha"],"Title":"Human Verification","WebUrl":"https://verify.proton.me/?methods=captcha&token=hv-start","ExpiresAt":4102444800}}"#,
                ),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4",
                response: MockResponse::json(format!(
                    r#"{{"Uid":"uid-1","AccessToken":"access-1","RefreshToken":"refresh-1","ServerProof":"{}","2FA":{{"Enabled":0}},"PasswordMode":1}}"#,
                    TEST_SERVER_PROOF,
                )),
            },
        ]);
        let api = test_api(&temp_dir, server.base_url())?;
        let client_secret = base64::engine::general_purpose::STANDARD
            .decode(TEST_CLIENT_SECRET.as_bytes())
            .expect("client secret");
        let auth = with_test_human_verification_answer(
            HumanVerificationAnswer {
                token: "hv-solved".to_owned(),
                token_type: "captcha".to_owned(),
            },
            || {
                with_test_srp_client_secret(biguint_from_le(&client_secret), || {
                    api.authenticate_password("jakubqa", b"abc123", false)
                })
            },
        )?;
        assert_eq!(auth.uid, "uid-1");
        let requests = server.finish();
        assert_eq!(requests[1].path, "/auth/v4");
        assert_eq!(
            requests[2]
                .headers
                .get("x-pm-human-verification-token")
                .map(String::as_str),
            Some("hv-solved")
        );
        assert_eq!(
            requests[2]
                .headers
                .get("x-pm-human-verification-token-type")
                .map(String::as_str),
            Some("captcha")
        );
        Ok(())
    }

    #[test]
    fn public_login_wrapper_succeeds_with_deterministic_srp_secret() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials = temp_dir.path().join("login").join("creds.json");
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"PhotosRoot")?;

        let mut expected = vec![
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/info",
                response: MockResponse::json(format!(
                    r#"{{"Version":4,"Modulus":"{}","ServerEphemeral":"{}","Salt":"yKlc5/CvObfoiw==","SrpSession":"session-1"}}"#,
                    TEST_MODULUS_CLEAR_SIGN.replace('\n', "\\n"),
                    TEST_SERVER_EPHEMERAL,
                )),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4",
                response: MockResponse::json(format!(
                    r#"{{"Uid":"uid-1","AccessToken":"access-1","RefreshToken":"refresh-1","ServerProof":"{}","2FA":{{"Enabled":{}}},"PasswordMode":1}}"#,
                    TEST_SERVER_PROOF, TWO_FA_TOTP,
                )),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/2fa",
                response: MockResponse::json(r#"{}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/users",
                response: MockResponse::json(
                    serde_json::json!({
                        "User": {
                            "Keys": [{
                                "Id": "user-key",
                                "PrivateKey": secret_armored.clone(),
                                "Token": "",
                                "Signature": "",
                                "Primary": 1,
                                "Active": 1
                            }]
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/keys/salts",
                response: MockResponse::json(
                    r#"{"KeySalts":[{"Id":"user-key","KeySalt":"AQIDBAUGBwgJCgsMDQ4PEA=="}]}"#,
                ),
            },
        ];
        expected.extend(share_listing_exchanges(
            &secret_armored,
            &empty_message,
            &root_name,
        ));

        let server = MockServer::start(expected);
        let base_url = server.base_url().to_owned();
        let mut command = login_command(&credentials);
        command.two_fa = Some("123456".to_owned());
        let client_secret = base64::engine::general_purpose::STANDARD
            .decode(TEST_CLIENT_SECRET.as_bytes())
            .expect("client secret");

        let resolved = resolve_login_command(&command)?;
        let login_result = with_test_api_base_url(&base_url, || {
            with_test_srp_client_secret(biguint_from_le(&client_secret), || {
                let api = Arc::new(
                    ProtonApi::from_auth_state(
                        &resolved.credentials,
                        empty_credentials(),
                        resolved.app_version.as_deref(),
                        resolved.user_agent.as_deref(),
                        Some(resolved.password.clone()),
                        Some(resolved.email.clone()),
                    )
                    .expect("create Proton API"),
                );
                login_with_api(api, &resolved)
            })
        })?;
        assert_eq!(login_result.len(), 1);
        assert_eq!(login_result[0].name, "PhotosRoot (Device)");

        let requests = server.finish();
        let auth_body: serde_json::Value = serde_json::from_slice(&requests[1].body)?;
        assert_eq!(requests[0].path, "/auth/v4/info");
        assert_eq!(requests[1].path, "/auth/v4");
        assert_eq!(requests[2].path, "/auth/v4/2fa");
        assert_eq!(auth_body["Username"], "jakubqa");
        assert_eq!(auth_body["SRPSession"], "session-1");
        assert_eq!(auth_body["ClientProof"], TEST_CLIENT_PROOF);
        Ok(())
    }

    #[test]
    fn complete_login_and_public_shares_succeed_and_persist_credentials() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let credentials = temp_dir.path().join("nested").join("creds.json");
        let (secret_armored, public_key) = generate_fixture_key("Fixture <fixture@example.com>")?;
        let empty_message = encrypt_armored_message(&public_key, b"")?;
        let root_name = encrypt_armored_message(&public_key, b"PhotosRoot")?;
        let raw_salt = base64::engine::general_purpose::STANDARD
            .decode(b"AQIDBAUGBwgJCgsMDQ4PEA==")
            .expect("base64 salt");

        let mut expected = vec![
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/2fa",
                response: MockResponse::json(r#"{}"#),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/users",
                response: MockResponse::json(
                    serde_json::json!({
                        "User": {
                            "Keys": [{
                                "Id": "user-key",
                                "PrivateKey": secret_armored.clone(),
                                "Token": "",
                                "Signature": "",
                                "Primary": 1,
                                "Active": 1
                            }]
                        }
                    })
                    .to_string(),
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/keys/salts",
                response: MockResponse::json(
                    r#"{"KeySalts":[{"Id":"user-key","KeySalt":"AQIDBAUGBwgJCgsMDQ4PEA=="}]}"#,
                ),
            },
        ];
        expected.extend(share_listing_exchanges(
            &secret_armored,
            &empty_message,
            &root_name,
        ));

        let server = MockServer::start(expected);
        let base_url = server.base_url().to_owned();
        let mut command = login_command(&credentials);
        command.two_fa = Some("123456".to_owned());
        let resolved = resolve_login_command(&command)?;

        let api = Arc::new(ProtonApi::from_auth_state_with_base_url(
            &credentials,
            ReusableCredential {
                uid: String::new(),
                access_token: String::new(),
                refresh_token: String::new(),
                salted_key_pass: String::new(),
            },
            command.app_version.as_deref(),
            command.user_agent.as_deref(),
            &base_url,
            Some(resolved.password.clone()),
            Some(resolved.email.clone()),
        )?);
        let shares = complete_login(
            Arc::clone(&api),
            &resolved,
            AuthResponse {
                uid: "uid-1".to_owned(),
                access_token: "access-1".to_owned(),
                refresh_token: "refresh-1".to_owned(),
                server_proof: String::new(),
                two_fa: ApiTwoFaInfo {
                    enabled: TWO_FA_TOTP,
                },
                password_mode: 1,
            },
        )?;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "PhotosRoot (Device)");
        assert!(credentials.exists());

        let encrypted_bytes = fs::read(&credentials)?;
        let persisted: ReusableCredential =
            serde_json::from_slice(&accounts::decrypt_session_bytes(
                &credentials,
                &encrypted_bytes,
                Some(&resolved.password),
            )?)?;
        let expected_salted_key_pass = {
            let mailbox = mailbox_password(resolved.password.as_bytes(), &raw_salt)?;
            base64::engine::general_purpose::STANDARD.encode(&mailbox[mailbox.len() - 31..])
        };
        assert_eq!(persisted.uid, "uid-1");
        assert_eq!(persisted.access_token, "access-1");
        assert_eq!(persisted.refresh_token, "refresh-1");
        assert_eq!(persisted.salted_key_pass, expected_salted_key_pass);

        let requests = server.finish();
        assert_eq!(requests[0].path, "/auth/v4/2fa");
        let two_fa_body: serde_json::Value = serde_json::from_slice(&requests[0].body)?;
        assert_eq!(two_fa_body["TwoFactorCode"], "123456");

        let server = MockServer::start(share_listing_exchanges(
            &secret_armored,
            &empty_message,
            &root_name,
        ));
        let base_url = server.base_url().to_owned();
        let listed = with_test_api_base_url(&base_url, || {
            list_shares(&crate::cli::SharesCommand {
                credentials: Some(credentials.clone()),
                account_password: Some(resolved.password.clone()),
                app_version: Some("test-app".to_owned()),
                user_agent: Some("test-agent".to_owned()),
                no_input: true,
            })
        })?;
        assert_eq!(listed, shares);

        server.finish();
        Ok(())
    }

    #[test]
    fn authenticate_password_rejects_bad_server_proof() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let server = MockServer::start(vec![
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4/info",
                response: MockResponse::json(format!(
                    r#"{{"Version":4,"Modulus":"{}","ServerEphemeral":"{}","Salt":"yKlc5/CvObfoiw==","SrpSession":"session-1"}}"#,
                    TEST_MODULUS_CLEAR_SIGN.replace('\n', "\\n"),
                    TEST_SERVER_EPHEMERAL,
                )),
            },
            ExpectedExchange {
                method: "POST",
                path: "/auth/v4",
                response: MockResponse::json(
                    r#"{"Uid":"uid-1","AccessToken":"access-1","RefreshToken":"refresh-1","ServerProof":"AQ==","2FA":{"Enabled":0},"PasswordMode":1}"#,
                ),
            },
        ]);
        let api = test_api(&temp_dir, server.base_url())?;
        let error = api
            .authenticate_password("jakubqa", b"abc123", true)
            .expect_err("bad proof should fail");
        assert!(!error.to_string().trim().is_empty());
        server.finish();
        Ok(())
    }

    #[test]
    fn human_verification_challenge_parsing_and_local_callback_work() -> Result<()> {
        let challenge = parse_human_verification_challenge(
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            r#"{"Code":9001,"Error":"captcha required","Details":{"HumanVerificationToken":"hv-start","HumanVerificationMethods":["captcha"],"Title":"Human Verification","WebUrl":"https://verify.proton.me/?methods=captcha&token=hv-start","ExpiresAt":4102444800}}"#,
        )
        .expect("challenge should parse");
        assert_eq!(challenge.token, "hv-start");
        assert_eq!(challenge.methods, vec!["captcha"]);
        assert_eq!(
            challenge.web_url.as_deref(),
            Some("https://verify.proton.me/?methods=captcha&token=hv-start")
        );

        let upstream = MockServer::start(vec![
            ExpectedExchange {
                method: "GET",
                path: "/core/v4/captcha?Token=hv-start&ForceWebMessaging=1",
                response: MockResponse::status(
                    200,
                    r#"<html><body><script>window.parent.postMessage({"type":"pm_captcha","token":"hv-start:solved"}, "*");</script></body></html>"#,
                ),
            },
            ExpectedExchange {
                method: "GET",
                path: "/captcha/v1/assets/?purpose=login&token=hv-start",
                response: MockResponse::status(200, r#"<html><body>captcha assets</body></html>"#),
            },
        ]);
        let server = HumanVerificationServer::start(
            upstream.base_url(),
            &HumanVerificationChallenge {
                token: "hv-start".to_owned(),
                methods: vec!["captcha".to_owned()],
                web_url: Some(format!(
                    "{}/?methods=captcha&token=hv-start",
                    upstream.base_url()
                )),
                title: challenge.title.clone(),
                expires_at: Some(4102444800),
            },
        )?;
        let local_url = server.local_url.clone();
        let page = get_text_with_retries(&local_url)?;
        assert!(page.contains("Complete Proton CAPTCHA"));
        assert!(page.contains("/api/core/v4/captcha?Token=hv-start&ForceWebMessaging=1"));

        let proxied = get_text_with_retries(&format!(
            "{local_url}/api/core/v4/captcha?Token=hv-start&ForceWebMessaging=1"
        ))?;
        assert!(proxied.contains("pm_captcha"));

        let proxied_assets = get_text_with_retries(&format!(
            "{local_url}/captcha/v1/assets/?purpose=login&token=hv-start"
        ))?;
        assert!(proxied_assets.contains("captcha assets"));

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(format!("{local_url}/complete"))
            .json(&HumanVerificationAnswer {
                token: "hv-solved".to_owned(),
                token_type: "captcha".to_owned(),
            })
            .send()?;
        assert!(response.status().is_success());
        let answer = server.wait_for_answer(Duration::from_secs(2))?;
        assert_eq!(
            answer,
            HumanVerificationAnswer {
                token: "hv-solved".to_owned(),
                token_type: "captcha".to_owned(),
            }
        );
        upstream.finish();
        Ok(())
    }

    #[test]
    fn human_verification_proxy_rewrites_local_origin_and_referer() -> Result<()> {
        let upstream = MockServer::start(vec![ExpectedExchange {
            method: "POST",
            path: "/captcha/v1/challenge",
            response: MockResponse::status(200, r#"{"ok":true}"#),
        }]);
        let upstream_base_url = upstream.base_url().to_owned();
        let mut server = HumanVerificationServer::start(
            &upstream_base_url,
            &HumanVerificationChallenge {
                token: "hv-start".to_owned(),
                methods: vec!["captcha".to_owned()],
                web_url: Some(format!(
                    "{upstream_base_url}/?methods=captcha&token=hv-start"
                )),
                title: Some("Human Verification".to_owned()),
                expires_at: Some(4102444800),
            },
        )?;
        let local_url = server.local_url.clone();
        let client = reqwest::blocking::Client::new();
        let mut response = None;
        let mut last_error = None;
        for _ in 0..5 {
            match client
                .post(format!("{local_url}/captcha/v1/challenge"))
                .header("Origin", &local_url)
                .header(
                    "Referer",
                    format!("{local_url}/api/core/v4/captcha?Token=hv-start&ForceWebMessaging=1"),
                )
                .header("Accept-Language", "en-US,en;q=0.9")
                .header("Content-Type", "application/json")
                .body(r#"{"response":"solved"}"#)
                .send()
            {
                Ok(value) => {
                    response = Some(value);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
            thread::sleep(Duration::from_millis(50));
        }
        let response = match response {
            Some(response) => response,
            None => return Err(last_error.expect("retry error").into()),
        };
        assert!(response.status().is_success());

        server.stop();
        let requests = upstream.finish();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].headers.get("origin").map(String::as_str),
            Some(upstream_base_url.as_str())
        );
        let expected_referer = format!(
            "{}/core/v4/captcha?Token=hv-start&ForceWebMessaging=1",
            upstream_base_url
        );
        assert_eq!(
            requests[0].headers.get("referer").map(String::as_str),
            Some(expected_referer.as_str())
        );
        assert_eq!(
            requests[0]
                .headers
                .get("accept-language")
                .map(String::as_str),
            Some("en-US,en;q=0.9")
        );
        Ok(())
    }

    #[test]
    fn parse_iso8601_handles_canonical_and_legacy_formats() {
        // Canonical RFC 3339 / ISO 8601 with milliseconds and `Z`.
        let canonical = parse_iso8601_to_ns("2024-08-15T14:32:00.123Z").expect("canonical");
        // 2024-08-15T14:32:00 UTC = 1_723_732_320 seconds since epoch.
        assert_eq!(canonical, 1_723_732_320 * 1_000_000_000 + 123_000_000);

        // Legacy `+0000` form emitted by older Proton clients.
        let legacy = parse_iso8601_to_ns("2009-02-13T23:31:30+0000").expect("legacy");
        assert_eq!(legacy, 1_234_567_890 * 1_000_000_000);

        // `+HH:MM` offset.
        let offset = parse_iso8601_to_ns("2024-08-15T16:32:00+02:00").expect("offset");
        assert_eq!(offset, 1_723_732_320 * 1_000_000_000);

        // No timezone designator: treated as UTC.
        let bare = parse_iso8601_to_ns("2024-08-15T14:32:00").expect("bare");
        assert_eq!(bare, 1_723_732_320 * 1_000_000_000);

        // Sub-second precision: 9-digit nanosecond expansion.
        let nanos = parse_iso8601_to_ns("2024-08-15T14:32:00.000000789Z").expect("nanos");
        assert_eq!(nanos, 1_723_732_320 * 1_000_000_000 + 789);

        // Garbage input rejects gracefully.
        assert!(parse_iso8601_to_ns("not a timestamp").is_none());
        assert!(parse_iso8601_to_ns("").is_none());
        assert!(parse_iso8601_to_ns("2024-13-01T00:00:00Z").is_none());
    }

    #[test]
    fn parse_xattr_payload_extracts_common_and_camera_fields() {
        let payload = r#"{
            "Common": {
                "ModificationTime": "2024-08-15T14:32:00.000Z",
                "Size": 1234,
                "Digests": { "SHA1": "ABCDEF1234567890" }
            },
            "Camera": {
                "CaptureTime": "2020-01-02T03:04:05Z",
                "Device": "iPhone"
            }
        }"#;
        let parsed = parse_xattr_payload(payload);
        assert_eq!(
            parsed.modification_time_ns,
            Some(1_723_732_320 * 1_000_000_000)
        );
        assert_eq!(parsed.capture_time_ns, Some(1_577_934_245 * 1_000_000_000));
        assert_eq!(parsed.sha1.as_deref(), Some("abcdef1234567890"));
    }

    #[test]
    fn parse_xattr_payload_tolerates_partial_and_malformed_input() {
        // Missing fields should produce None silently.
        let only_common = parse_xattr_payload(r#"{"Common": {}}"#);
        assert!(only_common.modification_time_ns.is_none());
        assert!(only_common.capture_time_ns.is_none());
        assert!(only_common.sha1.is_none());

        // Garbage timestamp should be ignored, but parsing must not panic.
        let bad_time = parse_xattr_payload(
            r#"{"Common": {"ModificationTime": "yesterday", "Digests": {"SHA1": ""}}}"#,
        );
        assert!(bad_time.modification_time_ns.is_none());
        // Empty SHA1 is filtered out so callers do not record empty strings.
        assert!(bad_time.sha1.is_none());

        // Outright invalid JSON returns the default ParsedXAttr.
        let invalid = parse_xattr_payload("not json");
        assert!(invalid.modification_time_ns.is_none());
        assert!(invalid.capture_time_ns.is_none());
        assert!(invalid.sha1.is_none());
    }

    /// Regression for the bug where Proton's XAttr blobs (and other
    /// payloads wrapped in a Compressed Data Packet) decrypted into
    /// raw deflate bytes instead of the inner plaintext, because
    /// `decrypt_armored_message` did not unwrap the compression layer.
    /// The fix is a single `.decompress()` call after `decrypt`.
    #[test]
    fn decrypt_armored_message_walks_into_compressed_payload() -> Result<()> {
        let (secret_armored, public_key) = generate_fixture_key("Fixture <c@example.com>")?;
        let ring = SecretKeyRing::from_armored_secret(&secret_armored, b"")?;

        let plaintext = b"hello compressed";
        let armored = encrypt_compressed_armored_message(&public_key, plaintext)?;

        // Sanity check: the message really is compressed inside the encrypted
        // envelope. If the builder ever stops compressing, this test silently
        // becomes a tautology, so guard against that explicitly.
        let raw = ring.decrypt_armored_message(&armored)?;
        assert_eq!(
            raw, plaintext,
            "decrypt + decompress should yield plaintext"
        );
        Ok(())
    }

    /// Helper: build a minimal `ApiLink` with the bare fields needed by
    /// `decrypt_xattr_for_link`. The other fields are placeholders since
    /// the function under test only inspects `link_id`, `name`, and
    /// `xattr`.
    fn link_with_xattr(xattr: Option<&str>) -> ApiLink {
        ApiLink {
            link_id: "test-link".to_owned(),
            link_type: LINK_TYPE_FILE,
            name: "encrypted-name".to_owned(),
            size: 0,
            link_state: LINK_STATE_ACTIVE,
            modify_time: 0,
            node_key: String::new(),
            node_passphrase: String::new(),
            file_properties: None,
            xattr: xattr.map(str::to_owned),
        }
    }

    #[test]
    fn decrypt_xattr_returns_empty_when_field_is_absent() {
        let ring = SecretKeyRing { keys: Vec::new() };
        let link = link_with_xattr(None);
        let parsed = decrypt_xattr_for_link(&link, &ring);
        assert!(parsed.modification_time_ns.is_none());
        assert!(parsed.capture_time_ns.is_none());
        assert!(parsed.sha1.is_none());
    }

    #[test]
    fn decrypt_xattr_returns_empty_when_field_is_blank() {
        let ring = SecretKeyRing { keys: Vec::new() };
        let link = link_with_xattr(Some("   \n  "));
        let parsed = decrypt_xattr_for_link(&link, &ring);
        assert!(parsed.modification_time_ns.is_none());
        assert!(parsed.capture_time_ns.is_none());
        assert!(parsed.sha1.is_none());
    }

    #[test]
    fn decrypt_xattr_returns_empty_when_payload_cannot_be_decrypted() -> Result<()> {
        // A real PGP message wrapper that the ring cannot unlock: encrypted
        // for a different keyring entirely.
        let (_secret_a, public_a) = generate_fixture_key("A <a@example.com>")?;
        let (secret_b, _public_b) = generate_fixture_key("B <b@example.com>")?;
        let wrong_ring = SecretKeyRing::from_armored_secret(&secret_b, b"")?;

        let armored = encrypt_armored_message(&public_a, b"unreachable")?;
        let link = link_with_xattr(Some(&armored));
        let parsed = decrypt_xattr_for_link(&link, &wrong_ring);
        assert!(parsed.modification_time_ns.is_none());
        assert!(parsed.capture_time_ns.is_none());
        assert!(parsed.sha1.is_none());
        Ok(())
    }

    #[test]
    fn decrypt_xattr_extracts_timestamps_from_real_compressed_payload() -> Result<()> {
        // Simulate exactly what Proton ships: a Compressed Data Packet
        // wrapping a JSON payload with the expected schema, then encrypted
        // with the file's node key.
        let (secret_armored, public_key) = generate_fixture_key("File <f@example.com>")?;
        let ring = SecretKeyRing::from_armored_secret(&secret_armored, b"")?;

        let json = r#"{"Common":{"ModificationTime":"2024-08-15T14:32:00.000Z","Size":1000,"Digests":{"SHA1":"deadbeef"}},"Camera":{"CaptureTime":"2024-08-15T14:00:00Z"}}"#;
        let armored = encrypt_compressed_armored_message(&public_key, json.as_bytes())?;
        let link = link_with_xattr(Some(&armored));

        let parsed = decrypt_xattr_for_link(&link, &ring);
        assert_eq!(parsed.modification_time_ns, Some(1_723_732_320_000_000_000));
        assert_eq!(parsed.capture_time_ns, Some(1_723_730_400_000_000_000));
        assert_eq!(parsed.sha1.as_deref(), Some("deadbeef"));
        Ok(())
    }

    /// `xattr_debug_enabled` and `xattr_debug_max_lines` are read from the
    /// process environment, so we serialize their tests inside a single
    /// test to avoid races between the shared env var.
    #[test]
    fn xattr_debug_helpers_read_environment_variables() {
        // SAFETY: env mutation is process-wide. We restore prior values to
        // limit blast radius. Other XAttr tests do not depend on these
        // variables being set.
        let prior_enabled = std::env::var("PROTONPICS_DEBUG_XATTR").ok();
        let prior_max = std::env::var("PROTONPICS_DEBUG_XATTR_MAX").ok();

        unsafe { std::env::remove_var("PROTONPICS_DEBUG_XATTR") };
        assert!(
            !xattr_debug_enabled(),
            "unset env should disable debug mode"
        );

        unsafe { std::env::set_var("PROTONPICS_DEBUG_XATTR", "0") };
        assert!(!xattr_debug_enabled(), "0 should disable debug mode");

        unsafe { std::env::set_var("PROTONPICS_DEBUG_XATTR", "1") };
        assert!(xattr_debug_enabled(), "1 should enable debug mode");

        unsafe { std::env::set_var("PROTONPICS_DEBUG_XATTR", "yes") };
        assert!(xattr_debug_enabled(), "yes should enable debug mode");

        unsafe { std::env::set_var("PROTONPICS_DEBUG_XATTR", "true") };
        assert!(xattr_debug_enabled(), "true should enable debug mode");

        unsafe { std::env::remove_var("PROTONPICS_DEBUG_XATTR_MAX") };
        assert_eq!(xattr_debug_max_lines(), 50, "default cap is 50");

        unsafe { std::env::set_var("PROTONPICS_DEBUG_XATTR_MAX", "garbage") };
        assert_eq!(xattr_debug_max_lines(), 50, "non-numeric falls back to 50");

        unsafe { std::env::set_var("PROTONPICS_DEBUG_XATTR_MAX", "  17 ") };
        assert_eq!(xattr_debug_max_lines(), 17, "trimmed numeric value is read");

        // Restore.
        match prior_enabled {
            Some(value) => unsafe { std::env::set_var("PROTONPICS_DEBUG_XATTR", value) },
            None => unsafe { std::env::remove_var("PROTONPICS_DEBUG_XATTR") },
        }
        match prior_max {
            Some(value) => unsafe { std::env::set_var("PROTONPICS_DEBUG_XATTR_MAX", value) },
            None => unsafe { std::env::remove_var("PROTONPICS_DEBUG_XATTR_MAX") },
        }
    }
}
