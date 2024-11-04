use std::str::FromStr;
use solana_sdk::instruction::CompiledInstruction;
use solana_sdk::message::VersionedMessage;
use {
    crate::{
        hbase::Error as HBaseError,
        hbase::HBaseConnection,
    },
    serde::{Deserialize, Serialize},
    solana_binary_encoder::{
        extract_memos,
        transaction_status::{
            TransactionWithStatusMeta,
            VersionedConfirmedBlock,
            TransactionByAddrInfo,
            VersionedTransactionWithStatusMeta,
            ConfirmedTransactionWithStatusMeta,
            TransactionStatusMeta,
        },
        convert::{
            generated,
            tx_by_addr
        },
        compression::compress_best,
    },
    solana_sdk::{
        clock::{Slot, UnixTimestamp},
        pubkey::Pubkey,
        sysvar::is_sysvar_id,
        transaction::{TransactionError, VersionedTransaction},
    },
    // solana_storage_proto::convert::generated,
    extract_memos::extract_and_fmt_memos,
    // transaction_error::TransactionError,
    log::{
        debug,
        error,
        info,
        // warn
    },
    std::{
        // time::Duration,
        collections::{HashMap, HashSet},
    },
    thiserror::Error,
    tokio::task::JoinError,
};
use md5::{compute};
use solana_sdk::message::v0::LoadedAddresses;
use memcache::{Client, MemcacheError};
use crate::hbase::HBase;

#[derive(Debug, Error)]
pub enum Error {
    #[error("HBase: {0}")]
    HBaseError(HBaseError),

    #[error("I/O Error: {0}")]
    IoError(std::io::Error),

    #[error("Transaction encoded is not supported")]
    UnsupportedTransactionEncoding,

    #[error("Missing signature")]
    MissingSignature,

    #[error("tokio error")]
    TokioJoinError(JoinError),

    #[error("Memcache error: {0}")]
    MemcacheError(MemcacheError),

    #[error("Protobuf error: {0}")]
    EncodingError(prost::EncodeError),
}

impl std::convert::From<HBaseError> for Error {
    fn from(err: HBaseError) -> Self {
        Self::HBaseError(err)
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<MemcacheError> for Error {
    fn from(err: MemcacheError) -> Self {
        Self::MemcacheError(err)
    }
}

impl From<TaskError> for Error {
    fn from(err: TaskError) -> Self {
        match err {
            TaskError::HBaseError(hbase_err) => Error::HBaseError(hbase_err),
            TaskError::MemcacheError(memcache_err) => Error::MemcacheError(memcache_err),
            TaskError::IoError(io_err) => Error::IoError(io_err),
            TaskError::EncodingError(enc_err) => Error::EncodingError(enc_err),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

enum TaskResult {
    BytesWritten(usize),
    CachedTransactions(usize),
}

#[derive(Debug)]
enum TaskError {
    HBaseError(HBaseError),
    MemcacheError(MemcacheError),
    IoError(std::io::Error),
    EncodingError(prost::EncodeError)
}

impl From<std::io::Error> for TaskError {
    fn from(err: std::io::Error) -> Self {
        TaskError::IoError(err)
    }
}

impl From<HBaseError> for TaskError {
    fn from(err: HBaseError) -> Self {
        TaskError::HBaseError(err)
    }
}

impl From<MemcacheError> for TaskError {
    fn from(err: MemcacheError) -> Self {
        TaskError::MemcacheError(err)
    }
}

#[derive(Debug)]
pub enum CacheWriteError {
    MemcacheError(MemcacheError),         // Error from cache client
    IoError(std::io::Error),                // Error from encoding (e.g., Protobuf)
    EncodingError(prost::EncodeError),
}

impl From<CacheWriteError> for TaskError {
    fn from(error: CacheWriteError) -> Self {
        match error {
            CacheWriteError::MemcacheError(e) => TaskError::MemcacheError(e),
            CacheWriteError::IoError(e) => TaskError::IoError(e),
            CacheWriteError::EncodingError(e) => TaskError::EncodingError(e),
        }
    }
}

// Convert a slot to its bucket representation whereby lower slots are always lexically ordered
// before higher slots
fn slot_to_key(slot: Slot) -> String {
    format!("{slot:016x}")
}

// fn slot_to_blocks_key(slot: Slot) -> String {
//     slot_to_key(slot)
// }

fn slot_to_blocks_key(slot: Slot, use_md5: bool) -> String {
    let slot_hex = slot_to_key(slot);

    if use_md5 {
        let hash_result = md5::compute(&slot_hex);
        let truncated_hash_hex = format!("{:x}", hash_result)[..10].to_string();

        format!("{}{}", truncated_hash_hex, slot_hex)
    } else {
        slot_hex
    }
}

fn slot_to_tx_by_addr_key(slot: Slot) -> String {
    slot_to_key(!slot)
}

// A serialized `TransactionInfo` is stored in the `tx` table
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct TransactionInfo {
    slot: Slot, // The slot that contains the block with this transaction in it
    index: u32, // Where the transaction is located in the block
    err: Option<TransactionError>, // None if the transaction executed successfully
    // memo: Option<String>, // Transaction memo
}

#[derive(Serialize, Deserialize)]
pub struct StoredConfirmedTransactionWithStatusMeta {
    pub slot: Slot,
    pub tx_with_meta: StoredConfirmedBlockTransaction,
    pub block_time: Option<UnixTimestamp>,
}

impl From<ConfirmedTransactionWithStatusMeta> for StoredConfirmedTransactionWithStatusMeta {
    fn from(value: ConfirmedTransactionWithStatusMeta) -> Self {
        Self {
            slot: value.slot,
            tx_with_meta: value.tx_with_meta.into(),
            block_time: value.block_time,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct StoredConfirmedBlockTransaction {
    transaction: VersionedTransaction,
    meta: Option<StoredConfirmedBlockTransactionStatusMeta>,
}

// #[cfg(test)]
impl From<TransactionWithStatusMeta> for StoredConfirmedBlockTransaction {
    fn from(value: TransactionWithStatusMeta) -> Self {
        match value {
            TransactionWithStatusMeta::MissingMetadata(transaction) => Self {
                transaction: VersionedTransaction::from(transaction),
                meta: None,
            },
            TransactionWithStatusMeta::Complete(VersionedTransactionWithStatusMeta {
                                                    transaction,
                                                    meta,
                                                }) => Self {
                transaction,
                meta: Some(meta.into()),
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct StoredConfirmedBlockTransactionStatusMeta {
    err: Option<TransactionError>,
    fee: u64,
    pre_balances: Vec<u64>,
    post_balances: Vec<u64>,
}

impl From<TransactionStatusMeta> for StoredConfirmedBlockTransactionStatusMeta {
    fn from(value: TransactionStatusMeta) -> Self {
        let TransactionStatusMeta {
            status,
            fee,
            pre_balances,
            post_balances,
            ..
        } = value;
        Self {
            err: status.err(),
            fee,
            pre_balances,
            post_balances,
        }
    }
}


pub const DEFAULT_ADDRESS: &str = "127.0.0.1:9090";
pub const BLOCKS_TABLE_NAME: &str = "blocks";
pub const TX_TABLE_NAME: &str = "tx";
pub const TX_BY_ADDR_TABLE_NAME: &str = "tx-by-addr";
pub const FULL_TX_TABLE_NAME: &str = "tx_full";
pub const DEFAULT_MEMCACHE_ADDRESS: &str = "127.0.0.1:11211";

#[derive(Debug)]
pub struct LedgerStorageConfig {
    pub read_only: bool,
    pub timeout: Option<std::time::Duration>,
    pub address: String,
    pub uploader_config: UploaderConfig,
    pub cache_config: LedgerCacheConfig,
}

impl Default for LedgerStorageConfig {
    fn default() -> Self {
        Self {
            read_only: false,
            timeout: None,
            address: DEFAULT_ADDRESS.to_string(),
            uploader_config: UploaderConfig::default(),
            cache_config: LedgerCacheConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LedgerCacheConfig {
    pub enable_full_tx_cache: bool,
    pub address: String,
    pub timeout: Option<std::time::Duration>,
    pub tx_cache_expiration: Option<std::time::Duration>,
}

impl Default for LedgerCacheConfig {
    fn default() -> Self {
        Self {
            enable_full_tx_cache: false,
            address: DEFAULT_MEMCACHE_ADDRESS.to_string(),
            timeout: Some(std::time::Duration::from_secs(1)),
            tx_cache_expiration: Some(std::time::Duration::from_secs(60 * 60 * 24 * 14)), // 14 days
        }
    }
}

#[derive(Debug, Clone)]
pub struct UploaderConfig {
    pub tx_full_filter: Option<FilterTxIncludeExclude>,
    pub tx_by_addr_filter: Option<FilterTxIncludeExclude>,
    pub disable_tx: bool,
    pub disable_tx_by_addr: bool,
    pub disable_blocks: bool,
    pub enable_full_tx: bool,
    pub blocks_table_name: String,
    pub tx_table_name: String,
    pub tx_by_addr_table_name: String,
    pub full_tx_table_name: String,
    pub use_md5_row_key_salt: bool,
    pub filter_program_accounts: bool,
    pub filter_voting_tx: bool,
    pub filter_error_tx: bool,
    pub use_blocks_compression: bool,
    pub use_tx_compression: bool,
    pub use_tx_by_addr_compression: bool,
    pub use_tx_full_compression: bool,
    pub hbase_write_to_wal: bool,
}

impl Default for UploaderConfig {
    fn default() -> Self {
        Self {
            tx_full_filter: None,
            tx_by_addr_filter: None,
            disable_tx: false,
            disable_tx_by_addr: false,
            disable_blocks: false,
            enable_full_tx: false,
            blocks_table_name: BLOCKS_TABLE_NAME.to_string(),
            tx_table_name: TX_TABLE_NAME.to_string(),
            tx_by_addr_table_name: TX_BY_ADDR_TABLE_NAME.to_string(),
            full_tx_table_name: FULL_TX_TABLE_NAME.to_string(),
            use_md5_row_key_salt: false,
            filter_program_accounts: false,
            filter_voting_tx: false,
            filter_error_tx: false,
            use_blocks_compression: true,
            use_tx_compression: true,
            use_tx_by_addr_compression: true,
            use_tx_full_compression: true,
            hbase_write_to_wal: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FilterTxIncludeExclude {
    pub exclude: bool,
    pub addrs: HashSet<Pubkey>,
}

#[derive(Clone)]
pub struct LedgerStorage {
    connection: HBaseConnection,
    uploader_config: UploaderConfig,
    cache_client: Option<Client>,
    enable_full_tx_cache: bool,
    tx_cache_expiration: Option<std::time::Duration>,
}

impl LedgerStorage {
    pub async fn new(
        read_only: bool,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        Self::new_with_config(LedgerStorageConfig {
            read_only,
            timeout,
            ..LedgerStorageConfig::default()
        })
            .await
    }

    pub async fn new_with_config(config: LedgerStorageConfig) -> Self {
        let LedgerStorageConfig {
            read_only,
            timeout,
            address,
            uploader_config,
            cache_config,
        } = config;
        let connection = HBaseConnection::new(
            address.as_str(),
            read_only,
            timeout,
        )
            .await;

        let cache_client = if cache_config.enable_full_tx_cache {
            // Add the "memcache://" prefix programmatically
            let memcache_url = format!("memcache://{}?protocol=ascii", cache_config.address);
            Some(Client::connect(memcache_url.as_str()).unwrap())
        } else {
            None
        };

        Self {
            connection,
            uploader_config,
            cache_client,
            enable_full_tx_cache: cache_config.enable_full_tx_cache,
            tx_cache_expiration: cache_config.tx_cache_expiration,
        }
    }

    pub async fn write_tx(&self, confirmed_tx: TransactionWithStatusMeta) -> Result<()> {
        let signature = match &confirmed_tx {
            TransactionWithStatusMeta::MissingMetadata(transaction) => transaction.signatures.get(0).cloned(),
            TransactionWithStatusMeta::Complete(versioned_tx_with_meta) => versioned_tx_with_meta.transaction.signatures.get(0).cloned(),
        };

        match signature {
            Some(signature) => {
                let tx_cells = [(signature.to_string(), confirmed_tx.into())];
                self.connection
                    .put_protobuf_cells_with_retry::<generated::ConfirmedTransaction>(
                        self.uploader_config.full_tx_table_name.as_str(),
                        &tx_cells,
                        self.uploader_config.use_tx_full_compression,
                        self.uploader_config.hbase_write_to_wal,
                    )
                    .await?;

                let log_output = format!(
                    "Encoded tx: {}",
                    signature.to_string(),
                );
                info!("{}", log_output);

                Ok(())
            },
            None => {
                let e = Error::MissingSignature;
                println!("Failed to convert transaction: {}", e.to_string());
                Err(e)
            }
        }
    }

    pub async fn upload_confirmed_block(
        &self,
        slot: Slot,
        confirmed_block: VersionedConfirmedBlock,
    ) -> Result<()> {
        let mut by_addr: HashMap<&Pubkey, Vec<TransactionByAddrInfo>> = HashMap::new();

        info!("HBase: Uploading block {:?} from slot {:?}", confirmed_block.blockhash, slot);

        let mut tx_cells = vec![];
        let mut full_tx_cells = vec![];
        let mut full_tx_cache = vec![];
        for (index, transaction_with_meta) in confirmed_block.transactions.iter().enumerate() {
            let VersionedTransactionWithStatusMeta { meta, transaction } = transaction_with_meta;
            let err = meta.status.clone().err();
            let index = index as u32;
            let signature = transaction.signatures[0];
            let memo = extract_and_fmt_memos(transaction_with_meta);

            let mut should_skip_tx = false;
            let mut should_skip_tx_by_addr = false;
            let mut should_skip_full_tx = false;

            let is_voting = is_voting_tx(transaction_with_meta);

            if self.uploader_config.filter_voting_tx && is_voting {
                should_skip_tx_by_addr = true;
                should_skip_full_tx = true;
            }

            let is_error = is_error_tx(transaction_with_meta);

            if self.uploader_config.filter_error_tx && is_error {
                should_skip_full_tx = true;
            }

            let combined_keys = get_account_keys(&transaction_with_meta);

            if !should_skip_tx_by_addr {
                for address in transaction_with_meta.account_keys().iter() {
                    // Filter program accounts from tx-by-addr index
                    if self.uploader_config.filter_program_accounts
                        && is_program_account(address, transaction_with_meta, &combined_keys) {
                        continue;
                    }

                    if should_skip_full_tx || !self.should_include_in_tx_full(address) {
                        should_skip_full_tx = true;
                    }

                    if !is_sysvar_id(address) && self.should_include_in_tx_by_addr(address) {
                        by_addr
                            .entry(address)
                            .or_default()
                            .push(TransactionByAddrInfo {
                                signature,
                                err: err.clone(),
                                index,
                                memo: memo.clone(),
                                block_time: confirmed_block.block_time,
                            });
                    }
                }
            }

            if self.uploader_config.enable_full_tx && !should_skip_full_tx {
                // should_skip_tx = true;

                full_tx_cells.push((
                    signature.to_string(),
                    ConfirmedTransactionWithStatusMeta {
                        slot,
                        tx_with_meta: transaction_with_meta.clone().into(),
                        block_time: confirmed_block.block_time,
                    }.into()
                ));
            }

            if self.enable_full_tx_cache
                && !is_voting
                && !transaction_with_meta.meta.status.is_err() {
                full_tx_cache.push((
                    signature.to_string(),
                    ConfirmedTransactionWithStatusMeta {
                        slot,
                        tx_with_meta: transaction_with_meta.clone().into(),
                        block_time: confirmed_block.block_time,
                    }
                ));
            }

            if !self.uploader_config.disable_tx /*&& !should_skip_tx*/ {
                tx_cells.push((
                    signature.to_string(),
                    TransactionInfo {
                        slot,
                        index,
                        err,
                        // memo,
                    },
                ));
            }
        }

        let tx_by_addr_cells: Vec<_> = by_addr
            .into_iter()
            .map(|(address, transaction_info_by_addr)| {
                (
                    format!("{}/{}", address, slot_to_tx_by_addr_key(slot)),
                    tx_by_addr::TransactionByAddr {
                        tx_by_addrs: transaction_info_by_addr
                            .into_iter()
                            .map(|by_addr| by_addr.into())
                            .collect(),
                    },
                )
            })
            .collect();

        let mut tasks = vec![];

        if !full_tx_cells.is_empty() && self.uploader_config.enable_full_tx {
            let conn = self.connection.clone();
            let full_tx_table_name = self.uploader_config.full_tx_table_name.clone();
            let use_tx_full_compression = self.uploader_config.use_tx_full_compression.clone();
            let write_to_wal = self.uploader_config.hbase_write_to_wal.clone();
            tasks.push(tokio::spawn(async move {
                conn.put_protobuf_cells_with_retry::<generated::ConfirmedTransactionWithStatusMeta>(
                    full_tx_table_name.as_str(),
                    &full_tx_cells,
                    use_tx_full_compression,
                    write_to_wal,
                )
                .await
                .map(TaskResult::BytesWritten)
                .map_err(TaskError::from)
            }));
        }

        if !full_tx_cache.is_empty() && self.enable_full_tx_cache {
            let mut cached_count = 0;
            let cache_client = self.cache_client.clone();
            let tx_cache_expiration = self.tx_cache_expiration;
            debug!("Writing block transactions to cache");
            tasks.push(tokio::spawn(async move {
                for (signature, transaction) in full_tx_cache {
                    if let Some(client) = &cache_client {
                        // let stored_tx: generated::ConfirmedTransactionWithStatusMeta = transaction.into();

                        cache_transaction::<generated::ConfirmedTransactionWithStatusMeta>(
                            &client,
                            &signature,
                            transaction.into(),
                            tx_cache_expiration,
                        )
                        .await
                        .map_err(TaskError::from)?;

                        cached_count += 1;
                        debug!("Cached transaction with signature {}", signature);
                    }
                }
                Ok::<TaskResult, TaskError>(TaskResult::CachedTransactions(cached_count))
            }));
        }

        if !tx_cells.is_empty() && !self.uploader_config.disable_tx {
            let conn = self.connection.clone();
            let tx_table_name = self.uploader_config.tx_table_name.clone();
            let use_tx_compression = self.uploader_config.use_tx_compression.clone();
            let write_to_wal = self.uploader_config.hbase_write_to_wal.clone();
            debug!("HBase: spawning tx upload thread");
            tasks.push(tokio::spawn(async move {
                debug!("HBase: calling put_bincode_cells_with_retry for tx");
                conn.put_bincode_cells_with_retry::<TransactionInfo>(
                    tx_table_name.as_str(),
                    &tx_cells,
                    use_tx_compression,
                    write_to_wal,
                )
                .await
                .map(TaskResult::BytesWritten)
                .map_err(TaskError::from)
            }));
        }

        if !tx_by_addr_cells.is_empty() && !self.uploader_config.disable_tx_by_addr {
            let conn = self.connection.clone();
            let tx_by_addr_table_name = self.uploader_config.tx_by_addr_table_name.clone();
            let use_tx_by_addr_compression = self.uploader_config.use_tx_by_addr_compression.clone();
            let write_to_wal = self.uploader_config.hbase_write_to_wal.clone();
            debug!("HBase: spawning tx-by-addr upload thread");
            tasks.push(tokio::spawn(async move {
                debug!("HBase: calling put_protobuf_cells_with_retry tx-by-addr");
                conn.put_protobuf_cells_with_retry::<tx_by_addr::TransactionByAddr>(
                    tx_by_addr_table_name.as_str(),
                    &tx_by_addr_cells,
                    use_tx_by_addr_compression,
                    write_to_wal
                )
               .await
               .map(TaskResult::BytesWritten)
               .map_err(TaskError::from)
                // info!("HBase: finished put_protobuf_cells_with_retry call for tx-by-addr");

                // match result {
                //     Ok(bytes_written) => Ok(TaskResult::BytesWritten(bytes_written)),
                //     Err(e) => Err(e),
                // }
            }));
        }

        let mut bytes_written = 0;
        let mut total_cached_transactions = 0;
        let mut maybe_first_err: Option<Error> = None;

        debug!("HBase: waiting for all upload threads to finish...");

        let results = futures::future::join_all(tasks).await;
        debug!("HBase: got upload results");
        for result in results {
            match result {
                Err(err) => {
                    debug!("HBase: got error result {:?}", err);
                    if maybe_first_err.is_none() {
                        maybe_first_err = Some(Error::TokioJoinError(err));
                    }
                }
                Ok(Err(err)) => {
                    debug!("HBase: got error result {:?}", err);
                    if maybe_first_err.is_none() {
                        // maybe_first_err = Some(Error::HBaseError(err));
                        match err {
                            TaskError::HBaseError(hbase_err) => {
                                maybe_first_err = Some(Error::HBaseError(hbase_err));
                            }
                            TaskError::MemcacheError(memcache_err) => {
                                maybe_first_err = Some(Error::MemcacheError(memcache_err));
                            }
                            TaskError::IoError(io_err) => {
                                maybe_first_err = Some(Error::IoError(io_err));
                            }
                            TaskError::EncodingError(enc_err) => {
                                maybe_first_err = Some(Error::EncodingError(enc_err));
                            }
                        }
                    }
                }
                Ok(Ok(task_result)) => {
                    match task_result {
                        TaskResult::BytesWritten(bytes) => bytes_written += bytes,
                        TaskResult::CachedTransactions(count) => total_cached_transactions += count,
                    }
                }
                // Ok(Ok(bytes)) => {
                //     info!("HBase: got success result");
                //     bytes_written += bytes;
                // }
            }
        }

        if let Some(err) = maybe_first_err {
            debug!("HBase: returning upload error result {:?}", err);
            return Err(err);
        }

        if self.enable_full_tx_cache {
            info!("Cached {} transactions from slot {}",slot, total_cached_transactions);
        }

        let num_transactions = confirmed_block.transactions.len();

        // let signature = "2Mh6diFhdKfy5MyJfWv2AWEYe71wdyMGceDGxTmtpsFDUMXptWe3RtEXAef9SCoNJveiEQUMDdeP6UJVDdrQzbdV";
        // print_ui_amount_for_signature(confirmed_block.clone().into(), signature);

        // Store the block itself last, after all other metadata about the block has been
        // successfully stored.  This avoids partial uploaded blocks from becoming visible to
        // `get_confirmed_block()` and `get_confirmed_blocks()`
        let blocks_cells = [(
            slot_to_blocks_key(slot, self.uploader_config.use_md5_row_key_salt),
            confirmed_block.into()
        )];

        debug!("HBase: calling put_protobuf_cells_with_retry for blocks");

        if !self.uploader_config.disable_blocks {
            bytes_written += self
                .connection
                .put_protobuf_cells_with_retry::<generated::ConfirmedBlock>(
                    self.uploader_config.blocks_table_name.as_str(),
                    &blocks_cells,
                    self.uploader_config.use_blocks_compression,
                        self.uploader_config.hbase_write_to_wal
                )
                .await
                .map_err(|err| {
                    error!("HBase: failed to upload block: {:?}", err);
                    err
                })?;
        }

        info!("HBase: successfully uploaded block from slot {}", slot);
        // datapoint_info!(
        //     "storage-hbase-upload-block",
        //     ("slot", slot, i64),
        //     ("transactions", num_transactions, i64),
        //     ("bytes", bytes_written, i64),
        // );
        Ok(())
    }

    fn should_include_in_tx_full(&self, address: &Pubkey) -> bool {
        if let Some(ref filter) = self.uploader_config.tx_full_filter {
            if filter.exclude {
                // If exclude is true, exclude the address if it's in the set.
                !filter.addrs.contains(address)
            } else {
                // If exclude is false, include the address only if it's in the set.
                filter.addrs.contains(address)
            }
        } else {
            true
        }
    }

    fn should_include_in_tx_by_addr(&self, address: &Pubkey) -> bool {
        if let Some(ref filter) = self.uploader_config.tx_by_addr_filter {
            if filter.exclude {
                // If exclude is true, exclude the address if it's in the set.
                !filter.addrs.contains(address)
            } else {
                // If exclude is false, include the address only if it's in the set.
                filter.addrs.contains(address)
            }
        } else {
            true
        }
    }
}

pub async fn cache_transaction<T>(
    cache_client: &Client,
    signature: &str,
    transaction: T,
    tx_cache_expiration: Option<std::time::Duration>,
) ->std::result::Result<(), CacheWriteError>
    where
        T: prost::Message,
{
    let mut buf = Vec::with_capacity(transaction.encoded_len());

    transaction.encode(&mut buf).map_err(CacheWriteError::EncodingError)?;

    let compressed_tx = compress_best(&buf).map_err(CacheWriteError::IoError)?;

    let expiration = tx_cache_expiration
        .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or(0);

    cache_client
        .set(signature, compressed_tx.as_slice(), expiration)
        .map_err(CacheWriteError::MemcacheError)?;

    Ok(())
}

fn get_account_keys(transaction_with_meta: &VersionedTransactionWithStatusMeta) -> Vec<Pubkey> {
    match &transaction_with_meta.transaction.message {
        VersionedMessage::V0(_) => {
            let static_keys = transaction_with_meta.transaction.message.static_account_keys();
            let LoadedAddresses { writable, readonly } = &transaction_with_meta.meta.loaded_addresses;

            static_keys.iter()
                .chain(writable.iter())
                .chain(readonly.iter())
                .cloned()
                .collect()
        },
        VersionedMessage::Legacy(_) => {
            Vec::from(transaction_with_meta.transaction.message.static_account_keys())
        }
    }
}

fn is_error_tx(transaction_with_meta: &VersionedTransactionWithStatusMeta) -> bool {
    transaction_with_meta.meta.status.is_err()
}

fn is_voting_tx(transaction_with_meta: &VersionedTransactionWithStatusMeta) -> bool {
    let account_address = Pubkey::from_str("Vote111111111111111111111111111111111111111").unwrap();

    has_account(transaction_with_meta, &account_address)
}

fn has_account(transaction_with_meta: &VersionedTransactionWithStatusMeta, address: &Pubkey) -> bool {
     transaction_with_meta
         .transaction
         .message
         .static_account_keys()
         .contains(&address)
}

fn is_program_account(
    address: &Pubkey,
    transaction_with_meta: &VersionedTransactionWithStatusMeta,
    combined_keys: &[Pubkey]
) -> bool {
    // Helper to check if the address is used as a program account in a given instruction
    let check_program_id = |instruction: &CompiledInstruction, account_keys: &[Pubkey]| -> bool {
        let program_id = &account_keys[instruction.program_id_index as usize];
        program_id == address
    };

    // Check in outer instructions
    let used_in_outer = transaction_with_meta.transaction.message.instructions().iter().any(|instruction| {
        check_program_id(instruction, combined_keys)
    });

    // Check in inner instructions
    let used_in_inner = transaction_with_meta.meta.inner_instructions.as_ref()
        .map_or(false, |inner_instructions| {
            inner_instructions.iter().flat_map(|inner| &inner.instructions)
                .any(|inner_instruction| check_program_id(&inner_instruction.instruction, combined_keys))
        });

    used_in_outer || used_in_inner
}
