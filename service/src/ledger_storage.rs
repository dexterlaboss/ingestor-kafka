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
        },
        convert::{
            generated,
            tx_by_addr
        },
    },
    solana_sdk::{
        clock::Slot,
        pubkey::Pubkey,
        sysvar::is_sysvar_id,
        transaction::TransactionError,
    },
    // solana_storage_proto::convert::generated,
    extract_memos::extract_and_fmt_memos,
    // transaction_error::TransactionError,
    log::{
        // debug,
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

pub type Result<T> = std::result::Result<T, Error>;

// Convert a slot to its bucket representation whereby lower slots are always lexically ordered
// before higher slots
fn slot_to_key(slot: Slot) -> String {
    format!("{slot:016x}")
}

fn slot_to_blocks_key(slot: Slot) -> String {
    slot_to_key(slot)
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
    memo: Option<String>, // Transaction memo
}

pub const DEFAULT_ADDRESS: &str = "127.0.0.1:9090";

#[derive(Debug)]
pub struct LedgerStorageConfig {
    pub read_only: bool,
    pub timeout: Option<std::time::Duration>,
    pub address: String,
    pub uploader_config: UploaderConfig,
}

impl Default for LedgerStorageConfig {
    fn default() -> Self {
        Self {
            read_only: false,
            timeout: None,
            address: DEFAULT_ADDRESS.to_string(),
            uploader_config: UploaderConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UploaderConfig {
    pub addrs: Option<FilterTxIncludeExclude>,
    pub disable_tx: bool,
    pub disable_tx_by_addr: bool,
    pub disable_blocks: bool,
    pub enable_full_tx: bool,
}

impl Default for UploaderConfig {
    fn default() -> Self {
        Self {
            addrs: None,
            disable_tx: false,
            disable_tx_by_addr: false,
            disable_blocks: false,
            enable_full_tx: false,
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
        } = config;
        let connection = HBaseConnection::new(
            address.as_str(),
            read_only,
            timeout,
        )
            .await;
        Self {
            connection,
            uploader_config,
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
                    .put_protobuf_cells_with_retry::<generated::ConfirmedTransaction>("tx_full", &tx_cells)
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
        for (index, transaction_with_meta) in confirmed_block.transactions.iter().enumerate() {
            let VersionedTransactionWithStatusMeta { meta, transaction } = transaction_with_meta;
            let err = meta.status.clone().err();
            let index = index as u32;
            let signature = transaction.signatures[0];
            let memo = extract_and_fmt_memos(transaction_with_meta);

            let mut store_tx = false;
            for address in transaction_with_meta.account_keys().iter() {
                if !is_sysvar_id(address) && self.include_tx(address) {
                    store_tx = true;
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

            if store_tx {
                if !self.uploader_config.disable_tx {
                    tx_cells.push((
                        signature.to_string(),
                        TransactionInfo {
                            slot,
                            index,
                            err,
                            memo,
                        },
                    ));
                }

                if self.uploader_config.enable_full_tx {
                    full_tx_cells.push((
                        signature.to_string(),
                        ConfirmedTransactionWithStatusMeta {
                            slot,
                            tx_with_meta: transaction_with_meta.clone().into(),
                            block_time: confirmed_block.block_time,
                        }.into()
                    ));
                }
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
            tasks.push(tokio::spawn(async move {
                let result = conn.put_protobuf_cells_with_retry::<generated::ConfirmedTransactionWithStatusMeta>(
                    "tx_full",
                    &full_tx_cells
                )
                    .await;
                result
            }));
        }

        if !tx_cells.is_empty() && !self.uploader_config.disable_tx {
            let conn = self.connection.clone();
            info!("HBase: spawning tx upload thread");
            tasks.push(tokio::spawn(async move {
                info!("HBase: calling put_bincode_cells_with_retry for tx");
                conn.put_bincode_cells_with_retry::<TransactionInfo>("tx", &tx_cells)
                    .await
            }));
        }

        if !tx_by_addr_cells.is_empty() && !self.uploader_config.disable_tx_by_addr {
            let conn = self.connection.clone();
            info!("HBase: spawning tx-by-addr upload thread");
            tasks.push(tokio::spawn(async move {
                info!("HBase: calling put_protobuf_cells_with_retry tx-by-addr");
                let result = conn.put_protobuf_cells_with_retry::<tx_by_addr::TransactionByAddr>(
                    "tx-by-addr",
                    &tx_by_addr_cells,
                )
                    .await;
                info!("HBase: finished put_protobuf_cells_with_retry call for tx-by-addr");
                result
            }));
        }

        let mut bytes_written = 0;
        let mut maybe_first_err: Option<Error> = None;

        info!("HBase: waiting for all upload threads to finish...");

        let results = futures::future::join_all(tasks).await;
        info!("HBase: got upload results");
        for result in results {
            match result {
                Err(err) => {
                    info!("HBase: got error result {:?}", err);
                    if maybe_first_err.is_none() {
                        maybe_first_err = Some(Error::TokioJoinError(err));
                    }
                }
                Ok(Err(err)) => {
                    info!("HBase: got error result {:?}", err);
                    if maybe_first_err.is_none() {
                        maybe_first_err = Some(Error::HBaseError(err));
                    }
                }
                Ok(Ok(bytes)) => {
                    info!("HBase: got success result");
                    bytes_written += bytes;
                }
            }
        }

        if let Some(err) = maybe_first_err {
            info!("HBase: returning upload error result {:?}", err);
            return Err(err);
        }

        let num_transactions = confirmed_block.transactions.len();

        // Store the block itself last, after all other metadata about the block has been
        // successfully stored.  This avoids partial uploaded blocks from becoming visible to
        // `get_confirmed_block()` and `get_confirmed_blocks()`
        let blocks_cells = [(slot_to_blocks_key(slot), confirmed_block.into())];

        info!("HBase: calling put_protobuf_cells_with_retry for blocks");

        if !self.uploader_config.disable_blocks {
            bytes_written += self
                .connection
                .put_protobuf_cells_with_retry::<generated::ConfirmedBlock>("blocks", &blocks_cells)
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

    fn include_tx(&self, address: &Pubkey) -> bool {
        if let Some(ref config) = self.uploader_config.addrs {
            if config.exclude {
                // If exclude is true, exclude the address if it's in the set.
                !config.addrs.contains(address)
            } else {
                // If exclude is false, include the address only if it's in the set.
                config.addrs.contains(address)
            }
        } else {
            true
        }
    }
}


