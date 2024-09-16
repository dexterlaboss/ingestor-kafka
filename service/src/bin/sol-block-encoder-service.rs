
use {
    service::{
        consumer::KafkaConsumer,
        producer::KafkaProducer,
        config::Config,
        cli::{DefaultBlockUploaderArgs, block_uploader_app},
        ledger_storage::{
            LedgerStorage,
            LedgerStorageConfig,
            FilterTxIncludeExclude,
            UploaderConfig,
            LedgerCacheConfig,
        },
    },
    std::sync::Arc,
    std::{
        collections::{HashSet},
    },
    // solana_binary_encoder::{
    //     convert::generated,
    // },
    solana_sdk::{
        pubkey::Pubkey,
    },
    clap::{value_t, value_t_or_exit, values_t, values_t_or_exit, ArgMatches},
    log::{debug, info},
};

/// Create a consumer based on the given configuration.
async fn create_consumer(
    config: Arc<Config>,
    uploader_config: UploaderConfig,
    cache_config: LedgerCacheConfig
) -> KafkaConsumer {
    info!("Connecting to kafka: {}", &config.kafka_brokers);

    let kproducer = create_producer(config.clone());

    let storage_config = LedgerStorageConfig {
        read_only: false,
        timeout: None,
        address: config.hbase_address.clone(),
        uploader_config: uploader_config.clone(),
        cache_config: cache_config.clone(),
    };
    let storage = LedgerStorage::new_with_config(storage_config).await;

    KafkaConsumer::new(
        &config.kafka_brokers,
        &config.kafka_group_id,
        &[&config.kafka_consume_topic],
        storage,
        kproducer
    ).await
}

/// Create a producer based on the given configuration.
fn create_producer(config: Arc<Config>) -> KafkaProducer {
    KafkaProducer::new(
        &config.kafka_brokers,
        &config.kafka_produce_error_topic)
}

/// Handle the message processing.
async fn handle_message_receiving(
    config: Arc<Config>,
    uploader_config: UploaderConfig,
    cache_config: LedgerCacheConfig) {
    debug!("Started consuming messages");

    let kconsumer = create_consumer(
        config.clone(),
        uploader_config.clone(),
        cache_config.clone()
    ).await;

    kconsumer.consume().await;
}

fn process_uploader_arguments(matches: &ArgMatches) -> UploaderConfig {
    let disable_tx = matches.is_present("disable_tx");
    let disable_tx_by_addr = matches.is_present("disable_tx_by_addr");
    let disable_blocks = matches.is_present("disable_blocks");
    let enable_full_tx = matches.is_present("enable_full_tx");
    let use_md5_row_key_salt = matches.is_present("use_md5_row_key_salt");
    let filter_program_accounts = matches.is_present("filter_tx_by_addr_programs");
    let filter_voting_tx = matches.is_present("filter_voting_tx");
    let use_blocks_compression = !matches.is_present("disable_block_compression");
    let use_tx_compression = !matches.is_present("disable_tx_compression");
    let use_tx_by_addr_compression = !matches.is_present("disable_tx_by_addr_compression");
    let use_tx_full_compression = !matches.is_present("disable_tx_full_compression");

    let filter_tx_full_include_addrs: HashSet<Pubkey> =
        values_t!(matches, "filter_tx_full_include_addr", Pubkey)
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect();

    let filter_tx_full_exclude_addrs: HashSet<Pubkey> =
        values_t!(matches, "filter_tx_full_exclude_addr", Pubkey)
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect();

    let filter_tx_by_addr_include_addrs: HashSet<Pubkey> =
        values_t!(matches, "filter_tx_by_addr_include_addr", Pubkey)
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect();

    let filter_tx_by_addr_exclude_addrs: HashSet<Pubkey> =
        values_t!(matches, "filter_tx_by_addr_exclude_addr", Pubkey)
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect();

    let tx_full_filter = create_filter(
        filter_tx_full_exclude_addrs,
        filter_tx_full_include_addrs
    );
    let tx_by_addr_filter = create_filter(
        filter_tx_by_addr_exclude_addrs,
        filter_tx_by_addr_include_addrs
    );

    UploaderConfig {
        tx_full_filter,
        tx_by_addr_filter,
        disable_tx,
        disable_tx_by_addr,
        disable_blocks,
        enable_full_tx,
        use_md5_row_key_salt,
        filter_program_accounts,
        filter_voting_tx,
        use_blocks_compression,
        use_tx_compression,
        use_tx_by_addr_compression,
        use_tx_full_compression,
        ..Default::default()
    }
}

fn process_cache_arguments(matches: &ArgMatches) -> LedgerCacheConfig {
    let enable_full_tx_cache = matches.is_present("enable_full_tx_cache");

    let address = if matches.is_present("cache_address") {
        value_t_or_exit!(matches, "cache_address", String)
    } else {
        String::new()
    };

    let timeout = if matches.is_present("cache_timeout") {
        Some(std::time::Duration::from_secs(
            value_t_or_exit!(matches, "cache_timeout", u64),
        ))
    } else {
        None
    };

    let tx_cache_expiration = if matches.is_present("tx_cache_expiration") {
        Some(std::time::Duration::from_secs(
            value_t_or_exit!(matches, "tx_cache_expiration", u64) * 24 * 60 * 60,
        ))
    } else {
        None
    };

    LedgerCacheConfig {
        enable_full_tx_cache,
        address,
        timeout,
        tx_cache_expiration,
        ..Default::default()
    }
}

fn create_filter(
    filter_tx_exclude_addrs: HashSet<Pubkey>,
    filter_tx_include_addrs: HashSet<Pubkey>,
) -> Option<FilterTxIncludeExclude> {
    let exclude_tx_addrs = !filter_tx_exclude_addrs.is_empty();
    let include_tx_addrs = !filter_tx_include_addrs.is_empty();

    if exclude_tx_addrs || include_tx_addrs {
        let filter_tx_addrs = FilterTxIncludeExclude {
            exclude: exclude_tx_addrs,
            addrs: if exclude_tx_addrs {
                filter_tx_exclude_addrs
            } else {
                filter_tx_include_addrs
            },
        };
        Some(filter_tx_addrs)
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let default_args = DefaultBlockUploaderArgs::new();
    let solana_version = solana_version::version!();
    let cli_app = block_uploader_app(solana_version, &default_args);
    let matches = cli_app.get_matches();

    let uploader_config = process_uploader_arguments(&matches);
    let cache_config = process_cache_arguments(&matches);

    env_logger::init();

    info!("Solana block encoder service started");

    let app_config = Arc::new(Config::new());

    handle_message_receiving(app_config, uploader_config, cache_config).await;

    Ok(())
}