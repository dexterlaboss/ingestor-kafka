
use {
    service::{
        consumer::KafkaConsumer,
        producer::KafkaProducer,
        config::Config,
        cli::{DefaultBlockUploaderArgs, block_uploader_service},
        ledger_storage::{
            LedgerStorage,
            LedgerStorageConfig,
            FilterTxIncludeExclude,
            UploaderConfig
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
async fn create_consumer(config: Arc<Config>, uploader_config: UploaderConfig) -> KafkaConsumer {
    info!("Connecting to kafka: {}", &config.kafka_brokers);

    let kproducer = create_producer(config.clone());

    let storage_config = LedgerStorageConfig {
        read_only: false,
        timeout: None,
        address: config.hbase_address.clone(),
        uploader_config: uploader_config.clone(),
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
async fn handle_message_receiving(config: Arc<Config>, uploader_config: UploaderConfig) {
    debug!("Started consuming messages");

    let kconsumer = create_consumer(config.clone(), uploader_config.clone()).await;

    kconsumer.consume().await;
}

fn process_arguments(matches: &ArgMatches) -> UploaderConfig {
    let disable_tx = matches.is_present("disable_tx");
    let disable_tx_by_addr = matches.is_present("disable_tx_by_addr");
    let disable_blocks = matches.is_present("disable_blocks");
    let enable_full_tx = matches.is_present("enable_full_tx");

    let filter_tx_include_addrs: HashSet<Pubkey> =
        values_t!(matches, "filter_tx_include_addr", Pubkey)
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect();

    let filter_tx_exclude_addrs: HashSet<Pubkey> =
        values_t!(matches, "filter_tx_exclude_addr", Pubkey)
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect();

    let exclude_addrs = !filter_tx_exclude_addrs.is_empty();
    let include_addrs = !filter_tx_include_addrs.is_empty();

    let addrs = if exclude_addrs || include_addrs {
        let filter_tx_addrs = FilterTxIncludeExclude {
            exclude: exclude_addrs,
            addrs: if exclude_addrs {
                filter_tx_exclude_addrs
            } else {
                filter_tx_include_addrs
            },
        };
        Some(filter_tx_addrs)
    } else {
        None
    };

    UploaderConfig {
        addrs,
        disable_tx,
        disable_tx_by_addr,
        disable_blocks,
        enable_full_tx,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let default_args = DefaultBlockUploaderArgs::new();
    let solana_version = solana_version::version!();
    let cli_app = block_uploader_service(solana_version, &default_args);
    let matches = cli_app.get_matches();

    let uploader_config = process_arguments(&matches);

    env_logger::init();

    info!("Solana block encoder service started");

    let app_config = Arc::new(Config::new());

    handle_message_receiving(app_config, uploader_config).await;

    Ok(())
}