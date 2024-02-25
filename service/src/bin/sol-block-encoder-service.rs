
use {
    service::{
        consumer::KafkaConsumer,
        producer::KafkaProducer,
        config::Config,
    },
    std::sync::Arc,
    // solana_binary_encoder::{
    //     convert::generated,
    // },
    log::{debug, info},
};
use service::ledger_storage::{LedgerStorage, LedgerStorageConfig};

/// Create a consumer based on the given configuration.
async fn create_consumer(config: Arc<Config>) -> KafkaConsumer {
    info!("Connecting to kafka: {}", &config.kafka_brokers);

    let kproducer = create_producer(config.clone());

    let storage_config = LedgerStorageConfig {
        read_only: false,
        timeout: None,
        address: config.hbase_address.clone(),
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
async fn handle_message_receiving(config: Arc<Config>) {
    debug!("Started consuming messages");

    let kconsumer = create_consumer(config.clone()).await;

    kconsumer.consume().await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("Solana block encoder service started");

    let app_config = Arc::new(Config::new());

    handle_message_receiving(app_config).await;

    Ok(())
}