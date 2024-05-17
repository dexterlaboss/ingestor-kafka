use {
    crate::{
        producer::KafkaProducer,
        ledger_storage::{LedgerStorage},
    },
    solana_binary_encoder::{
        transaction_status::{
            // EncodedTransactionWithStatusMeta,
            EncodedConfirmedBlock,
            // VersionedConfirmedBlock,
            // UiConfirmedBlock,
            // ConfirmedBlock,
            UiTransactionEncoding,
            BlockEncodingOptions,
            TransactionDetails,
            // EncodedConfirmedTransactionWithStatusMeta,
            // TransactionWithStatusMeta,
            // EncodeError,
        },
        // convert::generated,
        // cli_output::{CliBlock, OutputFormat},
        // encode_transaction,
        convert_block,
    },
    // solana_storage_proto::convert::generated,
    futures::StreamExt,
    log::{debug, error, info, warn},
    bytes::BytesMut,
    rdkafka::{
        config::{ClientConfig, RDKafkaLogLevel},
        consumer::{stream_consumer::StreamConsumer, CommitMode, Consumer},
        message::{
            Message,
            BorrowedMessage,
            // Headers,
            // OwnedHeaders
        },
    },
    std::time::{Duration, Instant},
    std::str,
    // std::io::{Write},
    // hdrs::Client,
    // chrono::prelude::*,
    // chrono::Utc,
};


pub struct KafkaConsumer {
    kafka_consumer: StreamConsumer,
    kafka_producer: KafkaProducer,
    storage: LedgerStorage,
}

impl KafkaConsumer {
    /// Create a new KafkaConsumer.
    pub async fn new(
        kafka_brokers: &str,
        group_id: &str,
        topics: &[&str],
        storage: LedgerStorage,
        kproducer: KafkaProducer
    ) -> KafkaConsumer {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", group_id)
            .set("bootstrap.servers", kafka_brokers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "10000")
            .set("enable.auto.commit", "true")
            .set("auto.offset.reset", "earliest")
            .set("max.partition.fetch.bytes", "10485760")
            .set("max.in.flight.requests.per.connection", "1")
            .set_log_level(RDKafkaLogLevel::Debug)
            .create()
            .expect("Consumer creation failed");

        consumer
            .subscribe(topics)
            .expect("Failed to subscribe to specified topics");

        KafkaConsumer {
            kafka_consumer: consumer,
            kafka_producer: kproducer,
            storage,
        }
    }

    /// Consume the incoming topic and publishes the raw-payload to an internal
    /// mpsc channel to be consumed by another async-task which then writes the
    /// data to postgres.
    pub async fn consume(&self) {
        info!("initiating data consumption from kafka-topic");

        let mut message_counter = 0;
        let report_interval = 10;
        let mut batch_time = Instant::now();

        let mut message_stream = self.kafka_consumer.stream();
        while let Some(message) = message_stream.next().await {
            match message {
                Err(e) => warn!("Kafka error: {}", e),
                Ok(m) => {
                    if let Some(raw_data) = m.payload() {
                        debug!(
							"Received message on offset {:?}",
							// &raw_data,
							m.offset()
						);

                        // let start = Instant::now();

                        let buffer = str::from_utf8(raw_data).unwrap();

                        // let block_id = m.headers().and_then(|headers| {
                        //     for i in 0..headers.count() {
                        //         if let Ok(header) = headers.get_as::<str>(i) {
                        //             if header.key == "slot" {
                        //                 // Handle Option before parsing
                        //                 return header.value.map(|val| str::parse::<u64>(val).ok()).flatten();
                        //             }
                        //         }
                        //     }
                        //     None
                        // });

                        let parsed_json: Result<serde_json::Value, _> = serde_json::from_str(&buffer);
                        let block_id = parsed_json.ok().and_then(|json| json["blockID"].as_u64());

                        let slot = match block_id {
                            Some(s) => s,
                            None => {
                                warn!("Invalid or missing 'blockID' field in message, skipping processing");
                                self.commit_message(&m);
                                continue;
                            }
                        };

                        info!("Parsing block with id {}", slot);

                        let block: EncodedConfirmedBlock = serde_json::from_str(&buffer).unwrap();

                        let options = BlockEncodingOptions {
                            transaction_details: TransactionDetails::Full,
                            show_rewards: true,
                            max_supported_transaction_version: Some(0),
                        };

                        match convert_block(block, UiTransactionEncoding::Json, options) {
                            Ok(versioned_block) => {
                                // output_block(versioned_block).await?;

                                match self.storage.upload_confirmed_block(slot, versioned_block).await {
                                    Ok(_) => (),
                                    Err(e) => self.handle_error(&m, &buffer, e.to_string()).await,
                                }
                            }
                            Err(e) => {
                                self.handle_error(&m, &buffer, e.to_string()).await;
                            }
                        }

                        // let duration: Duration = start.elapsed();
                        // info!("{} [time: {:?}]", log_output, duration);
                    } else {
                        warn!("Failed to read raw data from kafka topic")
                    }

                    self.commit_message(&m);
                }
            };

            message_counter += 1;

            if message_counter % report_interval == 0 {
                let batch_duration: Duration = batch_time.elapsed();
                info!("Processed {} messages, total time taken: {:?}", report_interval, batch_duration);
                batch_time = Instant::now();
            }
        }

        debug!("Returned from consumer");
    }

    async fn handle_error(&self, _m: &BorrowedMessage<'_>, block: &str, error_string: String) {
        warn!("Failed to encode block: {}",
            error_string
        );
        let payload = BytesMut::from(block);
        self.kafka_producer.produce_with_headers(payload, None).await;
    }

    fn commit_message(&self, m: &BorrowedMessage) {
        if let Err(e) = self.kafka_consumer.commit_message(m, CommitMode::Async) {
            error!("Failed to commit offset to kafka: {:?}", e);
        }
    }
}

