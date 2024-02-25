
use log::{debug, error};
use prost::bytes::BytesMut;
use rdkafka::{
    config::ClientConfig,
    producer::{FutureProducer, FutureRecord},
};
use std::time::Duration;
use std::str;
use rdkafka::message::{OwnedHeaders};

pub struct KafkaProducer {
    topic: String,
    producer: FutureProducer,
}

impl KafkaProducer {
    /// Create a new KafkaProducer instance with a provided FutureProducer
    pub fn new(kafka_brokers: &str, kafka_topic: &str) -> KafkaProducer {
        // Create the `FutureProducer` to produce asynchronously.
        let kafka_producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", kafka_brokers)
            .set("message.timeout.ms", "10000")
            .set("max.in.flight.requests.per.connection", "1")
            .set("message.max.bytes", "10485760")
            .create()
            .expect("Producer creation error");
        KafkaProducer {
            topic: kafka_topic.to_string(),
            producer: kafka_producer,
        }
    }

    /// Publish a BytesMut record to a given topic on Kafka.
    pub async fn produce(&self, data: BytesMut) {
        let message = &str::from_utf8(&data[..]).unwrap().to_string();
        let record: FutureRecord<String, String> = FutureRecord::to(self.topic.as_str()).payload(message);

        let produce_future = self.producer.send(record, Duration::from_millis(10000)).await;
        match produce_future {
            Ok(message) => debug!("Status: {:?}", message),
            Err(e) => error!("Future cancelled: {}", e.0),
        };
    }

    pub async fn produce_with_headers(&self, data: BytesMut, headers: Option<OwnedHeaders>) {
        let mut record: FutureRecord<String, [u8]> = FutureRecord::to(self.topic.as_str())
            .payload(&data[..]);

        if let Some(headers) = headers {
            record = record.headers(headers);
        }

        let produce_future = self.producer.send(record, Duration::from_millis(10000)).await;
        match produce_future {
            Ok(message) => debug!("Status: {:?}", message),
            Err(e) => error!("Future cancelled: {}", e.0),
        };
    }
}