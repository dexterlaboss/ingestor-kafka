
use::{
    std::env,
    log::info,
    serde::Deserialize,
};

const DEFAULT_CONFIG_ENV_KEY: &str = "SVC_CONFIG_PATH";
const CONFIG_PREFIX: &str = "SVC_";

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    /// Kafka topic on which we want to publish the data.
    pub kafka_consume_topic: String,

    /// Kafka topic to which we want to produce the errors.
    pub kafka_produce_error_topic: String,

    /// Kafka brokers to connect to.
    pub kafka_brokers: String,

    /// Kafka group id
    pub kafka_group_id: String,

    pub hbase_address: String,
}

impl Config {
    pub fn new() -> Config {
        let filename = match env::var(DEFAULT_CONFIG_ENV_KEY) {
            Ok(filepath) => filepath,
            Err(_) => ".env".into(),
        };
        info!("Trying to read the config file from [{}]", &filename);

        dotenv::from_filename(&filename).ok();
        match envy::prefixed(CONFIG_PREFIX).from_env::<Config>() {
            Ok(config) => config,
            Err(e) => panic!("Config file being read: {}. And error {:?}", &filename, e),
        }
    }
}
