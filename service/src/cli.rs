use {
    clap::{
        App,
        Arg,
        ArgMatches,
    },
    log::warn,
    solana_clap_utils::{
        input_validators::{
            is_pubkey,
        },
    },
};

const EXCLUDE_ADDR: &str = "filter-tx-exclude-addr";
const INCLUDE_ADDR: &str = "filter-tx-include-addr";

pub fn block_uploader_service<'a>(version: &'a str, default_args: &'a DefaultBlockUploaderArgs) -> App<'a, 'a> {
    return App::new("solana-block-uploader-service")
        .about("Solana Block Uploader Service")
        .version(version)
        .arg(
            Arg::with_name("disable_tx")
                .long("disable-tx")
                .takes_value(false)
                .help("Enable historical transaction info over JSON RPC, \
                       including the 'getConfirmedBlock' API."),
        )
        .arg(
            Arg::with_name("disable_tx_by_addr")
                .long("disable-tx-by-addr")
                .takes_value(false)
                .help("Enable historical transaction info over JSON RPC, \
                       including the 'getConfirmedBlock' API."),
        )
        .arg(
            Arg::with_name("disable_blocks")
                .long("disable-blocks")
                .takes_value(false)
                .help("Enable historical transaction info over JSON RPC, \
                       including the 'getConfirmedBlock' API."),
        )
        .arg(
            Arg::with_name("enable_full_tx")
                .long("enable-full-tx")
                .takes_value(false)
                .help("Enable historical transaction info over JSON RPC, \
                       including the 'getConfirmedBlock' API."),
        )
        .arg(
            Arg::with_name("filter_tx_include_addr")
                .long(INCLUDE_ADDR)
                .takes_value(true)
                .validator(is_pubkey)
                .multiple(true)
                .value_name("KEY")
                .help("Store only transactions with this account key."),
        )
        .arg(
            Arg::with_name("filter_tx_exclude_addr")
                .long(EXCLUDE_ADDR)
                .takes_value(true)
                .validator(is_pubkey)
                .conflicts_with("filter_tx_include_addr")
                .multiple(true)
                .value_name("KEY")
                .help("Store all transactions except the ones with this account key. Overrides filter_tx_include_addr."),
        )
    ;
}

pub struct DefaultBlockUploaderArgs {
    pub disable_tx: bool,
    pub disable_tx_by_addr: bool,
    pub disable_blocks: bool,
    pub enable_full_tx: bool,
}

impl DefaultBlockUploaderArgs {
    pub fn new() -> Self {
        DefaultBlockUploaderArgs {
            disable_tx: false,
            disable_tx_by_addr: false,
            disable_blocks: false,
            enable_full_tx: false,
        }
    }
}

impl Default for DefaultBlockUploaderArgs {
    fn default() -> Self {
        Self::new()
    }
}