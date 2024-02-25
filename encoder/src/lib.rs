use {
    crate::{
        compression::{compress_best},
    },
    // convert::generated,
    // block_processor::BlockProcessor,
    transaction_status::{
        EncodedTransactionWithStatusMeta,
        EncodedConfirmedBlock,
        VersionedConfirmedBlock,
        UiConfirmedBlock,
        ConfirmedBlock,
        UiTransactionEncoding,
        BlockEncodingOptions,
        TransactionDetails,

        EncodedConfirmedTransactionWithStatusMeta,
        TransactionWithStatusMeta
    },

    // config::Config,
    log::{debug, info},
};

// pub mod block_processor;
// pub mod account_decoder;
// pub mod account_keys;
// pub mod bincode_utils;
// pub mod cell_decoder;
// pub mod ledger_storage;
// pub mod cli_output;
// pub mod clock;
pub mod compression;
// pub mod consumer;
pub mod convert;
// pub mod custom_error;
// pub mod deserialize_utils;
pub mod extract_memos;
// pub mod output;
pub mod hash;
// pub mod instruction;
// pub mod loaded_addresses;
// pub mod loaded_message;
// pub mod message;
// pub mod message_header;
// pub mod message_v0;
// pub mod native_token;
pub mod option_serializer;
// pub mod packet;
pub mod parse_accounts;
pub mod parse_instruction;
// pub mod program_utils;
// pub mod pubkey;
pub mod parse_token;
// pub mod reward_type;
// pub mod short_vec;
// pub mod serde_varint;
pub mod sanitize;
// pub mod signature;
// pub mod stake_instruction;
// pub mod stake_state;
// pub mod system_instruction;
// pub mod sysvar;
// pub mod transaction;
// pub mod transaction_context;
pub mod transaction_status;
// pub mod transaction_error;
// pub mod versioned_message;
// pub mod versioned_transaction;
// pub mod vote_instruction;
// pub mod vote_state;

pub async fn encode_block<T>(
    // &mut self,
    // table: &str,
    data: T,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
    where
        T: prost::Message,
{
    // let mut bytes_written = 0;
    // let mut new_row_data = vec![];
    // for (row_key, data) in cells {
    let mut buf = Vec::with_capacity(data.encoded_len());
    data.encode(&mut buf).unwrap();
    let data = compress_best(&buf)?;
    // bytes_written += data.len();
    // new_row_data.push((row_key, vec![("encoder.proto".to_string(), data)]));
    // }

    // self.put_row_data(table, "x", &new_row_data).await?;
    // Ok(bytes_written)
    Ok(data)
}

pub fn convert_block(
    encoded_block: EncodedConfirmedBlock,
    encoding: UiTransactionEncoding,
    options: BlockEncodingOptions,
) -> Result<VersionedConfirmedBlock, Box<dyn std::error::Error>> {
    // Step 1: Convert EncodedConfirmedBlock to UiConfirmedBlock
    let ui_block: UiConfirmedBlock = encoded_block.into();

    // Step 2: Decode UiConfirmedBlock to ConfirmedBlock
    let confirmed_block = ConfirmedBlock::decode_with_options(ui_block, encoding, options)?;

    // Step 3: Try to convert ConfirmedBlock to VersionedConfirmedBlock
    let versioned_block = VersionedConfirmedBlock::try_from(confirmed_block)?;

    Ok(versioned_block)
}

pub async fn encode_transaction<T>(
    data: T,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
    where
        T: prost::Message,
{
    let mut buf = Vec::with_capacity(data.encoded_len());
    data.encode(&mut buf).unwrap();
    let data = compress_best(&buf)?;

    Ok(data)
}

pub fn convert_transaction(
    encoded_tx: EncodedTransactionWithStatusMeta,
    encoding: UiTransactionEncoding,
    // options: BlockEncodingOptions,
) -> Result<TransactionWithStatusMeta, Box<dyn std::error::Error>> {

    let confirmed_tx = TransactionWithStatusMeta::decode(encoded_tx, encoding)?;

    // Try to convert ConfirmedBlock to VersionedConfirmedBlock
    // let versioned_block = VersionedConfirmedBlock::try_from(confirmed_tx)?;

    Ok(confirmed_tx)
}
