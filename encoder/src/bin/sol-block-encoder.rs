
use {
    solana_binary_encoder::{
        convert::generated,
        transaction_status::{
            EncodedConfirmedBlock,
            VersionedConfirmedBlock,
            UiTransactionEncoding,
            BlockEncodingOptions,
            TransactionDetails,
        },
        encode_block,
        convert_block,
    },
    // solana_storage_proto::convert::generated,
};
use std::io;
use std::io::{Read, Write};

pub async fn output_block(
    block: VersionedConfirmedBlock
) -> Result<(), Box<dyn std::error::Error>> {
    let data: Vec<u8> = encode_block::<generated::ConfirmedBlock>(block.into()).await?;

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(&data)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Started encoder");

    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    if let Err(e) = io::stdin().read_to_string(&mut buffer) {
        println!("Failed to read from stdin: {}", e);
        return Err(Box::new(e) as Box<dyn std::error::Error>);
    }

    println!("Encoding block");

    let block: EncodedConfirmedBlock = serde_json::from_str(&buffer).unwrap();

    let options = BlockEncodingOptions {
        transaction_details: TransactionDetails::Full,
        show_rewards: true,
        max_supported_transaction_version: Some(0),
    };

    match convert_block(block, UiTransactionEncoding::Json, options) {
        Ok(versioned_block) => {
            output_block(versioned_block).await?;
        }
        Err(e) => {
            println!("Failed to convert block: {}", e);
        }
    }

    Ok(())
}