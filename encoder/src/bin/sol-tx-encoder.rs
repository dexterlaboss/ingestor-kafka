
use {
    solana_binary_encoder::{
        convert::generated,
        transaction_status::{
            EncodedTransactionWithStatusMeta,
            UiTransactionEncoding,
            TransactionWithStatusMeta
        },

        encode_transaction,
        convert_transaction,
    },
    // solana_storage_proto::convert::generated,
};
use std::io;
use std::io::{Read, Write};

pub async fn output_transaction(
    tx: TransactionWithStatusMeta
) -> Result<(), Box<dyn std::error::Error>> {
    let data: Vec<u8> = encode_transaction::<generated::ConfirmedTransaction>(tx.into()).await?;

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(&data)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    let transaction: EncodedTransactionWithStatusMeta = serde_json::from_str(&buffer).unwrap();
    match convert_transaction(transaction, UiTransactionEncoding::Json) {
        Ok(confirmed_tx) => {
            // let data: Vec<u8> = encode_transaction::<generated::ConfirmedTransaction>(confirmed_tx.into()).await?;
            output_transaction(confirmed_tx).await?;
            // println!("{:#?}", versioned_tx);
        }
        Err(e) => {
            println!("Failed to convert transaction: {}", e);
        }
    }

    Ok(())
}