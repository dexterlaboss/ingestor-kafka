
use {
    crate::{
        // transaction::Transaction,
        // instruction::CompiledInstruction,
        // transaction::{Result as TransactionResult},
        // versioned_transaction::{VersionedTransaction, TransactionVersion},
        // versioned_message::VersionedMessage,
        // message_v0::{Message as MessageV0, MessageAddressTableLookup},
        // message::Message,
        // loaded_message::LoadedMessage,
        // account_decoder::{
        //     UiTokenAmount
        // },
        // account_keys::AccountKeys,
        // reward_type::RewardType,
        option_serializer::OptionSerializer,
        // message_header::MessageHeader,
        parse_accounts::{ParsedAccount, parse_v0_message_accounts, parse_legacy_message_accounts},
        // clock::{Slot, UnixTimestamp},
        // transaction_error::TransactionError,
        // loaded_addresses::LoadedAddresses,
        parse_instruction::{parse, ParsedInstruction},
        // transaction_context::TransactionReturnData,
        // pubkey::{Pubkey, ParsePubkeyError},
        // hash::{Hash, ParseHashError},
        // signature::Signature,
    },
    solana_account_decoder::parse_token::UiTokenAmount,
    solana_sdk::{
        clock::{Slot, UnixTimestamp},
        instruction::CompiledInstruction,
        message::{
            v0::{
                self,
                LoadedAddresses,
                LoadedMessage,
                MessageAddressTableLookup
            },
            AccountKeys,
            Message,
            MessageHeader,
            VersionedMessage,
        },
        pubkey::{Pubkey, ParsePubkeyError},
        signature::Signature,
        transaction::{
            Result as TransactionResult,
            Transaction,
            TransactionError,
            TransactionVersion,
            VersionedTransaction,
        },
        transaction_context::TransactionReturnData,
        reward_type::RewardType,
        signature::ParseSignatureError,
        hash::{Hash, ParseHashError},
    },
    serde_derive::{Serialize,Deserialize},
    thiserror::Error,
};
use std::{error::Error, fmt};
use std::str::FromStr;
// use crate::hash::ParseHashError;
// use crate::signature::ParseSignatureError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionByAddrInfo {
    pub signature: Signature,          // The transaction signature
    pub err: Option<TransactionError>, // None if the transaction executed successfully
    pub index: u32,                    // Where the transaction is located in the block
    pub memo: Option<String>,          // Transaction memo
    pub block_time: Option<UnixTimestamp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransactionConfirmationStatus {
    Processed,
    Confirmed,
    Finalized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionStatus {
    pub slot: Slot,
    pub confirmations: Option<usize>,  // None = rooted
    pub status: TransactionResult<()>, // legacy field
    pub err: Option<TransactionError>,
    pub confirmation_status: Option<TransactionConfirmationStatus>,
}

pub struct BlockEncodingOptions {
    pub transaction_details: TransactionDetails,
    pub show_rewards: bool,
    pub max_supported_transaction_version: Option<u8>,
}

#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum TransactionWithStatusMeta {
    // Very old transactions may be missing metadata
    MissingMetadata(Transaction),
    // Versioned stored transaction always have metadata
    Complete(VersionedTransactionWithStatusMeta),
}



#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum EncodeError {
    #[error("Encoding does not support transaction version {0}")]
    UnsupportedTransactionVersion(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub struct VersionedTransactionWithStatusMeta {
    pub transaction: VersionedTransaction,
    pub meta: TransactionStatusMeta,
}



/// Represents types that can be encoded into one of several encoding formats
pub trait Encodable {
    type Encoded;
    fn encode(&self, encoding: UiTransactionEncoding) -> Self::Encoded;
}

/// Represents types that can be encoded into one of several encoding formats
pub trait EncodableWithMeta {
    type Encoded;
    fn encode_with_meta(
        &self,
        encoding: UiTransactionEncoding,
        meta: &TransactionStatusMeta,
    ) -> Self::Encoded;
    fn json_encode(&self) -> Self::Encoded;
}

impl EncodableWithMeta for VersionedTransaction {
    type Encoded = EncodedTransaction;
    fn encode_with_meta(
        &self,
        encoding: UiTransactionEncoding,
        meta: &TransactionStatusMeta,
    ) -> Self::Encoded {
        match encoding {
            UiTransactionEncoding::Binary => EncodedTransaction::LegacyBinary(
                bs58::encode(bincode::serialize(self).unwrap()).into_string(),
            ),
            UiTransactionEncoding::Base58 => EncodedTransaction::Binary(
                bs58::encode(bincode::serialize(self).unwrap()).into_string(),
                TransactionBinaryEncoding::Base58,
            ),
            UiTransactionEncoding::Base64 => EncodedTransaction::Binary(
                base64::encode(bincode::serialize(self).unwrap()),
                TransactionBinaryEncoding::Base64,
            ),
            UiTransactionEncoding::Json => self.json_encode(),
            UiTransactionEncoding::JsonParsed => EncodedTransaction::Json(UiTransaction {
                signatures: self.signatures.iter().map(ToString::to_string).collect(),
                message: match &self.message {
                    VersionedMessage::Legacy(message) => {
                        message.encode(UiTransactionEncoding::JsonParsed)
                    }
                    VersionedMessage::V0(message) => {
                        message.encode_with_meta(UiTransactionEncoding::JsonParsed, meta)
                    }
                },
            }),
        }
    }
    fn json_encode(&self) -> Self::Encoded {
        EncodedTransaction::Json(UiTransaction {
            signatures: self.signatures.iter().map(ToString::to_string).collect(),
            message: match &self.message {
                VersionedMessage::Legacy(message) => message.encode(UiTransactionEncoding::Json),
                VersionedMessage::V0(message) => message.json_encode(),
            },
        })
    }
}



impl Encodable for Transaction {
    type Encoded = EncodedTransaction;
    fn encode(&self, encoding: UiTransactionEncoding) -> Self::Encoded {
        match encoding {
            UiTransactionEncoding::Binary => EncodedTransaction::LegacyBinary(
                bs58::encode(bincode::serialize(self).unwrap()).into_string(),
            ),
            UiTransactionEncoding::Base58 => EncodedTransaction::Binary(
                bs58::encode(bincode::serialize(self).unwrap()).into_string(),
                TransactionBinaryEncoding::Base58,
            ),
            UiTransactionEncoding::Base64 => EncodedTransaction::Binary(
                base64::encode(bincode::serialize(self).unwrap()),
                TransactionBinaryEncoding::Base64,
            ),
            UiTransactionEncoding::Json | UiTransactionEncoding::JsonParsed => {
                EncodedTransaction::Json(UiTransaction {
                    signatures: self.signatures.iter().map(ToString::to_string).collect(),
                    message: self.message.encode(encoding),
                })
            }
        }
    }
}

impl Encodable for Message {
    type Encoded = UiMessage;
    fn encode(&self, encoding: UiTransactionEncoding) -> Self::Encoded {
        if encoding == UiTransactionEncoding::JsonParsed {
            let account_keys = AccountKeys::new(&self.account_keys, None);
            UiMessage::Parsed(UiParsedMessage {
                account_keys: parse_legacy_message_accounts(self),
                recent_blockhash: self.recent_blockhash.to_string(),
                instructions: self
                    .instructions
                    .iter()
                    .map(|instruction| UiInstruction::parse(instruction, &account_keys))
                    .collect(),
                address_table_lookups: None,
            })
        } else {
            UiMessage::Raw(UiRawMessage {
                header: self.header,
                account_keys: self.account_keys.iter().map(ToString::to_string).collect(),
                recent_blockhash: self.recent_blockhash.to_string(),
                instructions: self.instructions.iter().map(Into::into).collect(),
                address_table_lookups: None,
            })
        }
    }
}

impl EncodableWithMeta for v0::Message {
    type Encoded = UiMessage;
    fn encode_with_meta(
        &self,
        encoding: UiTransactionEncoding,
        meta: &TransactionStatusMeta,
    ) -> Self::Encoded {
        if encoding == UiTransactionEncoding::JsonParsed {
            let account_keys = AccountKeys::new(&self.account_keys, Some(&meta.loaded_addresses));
            let loaded_message = LoadedMessage::new_borrowed(self, &meta.loaded_addresses);
            UiMessage::Parsed(UiParsedMessage {
                account_keys: parse_v0_message_accounts(&loaded_message),
                recent_blockhash: self.recent_blockhash.to_string(),
                instructions: self
                    .instructions
                    .iter()
                    .map(|instruction| UiInstruction::parse(instruction, &account_keys))
                    .collect(),
                address_table_lookups: Some(
                    self.address_table_lookups.iter().map(Into::into).collect(),
                ),
            })
        } else {
            self.json_encode()
        }
    }
    fn json_encode(&self) -> Self::Encoded {
        UiMessage::Raw(UiRawMessage {
            header: self.header,
            account_keys: self.account_keys.iter().map(ToString::to_string).collect(),
            recent_blockhash: self.recent_blockhash.to_string(),
            instructions: self.instructions.iter().map(Into::into).collect(),
            address_table_lookups: Some(
                self.address_table_lookups.iter().map(Into::into).collect(),
            ),
        })
    }
}

impl DecodableWithMeta for v0::Message {
    type Encoded = UiMessage;
    type Decoded = v0::Message;

    fn decode_with_meta(
        encoded: Self::Encoded,
        decoding: UiTransactionEncoding,
        version: Option<TransactionVersion>
        // _meta: &TransactionStatusMeta,
    ) -> Result<Self::Decoded, DecodeError> {
        match decoding {
            UiTransactionEncoding::Json => match encoded {
                UiMessage::Raw(_) => Self::json_decode(encoded, version),
                UiMessage::Parsed(_) => Err(DecodeError::UnsupportedEncoding),
            },
            _ => Err(DecodeError::UnsupportedEncoding),
        }
    }

    fn json_decode(encoded: Self::Encoded, version: Option<TransactionVersion>) -> Result<Self::Decoded, DecodeError> {
    // fn decode(encoded: Self::Encoded) -> Result<Self::Decoded, DecodeError> {
        if let UiMessage::Raw(raw_msg) = encoded {
            let header = raw_msg.header;
            let account_keys = raw_msg.account_keys
                .iter()
                .map(|s| s.parse::<Pubkey>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| DecodeError::InvalidAccountKey)?;
            let recent_blockhash = raw_msg.recent_blockhash.parse::<Hash>()
                .map_err(|_| DecodeError::InvalidBlockhash)?;
            // let instructions = raw_msg.instructions
            //     .iter()
            //     .map(|i| decode_ui_instruction(i))
            //     .collect::<Result<Vec<_>, _>>()?;
            // let address_table_lookups = match raw_msg.address_table_lookups {
            //     Some(lookups) => lookups
            //         .iter()
            //         .map(|lookup| decode_ui_address_table_lookup(lookup))
            //         .collect::<Result<Vec<_>, _>>()?,
            //     None => vec![],
            // };
            let instructions = raw_msg.instructions
                .iter()
                .map(|i| CompiledInstruction::from(i.clone()))
                .collect::<Vec<_>>();
            let address_table_lookups = match raw_msg.address_table_lookups {
                Some(lookups) => lookups
                    .iter()
                    .map(|lookup| MessageAddressTableLookup::try_from(lookup))
                    .collect::<Result<Vec<_>, _>>()?,
                None => vec![],
            };

            Ok(Self {
                header,
                account_keys,
                recent_blockhash,
                instructions,
                address_table_lookups,
            })
        } else {
            Err(DecodeError::UnsupportedEncoding)
        }
    }
}


trait JsonAccounts {
    type Encoded;
    fn build_json_accounts(&self) -> Self::Encoded;
}

impl JsonAccounts for Transaction {
    type Encoded = EncodedTransaction;
    fn build_json_accounts(&self) -> Self::Encoded {
        EncodedTransaction::Accounts(UiAccountsList {
            signatures: self.signatures.iter().map(ToString::to_string).collect(),
            account_keys: parse_legacy_message_accounts(&self.message),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransactionStatusMeta {
    pub status: TransactionResult<()>,
    pub fee: u64,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    pub inner_instructions: Option<Vec<InnerInstructions>>,
    pub log_messages: Option<Vec<String>>,
    pub pre_token_balances: Option<Vec<TransactionTokenBalance>>,
    pub post_token_balances: Option<Vec<TransactionTokenBalance>>,
    pub rewards: Option<Rewards>,
    pub loaded_addresses: LoadedAddresses,
    pub return_data: Option<TransactionReturnData>,
    pub compute_units_consumed: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerInstructions {
    /// Transaction instruction index
    pub index: u8,
    /// List of inner instructions
    pub instructions: Vec<CompiledInstruction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiInnerInstructions {
    /// Transaction instruction index
    pub index: u8,
    /// List of inner instructions
    pub instructions: Vec<UiInstruction>,
}

impl UiInnerInstructions {
    fn parse(inner_instructions: InnerInstructions, account_keys: &AccountKeys) -> Self {
        Self {
            index: inner_instructions.index,
            instructions: inner_instructions
                .instructions
                .iter()
                .map(|ix| UiInstruction::parse(ix, account_keys))
                .collect(),
        }
    }
}

impl From<InnerInstructions> for UiInnerInstructions {
    fn from(inner_instructions: InnerInstructions) -> Self {
        Self {
            index: inner_instructions.index,
            instructions: inner_instructions
                .instructions
                .iter()
                .map(|ix| UiInstruction::Compiled(ix.into()))
                .collect(),
        }
    }
}

/// A duplicate representation of an Instruction for pretty JSON serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum UiInstruction {
    Compiled(UiCompiledInstruction),
    Parsed(UiParsedInstruction),
}

impl UiInstruction {
    fn parse(instruction: &CompiledInstruction, account_keys: &AccountKeys) -> Self {
        let program_id = &account_keys[instruction.program_id_index as usize];
        if let Ok(parsed_instruction) = parse(program_id, instruction, account_keys) {
            UiInstruction::Parsed(UiParsedInstruction::Parsed(parsed_instruction))
        } else {
            UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(
                UiPartiallyDecodedInstruction::from(instruction, account_keys),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum UiParsedInstruction {
    Parsed(ParsedInstruction),
    PartiallyDecoded(UiPartiallyDecodedInstruction),
}

// #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
// #[serde(rename_all = "camelCase")]
// pub struct ParsedInstruction {
//     pub program: String,
//     pub program_id: String,
//     pub parsed: Value,
// }

/// A partially decoded CompiledInstruction that includes explicit account addresses
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiPartiallyDecodedInstruction {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub data: String,
}

impl UiPartiallyDecodedInstruction {
    fn from(instruction: &CompiledInstruction, account_keys: &AccountKeys) -> Self {
        Self {
            program_id: account_keys[instruction.program_id_index as usize].to_string(),
            accounts: instruction
                .accounts
                .iter()
                .map(|&i| account_keys[i as usize].to_string())
                .collect(),
            data: bs58::encode(instruction.data.clone()).into_string(),
        }
    }
}

/// A duplicate representation of a CompiledInstruction for pretty JSON serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiCompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: String,
}

impl From<&CompiledInstruction> for UiCompiledInstruction {
    fn from(instruction: &CompiledInstruction) -> Self {
        Self {
            program_id_index: instruction.program_id_index,
            accounts: instruction.accounts.clone(),
            data: bs58::encode(instruction.data.clone()).into_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransactionTokenBalance {
    pub account_index: u8,
    pub mint: String,
    pub ui_token_amount: UiTokenAmount,
    pub owner: String,
    pub program_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmedTransactionWithStatusMeta {
    pub slot: Slot,
    pub tx_with_meta: TransactionWithStatusMeta,
    pub block_time: Option<UnixTimestamp>,
}

// Not used for now.
#[allow(dead_code)]
impl ConfirmedTransactionWithStatusMeta {
    pub fn encode(
        self,
        encoding: UiTransactionEncoding,
        max_supported_transaction_version: Option<u8>,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta, EncodeError> {
        Ok(EncodedConfirmedTransactionWithStatusMeta {
            slot: self.slot,
            transaction: self.tx_with_meta.encode(
                encoding,
                max_supported_transaction_version,
                true,
            )?,
            block_time: self.block_time,
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedConfirmedTransactionWithStatusMeta {
    pub slot: Slot,
    #[serde(flatten)]
    pub transaction: EncodedTransactionWithStatusMeta,
    pub block_time: Option<UnixTimestamp>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedTransactionWithStatusMeta {
    pub transaction: EncodedTransaction,
    pub meta: Option<UiTransactionStatusMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<TransactionVersion>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum EncodedTransaction {
    LegacyBinary(String), // Old way of expressing base-58, retained for RPC backwards compatibility
    Binary(String, TransactionBinaryEncoding),
    Json(UiTransaction),
    Accounts(UiAccountsList),
}

impl EncodedTransaction {
    pub fn decode(&self) -> Option<VersionedTransaction> {
        let (blob, encoding) = match self {
            Self::Json(_) | Self::Accounts(_) => return None,
            Self::LegacyBinary(blob) => (blob, TransactionBinaryEncoding::Base58),
            Self::Binary(blob, encoding) => (blob, *encoding),
        };

        let transaction: Option<VersionedTransaction> = match encoding {
            TransactionBinaryEncoding::Base58 => bs58::decode(blob)
                .into_vec()
                .ok()
                .and_then(|bytes| bincode::deserialize(&bytes).ok()),
            TransactionBinaryEncoding::Base64 => base64::decode(blob)
                .ok()
                .and_then(|bytes| bincode::deserialize(&bytes).ok()),
        };

        transaction.filter(|transaction| {
            transaction
                .sanitize(
                    true, // require_static_program_ids
                )
                .is_ok()
        })
    }
}

/// A duplicate representation of TransactionStatusMeta with `err` field
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiTransactionStatusMeta {
    pub err: Option<TransactionError>,
    pub status: TransactionResult<()>, // This field is deprecated.  See https://github.com/solana-labs/solana/issues/9302
    pub fee: u64,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    #[serde(
        default = "OptionSerializer::none",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub inner_instructions: OptionSerializer<Vec<UiInnerInstructions>>,
    #[serde(
        default = "OptionSerializer::none",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub log_messages: OptionSerializer<Vec<String>>,
    #[serde(
        default = "OptionSerializer::none",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub pre_token_balances: OptionSerializer<Vec<UiTransactionTokenBalance>>,
    #[serde(
        default = "OptionSerializer::none",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub post_token_balances: OptionSerializer<Vec<UiTransactionTokenBalance>>,
    #[serde(
        default = "OptionSerializer::none",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub rewards: OptionSerializer<Rewards>,
    #[serde(
        default = "OptionSerializer::skip",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub loaded_addresses: OptionSerializer<UiLoadedAddresses>,
    #[serde(
        default = "OptionSerializer::skip",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub return_data: OptionSerializer<UiTransactionReturnData>,
    #[serde(
        default = "OptionSerializer::skip",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub compute_units_consumed: OptionSerializer<u64>,
}

impl UiTransactionStatusMeta {
    fn parse(meta: TransactionStatusMeta, static_keys: &[Pubkey], show_rewards: bool) -> Self {
        let account_keys = AccountKeys::new(static_keys, Some(&meta.loaded_addresses));
        Self {
            err: meta.status.clone().err(),
            status: meta.status,
            fee: meta.fee,
            pre_balances: meta.pre_balances,
            post_balances: meta.post_balances,
            inner_instructions: meta
                .inner_instructions
                .map(|ixs| {
                    ixs.into_iter()
                        .map(|ix| UiInnerInstructions::parse(ix, &account_keys))
                        .collect()
                })
                .into(),
            log_messages: meta.log_messages.into(),
            pre_token_balances: meta
                .pre_token_balances
                .map(|balance| balance.into_iter().map(Into::into).collect())
                .into(),
            post_token_balances: meta
                .post_token_balances
                .map(|balance| balance.into_iter().map(Into::into).collect())
                .into(),
            rewards: if show_rewards { meta.rewards } else { None }.into(),
            loaded_addresses: OptionSerializer::Skip,
            return_data: OptionSerializer::or_skip(
                meta.return_data.map(|return_data| return_data.into()),
            ),
            compute_units_consumed: OptionSerializer::or_skip(meta.compute_units_consumed),
        }
    }

    fn build_simple(meta: TransactionStatusMeta, show_rewards: bool) -> Self {
        Self {
            err: meta.status.clone().err(),
            status: meta.status,
            fee: meta.fee,
            pre_balances: meta.pre_balances,
            post_balances: meta.post_balances,
            inner_instructions: OptionSerializer::Skip,
            log_messages: OptionSerializer::Skip,
            pre_token_balances: meta
                .pre_token_balances
                .map(|balance| balance.into_iter().map(Into::into).collect())
                .into(),
            post_token_balances: meta
                .post_token_balances
                .map(|balance| balance.into_iter().map(Into::into).collect())
                .into(),
            rewards: if show_rewards {
                meta.rewards.into()
            } else {
                OptionSerializer::Skip
            },
            loaded_addresses: OptionSerializer::Skip,
            return_data: OptionSerializer::Skip,
            compute_units_consumed: OptionSerializer::Skip,
        }
    }
}

impl From<TransactionStatusMeta> for UiTransactionStatusMeta {
    fn from(meta: TransactionStatusMeta) -> Self {
        Self {
            err: meta.status.clone().err(),
            status: meta.status,
            fee: meta.fee,
            pre_balances: meta.pre_balances,
            post_balances: meta.post_balances,
            inner_instructions: meta
                .inner_instructions
                .map(|ixs| ixs.into_iter().map(Into::into).collect())
                .into(),
            log_messages: meta.log_messages.into(),
            pre_token_balances: meta
                .pre_token_balances
                .map(|balance| balance.into_iter().map(Into::into).collect())
                .into(),
            post_token_balances: meta
                .post_token_balances
                .map(|balance| balance.into_iter().map(Into::into).collect())
                .into(),
            rewards: meta.rewards.into(),
            loaded_addresses: Some(UiLoadedAddresses::from(&meta.loaded_addresses)).into(),
            return_data: OptionSerializer::or_skip(
                meta.return_data.map(|return_data| return_data.into()),
            ),
            compute_units_consumed: OptionSerializer::or_skip(meta.compute_units_consumed),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reward {
    pub pubkey: String,
    pub lamports: i64,
    pub post_balance: u64, // Account balance in lamports after `lamports` was applied
    pub reward_type: Option<RewardType>,
    pub commission: Option<u8>, // Vote account commission when the reward was credited, only present for voting and staking rewards
}

pub type Rewards = Vec<Reward>;

/// A duplicate representation of LoadedAddresses
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiLoadedAddresses {
    pub writable: Vec<String>,
    pub readonly: Vec<String>,
}

impl From<&LoadedAddresses> for UiLoadedAddresses {
    fn from(loaded_addresses: &LoadedAddresses) -> Self {
        Self {
            writable: loaded_addresses
                .writable
                .iter()
                .map(ToString::to_string)
                .collect(),
            readonly: loaded_addresses
                .readonly
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UiTransactionReturnData {
    pub program_id: String,
    pub data: (String, UiReturnDataEncoding),
}

impl Default for UiTransactionReturnData {
    fn default() -> Self {
        Self {
            program_id: String::default(),
            data: (String::default(), UiReturnDataEncoding::Base64),
        }
    }
}

impl From<TransactionReturnData> for UiTransactionReturnData {
    fn from(return_data: TransactionReturnData) -> Self {
        Self {
            program_id: return_data.program_id.to_string(),
            data: (
                base64::encode(return_data.data),
                UiReturnDataEncoding::Base64,
            ),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum UiReturnDataEncoding {
    Base64,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum TransactionBinaryEncoding {
    Base58,
    Base64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiTransactionTokenBalance {
    pub account_index: u8,
    pub mint: String,
    pub ui_token_amount: UiTokenAmount,
    #[serde(
        default = "OptionSerializer::skip",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub owner: OptionSerializer<String>,
    #[serde(
        default = "OptionSerializer::skip",
        skip_serializing_if = "OptionSerializer::should_skip"
    )]
    pub program_id: OptionSerializer<String>,
}

impl From<TransactionTokenBalance> for UiTransactionTokenBalance {
    fn from(token_balance: TransactionTokenBalance) -> Self {
        Self {
            account_index: token_balance.account_index,
            mint: token_balance.mint,
            ui_token_amount: token_balance.ui_token_amount,
            owner: if !token_balance.owner.is_empty() {
                OptionSerializer::Some(token_balance.owner)
            } else {
                OptionSerializer::Skip
            },
            program_id: if !token_balance.program_id.is_empty() {
                OptionSerializer::Some(token_balance.program_id)
            } else {
                OptionSerializer::Skip
            },
        }
    }
}

/// A duplicate representation of a Transaction for pretty JSON serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiTransaction {
    pub signatures: Vec<String>,
    pub message: UiMessage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum UiMessage {
    Parsed(UiParsedMessage),
    Raw(UiRawMessage),
}

/// A duplicate representation of a Message, in raw format, for pretty JSON serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiRawMessage {
    pub header: MessageHeader,
    pub account_keys: Vec<String>,
    pub recent_blockhash: String,
    pub instructions: Vec<UiCompiledInstruction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_table_lookups: Option<Vec<UiAddressTableLookup>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiAccountsList {
    pub signatures: Vec<String>,
    pub account_keys: Vec<ParsedAccount>,
}

/// A duplicate representation of a MessageAddressTableLookup, in raw format, for pretty JSON serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiAddressTableLookup {
    pub account_key: String,
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

impl From<&MessageAddressTableLookup> for UiAddressTableLookup {
    fn from(lookup: &MessageAddressTableLookup) -> Self {
        Self {
            account_key: lookup.account_key.to_string(),
            writable_indexes: lookup.writable_indexes.clone(),
            readonly_indexes: lookup.readonly_indexes.clone(),
        }
    }
}

impl TryFrom<&UiAddressTableLookup> for MessageAddressTableLookup {
    type Error = DecodeError;

    fn try_from(lookup: &UiAddressTableLookup) -> Result<Self, Self::Error> {
        let account_key = Pubkey::from_str(&lookup.account_key)
            .map_err(|_| DecodeError::ParsePubkeyFailed(ParsePubkeyError::Invalid))?;
        Ok(Self {
            account_key,
            writable_indexes: lookup.writable_indexes.clone(),
            readonly_indexes: lookup.readonly_indexes.clone(),
        })
    }
}

/// A duplicate representation of a Message, in parsed format, for pretty JSON serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiParsedMessage {
    pub account_keys: Vec<ParsedAccount>,
    pub recent_blockhash: String,
    pub instructions: Vec<UiInstruction>,
    pub address_table_lookups: Option<Vec<UiAddressTableLookup>>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum UiTransactionEncoding {
    Binary, // Legacy. Retained for RPC backwards compatibility
    Base64,
    Base58,
    Json,
    JsonParsed,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransactionDetails {
    Full,
    Signatures,
    None,
    Accounts,
}

impl Default for TransactionDetails {
    fn default() -> Self {
        Self::Full
    }
}

#[derive(Debug, Error)]
pub enum ConvertBlockError {
    #[error("transactions missing after converted, before: {0}, after: {1}")]
    TransactionsMissing(usize, usize),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConfirmedBlock {
    pub previous_blockhash: String,
    pub blockhash: String,
    pub parent_slot: Slot,
    pub transactions: Vec<TransactionWithStatusMeta>,
    pub rewards: Rewards,
    pub block_time: Option<UnixTimestamp>,
    pub block_height: Option<u64>,
}

// Confirmed block with type guarantees that transaction metadata
// is always present. Used for uploading to HBase.
#[derive(Clone, Debug, PartialEq)]
pub struct VersionedConfirmedBlock {
    pub previous_blockhash: String,
    pub blockhash: String,
    pub parent_slot: Slot,
    pub transactions: Vec<VersionedTransactionWithStatusMeta>,
    pub rewards: Rewards,
    pub block_time: Option<UnixTimestamp>,
    pub block_height: Option<u64>,
}

impl From<VersionedConfirmedBlock> for ConfirmedBlock {
    fn from(block: VersionedConfirmedBlock) -> Self {
        Self {
            previous_blockhash: block.previous_blockhash,
            blockhash: block.blockhash,
            parent_slot: block.parent_slot,
            transactions: block
                .transactions
                .into_iter()
                .map(TransactionWithStatusMeta::Complete)
                .collect(),
            rewards: block.rewards,
            block_time: block.block_time,
            block_height: block.block_height,
        }
    }
}



#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UiConfirmedBlock {
    pub previous_blockhash: String,
    pub blockhash: String,
    pub parent_slot: Slot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Vec<EncodedTransactionWithStatusMeta>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewards: Option<Rewards>,
    pub block_time: Option<UnixTimestamp>,
    pub block_height: Option<u64>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedConfirmedBlock {
    pub previous_blockhash: String,
    pub blockhash: String,
    pub parent_slot: Slot,
    pub transactions: Vec<EncodedTransactionWithStatusMeta>,
    pub rewards: Rewards,
    pub block_time: Option<UnixTimestamp>,
    pub block_height: Option<u64>,
}

impl From<UiConfirmedBlock> for EncodedConfirmedBlock {
    fn from(block: UiConfirmedBlock) -> Self {
        Self {
            previous_blockhash: block.previous_blockhash,
            blockhash: block.blockhash,
            parent_slot: block.parent_slot,
            transactions: block.transactions.unwrap_or_default(),
            rewards: block.rewards.unwrap_or_default(),
            block_time: block.block_time,
            block_height: block.block_height,
        }
    }
}



impl VersionedTransactionWithStatusMeta {
    fn validate_version(
        &self,
        max_supported_transaction_version: Option<u8>,
    ) -> Result<Option<TransactionVersion>, EncodeError> {
        match (
            max_supported_transaction_version,
            self.transaction.version(),
        ) {
            // Set to none because old clients can't handle this field
            (None, TransactionVersion::LEGACY) => Ok(None),
            (None, TransactionVersion::Number(version)) => {
                Err(EncodeError::UnsupportedTransactionVersion(version))
            }
            (Some(_), TransactionVersion::LEGACY) => Ok(Some(TransactionVersion::LEGACY)),
            (Some(max_version), TransactionVersion::Number(version)) => {
                if version <= max_version {
                    Ok(Some(TransactionVersion::Number(version)))
                } else {
                    Err(EncodeError::UnsupportedTransactionVersion(version))
                }
            }
        }
    }

    pub fn account_keys(&self) -> AccountKeys {
        AccountKeys::new(
            self.transaction.message.static_account_keys(),
            Some(&self.meta.loaded_addresses),
        )
    }

    pub fn encode(
        self,
        encoding: UiTransactionEncoding,
        max_supported_transaction_version: Option<u8>,
        show_rewards: bool,
    ) -> Result<EncodedTransactionWithStatusMeta, EncodeError> {
        let version = self.validate_version(max_supported_transaction_version)?;

        Ok(EncodedTransactionWithStatusMeta {
            transaction: self.transaction.encode_with_meta(encoding, &self.meta),
            meta: Some(match encoding {
                UiTransactionEncoding::JsonParsed => UiTransactionStatusMeta::parse(
                    self.meta,
                    self.transaction.message.static_account_keys(),
                    show_rewards,
                ),
                _ => {
                    let mut meta = UiTransactionStatusMeta::from(self.meta);
                    if !show_rewards {
                        meta.rewards = OptionSerializer::None;
                    }
                    meta
                }
            }),
            version,
        })
    }

    pub fn decode(
        encoded: EncodedTransactionWithStatusMeta,
        encoding: UiTransactionEncoding,
        // meta: Option<&UiTransactionStatusMeta>,
    ) -> Result<Self, DecodeError> {
        // Decoding the transaction
        let transaction = match VersionedTransaction::decode_with_meta(encoded.transaction, encoding, encoded.version /*, meta*/) {
            Ok(decoded) => decoded,
            Err(e) => return Err(e),
        };

        // Decoding the meta
        let meta = match encoded.meta {
            Some(ui_meta) => match TransactionStatusMeta::try_from(ui_meta) {
                Ok(meta) => meta,
                Err(_) => return Err(DecodeError::InvalidData),
            },
            None => return Err(DecodeError::InvalidData),
        };

        Ok(Self {
            transaction,
            meta,
        })
    }

    fn build_json_accounts(
        self,
        max_supported_transaction_version: Option<u8>,
        show_rewards: bool,
    ) -> Result<EncodedTransactionWithStatusMeta, EncodeError> {
        let version = self.validate_version(max_supported_transaction_version)?;

        let account_keys = match &self.transaction.message {
            VersionedMessage::Legacy(message) => parse_legacy_message_accounts(message),
            VersionedMessage::V0(message) => {
                let loaded_message =
                    LoadedMessage::new_borrowed(message, &self.meta.loaded_addresses);
                parse_v0_message_accounts(&loaded_message)
            }
        };

        Ok(EncodedTransactionWithStatusMeta {
            transaction: EncodedTransaction::Accounts(UiAccountsList {
                signatures: self
                    .transaction
                    .signatures
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                account_keys,
            }),
            meta: Some(UiTransactionStatusMeta::build_simple(
                self.meta,
                show_rewards,
            )),
            version,
        })
    }
}


#[derive(Debug, PartialEq)]
pub enum DecodeError {
    InvalidEncoding,
    InvalidAccountKey,
    InvalidBlockhash,
    DecodeFailed,
    DeserializeFailed,
    ParseSignatureFailed(ParseSignatureError),
    ParseHashFailed(ParseHashError),
    ParsePubkeyFailed(ParsePubkeyError),
    NotImplemented,
    InvalidData,
    UnsupportedEncoding,
    UnsupportedVersion,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::InvalidEncoding => write!(f, "Invalid encoding"),
            DecodeError::DecodeFailed => write!(f, "Decoding failed"),
            DecodeError::DeserializeFailed => write!(f, "Deserialization failed"),
            DecodeError::InvalidAccountKey => write!(f, "Invalid account key"),
            DecodeError::InvalidBlockhash => write!(f, "Invalid blockhash"),
            DecodeError::ParseSignatureFailed(err) => write!(f, "Failed to parse signature: {}", err),
            DecodeError::ParseHashFailed(err) => write!(f, "Failed to parse hash: {}", err),
            DecodeError::ParsePubkeyFailed(err) => write!(f, "Failed to parse pubkey: {}", err),
            DecodeError::NotImplemented => write!(f, "Not implemented"),
            DecodeError::InvalidData => write!(f, "Invalid data"),
            DecodeError::UnsupportedEncoding => write!(f, "Encoding is not supported"),
            DecodeError::UnsupportedVersion => write!(f, "Transaction version is not supported"),
        }
    }
}

impl Error for DecodeError {}

impl From<ParsePubkeyError> for DecodeError {
    fn from(err: ParsePubkeyError) -> Self {
        DecodeError::ParsePubkeyFailed(err)
    }
}





pub trait Decodable {
    type Encoded;
    type Decoded;
    fn decode(encoded: &Self::Encoded) -> Result<Self::Decoded, DecodeError>;
}

impl Decodable for Message {
    type Encoded = UiMessage;
    type Decoded = Message;

    fn decode(encoded: &Self::Encoded) -> Result<Self::Decoded, DecodeError> {
        match encoded {
            UiMessage::Raw(raw_message) => {
                let header = raw_message.header;
                let account_keys: Result<Vec<Pubkey>, _> = raw_message
                    .account_keys
                    .iter()
                    .map(|key_str| key_str.parse())
                    .collect();
                let account_keys = account_keys?;
                let recent_blockhash = Hash::from_str(&raw_message.recent_blockhash)
                    .map_err(|err| DecodeError::ParseHashFailed(err))?;
                let instructions: Vec<CompiledInstruction> = raw_message
                    .instructions
                    .iter()
                    // .map(|ui_instruction| (*ui_instruction).into() )
                    .map(|ui_instruction| ui_instruction.clone().into() )
                    .collect();

                Ok(Message {
                    header,
                    account_keys,
                    recent_blockhash,
                    instructions,
                })
            }
            UiMessage::Parsed(_) => {
                Err(DecodeError::UnsupportedEncoding)
            }
        }
    }
}

impl Decodable for Transaction {
    type Encoded = EncodedTransaction;
    type Decoded = Transaction;

    fn decode(encoded: &Self::Encoded) -> Result<Self::Decoded, DecodeError> {
        match encoded {
            EncodedTransaction::LegacyBinary(s) | EncodedTransaction::Binary(s, TransactionBinaryEncoding::Base58) => {
                // let data = bs58::decode(s).into_vec()?;
                let data = bs58::decode(s)
                    .into_vec()
                    .map_err(|_| DecodeError::DeserializeFailed)?;
                // let transaction: Transaction = bincode::deserialize(&data)?;
                let transaction: Transaction = bincode::deserialize(&data)
                    .map_err(|_| DecodeError::DeserializeFailed)?;
                Ok(transaction)
            }
            EncodedTransaction::Binary(s, TransactionBinaryEncoding::Base64) => {
                // let data = base64::decode(s)?;
                let data = base64::decode(s)
                    .map_err(|_| DecodeError::DeserializeFailed)?;
                // let transaction: Transaction = bincode::deserialize(&data)?;
                let transaction: Transaction = bincode::deserialize(&data)
                    .map_err(|_| DecodeError::DeserializeFailed)?;
                Ok(transaction)
            }
            EncodedTransaction::Json(ui_transaction) => {
                let message = Message::decode(&ui_transaction.message)?;
                let signatures: Result<Vec<Signature>, ParseSignatureError> = ui_transaction.signatures.iter()
                    .map(|s| Signature::from_str(s))
                    .collect();
                let signatures = match signatures {
                    Ok(signatures) => signatures,
                    Err(error) => return Err(DecodeError::ParseSignatureFailed(error)),
                };
                Ok(Transaction {
                    signatures,
                    message,
                })
            }
            EncodedTransaction::Accounts(_) => {
                Err(DecodeError::UnsupportedEncoding)
            }
        }
    }
}



pub trait DecodableWithMeta {
    type Encoded;
    type Decoded;
    fn decode_with_meta(
        encoded: Self::Encoded,
        encoding: UiTransactionEncoding,
        version: Option<TransactionVersion>
        // meta: Option<&TransactionStatusMeta>,
    ) -> Result<Self::Decoded, DecodeError>;
    // fn json_decode(ui_transaction: UiTransaction) -> Result<Self::Decoded, DecodeError>;
    fn json_decode(encoded: Self::Encoded, version: Option<TransactionVersion>) -> Result<Self::Decoded, DecodeError>;
}

impl DecodableWithMeta for VersionedTransaction {
    type Encoded = EncodedTransaction;
    type Decoded = VersionedTransaction;

    fn decode_with_meta(
        encoded: Self::Encoded,
        decoding: UiTransactionEncoding,
        version: Option<TransactionVersion>
    ) -> Result<Self::Decoded, DecodeError> {
        match decoding {
            UiTransactionEncoding::Binary | UiTransactionEncoding::Base58 => {
                if let EncodedTransaction::LegacyBinary(encoded_string) = encoded {
                    let decoded_bytes = bs58::decode(encoded_string).into_vec().unwrap();
                    let decoded: Self::Decoded =
                        bincode::deserialize(&decoded_bytes).map_err(|_| DecodeError::DeserializeFailed)?;
                    Ok(decoded)
                } else {
                    Err(DecodeError::UnsupportedEncoding)
                }
            }
            UiTransactionEncoding::Base64 => {
                if let EncodedTransaction::Binary(encoded_string, _) = encoded {
                    let decoded_bytes = base64::decode(encoded_string).unwrap();
                    let decoded: Self::Decoded =
                        bincode::deserialize(&decoded_bytes).map_err(|_| DecodeError::DeserializeFailed)?;
                    Ok(decoded)
                } else {
                    Err(DecodeError::UnsupportedEncoding)
                }
            }
            UiTransactionEncoding::Json => Self::json_decode(encoded, version),
            UiTransactionEncoding::JsonParsed => Err(DecodeError::UnsupportedEncoding),
        }
    }

    // fn decode_with_meta(
    //     encoded: EncodedTransaction,
    //     encoding: UiTransactionEncoding,
    //     // meta: Option<&TransactionStatusMeta>,
    // ) -> Result<Self::Decoded, DecodeError> {
    //     let (signatures, message) = match encoded {
    //         // EncodedTransaction::Json(ui_transaction) => {
    //         EncodedTransaction::Json(_) => {
    //             return Self::json_decode(encoded);
    //         }
    //         // EncodedTransaction::JsonParsed(ui_transaction) => {
    //         //     let signatures = ui_transaction
    //         //         .signatures
    //         //         .iter()
    //         //         .map(|s| s.parse::<Signature>())
    //         //         .collect::<Result<Vec<_>, _>>()
    //         //         .map_err(|_| DecodeError::InvalidData)?;
    //         //
    //         //     let message = match encoding {
    //         //         UiTransactionEncoding::JsonParsed => {
    //         //             let message = VersionedMessage::decode(ui_transaction.message)?;
    //         //             match (&message, meta) {
    //         //                 (VersionedMessage::V0(message), Some(meta)) => {
    //         //                     message.decode_with_meta(meta)?
    //         //                 }
    //         //                 _ => message,
    //         //             }
    //         //         }
    //         //         _ => return Err(DecodeError::InvalidEncoding),
    //         //     };
    //         //
    //         //     (signatures, message)
    //         // }
    //         EncodedTransaction::Accounts(_) => return Err(DecodeError::InvalidEncoding),
    //         _ => {}
    //     };
    //
    //     Ok(Self {
    //         signatures,
    //         message,
    //     })
    // }

    // fn json_encode(&self) -> Self::Encoded {
    //     EncodedTransaction::Json(UiTransaction {
    //         signatures: self.signatures.iter().map(ToString::to_string).collect(),
    //         message: match &self.message {
    //             VersionedMessage::Legacy(message) => message.encode(UiTransactionEncoding::Json),
    //             VersionedMessage::V0(message) => message.json_encode(),
    //         },
    //     })
    // }

    // VersionedMessage::decode(&ui_transaction.message)?

    fn json_decode(encoded: Self::Encoded, version: Option<TransactionVersion>) -> Result<Self::Decoded, DecodeError> {
        if let EncodedTransaction::Json(ui_transaction) = encoded {
            let signatures = ui_transaction
                .signatures
                .iter()
                .map(|s| s.parse::<Signature>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| DecodeError::ParseSignatureFailed(err))?;

            let message = match ui_transaction.message {
                UiMessage::Raw(_) => {
                    match version {
                        Some(TransactionVersion::Number(0)) => {
                            // Handle Version 0 message decoding for raw messages
                            let v0_message = v0::Message::json_decode(ui_transaction.message, version)?;
                            VersionedMessage::V0(v0_message)
                        }
                        Some(TransactionVersion::Legacy(_)) | None => {
                            // Default to legacy message decoding for raw messages
                            let legacy_message = Message::decode(&ui_transaction.message)?;
                            VersionedMessage::Legacy(legacy_message)
                        }
                        // Add additional cases here for other versions as needed
                        _ => {
                            // Handle other versions or return an error if not supported
                            return Err(DecodeError::UnsupportedVersion);
                        }
                    }
                }
                UiMessage::Parsed(_) => {
                    return Err(DecodeError::UnsupportedEncoding);
                }
            };

            Ok(Self {
                signatures,
                message,
            })
        } else {
            Err(DecodeError::UnsupportedEncoding)
        }
    }

    // fn json_decode(ui_transaction: UiTransaction) -> Result<Self::Decoded, DecodeError> {
    // fn json_decode(encoded: Self::Encoded) -> Result<Self::Decoded, DecodeError> {
    //     let ui_transaction = match encoded {
    //         EncodedTransaction::Json(ui_transaction) => ui_transaction,
    //         _ => return Err(DecodeError::InvalidData),
    //     };
    //
    //     let signatures = ui_transaction
    //         .signatures
    //         .iter()
    //         .map(|s| s.parse::<Signature>())
    //         .collect::<Result<Vec<_>, _>>()
    //         .map_err(|_| DecodeError::InvalidData)?;
    //
    //     let message = VersionedMessage::decode(ui_transaction.message)?;
    //     Ok(Self {
    //         signatures,
    //         message,
    //     })
    // }
}


impl TransactionWithStatusMeta {
    pub fn encode(
        self,
        encoding: UiTransactionEncoding,
        max_supported_transaction_version: Option<u8>,
        show_rewards: bool,
    ) -> Result<EncodedTransactionWithStatusMeta, EncodeError> {
        match self {
            Self::MissingMetadata(ref transaction) => Ok(EncodedTransactionWithStatusMeta {
                version: None,
                transaction: transaction.encode(encoding),
                meta: None,
            }),
            Self::Complete(tx_with_meta) => {
                tx_with_meta.encode(encoding, max_supported_transaction_version, show_rewards)
            }
        }
    }

    pub fn decode(
        encoded: EncodedTransactionWithStatusMeta,
        encoding: UiTransactionEncoding,
    ) -> Result<Self, DecodeError> {
        match encoded.meta {
            Some(_) => {
                let complete = VersionedTransactionWithStatusMeta::decode(encoded, encoding /*, None*/)?;
                Ok(Self::Complete(complete))
            },
            None => {
                let transaction = Transaction::decode(&encoded.transaction)?;
                Ok(Self::MissingMetadata(transaction))
            }
        }
    }

    // pub fn decode(
    //     encoded: EncodedTransactionWithStatusMeta,
    //     encoding: UiTransactionEncoding,
    //     // max_supported_transaction_version: Option<u8>,
    //     // show_rewards: bool,
    // ) -> Result<Self, DecodeError> {
    //     match encoded {
    //         EncodedTransactionWithStatusMeta::MissingMetadata(encoded_transaction) => {
    //             let transaction = Transaction::decode(&encoded_transaction)?;
    //
    //             Ok(Self::MissingMetadata(transaction))
    //         },
    //         EncodedTransactionWithStatusMeta::Complete(encoded_tx_with_meta) => {
    //             let tx_with_meta = VersionedTransactionWithStatusMeta::decode(
    //                 encoded_tx_with_meta,
    //                 encoding,
    //                 // max_supported_transaction_version,
    //                 // show_rewards
    //             )?;
    //
    //             Ok(Self::Complete(tx_with_meta))
    //         }
    //     }
    // }

    pub fn transaction_signature(&self) -> &Signature {
        match self {
            Self::MissingMetadata(transaction) => &transaction.signatures[0],
            Self::Complete(VersionedTransactionWithStatusMeta { transaction, .. }) => {
                &transaction.signatures[0]
            }
        }
    }

    fn build_json_accounts(
        self,
        max_supported_transaction_version: Option<u8>,
        show_rewards: bool,
    ) -> Result<EncodedTransactionWithStatusMeta, EncodeError> {
        match self {
            Self::MissingMetadata(ref transaction) => Ok(EncodedTransactionWithStatusMeta {
                version: None,
                transaction: transaction.build_json_accounts(),
                meta: None,
            }),
            Self::Complete(tx_with_meta) => {
                tx_with_meta.build_json_accounts(max_supported_transaction_version, show_rewards)
            }
        }
    }
}


// impl From<UiTransactionStatusMeta> for TransactionStatusMeta {
//     fn from(meta: UiTransactionStatusMeta) -> Self {
//         Self {
//             status: meta.status,
//             fee: meta.fee,
//             pre_balances: meta.pre_balances,
//             post_balances: meta.post_balances,
//             inner_instructions: meta.inner_instructions.into_option().map(|ixs|
//                 ixs.into_iter().map(Into::into).collect()
//             ),
//             log_messages: meta.log_messages.into_option(),
//             pre_token_balances: meta.pre_token_balances.into_option().map(|balance|
//                 balance.into_iter().map(Into::into).collect()
//             ),
//             post_token_balances: meta.post_token_balances.into_option().map(|balance|
//                 balance.into_iter().map(Into::into).collect()
//             ),
//             rewards: meta.rewards.into_option(),
//             loaded_addresses: LoadedAddresses::from(meta.loaded_addresses.into_option().unwrap_or_default()),
//             return_data: meta.return_data.into_option().map(|return_data| return_data.into()),
//             compute_units_consumed: meta.compute_units_consumed.into_option(),
//         }
//     }
// }

impl TryFrom<UiTransactionStatusMeta> for TransactionStatusMeta {
    type Error = ConversionError;

    fn try_from(meta: UiTransactionStatusMeta) -> Result<Self, Self::Error> {
        let inner_instructions: Option<Vec<InnerInstructions>> = match meta.inner_instructions {
            OptionSerializer::Some(ui_inner_instructions) => {
                let inner_instructions_result: Result<Vec<_>, _> = ui_inner_instructions
                    .into_iter()
                    .map(|ui_inner_instruction| InnerInstructions::try_from(ui_inner_instruction))
                    .collect();

                match inner_instructions_result {
                    Ok(inner_instructions) => Some(inner_instructions),
                    Err(e) => return Err(e),
                }
            }
            _ => None,
        };

        let pre_token_balances: Option<Vec<TransactionTokenBalance>> = match meta.pre_token_balances {
            OptionSerializer::Some(ui_pre_token_balances) => {
                let pre_token_balances: Vec<_> = ui_pre_token_balances
                    .into_iter()
                    .map(TransactionTokenBalance::from)
                    .collect();

                Some(pre_token_balances)
            }
            _ => None,
        };

        let post_token_balances: Option<Vec<TransactionTokenBalance>> = match meta.post_token_balances {
            OptionSerializer::Some(ui_post_token_balances) => {
                let post_token_balances: Vec<_> = ui_post_token_balances
                    .into_iter()
                    .map(TransactionTokenBalance::from)
                    .collect();

                Some(post_token_balances)
            }
            _ => None,
        };

        let return_data: Option<TransactionReturnData> = match meta.return_data {
            OptionSerializer::Some(ui_return_data) => {
                let return_data = TransactionReturnData::try_from(ui_return_data)?;
                Some(return_data)
            }
            _ => None,
        };

        // let loaded_addresses: LoadedAddresses = match LoadedAddresses::try_from(&meta.loaded_addresses) {
        //     Ok(loaded_addresses) => loaded_addresses,
        //     Err(_) => return Err(ConversionError::InvalidProgramId),
        // };

        let loaded_addresses: LoadedAddresses = match &meta.loaded_addresses {
            OptionSerializer::Some(ui_loaded_addresses) => {
                match LoadedAddresses::try_from(ui_loaded_addresses) {
                    Ok(loaded_addresses) => loaded_addresses,
                    Err(_) => return Err(ConversionError::InvalidProgramId),
                }
                // match (*ui_loaded_addresses).into() {
                //     Ok(loaded_addresses) => loaded_addresses,
                //     Err(_) => return Err(ConversionError::InvalidProgramId),
                // }
            }
            _ => return Err(ConversionError::InvalidProgramId),
        };

        let compute_units_consumed: Option<u64> = match meta.compute_units_consumed {
            OptionSerializer::Some(cuc) => Some(cuc),
            _ => None,
        };

        Ok(Self {
            status: meta.status,
            fee: meta.fee,
            pre_balances: meta.pre_balances,
            post_balances: meta.post_balances,
            inner_instructions,
            log_messages: match meta.log_messages {
                OptionSerializer::Some(logs) => Some(logs),
                _ => None,
            },
            pre_token_balances,
            post_token_balances,
            rewards: match meta.rewards {
                OptionSerializer::Some(rewards) => Some(rewards),
                _ => None,
            },
            loaded_addresses,
            return_data,
            compute_units_consumed,
        })
    }
}



// impl From<UiInnerInstructions> for InnerInstructions {
//     fn from(ui_inner_instructions: UiInnerInstructions) -> Self {
//         Self {
//             index: ui_inner_instructions.index,
//             instructions: ui_inner_instructions
//                 .instructions
//                 .into_iter()
//                 .map(|ix| match ix {
//                     UiInstruction::Compiled(ui_compiled) => CompiledInstruction::from(ui_compiled),
//                     _ => panic!("Cannot convert from UiInstruction::Parsed to CompiledInstruction"),
//                 })
//                 .collect(),
//         }
//     }
// }

impl TryFrom<UiInnerInstructions> for InnerInstructions {
    type Error = ConversionError;

    fn try_from(ui_inner_instructions: UiInnerInstructions) -> Result<Self, Self::Error> {
        let instructions_result: Result<Vec<_>, _> = ui_inner_instructions
            .instructions
            .into_iter()
            .map(|ix| match ix {
                UiInstruction::Compiled(ui_compiled) => Ok(CompiledInstruction::from(ui_compiled)),
                _ => Err(ConversionError::UnsupportedInstructionFormat),
            })
            .collect();

        match instructions_result {
            Ok(instructions) => Ok(Self {
                index: ui_inner_instructions.index,
                instructions,
            }),
            Err(e) => Err(e),
        }
    }
}

impl From<UiCompiledInstruction> for CompiledInstruction {
    fn from(ui_compiled_instruction: UiCompiledInstruction) -> Self {
        Self {
            program_id_index: ui_compiled_instruction.program_id_index,
            accounts: ui_compiled_instruction.accounts,
            data: bs58::decode(ui_compiled_instruction.data).into_vec().unwrap(),
        }
    }
}

impl From<UiTransactionTokenBalance> for TransactionTokenBalance {
    fn from(token_balance: UiTransactionTokenBalance) -> Self {
        Self {
            account_index: token_balance.account_index,
            mint: token_balance.mint,
            ui_token_amount: token_balance.ui_token_amount,
            owner: match token_balance.owner {
                OptionSerializer::Some(owner) => owner,
                _ => String::new(),
            },
            program_id: match token_balance.program_id {
                OptionSerializer::Some(program_id) => program_id,
                _ => String::new(),
            },
        }
    }
}

#[derive(Debug)]
pub enum ConversionError {
    InvalidProgramId,
    InvalidData,
    UnsupportedInstructionFormat,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidProgramId => write!(f, "Invalid program id"),
            Self::InvalidData => write!(f, "Invalid data"),
            Self::UnsupportedInstructionFormat => write!(f, "Cannot convert from UiInstruction::Parsed to CompiledInstruction"),
        }
    }
}

impl Error for ConversionError {} // Implements the standard Error trait

impl TryFrom<UiTransactionReturnData> for TransactionReturnData {
    type Error = ConversionError;

    fn try_from(ui_return_data: UiTransactionReturnData) -> Result<Self, Self::Error> {
        let program_id = Pubkey::from_str(&ui_return_data.program_id)
            .map_err(|_| ConversionError::InvalidProgramId)?;

        let data = base64::decode(&ui_return_data.data.0)
            .map_err(|_| ConversionError::InvalidData)?;

        Ok(Self { program_id, data })
    }
}

// impl From<&UiLoadedAddresses> for Result<LoadedAddresses, ParsePubkeyError> {
//     fn from(ui_loaded_addresses: &UiLoadedAddresses) -> Self {
//         let writable: Result<Vec<Pubkey>, _> = ui_loaded_addresses
//             .writable
//             .iter()
//             .map(|s| Pubkey::from_str(s))
//             .collect();
//
//         let readonly: Result<Vec<Pubkey>, _> = ui_loaded_addresses
//             .readonly
//             .iter()
//             .map(|s| Pubkey::from_str(s))
//             .collect();
//
//         Ok(LoadedAddresses {
//             writable: writable?,
//             readonly: readonly?,
//         })
//     }
// }

// impl From<&UiLoadedAddresses> for LoadedAddresses {
//     fn from(ui_loaded_addresses: &UiLoadedAddresses) -> Self {
//         Self {
//             writable: ui_loaded_addresses
//                 .writable
//                 .iter()
//                 .filter_map(|s| s.parse().ok())
//                 .collect(),
//             readonly: ui_loaded_addresses
//                 .readonly
//                 .iter()
//                 .filter_map(|s| s.parse().ok())
//                 .collect(),
//         }
//     }
// }

impl TryFrom<&UiLoadedAddresses> for LoadedAddresses {
    type Error = ParsePubkeyError;

    fn try_from(ui_loaded_addresses: &UiLoadedAddresses) -> Result<Self, Self::Error> {
        let writable: Result<Vec<Pubkey>, _> = ui_loaded_addresses
            .writable
            .iter()
            .map(|s| Pubkey::from_str(s))
            .collect();

        let readonly: Result<Vec<Pubkey>, _> = ui_loaded_addresses
            .readonly
            .iter()
            .map(|s| Pubkey::from_str(s))
            .collect();

        Ok(Self {
            writable: writable?,
            readonly: readonly?,
        })
    }
}




impl TryFrom<ConfirmedBlock> for VersionedConfirmedBlock {
    type Error = ConvertBlockError;

    fn try_from(block: ConfirmedBlock) -> Result<Self, Self::Error> {
        let expected_transaction_count = block.transactions.len();

        let txs: Vec<_> = block
            .transactions
            .into_iter()
            .filter_map(|tx| match tx {
                TransactionWithStatusMeta::MissingMetadata(_) => None,
                TransactionWithStatusMeta::Complete(tx) => Some(tx),
            })
            .collect();

        if txs.len() != expected_transaction_count {
            return Err(ConvertBlockError::TransactionsMissing(
                expected_transaction_count,
                txs.len(),
            ));
        }

        Ok(Self {
            previous_blockhash: block.previous_blockhash,
            blockhash: block.blockhash,
            parent_slot: block.parent_slot,
            transactions: txs,
            rewards: block.rewards,
            block_time: block.block_time,
            block_height: block.block_height,
        })
    }
}

impl ConfirmedBlock {
    pub fn encode_with_options(
        self,
        encoding: UiTransactionEncoding,
        options: BlockEncodingOptions,
    ) -> Result<UiConfirmedBlock, EncodeError> {
        let (transactions, signatures) = match options.transaction_details {
            TransactionDetails::Full => (
                Some(
                    self.transactions
                        .into_iter()
                        .map(|tx_with_meta| {
                            tx_with_meta.encode(
                                encoding,
                                options.max_supported_transaction_version,
                                options.show_rewards,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                None,
            ),
            TransactionDetails::Signatures => (
                None,
                Some(
                    self.transactions
                        .into_iter()
                        .map(|tx_with_meta| tx_with_meta.transaction_signature().to_string())
                        .collect(),
                ),
            ),
            TransactionDetails::None => (None, None),
            TransactionDetails::Accounts => (
                Some(
                    self.transactions
                        .into_iter()
                        .map(|tx_with_meta| {
                            tx_with_meta.build_json_accounts(
                                options.max_supported_transaction_version,
                                options.show_rewards,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                None,
            ),
        };
        Ok(UiConfirmedBlock {
            previous_blockhash: self.previous_blockhash,
            blockhash: self.blockhash,
            parent_slot: self.parent_slot,
            transactions,
            signatures,
            rewards: if options.show_rewards {
                Some(self.rewards)
            } else {
                None
            },
            block_time: self.block_time,
            block_height: self.block_height,
        })
    }

    pub fn decode_with_options(
        ui_confirmed_block: UiConfirmedBlock,
        encoding: UiTransactionEncoding,
        options: BlockEncodingOptions,
    ) -> Result<Self, DecodeError> {
        let transactions = match options.transaction_details {
            TransactionDetails::Full => {
                let transactions = ui_confirmed_block
                    .transactions
                    .ok_or(DecodeError::InvalidEncoding)?
                    .into_iter()
                    .map(|encoded_tx_with_meta| {
                        TransactionWithStatusMeta::decode(encoded_tx_with_meta, encoding)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                transactions
            }
            TransactionDetails::Signatures => {
                let signatures = ui_confirmed_block
                    .signatures
                    .ok_or(DecodeError::InvalidEncoding)?;
                // Implement a method or mechanism to retrieve transactions using signatures
                return Err(DecodeError::NotImplemented);
            }
            TransactionDetails::None => Vec::new(),
            TransactionDetails::Accounts => {
                let transactions = ui_confirmed_block
                    .transactions
                    .ok_or(DecodeError::InvalidEncoding)?
                    .into_iter()
                    .map(|encoded_tx_with_meta| {
                        TransactionWithStatusMeta::decode(encoded_tx_with_meta, encoding)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                transactions
            }
        };

        Ok(ConfirmedBlock {
            previous_blockhash: ui_confirmed_block.previous_blockhash,
            blockhash: ui_confirmed_block.blockhash,
            parent_slot: ui_confirmed_block.parent_slot,
            transactions,
            rewards: ui_confirmed_block
                .rewards
                .unwrap_or_default(),
            block_time: ui_confirmed_block.block_time,
            block_height: ui_confirmed_block.block_height,
        })
    }
}

impl From<EncodedConfirmedBlock> for UiConfirmedBlock {
    fn from(block: EncodedConfirmedBlock) -> Self {
        Self {
            previous_blockhash: block.previous_blockhash,
            blockhash: block.blockhash,
            parent_slot: block.parent_slot,
            transactions: Some(block.transactions),
            signatures: None, // Set to None since it's not available in EncodedConfirmedBlock
            rewards: Some(block.rewards),
            block_time: block.block_time,
            block_height: block.block_height,
        }
    }
}