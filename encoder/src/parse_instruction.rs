
use {
    // crate::{
    //     // pubkey::Pubkey,
    //     // instruction::CompiledInstruction,
    //     // account_keys::AccountKeys,
    //     // parse_address_lookup_table::parse_address_lookup_table,
    // },
    solana_sdk::{
        instruction::CompiledInstruction,
        message::AccountKeys,
        pubkey::Pubkey
    },
    serde_derive::{Serialize, Deserialize},
    serde_json::Value,
    thiserror::Error,
    inflector::Inflector,
    lazy_static::lazy_static,
    std::{
        collections::HashMap,
        str::{from_utf8, Utf8Error},
    },
};

lazy_static! {
    // static ref ADDRESS_LOOKUP_PROGRAM_ID: Pubkey = solana_address_lookup_table_program::id();
    // static ref ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey = spl_associated_token_id();
    // static ref BPF_LOADER_PROGRAM_ID: Pubkey = solana_sdk::bpf_loader::id();
    // static ref BPF_UPGRADEABLE_LOADER_PROGRAM_ID: Pubkey = solana_sdk::bpf_loader_upgradeable::id();
    // static ref MEMO_V1_PROGRAM_ID: Pubkey = spl_memo_id_v1();
    // static ref MEMO_V3_PROGRAM_ID: Pubkey = spl_memo_id_v3();
    // static ref STAKE_PROGRAM_ID: Pubkey = stake::program::id();
    // static ref SYSTEM_PROGRAM_ID: Pubkey = system_program::id();
    // static ref VOTE_PROGRAM_ID: Pubkey = vote::program::id();
    static ref PARSABLE_PROGRAM_IDS: HashMap<Pubkey, ParsableProgram> = {
        let m = HashMap::new();
        // let mut m = HashMap::new();
        // m.insert(
        //     *ADDRESS_LOOKUP_PROGRAM_ID,
        //     ParsableProgram::AddressLookupTable,
        // );
        // m.insert(
        //     *ASSOCIATED_TOKEN_PROGRAM_ID,
        //     ParsableProgram::SplAssociatedTokenAccount,
        // );
        // m.insert(*MEMO_V1_PROGRAM_ID, ParsableProgram::SplMemo);
        // m.insert(*MEMO_V3_PROGRAM_ID, ParsableProgram::SplMemo);
        // for spl_token_id in spl_token_ids() {
        //     m.insert(spl_token_id, ParsableProgram::SplToken);
        // }
        // m.insert(*BPF_LOADER_PROGRAM_ID, ParsableProgram::BpfLoader);
        // m.insert(
        //     *BPF_UPGRADEABLE_LOADER_PROGRAM_ID,
        //     ParsableProgram::BpfUpgradeableLoader,
        // );
        // m.insert(*STAKE_PROGRAM_ID, ParsableProgram::Stake);
        // m.insert(*SYSTEM_PROGRAM_ID, ParsableProgram::System);
        // m.insert(*VOTE_PROGRAM_ID, ParsableProgram::Vote);
        m
    };
}

#[derive(Error, Debug)]
pub enum ParseInstructionError {
    #[error("{0:?} instruction not parsable")]
    InstructionNotParsable(ParsableProgram),

    // #[error("{0:?} instruction key mismatch")]
    // InstructionKeyMismatch(ParsableProgram),

    #[error("Program not parsable")]
    ProgramNotParsable,

    #[error("Internal error, please report")]
    SerdeJsonError(#[from] serde_json::error::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ParsedInstruction {
    pub program: String,
    pub program_id: String,
    pub parsed: Value,
    pub stack_height: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ParsedInstructionEnum {
    #[serde(rename = "type")]
    pub instruction_type: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub info: Value,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ParsableProgram {
    // AddressLookupTable,
    // SplAssociatedTokenAccount,
    SplMemo,
    // SplToken,
    // BpfLoader,
    // BpfUpgradeableLoader,
    // Stake,
    // System,
    // Vote,
}

pub fn parse(
    program_id: &Pubkey,
    instruction: &CompiledInstruction,
    _account_keys: &AccountKeys,
    stack_height: Option<u32>,
) -> Result<ParsedInstruction, ParseInstructionError> {
    let program_name = PARSABLE_PROGRAM_IDS
        .get(program_id)
        .ok_or(ParseInstructionError::ProgramNotParsable)?;
    let parsed_json = match program_name {
        // ParsableProgram::AddressLookupTable => {
        //     serde_json::to_value(parse_address_lookup_table(instruction, account_keys)?)?
        // }
        // ParsableProgram::SplAssociatedTokenAccount => {
        //     serde_json::to_value(parse_associated_token(instruction, account_keys)?)?
        // }
        ParsableProgram::SplMemo => parse_memo(instruction)?,
        // ParsableProgram::SplToken => serde_json::to_value(parse_token(instruction, account_keys)?)?,
        // ParsableProgram::BpfLoader => {
        //     serde_json::to_value(parse_bpf_loader(instruction, account_keys)?)?
        // }
        // ParsableProgram::BpfUpgradeableLoader => {
        //     serde_json::to_value(parse_bpf_upgradeable_loader(instruction, account_keys)?)?
        // }
        // ParsableProgram::Stake => serde_json::to_value(parse_stake(instruction, account_keys)?)?,
        // ParsableProgram::System => serde_json::to_value(parse_system(instruction, account_keys)?)?,
        // ParsableProgram::Vote => serde_json::to_value(parse_vote(instruction, account_keys)?)?,
    };
    Ok(ParsedInstruction {
        program: format!("{:?}", program_name).to_kebab_case(),
        program_id: program_id.to_string(),
        parsed: parsed_json,
        stack_height,
    })
}

fn parse_memo(instruction: &CompiledInstruction) -> Result<Value, ParseInstructionError> {
    parse_memo_data(&instruction.data)
        .map(Value::String)
        .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::SplMemo))
}

pub fn parse_memo_data(data: &[u8]) -> Result<String, Utf8Error> {
    from_utf8(data).map(|s| s.to_string())
}