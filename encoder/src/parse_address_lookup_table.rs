
use {
    crate::{
        parse_instruction::{ParseInstructionError, ParsableProgram, ParsedInstructionEnum},
        // instruction::CompiledInstruction,
        // account_keys::AccountKeys,
    },
    bincode::deserialize,
    solana_sdk::{instruction::CompiledInstruction, message::AccountKeys},
};

pub fn parse_address_lookup_table(
    instruction: &CompiledInstruction,
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    let address_lookup_table_instruction: ProgramInstruction = deserialize(&instruction.data)
        .map_err(|_| {
            ParseInstructionError::InstructionNotParsable(ParsableProgram::AddressLookupTable)
        })?;
    match instruction.accounts.iter().max() {
        Some(index) if (*index as usize) < account_keys.len() => {}
        _ => {
            // Runtime should prevent this from ever happening
            return Err(ParseInstructionError::InstructionKeyMismatch(
                ParsableProgram::AddressLookupTable,
            ));
        }
    }
    match address_lookup_table_instruction {
        ProgramInstruction::CreateLookupTable {
            recent_slot,
            bump_seed,
        } => {
            check_num_address_lookup_table_accounts(&instruction.accounts, 4)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "createLookupTable".to_string(),
                info: json!({
                    "lookupTableAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "lookupTableAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                    "payerAccount": account_keys[instruction.accounts[2] as usize].to_string(),
                    "systemProgram": account_keys[instruction.accounts[3] as usize].to_string(),
                    "recentSlot": recent_slot,
                    "bumpSeed": bump_seed,
                }),
            })
        }
        ProgramInstruction::FreezeLookupTable => {
            check_num_address_lookup_table_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "freezeLookupTable".to_string(),
                info: json!({
                    "lookupTableAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "lookupTableAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                }),
            })
        }
        ProgramInstruction::ExtendLookupTable { new_addresses } => {
            check_num_address_lookup_table_accounts(&instruction.accounts, 2)?;
            let new_addresses: Vec<String> = new_addresses
                .into_iter()
                .map(|address| address.to_string())
                .collect();
            let mut value = json!({
                "lookupTableAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                "lookupTableAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                "newAddresses": new_addresses,
            });
            let map = value.as_object_mut().unwrap();
            if instruction.accounts.len() >= 4 {
                map.insert(
                    "payerAccount".to_string(),
                    json!(account_keys[instruction.accounts[2] as usize].to_string()),
                );
                map.insert(
                    "systemProgram".to_string(),
                    json!(account_keys[instruction.accounts[3] as usize].to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "extendLookupTable".to_string(),
                info: value,
            })
        }
        ProgramInstruction::DeactivateLookupTable => {
            check_num_address_lookup_table_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "deactivateLookupTable".to_string(),
                info: json!({
                    "lookupTableAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "lookupTableAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                }),
            })
        }
        ProgramInstruction::CloseLookupTable => {
            check_num_address_lookup_table_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "closeLookupTable".to_string(),
                info: json!({
                    "lookupTableAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "lookupTableAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                    "recipient": account_keys[instruction.accounts[2] as usize].to_string(),
                }),
            })
        }
    }
}

fn check_num_address_lookup_table_accounts(
    accounts: &[u8],
    num: usize,
) -> Result<(), ParseInstructionError> {
    check_num_accounts(accounts, num, ParsableProgram::AddressLookupTable)
}