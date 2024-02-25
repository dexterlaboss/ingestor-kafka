
use {
    // crate::{
    //     account_decoder::StringDecimals,
    // }
    solana_account_decoder::StringDecimals,
};

pub fn real_number_string(amount: u64, decimals: u8) -> StringDecimals {
    let decimals = decimals as usize;
    if decimals > 0 {
        // Left-pad zeros to decimals + 1, so we at least have an integer zero
        let mut s = format!("{:01$}", amount, decimals + 1);
        // Add the decimal point (Sorry, "," locales!)
        s.insert(s.len() - decimals, '.');
        s
    } else {
        amount.to_string()
    }
}

pub fn real_number_string_trimmed(amount: u64, decimals: u8) -> StringDecimals {
    let mut s = real_number_string(amount, decimals);
    if decimals > 0 {
        let zeros_trimmed = s.trim_end_matches('0');
        s = zeros_trimmed.trim_end_matches('.').to_string();
    }
    s
}