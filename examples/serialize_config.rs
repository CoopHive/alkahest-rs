use alkahest_rs::{
    DefaultExtensionConfig,
    addresses::{BASE_SEPOLIA_ADDRESSES, FILECOIN_CALIBRATION_ADDRESSES},
};
use serde_json;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Alkahest Config Serialization Example ===\n");

    // 1. Create a default config (uses Base Sepolia addresses)
    let default_config = DefaultExtensionConfig::default();
    println!("Created default config using Base Sepolia addresses");
    println!("EAS Address: {}", default_config.arbiters_addresses.eas);
    println!(
        "Barter Utils: {}\n",
        default_config.erc20_addresses.barter_utils
    );

    // 2. Serialize to JSON string
    let json_string = serde_json::to_string_pretty(&default_config)?;
    println!("Serialized to JSON:");
    println!("{}", &json_string[..200]); // Print first 200 chars
    println!("...\n");

    // 3. Save to file
    let file_path = "config.json";
    fs::write(file_path, &json_string)?;
    println!("Saved config to {}", file_path);

    // 4. Load from file
    let loaded_json = fs::read_to_string(file_path)?;
    let loaded_config: DefaultExtensionConfig = serde_json::from_str(&loaded_json)?;
    println!("Loaded config from {}", file_path);
    println!(
        "Loaded EAS Address: {}",
        loaded_config.arbiters_addresses.eas
    );
    println!(
        "Config matches original: {}\n",
        loaded_config.arbiters_addresses.eas == default_config.arbiters_addresses.eas
    );

    // 5. Create a custom config mixing different network addresses
    let custom_config = DefaultExtensionConfig {
        arbiters_addresses: FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses.clone(),
        erc20_addresses: BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone(),
        ..FILECOIN_CALIBRATION_ADDRESSES
    };
    println!("Created custom config mixing Filecoin and Base Sepolia addresses");
    println!(
        "Arbiters EAS (Filecoin): {}",
        custom_config.arbiters_addresses.eas
    );
    println!(
        "ERC20 EAS (Base Sepolia): {}",
        custom_config.erc20_addresses.eas
    );

    // 6. Serialize custom config
    let custom_json = serde_json::to_string_pretty(&custom_config)?;
    fs::write("custom_config.json", &custom_json)?;
    println!("\nSaved custom config to custom_config.json");

    // 7. Demonstrate round-trip serialization
    let round_trip_json = serde_json::to_string(&custom_config)?;
    let round_trip_config: DefaultExtensionConfig = serde_json::from_str(&round_trip_json)?;
    println!("\nRound-trip serialization test:");
    println!(
        "Config preserved after round-trip: {}",
        round_trip_config.arbiters_addresses.eas == custom_config.arbiters_addresses.eas
    );

    // Clean up
    fs::remove_file(file_path).ok();
    fs::remove_file("custom_config.json").ok();
    println!("\nCleaned up temporary files");

    println!("\n=== Example completed successfully ===");
    Ok(())
}
