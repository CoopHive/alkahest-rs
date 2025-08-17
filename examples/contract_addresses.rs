//! Example demonstrating the new contract address API
//!
//! This example shows how to use the new structured approach to accessing
//! contract addresses in the Alkahest SDK.

use alkahest_rs::{
    DefaultAlkahestClient, contracts,
    extensions::{HasArbiters, HasErc20, HasErc721},
    registry::{ArbitersContract, Erc20Contract, Erc721Contract},
};
use alloy::signers::local::PrivateKeySigner;
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup client with your private key and RPC URL
    let private_key: PrivateKeySigner = std::env::var("PRIVKEY_ALICE")
        .unwrap_or_else(|_| {
            // Default test key - DO NOT USE IN PRODUCTION
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string()
        })
        .parse()?;

    let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string());

    // Create client with default configuration (Base Sepolia addresses)
    let client =
        DefaultAlkahestClient::with_base_extensions(private_key.clone(), rpc_url, None).await?;

    println!("🔍 Contract Address Examples\n");

    // ==========================================================================
    // Method 1: Using the new type-safe address getter methods
    // ==========================================================================
    println!("Method 1: Type-safe address getters");
    println!("────────────────────────────────────");

    // Get ERC20 contract addresses
    let erc20_escrow = client.erc20_address(Erc20Contract::EscrowObligation);
    let erc20_payment = client.erc20_address(Erc20Contract::PaymentObligation);
    let erc20_barter = client.erc20_address(Erc20Contract::BarterUtils);

    println!("ERC20 Contracts:");
    println!("  Escrow Obligation:  {}", erc20_escrow);
    println!("  Payment Obligation: {}", erc20_payment);
    println!("  Barter Utils:       {}", erc20_barter);

    // Get ERC721 contract addresses
    let erc721_escrow = client.erc721_address(Erc721Contract::EscrowObligation);

    println!("\nERC721 Contracts:");
    println!("  Escrow Obligation:  {}", erc721_escrow);

    // Get Arbiter contract addresses
    let trusted_party = client.arbiters_address(ArbitersContract::TrustedPartyArbiter);
    let trivial = client.arbiters_address(ArbitersContract::TrivialArbiter);

    println!("\nArbiter Contracts:");
    println!("  Trusted Party:      {}", trusted_party);
    println!("  Trivial:            {}", trivial);

    // ==========================================================================
    // Method 2: Using enum imports for cleaner code
    // ==========================================================================
    println!("\n\nMethod 2: Using enum imports");
    println!("────────────────────────────────────");

    // Import enum variants for cleaner code
    use Erc20Contract::*;

    let addresses = vec![
        ("EAS", client.erc20_address(Eas)),
        ("Barter Utils", client.erc20_address(BarterUtils)),
        ("Escrow", client.erc20_address(EscrowObligation)),
        ("Payment", client.erc20_address(PaymentObligation)),
    ];

    println!("ERC20 Addresses:");
    for (name, addr) in addresses {
        println!("  {:<15} {}", format!("{}:", name), addr);
    }

    // ==========================================================================
    // Method 3: Direct access (old way, still supported)
    // ==========================================================================
    println!("\n\nMethod 3: Direct access (legacy)");
    println!("────────────────────────────────────");

    // You can still access addresses directly through the client
    let erc20_client = client.erc20();
    let direct_escrow = erc20_client.addresses.escrow_obligation;

    println!("Direct access to escrow: {}", direct_escrow);
    println!("Same as new API:         {}", erc20_escrow == direct_escrow);

    // ==========================================================================
    // Creating contract instances from addresses
    // ==========================================================================
    println!("\n\nCreating Contract Instances");
    println!("────────────────────────────────────");

    // Get an address using the new API
    let escrow_addr = client.erc20_address(Erc20Contract::EscrowObligation);

    // Create a contract instance for direct interaction
    let escrow_contract =
        contracts::ERC20EscrowObligation::new(escrow_addr, client.wallet_provider.clone());

    println!(
        "Created ERC20EscrowObligation contract at: {}",
        escrow_contract.address()
    );

    // Similarly for other contract types
    let barter_addr = client.erc721_address(Erc721Contract::BarterUtils);
    let barter_contract =
        contracts::ERC721BarterUtils::new(barter_addr, client.wallet_provider.clone());

    println!(
        "Created ERC721BarterUtils contract at:     {}",
        barter_contract.address()
    );

    // ==========================================================================
    // Using with custom network configuration
    // ==========================================================================
    println!("\n\nCustom Network Configuration");
    println!("────────────────────────────────────");

    // You can use different network configurations
    use alkahest_rs::addresses::FILECOIN_CALIBRATION_ADDRESSES;

    let filecoin_client = DefaultAlkahestClient::with_base_extensions(
        private_key,
        "http://localhost:8545", // Would be actual Filecoin RPC in production
        Some(FILECOIN_CALIBRATION_ADDRESSES),
    )
    .await?;

    let filecoin_escrow = filecoin_client.erc20_address(Erc20Contract::EscrowObligation);
    println!("Filecoin Calibration ERC20 Escrow: {}", filecoin_escrow);

    // ==========================================================================
    // Benefits of the new API
    // ==========================================================================
    println!("\n\n✨ Benefits of the New API:");
    println!("────────────────────────────────────");
    println!("1. Type-safe: Can't request invalid contracts for a module");
    println!("2. Discoverable: IDE autocomplete shows available contracts");
    println!("3. Organized: Contracts grouped by module (ERC20, ERC721, etc.)");
    println!("4. Flexible: Works with any extension configuration");
    println!("5. Backward compatible: Old direct access still works");

    Ok(())
}
