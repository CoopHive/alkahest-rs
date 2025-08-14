//! Example demonstrating the new contract address API
//!
//! This shows how to access contract addresses through the Has* traits,
//! which are only available when the corresponding modules are loaded.

use alkahest_rs::{
    DefaultAlkahestClient,
    extensions::{HasArbiters, HasAttestation, HasErc20, HasErc721},
    registry::{ArbitersContract, AttestationContract, Erc20Contract, Erc721Contract},
};
use alloy::signers::local::PrivateKeySigner;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Create a client with the default extensions (BaseExtensions)
    // This includes all standard modules
    let private_key: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let client = DefaultAlkahestClient::new(
        private_key,
        "https://eth-sepolia.g.alchemy.com/v2/your-api-key",
        None, // Use default config
    )
    .await?;

    // The address methods are now available through the Has* traits
    // These traits are automatically implemented for clients that have the corresponding modules

    // Access ERC20 contract addresses
    let erc20_escrow = client.erc20_address(Erc20Contract::EscrowObligation);
    let erc20_payment = client.erc20_address(Erc20Contract::PaymentObligation);
    let erc20_barter = client.erc20_address(Erc20Contract::BarterUtils);

    println!("ERC20 Contracts:");
    println!("  Escrow: {}", erc20_escrow);
    println!("  Payment: {}", erc20_payment);
    println!("  Barter: {}", erc20_barter);

    // Access ERC721 contract addresses
    let erc721_escrow = client.erc721_address(Erc721Contract::EscrowObligation);
    let erc721_eas = client.erc721_address(Erc721Contract::Eas);

    println!("\nERC721 Contracts:");
    println!("  Escrow: {}", erc721_escrow);
    println!("  EAS: {}", erc721_eas);

    // Access Attestation contract addresses
    let attestation_eas = client.attestation_address(AttestationContract::Eas);
    let attestation_registry = client.attestation_address(AttestationContract::EasSchemaRegistry);

    println!("\nAttestation Contracts:");
    println!("  EAS: {}", attestation_eas);
    println!("  Schema Registry: {}", attestation_registry);

    // Access Arbiter contract addresses
    let trusted_party = client.arbiters_address(ArbitersContract::TrustedPartyArbiter);
    let trivial = client.arbiters_address(ArbitersContract::TrivialArbiter);

    println!("\nArbiter Contracts:");
    println!("  Trusted Party: {}", trusted_party);
    println!("  Trivial: {}", trivial);

    // Alternative: You can also access the module directly and get addresses from there
    let erc20_module = client.erc20();
    let direct_escrow = erc20_module.addresses.escrow_obligation;

    // This should be the same as using the address method
    assert_eq!(erc20_escrow, direct_escrow);
    println!("\n✅ Direct module access gives same address");

    // The address methods use the ContractModule trait under the hood
    use alkahest_rs::registry::ContractModule;
    let via_trait = erc20_module.address(Erc20Contract::EscrowObligation);
    assert_eq!(erc20_escrow, via_trait);
    println!("✅ ContractModule trait also gives same address");

    Ok(())
}
