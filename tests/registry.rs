use alkahest_rs::{
    extensions::{
        HasArbiters, HasAttestation, HasErc20, HasErc721, HasErc1155, HasStringObligation,
        HasTokenBundle,
    },
    registry::{
        ArbitersContract, AttestationContract, Erc20Contract, Erc721Contract, Erc1155Contract,
        StringObligationContract, TokenBundleContract,
    },
    utils::setup_test_environment,
};

#[tokio::test]
async fn test_erc20_addresses() -> eyre::Result<()> {
    // Setup the complete test environment with deployed contracts
    let context = setup_test_environment().await?;

    // Test getting various ERC20 contract addresses using the new API
    let eas_addr = context.alice_client.erc20_address(Erc20Contract::Eas);
    let barter_utils_addr = context
        .alice_client
        .erc20_address(Erc20Contract::BarterUtils);
    let escrow_addr = context
        .alice_client
        .erc20_address(Erc20Contract::EscrowObligation);
    let payment_addr = context
        .alice_client
        .erc20_address(Erc20Contract::PaymentObligation);

    // Verify addresses match what's in the test context
    assert_eq!(eas_addr, context.addresses.erc20_addresses.eas);
    assert_eq!(
        barter_utils_addr,
        context.addresses.erc20_addresses.barter_utils
    );
    assert_eq!(
        escrow_addr,
        context.addresses.erc20_addresses.escrow_obligation
    );
    assert_eq!(
        payment_addr,
        context.addresses.erc20_addresses.payment_obligation
    );

    println!("✅ ERC20 addresses from test environment match!");
    println!("  EAS: {}", eas_addr);
    println!("  BarterUtils: {}", barter_utils_addr);
    println!("  EscrowObligation: {}", escrow_addr);
    println!("  PaymentObligation: {}", payment_addr);

    Ok(())
}

#[tokio::test]
async fn test_all_module_addresses() -> eyre::Result<()> {
    let context = setup_test_environment().await?;
    let client = &context.alice_client;

    // Test ERC20 addresses
    let erc20_escrow = client.erc20_address(Erc20Contract::EscrowObligation);
    assert_eq!(
        erc20_escrow,
        context.addresses.erc20_addresses.escrow_obligation
    );
    println!("ERC20 Escrow: {}", erc20_escrow);

    // Test ERC721 addresses
    let erc721_barter = client.erc721_address(Erc721Contract::BarterUtils);
    let erc721_payment = client.erc721_address(Erc721Contract::PaymentObligation);
    assert_eq!(
        erc721_barter,
        context.addresses.erc721_addresses.barter_utils
    );
    assert_eq!(
        erc721_payment,
        context.addresses.erc721_addresses.payment_obligation
    );
    println!("ERC721 Barter: {}", erc721_barter);
    println!("ERC721 Payment: {}", erc721_payment);

    // Test ERC1155 addresses
    let erc1155_escrow = client.erc1155_address(Erc1155Contract::EscrowObligation);
    let erc1155_payment = client.erc1155_address(Erc1155Contract::PaymentObligation);
    assert_eq!(
        erc1155_escrow,
        context.addresses.erc1155_addresses.escrow_obligation
    );
    assert_eq!(
        erc1155_payment,
        context.addresses.erc1155_addresses.payment_obligation
    );
    println!("ERC1155 Escrow: {}", erc1155_escrow);
    println!("ERC1155 Payment: {}", erc1155_payment);

    // Test TokenBundle addresses
    let bundle_barter = client.token_bundle_address(TokenBundleContract::BarterUtils);
    let bundle_escrow = client.token_bundle_address(TokenBundleContract::EscrowObligation);
    assert_eq!(
        bundle_barter,
        context.addresses.token_bundle_addresses.barter_utils
    );
    assert_eq!(
        bundle_escrow,
        context.addresses.token_bundle_addresses.escrow_obligation
    );
    println!("TokenBundle Barter: {}", bundle_barter);
    println!("TokenBundle Escrow: {}", bundle_escrow);

    // Test Attestation addresses
    let attestation_eas = client.attestation_address(AttestationContract::Eas);
    let attestation_registry = client.attestation_address(AttestationContract::EasSchemaRegistry);
    assert_eq!(attestation_eas, context.addresses.attestation_addresses.eas);
    assert_eq!(
        attestation_registry,
        context.addresses.attestation_addresses.eas_schema_registry
    );
    println!("Attestation EAS: {}", attestation_eas);
    println!("Attestation Registry: {}", attestation_registry);

    // Test StringObligation addresses
    let string_obligation = client.string_obligation_address(StringObligationContract::Obligation);
    assert_eq!(
        string_obligation,
        context.addresses.string_obligation_addresses.obligation
    );
    println!("String Obligation: {}", string_obligation);

    // Test Arbiters addresses
    let trusted_party = client.arbiters_address(ArbitersContract::TrustedPartyArbiter);
    let trivial = client.arbiters_address(ArbitersContract::TrivialArbiter);
    assert_eq!(
        trusted_party,
        context.addresses.arbiters_addresses.trusted_party_arbiter
    );
    assert_eq!(
        trivial,
        context.addresses.arbiters_addresses.trivial_arbiter
    );
    println!("Trusted Party Arbiter: {}", trusted_party);
    println!("Trivial Arbiter: {}", trivial);

    println!("\n✅ All module addresses retrieved successfully from test environment!");

    Ok(())
}

#[tokio::test]
async fn test_address_consistency_between_clients() -> eyre::Result<()> {
    let context = setup_test_environment().await?;

    // Both Alice and Bob clients should see the same contract addresses
    let alice_escrow = context
        .alice_client
        .erc20_address(Erc20Contract::EscrowObligation);
    let bob_escrow = context
        .bob_client
        .erc20_address(Erc20Contract::EscrowObligation);

    assert_eq!(alice_escrow, bob_escrow);

    let alice_attestation = context
        .alice_client
        .attestation_address(AttestationContract::BarterUtils);
    let bob_attestation = context
        .bob_client
        .attestation_address(AttestationContract::BarterUtils);

    assert_eq!(alice_attestation, bob_attestation);

    println!("✅ Contract addresses are consistent between different clients");

    Ok(())
}

#[tokio::test]
async fn test_contract_enum_ergonomics() -> eyre::Result<()> {
    use ArbitersContract::*;
    use Erc20Contract::*;
    use Erc721Contract as E721;

    let context = setup_test_environment().await?;
    let client = &context.alice_client;

    // Demonstrate ergonomic use of enum variants
    let addresses = vec![
        ("ERC20 EAS", client.erc20_address(Erc20Contract::Eas)),
        ("ERC20 Barter", client.erc20_address(BarterUtils)),
        ("ERC20 Escrow", client.erc20_address(EscrowObligation)),
        ("ERC20 Payment", client.erc20_address(PaymentObligation)),
    ];

    for (name, addr) in &addresses {
        println!("{}: {}", name, addr);
        assert_ne!(*addr, alloy::primitives::Address::ZERO);
    }

    // Can also use aliased imports for clarity
    let erc721_escrow = client.erc721_address(E721::EscrowObligation);
    println!("ERC721 Escrow: {}", erc721_escrow);

    // Direct enum usage for arbiters
    let arbiter_addrs = vec![
        client.arbiters_address(TrustedPartyArbiter),
        client.arbiters_address(TrivialArbiter),
        client.arbiters_address(TrustedOracleArbiter),
    ];

    for addr in &arbiter_addrs {
        assert_ne!(*addr, alloy::primitives::Address::ZERO);
    }

    println!("✅ Contract enum variants are ergonomic to use");

    Ok(())
}

#[tokio::test]
async fn test_direct_client_access_comparison() -> eyre::Result<()> {
    let context = setup_test_environment().await?;
    let client = &context.alice_client;

    // New API
    let escrow_via_api = client.erc20_address(Erc20Contract::EscrowObligation);

    // Direct access to client addresses (old way)
    let escrow_direct = client.erc20().addresses.escrow_obligation;

    // Both should give the same result
    assert_eq!(escrow_via_api, escrow_direct);

    // Same for other modules
    let attestation_via_api = client.attestation_address(AttestationContract::BarterUtils);
    let attestation_direct = client.attestation().addresses.barter_utils;
    assert_eq!(attestation_via_api, attestation_direct);

    let arbiters_via_api = client.arbiters_address(ArbitersContract::TrivialArbiter);
    let arbiters_direct = client.arbiters().addresses.trivial_arbiter;
    assert_eq!(arbiters_via_api, arbiters_direct);

    println!("✅ New API produces same addresses as direct access");

    Ok(())
}

#[tokio::test]
async fn test_contract_instance_creation() -> eyre::Result<()> {
    use alkahest_rs::contracts;

    let context = setup_test_environment().await?;
    let client = &context.alice_client;

    // Get address using the new API
    let escrow_addr = client.erc20_address(Erc20Contract::EscrowObligation);

    // Create contract instance using the address
    let escrow_contract =
        contracts::ERC20EscrowObligation::new(escrow_addr, client.wallet_provider.clone());

    // Verify the contract has the correct address
    assert_eq!(*escrow_contract.address(), escrow_addr);

    // Similarly for other contract types
    let barter_addr = client.erc721_address(Erc721Contract::BarterUtils);
    let barter_contract =
        contracts::ERC721BarterUtils::new(barter_addr, client.wallet_provider.clone());
    assert_eq!(*barter_contract.address(), barter_addr);

    println!("✅ Contract instances can be created from retrieved addresses");

    Ok(())
}
