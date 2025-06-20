use alkahest_rs::utils::setup_test_environment;
use alloy::providers::Provider;
use eyre::Result;

#[tokio::test]
async fn test_arbiters_deployment() -> Result<()> {
    let test_context = setup_test_environment().await?;

    // Verify that arbiters addresses are properly set
    let arbiters = test_context.addresses.arbiters_addresses.as_ref().unwrap();

    // Basic arbiters
    assert_ne!(
        arbiters.trusted_party_arbiter,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(arbiters.trivial_arbiter, alloy::primitives::Address::ZERO);
    assert_ne!(
        arbiters.specific_attestation_arbiter,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.trusted_oracle_arbiter,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.intrinsics_arbiter,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.intrinsics_arbiter_2,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(arbiters.any_arbiter, alloy::primitives::Address::ZERO);
    assert_ne!(arbiters.all_arbiter, alloy::primitives::Address::ZERO);
    assert_ne!(arbiters.uid_arbiter, alloy::primitives::Address::ZERO);
    assert_ne!(arbiters.recipient_arbiter, alloy::primitives::Address::ZERO);

    // New arbiters
    assert_ne!(arbiters.not_arbiter, alloy::primitives::Address::ZERO);
    assert_ne!(
        arbiters.attester_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.attester_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );

    // Expiration time arbiters
    assert_ne!(
        arbiters.expiration_time_after_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.expiration_time_before_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.expiration_time_equal_arbiter_composing,
        alloy::primitives::Address::ZERO
    );

    // Extended arbiters
    assert_ne!(
        arbiters.recipient_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.ref_uid_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.revocable_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.schema_arbiter_composing,
        alloy::primitives::Address::ZERO
    );

    // Time arbiters
    assert_ne!(
        arbiters.time_after_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.time_before_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.time_equal_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.uid_arbiter_composing,
        alloy::primitives::Address::ZERO
    );

    // Payment fulfillment arbiters
    assert_ne!(
        arbiters.erc20_payment_fulfillment_arbiter,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.erc721_payment_fulfillment_arbiter,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.erc1155_payment_fulfillment_arbiter,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.token_bundle_payment_fulfillment_arbiter,
        alloy::primitives::Address::ZERO
    );

    // Non-composing arbiters
    assert_ne!(
        arbiters.expiration_time_after_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.expiration_time_before_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.expiration_time_equal_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.recipient_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.ref_uid_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.revocable_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.schema_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.time_after_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.time_before_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.time_equal_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.uid_arbiter_non_composing,
        alloy::primitives::Address::ZERO
    );

    // Confirmation arbiters
    assert_ne!(
        arbiters.confirmation_arbiter,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.confirmation_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.revocable_confirmation_arbiter,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.revocable_confirmation_arbiter_composing,
        alloy::primitives::Address::ZERO
    );
    assert_ne!(
        arbiters.unrevocable_confirmation_arbiter,
        alloy::primitives::Address::ZERO
    );

    println!("All arbiters deployed successfully!");
    println!("NotArbiter address: {:?}", arbiters.not_arbiter);
    println!(
        "AttesterArbiterComposing address: {:?}",
        arbiters.attester_arbiter_composing
    );
    println!(
        "ERC20PaymentFulfillmentArbiter address: {:?}",
        arbiters.erc20_payment_fulfillment_arbiter
    );
    println!(
        "ConfirmationArbiter address: {:?}",
        arbiters.confirmation_arbiter
    );

    Ok(())
}

#[tokio::test]
async fn test_arbiter_basic_functionality() -> Result<()> {
    let test_context = setup_test_environment().await?;
    let arbiters = test_context.addresses.arbiters_addresses.as_ref().unwrap();

    let provider = &test_context.god_provider;

    // Basic arbiters
    let code = provider.get_code_at(arbiters.trusted_party_arbiter).await?;
    assert!(
        !code.is_empty(),
        "TrustedPartyArbiter should have code deployed"
    );

    let code = provider.get_code_at(arbiters.trivial_arbiter).await?;
    assert!(!code.is_empty(), "TrivialArbiter should have code deployed");

    let code = provider
        .get_code_at(arbiters.specific_attestation_arbiter)
        .await?;
    assert!(
        !code.is_empty(),
        "SpecificAttestationArbiter should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.trusted_oracle_arbiter)
        .await?;
    assert!(
        !code.is_empty(),
        "TrustedOracleArbiter should have code deployed"
    );

    let code = provider.get_code_at(arbiters.intrinsics_arbiter).await?;
    assert!(
        !code.is_empty(),
        "IntrinsicsArbiter should have code deployed"
    );

    let code = provider.get_code_at(arbiters.intrinsics_arbiter_2).await?;
    assert!(
        !code.is_empty(),
        "IntrinsicsArbiter2 should have code deployed"
    );

    let code = provider.get_code_at(arbiters.any_arbiter).await?;
    assert!(!code.is_empty(), "AnyArbiter should have code deployed");

    let code = provider.get_code_at(arbiters.all_arbiter).await?;
    assert!(!code.is_empty(), "AllArbiter should have code deployed");

    let code = provider.get_code_at(arbiters.uid_arbiter).await?;
    assert!(!code.is_empty(), "UidArbiter should have code deployed");

    let code = provider.get_code_at(arbiters.recipient_arbiter).await?;
    assert!(
        !code.is_empty(),
        "RecipientArbiter should have code deployed"
    );

    // New arbiters
    let code = provider.get_code_at(arbiters.not_arbiter).await?;
    assert!(!code.is_empty(), "NotArbiter should have code deployed");

    let code = provider
        .get_code_at(arbiters.attester_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "AttesterArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.attester_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "AttesterArbiterNonComposing should have code deployed"
    );

    // Expiration time arbiters (composing)
    let code = provider
        .get_code_at(arbiters.expiration_time_after_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "ExpirationTimeAfterArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.expiration_time_before_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "ExpirationTimeBeforeArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.expiration_time_equal_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "ExpirationTimeEqualArbiterComposing should have code deployed"
    );

    // Extended arbiters (composing)
    let code = provider
        .get_code_at(arbiters.recipient_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "RecipientArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.ref_uid_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "RefUidArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.revocable_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "RevocableArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.schema_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "SchemaArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.time_after_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "TimeAfterArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.time_before_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "TimeBeforeArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.time_equal_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "TimeEqualArbiterComposing should have code deployed"
    );

    let code = provider.get_code_at(arbiters.uid_arbiter_composing).await?;
    assert!(
        !code.is_empty(),
        "UidArbiterComposing should have code deployed"
    );

    // Payment fulfillment arbiters
    let code = provider
        .get_code_at(arbiters.erc20_payment_fulfillment_arbiter)
        .await?;
    assert!(
        !code.is_empty(),
        "ERC20PaymentFulfillmentArbiter should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.erc721_payment_fulfillment_arbiter)
        .await?;
    assert!(
        !code.is_empty(),
        "ERC721PaymentFulfillmentArbiter should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.erc1155_payment_fulfillment_arbiter)
        .await?;
    assert!(
        !code.is_empty(),
        "ERC1155PaymentFulfillmentArbiter should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.token_bundle_payment_fulfillment_arbiter)
        .await?;
    assert!(
        !code.is_empty(),
        "TokenBundlePaymentFulfillmentArbiter should have code deployed"
    );

    // Non-composing arbiters
    let code = provider
        .get_code_at(arbiters.expiration_time_after_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "ExpirationTimeAfterArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.expiration_time_before_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "ExpirationTimeBeforeArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.expiration_time_equal_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "ExpirationTimeEqualArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.recipient_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "RecipientArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.ref_uid_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "RefUidArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.revocable_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "RevocableArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.schema_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "SchemaArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.time_after_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "TimeAfterArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.time_before_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "TimeBeforeArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.time_equal_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "TimeEqualArbiterNonComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.uid_arbiter_non_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "UidArbiterNonComposing should have code deployed"
    );

    // Confirmation arbiters
    let code = provider.get_code_at(arbiters.confirmation_arbiter).await?;
    assert!(
        !code.is_empty(),
        "ConfirmationArbiter should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.confirmation_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "ConfirmationArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.revocable_confirmation_arbiter)
        .await?;
    assert!(
        !code.is_empty(),
        "RevocableConfirmationArbiter should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.revocable_confirmation_arbiter_composing)
        .await?;
    assert!(
        !code.is_empty(),
        "RevocableConfirmationArbiterComposing should have code deployed"
    );

    let code = provider
        .get_code_at(arbiters.unrevocable_confirmation_arbiter)
        .await?;
    assert!(
        !code.is_empty(),
        "UnrevocableConfirmationArbiter should have code deployed"
    );

    println!("All arbiters have code deployed successfully!");
    println!("Total arbiters checked: {}", 44);

    Ok(())
}
