#[cfg(test)]
mod tests {
    use alkahest_rs::{
        AlkahestClient,
        clients::oracle::{
            ArbitrateOptions, AttestationFilter, AttestationFilterWithoutRefUid, EscrowParams,
            FulfillmentParams, FulfillmentParamsWithoutRefUid,
        },
        contracts::StringObligation,
        fixtures::MockERC20Permit,
        types::{ArbiterData, Erc20Data},
        utils::TestContext,
    };
    use alloy::{
        eips::BlockNumberOrTag,
        primitives::{Address, Bytes, FixedBytes, bytes},
        providers::Provider as _,
        rpc::types::{FilterBlockOption, ValueOrArray},
        sol,
        sol_types::SolValue,
    };
    use std::{
        marker::PhantomData,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use {
        alkahest_rs::clients::arbiters::{
            ArbitersClient, IntrinsicsArbiter2, MultiArbiter, RecipientArbiterNonComposing,
            SpecificAttestationArbiter, TrustedOracleArbiter, TrustedPartyArbiter,
            UidArbiterComposing,
        },
        alkahest_rs::clients::oracle::OracleClient,
        alkahest_rs::contracts,
        alkahest_rs::utils::setup_test_environment,
    };

    async fn setup_escrow(
        test: &TestContext,
    ) -> eyre::Result<(Erc20Data, ArbiterData, FixedBytes<32>)> {
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100u64.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let price = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100u64.try_into()?,
        };

        let arbiter = test
            .addresses
            .arbiters_addresses
            .as_ref()
            .ok_or(eyre::eyre!("Missing arbiter addresses"))?
            .trusted_oracle_arbiter;

        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        let demand = ArbitersClient::encode_trusted_oracle_arbiter_demand(&demand_data);
        let item = ArbiterData { arbiter, demand };
        let expiration = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;

        let escrow_receipt = test
            .alice_client
            .erc20
            .permit_and_buy_with_erc20(&price, &item, expiration)
            .await?;

        let escrow_event = AlkahestClient::get_attested_event(escrow_receipt)?;

        Ok((price, item, escrow_event.uid))
    }

    async fn make_fulfillment(
        test: &TestContext,
        statement: &str,
        ref_uid: FixedBytes<32>,
    ) -> eyre::Result<FixedBytes<32>> {
        let receipt = test
            .bob_client
            .string_obligation
            .make_statement(
                StringObligation::StatementData {
                    item: statement.to_string(),
                },
                Some(ref_uid),
            )
            .await?;
        Ok(AlkahestClient::get_attested_event(receipt)?.uid)
    }

    fn make_filter(test: &TestContext, ref_uid: Option<FixedBytes<32>>) -> AttestationFilter {
        AttestationFilter {
            attester: Some(ValueOrArray::Value(
                test.addresses
                    .string_obligation_addresses
                    .as_ref()
                    .unwrap()
                    .obligation,
            )),
            recipient: Some(ValueOrArray::Value(test.bob.address())),
            schema_uid: None,
            uid: None,
            ref_uid: ref_uid.map(ValueOrArray::Value),
            block_option: Some(FilterBlockOption::Range {
                from_block: Some(BlockNumberOrTag::Earliest),
                to_block: Some(BlockNumberOrTag::Latest),
            }),
        }
    }

    fn make_filter_for_escrow(
        test: &TestContext,
        ref_uid: Option<FixedBytes<32>>,
    ) -> AttestationFilter {
        AttestationFilter {
            attester: Some(ValueOrArray::Value(
                test.addresses
                    .erc20_addresses
                    .as_ref()
                    .unwrap()
                    .escrow_obligation,
            )),
            recipient: None,
            schema_uid: None,
            uid: None,
            ref_uid: ref_uid.map(ValueOrArray::Value),
            block_option: Some(FilterBlockOption::Range {
                from_block: Some(BlockNumberOrTag::Earliest),
                to_block: Some(BlockNumberOrTag::Latest),
            }),
        }
    }

    fn make_fulfillment_params(
        filter: AttestationFilter,
    ) -> FulfillmentParams<StringObligation::StatementData> {
        FulfillmentParams {
            filter,
            _statement_data: PhantomData::<StringObligation::StatementData>,
        }
    }

    fn make_filter_without_refuid(test: &TestContext) -> AttestationFilterWithoutRefUid {
        AttestationFilterWithoutRefUid {
            attester: Some(ValueOrArray::Value(
                test.addresses
                    .string_obligation_addresses
                    .as_ref()
                    .unwrap()
                    .obligation,
            )),
            recipient: Some(ValueOrArray::Value(test.bob.address())),
            schema_uid: None,
            uid: None,
            block_option: Some(FilterBlockOption::Range {
                from_block: Some(BlockNumberOrTag::Earliest),
                to_block: Some(BlockNumberOrTag::Latest),
            }),
        }
    }

    fn make_fulfillment_params_without_refuid(
        filter: AttestationFilterWithoutRefUid,
    ) -> FulfillmentParamsWithoutRefUid<StringObligation::StatementData> {
        FulfillmentParamsWithoutRefUid {
            filter,
            _statement_data: std::marker::PhantomData,
        }
    }

    #[tokio::test]
    async fn test_trivial_arbitrate_past() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past(
                &fulfillment,
                &|s| Some(s.item == "good"),
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: false,
                },
            )
            .await?;

        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].decision, true);

        let collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        println!("✅ Arbitrate decision passed. Tx: {:?}", collection);

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_arbitrate_past() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past(
                &fulfillment,
                &|s| Some(s.item == "good"),
                &ArbitrateOptions::default(),
            )
            .await?;

        for decision in &decisions {
            assert_eq!(decision.decision, decision.statement.item == "good");
        }

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_skip_arbitrated_arbitrate_past() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past(
                &fulfillment,
                &|s| {
                    println!("Arbitrating for item: {}", s.item);
                    Some(s.item == "good")
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: true,
                },
            )
            .await?;
        assert_eq!(decisions.len(), 1);

        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past(
                &fulfillment,
                &|s| {
                    println!("Arbitrating for item: {}", s.item);
                    Some(s.item == "good")
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: true,
                },
            )
            .await?;
        assert_eq!(decisions.len(), 1);

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_skip_arbitrated_arbitrate_past_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past_async(
                &fulfillment,
                |s| {
                    println!("Arbitrating for item: {}", s.item);
                    let result = s.item == "good";
                    async move { Some(result) }
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: true,
                },
            )
            .await?;
        assert_eq!(decisions.len(), 1);

        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past_async(
                &fulfillment,
                |s| {
                    println!("Arbitrating for item: {}", s.item);
                    let result = s.item == "good";
                    async move { Some(result) }
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: true,
                },
            )
            .await?;
        assert_eq!(decisions.len(), 1);

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trivial_listen_and_arbitrate() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        println!("Listening for decisions...");

        let oracle = test.bob_client.oracle.clone();

        // ⬇️ Directly call listen_and_arbitrate (no need to spawn)
        let listen_result = oracle
            .listen_and_arbitrate(
                &fulfillment,
                &|_statement: &StringObligation::StatementData| -> Option<bool> { Some(true) },
                |decision| {
                    let statement_item = decision.statement.item.clone();
                    let decision_value = decision.decision;
                    async move {
                        assert_eq!(statement_item, "good");
                        assert!(decision_value);
                    }
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: false,
                },
            )
            .await?;

        // Trigger fulfillment
        let fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        // Allow time for listener to process
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        println!("✅ Arbitrate decision passed. Tx: {:?}", collection);

        // Cleanup
        oracle.unsubscribe(listen_result.subscription_id).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_trivial_listen_and_arbitrate_no_spawn() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        println!("Listening for decisions no spawn ...");

        let oracle = test.bob_client.oracle.clone();

        // ⬇️ Spawn the listen_and_arbitrate_no_spawn as a background task
        let listen_handle = tokio::spawn(async move {
            oracle
                .listen_and_arbitrate_no_spawn(
                    &fulfillment,
                    &|_statement: &StringObligation::StatementData| -> Option<bool> { Some(true) },
                    |decision| {
                        let statement_item = decision.statement.item.clone();
                        let decision_value = decision.decision;
                        println!("📣 Decision for '{}': {}", statement_item, decision_value);
                        async move {
                            assert_eq!(statement_item, "good");
                            assert!(decision_value);
                        }
                    },
                    &ArbitrateOptions {
                        require_oracle: true,
                        skip_arbitrated: false,
                    },
                    Some(Duration::from_secs(10)),
                )
                .await
        });

        // Allow time for the listener to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Trigger fulfillment
        let fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        // Allow time for listener to process
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        println!("✅ Arbitrate decision passed. Tx: {:?}", collection);

        // Get the result from the spawned task and cleanup

        Ok(())
    }

        #[tokio::test]
    async fn test_trivial_listen_and_arbitrate_new_fulfillments_no_spawn() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        println!("Listening for decisions no spawn ...");

        let oracle = test.bob_client.oracle.clone();

        // ⬇️ Spawn the listen_and_arbitrate_no_spawn as a background task
        let listen_handle = tokio::spawn(async move {
            oracle
                .listen_and_arbitrate_new_fulfillments_no_spawn(
                    &fulfillment,
                    &|_statement: &StringObligation::StatementData| -> Option<bool> { Some(true) },
                    |decision| {
                        let statement_item = decision.statement.item.clone();
                        let decision_value = decision.decision;
                        println!("📣 Decision for '{}': {}", statement_item, decision_value);
                        async move {
                            assert_eq!(statement_item, "good");
                            assert!(decision_value);
                        }
                    },
                    &ArbitrateOptions {
                        require_oracle: true,
                        skip_arbitrated: false,
                    },
                    Some(Duration::from_secs(10)),
                )
                .await
        });

        // Allow time for the listener to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Trigger fulfillment
        let fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        // Allow time for listener to process
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        println!("✅ Arbitrate decision passed. Tx: {:?}", collection);

        // Get the result from the spawned task and cleanup

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_listen_and_arbitrate() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        println!("Listening for decisions...");

        let oracle = test.bob_client.oracle.clone();
        let listen_result = test
            .bob_client
            .oracle
            .listen_and_arbitrate(
                &fulfillment,
                &|_statement: &StringObligation::StatementData| -> Option<bool> {
                    Some(_statement.item == "good")
                },
                |decision| {
                    let statement_item = decision.statement.item.clone();
                    let decision_value = decision.decision;
                    async move {
                        println!("📣 Decision for '{}': {}", statement_item, decision_value);
                    }
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: false,
                },
            )
            .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        println!("Fulfillment 2 UID: {:?}", bad_fulfillment_uid);
        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        println!("Fulfillment 1 UID: {:?}", good_fulfillment_uid);
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        oracle.unsubscribe(listen_result.subscription_id).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_listen_and_arbitrate_new_fulfillments() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        println!("Listening for decisions...");

        let oracle = test.bob_client.oracle.clone();
        let listen_result = oracle
            .listen_and_arbitrate_new_fulfillments(
                &fulfillment,
                &|_statement: &StringObligation::StatementData| -> Option<bool> {
                    Some(_statement.item == "good")
                },
                |decision| {
                    let statement_item = decision.statement.item.clone();
                    let decision_value = decision.decision;
                    async move {
                        assert_eq!(
                            decision_value,
                            statement_item == "good",
                            "❌ Expected decision to be {} for item '{}'",
                            statement_item == "good",
                            statement_item
                        );
                    }
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: false,
                },
            )
            .await?;

        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        oracle.unsubscribe(listen_result.subscription_id).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_trivial_listen_and_arbitrate_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        let oracle = test.bob_client.oracle.clone();
        let listen_result = oracle
            .listen_and_arbitrate_async(
                &fulfillment,
                |_stmt: &StringObligation::StatementData| {
                    let item = _stmt.item.clone();
                    println!("Arbitrating for item: {}", item);
                    async move { Some(item == "async good") }
                },
                |decision| {
                    let statement_item = decision.statement.item.clone();
                    let decision_value = decision.decision;
                    println!(
                        "Decision made for item '{}': {}",
                        statement_item, decision_value
                    );
                    async move {
                        assert_eq!(statement_item, "async good");
                        assert!(decision_value);
                    }
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: false,
                },
            )
            .await?;

        // Ensure listener starts
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let fulfillment_uid = make_fulfillment(&test, "async good", escrow_uid).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let _collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        oracle.unsubscribe(listen_result.subscription_id).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_listen_and_arbitrate_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        // ✅ Spawn async listener
        let oracle = test.bob_client.oracle.clone();
        let listen_result = oracle
            .listen_and_arbitrate_async(
                &fulfillment,
                |_stmt: &StringObligation::StatementData| {
                    let item = _stmt.item.clone();
                    async move {
                        println!("🧠 Arbitrating for item: {}", item);
                        Some(item == "async good")
                    }
                },
                |decision| {
                    let statement_item = decision.statement.item.clone();
                    let decision_value = decision.decision;
                    async move {
                        println!("📣 Decision for '{}': {}", statement_item, decision_value);
                        assert_eq!(
                            decision_value,
                            statement_item == "async good",
                            "❌ Expected decision to be {} for item '{}'",
                            statement_item == "async good",
                            statement_item
                        );
                    }
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: false,
                },
            )
            .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let good_fulfillment_uid = make_fulfillment(&test, "async good", escrow_uid).await?;

        println!("Fulfillment 1 UID: {:?}", good_fulfillment_uid);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        println!("Waiting for async decision...");
        let bad_fulfillment_uid = make_fulfillment(&test, "async bad", escrow_uid).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!("✅ Collection 1 succeeded: {:?}", good_collection);

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected collection 2 to fail due to arbitration rejection"
        );

        oracle.unsubscribe(listen_result.subscription_id).await?;
        Ok(())
    }
    #[tokio::test]
    async fn test_conditional_listen_and_arbitrate_new_fulfillments_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        println!("Listening for decisions...");

        let oracle = test.bob_client.oracle.clone();
        let listen_result = oracle
            .listen_and_arbitrate_new_fulfillments_async(
                &fulfillment,
                |_statement: &StringObligation::StatementData| {
                    let result = _statement.item == "good";
                    async move { Some(result) }
                },
                |decision| {
                    let statement_item = decision.statement.item.clone();
                    let decision_value = decision.decision;
                    async move {
                        assert_eq!(
                            decision_value,
                            statement_item == "good",
                            "❌ Expected decision to be {} for item '{}'",
                            statement_item == "good",
                            statement_item
                        );
                    }
                },
                &ArbitrateOptions {
                    require_oracle: true,
                    skip_arbitrated: false,
                },
            )
            .await?;

        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        oracle.unsubscribe(listen_result.subscription_id).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_trivial_arbitrate_past_for_escrow() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let (decisions, _, _) = test
            .bob_client
            .oracle
            .arbitrate_past_for_escrow(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    Some(item == "good")
                },
                None,
            )
            .await?;

        let collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        println!("✅ Arbitrate decision passed. Tx: {:?}", collection);

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_arbitrate_past_for_escrow() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let (decisions, _, _) = test
            .bob_client
            .oracle
            .arbitrate_past_for_escrow(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    Some(item == "good")
                },
                None,
            )
            .await?;

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_skip_arbitrated_arbitrate_past_for_escrow() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let (decisions, _, _) = test
            .bob_client
            .oracle
            .arbitrate_past_for_escrow(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    Some(item == "good")
                },
                None,
            )
            .await?;
        assert_eq!(decisions.len(), 1);

        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        let (decisions, _, _) = test
            .bob_client
            .oracle
            .arbitrate_past_for_escrow(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    Some(item == "good")
                },
                Some(true),
            )
            .await?;

        assert_eq!(decisions.len(), 1);

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_arbitrate_past_for_escrow_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let (decisions, _, _) = test
            .bob_client
            .oracle
            .arbitrate_past_for_escrow_async(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    async move { Some(item == "good") }
                },
                None,
            )
            .await?;

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_skip_arbitrated_arbitrate_past_for_escrow_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let bad_fulfillment_uid = make_fulfillment(&test, "bad", escrow_uid).await?;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let (decisions, _, _) = test
            .bob_client
            .oracle
            .arbitrate_past_for_escrow_async(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    async move { Some(item == "good") }
                },
                None,
            )
            .await?;
        assert_eq!(decisions.len(), 1);

        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        let (decisions, _, _) = test
            .bob_client
            .oracle
            .arbitrate_past_for_escrow_async(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    async move { Some(item == "good") }
                },
                Some(true),
            )
            .await?;

        assert_eq!(decisions.len(), 1);

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid)
            .await;

        assert!(
            bad_collection.is_err(),
            "❌ Expected bad_collection to fail due to failed arbitration, but it succeeded"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trivial_listen_and_arbitrate_for_escrow() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let oracle = test.bob_client.oracle.clone();

        let listen_result = oracle
            .listen_and_arbitrate_for_escrow(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    Some(item == "good")
                },
                |_decision| {
                    let statement_item = _decision.statement.item.clone();
                    let decision_value = _decision.decision;
                    async move {
                        assert_eq!(statement_item, "good");
                        assert!(decision_value);
                    }
                },
                None,
            )
            .await?;

        // Ensure listener starts
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let _collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        oracle
            .unsubscribe(listen_result.escrow_subscription_id)
            .await?;
        oracle
            .unsubscribe(listen_result.fulfillment_subscription_id)
            .await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_trivial_listen_and_arbitrate_for_escrow_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let oracle = test.bob_client.oracle.clone();

        let listen_result = oracle
            .listen_and_arbitrate_for_escrow_async(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    async move { Some(item == "good") }
                },
                |_decision| {
                    let statement_item = _decision.statement.item.clone();
                    let decision_value = _decision.decision;
                    async move {
                        assert_eq!(statement_item, "good");
                        assert!(decision_value);
                    }
                },
                None,
            )
            .await?;

        // Ensure listener starts
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let _collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        oracle
            .unsubscribe(listen_result.escrow_subscription_id)
            .await?;
        oracle
            .unsubscribe(listen_result.fulfillment_subscription_id)
            .await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_listen_and_arbitrate_for_escrow() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let bad_fulfillment_uid1 = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let oracle = test.bob_client.oracle.clone();

        let listen_result = oracle
            .listen_and_arbitrate_for_escrow(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    println!("Result: {:?}", Some(item == "good"));
                    Some(item == "good")
                },
                |_decision| {
                    let statement_item = _decision.statement.item.clone();
                    let decision_value = _decision.decision;

                    async move {
                        println!("📣 Decision for '{}': {}", statement_item, decision_value);
                    }
                },
                None,
            )
            .await?;

        let bad_fulfillment_uid2 = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection1 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid1)
            .await;

        assert!(
            bad_collection1.is_err(),
            "❌ Expected bad_collection1 to fail due to failed arbitration, but it succeeded"
        );

        let bad_collection2 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid2)
            .await;

        assert!(
            bad_collection2.is_err(),
            "❌ Expected bad_collection2 to fail due to failed arbitration, but it succeeded"
        );

        oracle
            .unsubscribe(listen_result.escrow_subscription_id)
            .await?;
        oracle
            .unsubscribe(listen_result.fulfillment_subscription_id)
            .await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_listen_and_arbitrate_for_escrow_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let bad_fulfillment_uid1 = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let oracle = test.bob_client.oracle.clone();

        let listen_result = oracle
            .listen_and_arbitrate_for_escrow_async(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    async move { Some(item == "good") }
                },
                |_decision| {
                    let statement_item = _decision.statement.item.clone();
                    let decision_value = _decision.decision;
                    async move {
                        println!("📣 Decision for '{}': {}", statement_item, decision_value);
                    }
                },
                None,
            )
            .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let bad_fulfillment_uid2 = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection1 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid1)
            .await;

        assert!(
            bad_collection1.is_err(),
            "❌ Expected bad_collection1 to fail due to failed arbitration, but it succeeded"
        );

        let bad_collection2 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid2)
            .await;
        assert!(
            bad_collection2.is_err(),
            "❌ Expected bad_collection2 to fail due to failed arbitration, but it succeeded"
        );

        oracle
            .unsubscribe(listen_result.escrow_subscription_id)
            .await?;
        oracle
            .unsubscribe(listen_result.fulfillment_subscription_id)
            .await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_listen_and_arbitrate_new_fulfillments_for_escrow() -> eyre::Result<()>
    {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let bad_fulfillment_uid1 = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let oracle = test.bob_client.oracle.clone();

        let listen_result = oracle
            .listen_and_arbitrate_new_fulfillments_for_escrow(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    println!("Result: {:?}", Some(item == "good"));
                    Some(item == "good")
                },
                |_decision| {
                    let statement_item = _decision.statement.item.clone();
                    let decision_value = _decision.decision;

                    async move {
                        println!("📣 Decision for '{}': {}", statement_item, decision_value);
                    }
                },
            )
            .await?;

        let bad_fulfillment_uid2 = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection1 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid1)
            .await;

        assert!(
            bad_collection1.is_err(),
            "❌ Expected bad_collection1 to fail due to failed arbitration, but it succeeded"
        );

        let bad_collection2 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid2)
            .await;

        assert!(
            bad_collection2.is_err(),
            "❌ Expected bad_collection2 to fail due to failed arbitration, but it succeeded"
        );

        oracle
            .unsubscribe(listen_result.escrow_subscription_id)
            .await?;
        oracle
            .unsubscribe(listen_result.fulfillment_subscription_id)
            .await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_listen_and_arbitrate_new_fulfillments_for_escrow_async()
    -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, item, escrow_uid) = setup_escrow(&test).await?;

        let bad_fulfillment_uid1 = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let filter = make_filter_without_refuid(&test);
        let fulfillment = make_fulfillment_params_without_refuid(filter);

        let demand_data = TrustedOracleArbiter::DemandData::abi_decode(&item.demand)?;
        let escrow = EscrowParams {
            filter: make_filter_for_escrow(&test, None),
            _demand_data: PhantomData::<TrustedOracleArbiter::DemandData>,
        };
        let oracle = test.bob_client.oracle.clone();

        let listen_result = oracle
            .listen_and_arbitrate_new_fulfillments_for_escrow_async(
                &escrow,
                &fulfillment,
                |_statement, _demand| {
                    println!(
                        "🔍 Checking item: '{}', demand: {:?}",
                        _statement.item, _demand.oracle
                    );
                    let item = _statement.item.clone();
                    let oracle_addr = _demand.oracle;
                    println!("🔍 Checking item: '{}', oracle: {}", item, oracle_addr);
                    async move { Some(item == "good") }
                },
                |_decision| {
                    let statement_item = _decision.statement.item.clone();
                    let decision_value = _decision.decision;
                    async move {
                        println!("📣 Decision for '{}': {}", statement_item, decision_value);
                    }
                },
            )
            .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let bad_fulfillment_uid2 = make_fulfillment(&test, "bad", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let good_fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let good_collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, good_fulfillment_uid)
            .await?;

        println!(
            "✅ Expected good_collection to succeed, got receipt: {:?}",
            good_collection
        );

        let bad_collection1 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid1)
            .await;

        assert!(
            bad_collection1.is_err(),
            "❌ Expected bad_collection1 to fail due to failed arbitration, but it succeeded"
        );

        let bad_collection2 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, bad_fulfillment_uid2)
            .await;
        assert!(
            bad_collection2.is_err(),
            "❌ Expected bad_collection2 to fail due to failed arbitration, but it succeeded"
        );

        oracle
            .unsubscribe(listen_result.escrow_subscription_id)
            .await?;
        oracle
            .unsubscribe(listen_result.fulfillment_subscription_id)
            .await?;

        Ok(())
    }
}
