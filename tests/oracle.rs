#[cfg(test)]
mod tests {
    use alkahest_rs::{
        AlkahestClient,
        clients::oracle::{AttestationFilter, FulfillmentParams},
        contracts::StringObligation,
        fixtures::MockERC20Permit,
        types::{ArbiterData, Erc20Data},
        utils::TestContext,
    };
    use alloy::{
        primitives::{Address, Bytes, FixedBytes, bytes},
        providers::Provider as _,
        rpc::types::ValueOrArray,
        sol,
        sol_types::SolValue,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use {
        alkahest_rs::clients::arbiters::{
            ArbitersClient, IntrinsicsArbiter2, MultiArbiter, RecipientArbiterNoncomposing,
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
            .ok_or(eyre::eyre!("Missing arbiter"))?
            .trusted_oracle_arbiter;

        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        let demand = ArbitersClient::encode_trusted_oracle_demand(&demand_data);
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
        }
    }

    fn make_fulfillment_params(
        filter: AttestationFilter,
    ) -> FulfillmentParams<StringObligation::StatementData> {
        FulfillmentParams {
            statement_abi: StringObligation::StatementData {
                item: "".to_string(),
            },
            filter,
        }
    }

    #[tokio::test]
    async fn test_trivival_arbitrate_past() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past(&fulfillment, |s| Some(s.item == "good"))
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

        let fulfillment1_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        let fulfillment2_uid = make_fulfillment(&test, "bad", escrow_uid).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past(&fulfillment, |s| Some(s.item == "good"))
            .await?;

        for decision in &decisions {
            assert_eq!(decision.decision, decision.statement.item == "good");
        }

        let collection1 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment1_uid)
            .await?;

        println!(
            "✅ Expected collection1 to succeed, got receipt: {:?}",
            collection1
        );

        let collection2 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment2_uid)
            .await;

        assert!(
            collection2.is_err(),
            "❌ Expected collection2 to fail due to failed arbitration, but it succeeded"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trivival_listen_and_arbitrate() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        println!("Listening for decisions...");

        let listener_handle = tokio::spawn({
            let oracle = test.bob_client.oracle.clone(); // make sure it's Arc or Clone
            async move {
                oracle
                    .listen_and_arbitrate(
                        &fulfillment,
                        |_statement: &StringObligation::StatementData| -> Option<bool> {
                            Some(true)
                        },
                        |decision| {
                            let statement_item = decision.statement.item.clone();
                            let decision_value = decision.decision;
                            async move {
                                assert_eq!(statement_item, "good");
                                assert!(decision_value);
                            }
                        },
                        Some(1),
                    )
                    .await
            }
        });

        let fulfillment_uid = make_fulfillment(&test, "good", escrow_uid).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        println!("✅ Arbitrate decision passed. Tx: {:?}", collection);
        Ok(())
    }

    #[tokio::test]
    async fn test_conditonal_listen_and_arbitrate() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        println!("Listening for decisions...");

        let listener_handle = tokio::spawn({
            let oracle = test.bob_client.oracle.clone(); // make sure it's Arc or Clone
            async move {
                oracle
                    .listen_and_arbitrate(
                        &fulfillment,
                        |_statement: &StringObligation::StatementData| -> Option<bool> {
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
                        Some(2),
                    )
                    .await
            }
        });

        let fulfillment1_uid = make_fulfillment(&test, "good", escrow_uid).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let fulfillment2_uid = make_fulfillment(&test, "bad", escrow_uid).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let collection1 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment1_uid)
            .await?;

        println!(
            "✅ Expected collection1 to succeed, got receipt: {:?}",
            collection1
        );

        let collection2 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment2_uid)
            .await;

        assert!(
            collection2.is_err(),
            "❌ Expected collection2 to fail due to failed arbitration, but it succeeded"
        );

        let decisions = listener_handle.await??;
        assert_eq!(decisions.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn test_trivival_listen_and_arbitrate_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        let listener_handle = tokio::spawn({
            let oracle = test.bob_client.oracle.clone();
            async move {
                oracle
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
                        Some(1),
                    )
                    .await
            }
        });

        // Ensure listener starts
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let fulfillment_uid = make_fulfillment(&test, "async good", escrow_uid).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let _collection = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment_uid)
            .await?;

        // ✅ Wait for listener to complete
        let decisions = listener_handle.await??;
        assert_eq!(decisions.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_conditional_listen_and_arbitrate_async() -> eyre::Result<()> {
        let test = setup_test_environment().await?;
        let (_, _, escrow_uid) = setup_escrow(&test).await?;

        let filter = make_filter(&test, Some(escrow_uid));
        let fulfillment = make_fulfillment_params(filter);

        // ✅ Spawn async listener
        let listener_handle = tokio::spawn({
            let oracle = test.bob_client.oracle.clone();
            async move {
                oracle
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
                                println!(
                                    "📣 Decision for '{}': {}",
                                    statement_item, decision_value
                                );
                                assert_eq!(
                                    decision_value,
                                    statement_item == "async good",
                                    "❌ Expected decision to be {} for item '{}'",
                                    statement_item == "async good",
                                    statement_item
                                );
                            }
                        },
                        Some(2),
                    )
                    .await
            }
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let fulfillment1_uid = make_fulfillment(&test, "async good", escrow_uid).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let fulfillment2_uid = make_fulfillment(&test, "async bad", escrow_uid).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let collection1 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment1_uid)
            .await?;

        println!("✅ Collection 1 succeeded: {:?}", collection1);

        let collection2 = test
            .bob_client
            .erc20
            .collect_payment(escrow_uid, fulfillment2_uid)
            .await;

        assert!(
            collection2.is_err(),
            "❌ Expected collection 2 to fail due to arbitration rejection"
        );

        let decisions = listener_handle.await??;
        assert_eq!(decisions.len(), 2); // Only one good fulfillment should pass

        Ok(())
    }
}
