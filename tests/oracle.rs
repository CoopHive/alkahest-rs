#[cfg(test)]
mod tests {
    use alkahest_rs::{
        AlkahestClient,
        clients::oracle::{AttestationFilter, FulfillmentParams},
        contracts::StringObligation,
        fixtures::MockERC20Permit,
        types::{ArbiterData, Erc20Data},
    };
    use alloy::{
        primitives::{Address, Bytes, FixedBytes, bytes},
        providers::Provider as _,
        rpc::types::ValueOrArray,
        sol,
        sol_types::SolValue,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[tokio::test]
    async fn test_trivival_arbitrate_past() -> eyre::Result<()> {
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let price = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };

        // Create custom arbiter data
        let arbiter = test
            .addresses
            .arbiters_addresses
            .clone()
            .ok_or(eyre::eyre!("no erc20-related addresses"))?
            .trusted_oracle_arbiter;

        // Create demand data with oracle as bob
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersClient::encode_trusted_oracle_demand(&demand_data);

        let item = ArbiterData { arbiter, demand };

        let expiration = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600; // 1 hour

        // alice makes direct payment to bob using permit (no pre-approval needed)
        let escrow_receipt = test
            .alice_client
            .erc20
            .permit_and_buy_with_erc20(&price, &item, expiration)
            .await?;

        let escrow_event = AlkahestClient::get_attested_event(escrow_receipt)?;
        let escrow_uid = escrow_event.uid;

        // Verify escrow happened
        let alice_balance = mock_erc20_a
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let escrow_balance = mock_erc20_a
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // all tokens in escrow
        assert_eq!(alice_balance, 0.try_into()?);
        assert_eq!(escrow_balance, 100.try_into()?);

        let fulfillment_receipt = test
            .bob_client
            .string_obligation
            .make_statement(
                StringObligation::StatementData {
                    item: "fulfillment data".to_string(),
                },
                Some(escrow_uid),
            )
            .await?;

        let fulfillment_event = AlkahestClient::get_attested_event(fulfillment_receipt)?;
        let fulfillment_uid = fulfillment_event.uid;

        // Create FulfillmentParams
        let filter = AttestationFilter {
            attester: Some(ValueOrArray::Value(
                test.addresses
                    .string_obligation_addresses
                    .as_ref()
                    .ok_or(eyre::eyre!("no string obligation addresses"))?
                    .obligation, // or the correct field of type Address
            )),
            recipient: Some(ValueOrArray::Value(test.bob.address())),
            schema_uid: None,
            uid: Some(ValueOrArray::Value(fulfillment_uid)),
            ref_uid: Some(ValueOrArray::Value(escrow_uid)),
        };

        let fulfillment = FulfillmentParams {
            statement_abi: StringObligation::StatementData {
                item: "fulfillment data".to_string(),
            },
            filter,
        };

        // Define arbitrate function
        let arbitrate =
            |_statement: &StringObligation::StatementData| -> Option<bool> { Some(true) };

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past(&fulfillment, arbitrate)
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

        // give alice some erc20 tokens
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let price = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };

        // Create custom arbiter data
        let arbiter = test
            .addresses
            .arbiters_addresses
            .clone()
            .ok_or(eyre::eyre!("no erc20-related addresses"))?
            .trusted_oracle_arbiter;

        // Create demand data with oracle as bob
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersClient::encode_trusted_oracle_demand(&demand_data);

        let item = ArbiterData { arbiter, demand };

        let expiration = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600; // 1 hour

        // alice makes direct payment to bob using permit (no pre-approval needed)
        let escrow_receipt = test
            .alice_client
            .erc20
            .permit_and_buy_with_erc20(&price, &item, expiration)
            .await?;

        let escrow_event = AlkahestClient::get_attested_event(escrow_receipt)?;
        let escrow_uid = escrow_event.uid;

        // Verify escrow happened
        let alice_balance = mock_erc20_a
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let escrow_balance = mock_erc20_a
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // all tokens in escrow
        assert_eq!(alice_balance, 0.try_into()?);
        assert_eq!(escrow_balance, 100.try_into()?);

        let fulfillment1_receipt = test
            .bob_client
            .string_obligation
            .make_statement(
                StringObligation::StatementData {
                    item: "good".to_string(),
                },
                Some(escrow_uid),
            )
            .await?;
        let fulfillment1_event = AlkahestClient::get_attested_event(fulfillment1_receipt)?;
        let fulfillment1_uid = fulfillment1_event.uid;

        let fulfillment2_receipt = test
            .bob_client
            .string_obligation
            .make_statement(
                StringObligation::StatementData {
                    item: "bad".to_string(),
                },
                Some(escrow_uid),
            )
            .await?;

        let fulfillment2_event = AlkahestClient::get_attested_event(fulfillment2_receipt)?;
        let fulfillment2_uid = fulfillment2_event.uid;

        // Create FulfillmentParams
        let filter = AttestationFilter {
            attester: Some(ValueOrArray::Value(
                test.addresses
                    .string_obligation_addresses
                    .as_ref()
                    .ok_or(eyre::eyre!("no string obligation addresses"))?
                    .obligation, // or the correct field of type Address
            )),
            recipient: Some(ValueOrArray::Value(test.bob.address())),
            schema_uid: None,
            uid: None,
            ref_uid: None,
        };

        let fulfillment = FulfillmentParams {
            statement_abi: StringObligation::StatementData {
                item: "fulfillment data".to_string(),
            },
            filter,
        };

        // Define arbitrate function
        let arbitrate = |_statement: &StringObligation::StatementData| -> Option<bool> {
            Some(_statement.item == "good")
        };

        let decisions = test
            .bob_client
            .oracle
            .arbitrate_past(&fulfillment, arbitrate)
            .await?;

        for decision in decisions.iter() {
            assert_eq!(
                decision.decision,
                decision.statement.item == "good",
                "❌ Expected decision to be {} for item '{}'",
                decision.statement.item == "good",
                decision.statement.item
            );
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
}
