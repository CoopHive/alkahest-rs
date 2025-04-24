use alloy::{
    primitives::{Address, Bytes, FixedBytes, Log},
    providers::Provider as _,
    rpc::types::{Filter, TransactionReceipt},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolEvent as _, SolValue as _},
};
use futures_util::StreamExt as _;

use crate::{
    addresses::FILECOIN_CALIBRATION_ADDRESSES,
    contracts,
    types::{PublicProvider, WalletProvider},
    utils,
};

#[derive(Debug, Clone)]
pub struct ArbitersAddresses {
    pub trusted_party_arbiter: Address,
    pub trivial_arbiter: Address,
    pub specific_attestation_arbiter: Address,
    pub trusted_oracle_arbiter: Address,
    pub intrinsics_arbiter: Address,
    pub intrinsics_arbiter_2: Address,
    pub any_arbiter: Address,
    pub all_arbiter: Address,
}

#[derive(Clone)]
pub struct ArbitersClient {
    _signer: PrivateKeySigner,
    public_provider: PublicProvider,
    wallet_provider: WalletProvider,

    pub addresses: ArbitersAddresses,
}

impl Default for ArbitersAddresses {
    fn default() -> Self {
        FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses.unwrap()
    }
}

sol! {
    contract TrustedPartyArbiter {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            address creator;
        }
    }
}

sol! {
    contract SpecificAttestationArbiter {
        struct DemandData {
            bytes32 uid;
        }
    }
}

sol! {
    contract TrustedOracleArbiter {
        struct DemandData {
            address oracle;
            bytes data;
        }
    }
}

sol! {
    contract IntrinsicsArbiter2 {
        struct DemandData {
            bytes32 schema;
        }
    }
}

sol! {
    contract MultiArbiter {
        // Shared structure for both AnyArbiter and AllArbiter
        struct DemandData {
            address[] arbiters;
            bytes[] demands;
        }
    }
}

impl ArbitersClient {
    pub async fn new(
        signer: PrivateKeySigner,
        rpc_url: impl ToString + Clone,
        addresses: Option<ArbitersAddresses>,
    ) -> eyre::Result<Self> {
        let public_provider = utils::get_public_provider(rpc_url.clone()).await?;
        let wallet_provider = utils::get_wallet_provider(signer.clone(), rpc_url.clone()).await?;

        Ok(ArbitersClient {
            _signer: signer,
            public_provider: public_provider.clone(),
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    pub fn encode_intrinsics_demand_2(demand: &IntrinsicsArbiter2::DemandData) -> Bytes {
        demand.abi_encode().into()
    }

    pub fn decode_intrinsics_demand_2(
        data: &Bytes,
    ) -> eyre::Result<IntrinsicsArbiter2::DemandData> {
        Ok(IntrinsicsArbiter2::DemandData::abi_decode(data, true)?)
    }

    pub fn encode_multi_demand(demand: &MultiArbiter::DemandData) -> Bytes {
        demand.abi_encode().into()
    }

    pub fn decode_multi_demand(data: &Bytes) -> eyre::Result<MultiArbiter::DemandData> {
        Ok(MultiArbiter::DemandData::abi_decode(data, true)?)
    }

    pub fn encode_trusted_party_demand(demand: &TrustedPartyArbiter::DemandData) -> Bytes {
        demand.abi_encode().into()
    }

    pub fn decode_trusted_party_demand(
        data: &Bytes,
    ) -> eyre::Result<TrustedPartyArbiter::DemandData> {
        Ok(TrustedPartyArbiter::DemandData::abi_decode(data, true)?)
    }

    pub fn encode_specific_attestation_demand(
        demand: &SpecificAttestationArbiter::DemandData,
    ) -> Bytes {
        demand.abi_encode().into()
    }

    pub fn decode_specific_attestation_demand(
        data: &Bytes,
    ) -> eyre::Result<SpecificAttestationArbiter::DemandData> {
        Ok(SpecificAttestationArbiter::DemandData::abi_decode(
            data, true,
        )?)
    }

    pub fn encode_trusted_oracle_demand(demand: &TrustedOracleArbiter::DemandData) -> Bytes {
        demand.abi_encode().into()
    }

    pub fn decode_trusted_oracle_demand(
        data: &Bytes,
    ) -> eyre::Result<TrustedOracleArbiter::DemandData> {
        Ok(TrustedOracleArbiter::DemandData::abi_decode(data, true)?)
    }

    pub async fn arbitrate_as_trusted_oracle(
        &self,
        statement: FixedBytes<32>,
        decision: bool,
    ) -> eyre::Result<TransactionReceipt> {
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            self.addresses.trusted_oracle_arbiter,
            &self.wallet_provider,
        );

        let receipt = trusted_oracle_arbiter
            .arbitrate(statement, decision)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn wait_for_trusted_oracle_arbitration(
        &self,
        oracle: Address,
        statement: FixedBytes<32>,
        from_block: Option<u64>,
    ) -> eyre::Result<Log<contracts::TrustedOracleArbiter::ArbitrationMade>> {
        let filter = Filter::new()
            .from_block(from_block.unwrap_or(0))
            .address(self.addresses.trusted_oracle_arbiter)
            .event_signature(contracts::TrustedOracleArbiter::ArbitrationMade::SIGNATURE_HASH)
            .topic1(oracle.into_word())
            .topic2(statement);

        let logs = self.public_provider.get_logs(&filter).await?;
        if let Some(log) = logs
            .iter()
            .collect::<Vec<_>>()
            .first()
            .map(|log| log.log_decode::<contracts::TrustedOracleArbiter::ArbitrationMade>())
        {
            return Ok(log?.inner);
        }

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        if let Some(log) = stream.next().await {
            let log = log.log_decode::<contracts::TrustedOracleArbiter::ArbitrationMade>()?;
            return Ok(log.inner);
        }

        Err(eyre::eyre!("No ArbitrationMade event found"))
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{Address, Bytes, FixedBytes, bytes},
        providers::Provider as _,
        sol,
        sol_types::SolValue,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        clients::arbiters::{
            ArbitersClient, SpecificAttestationArbiter, TrustedOracleArbiter, TrustedPartyArbiter,
        },
        contracts,
        utils::setup_test_environment,
    };

    // Helper to create a test attestation for arbiter tests
    fn create_test_attestation(
        uid: Option<FixedBytes<32>>,
        recipient: Option<Address>,
    ) -> contracts::IEAS::Attestation {
        contracts::IEAS::Attestation {
            uid: uid.unwrap_or_default(),
            schema: FixedBytes::<32>::default(),
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .into(),
            expirationTime: 0u64.into(),
            revocationTime: 0u64.into(),
            refUID: FixedBytes::<32>::default(),
            recipient: recipient.unwrap_or_default(),
            attester: Address::default(),
            revocable: true,
            data: Bytes::default(),
        }
    }

    #[tokio::test]
    async fn test_trivial_arbiter_always_returns_true() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation (values don't matter for TrivialArbiter)
        let attestation = create_test_attestation(None, None);

        // Empty demand data
        let demand = Bytes::default();
        let counteroffer = FixedBytes::<32>::default();

        // Check that the arbiter returns true
        let trivial_arbiter = contracts::TrivialArbiter::new(
            test.addresses
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .trivial_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trivial_arbiter
            .checkStatement(attestation.clone().into(), demand.clone(), counteroffer)
            .call()
            .await?
            ._0;

        // Should always return true
        assert!(result, "TrivialArbiter should always return true");

        // Try with different values, should still return true
        let attestation2 = contracts::IEAS::Attestation {
            uid: FixedBytes::<32>::from_slice(&[1u8; 32]),
            ..attestation
        };

        sol! {
            struct TestDemand {
                bool data;
            }
        }

        let demand2 = TestDemand { data: true }.abi_encode().into();
        let counteroffer2 = FixedBytes::<32>::from_slice(&[42u8; 32]);

        let result2 = trivial_arbiter
            .checkStatement(attestation2.into(), demand2, counteroffer2)
            .call()
            .await?
            ._0;

        // Should still return true
        assert!(
            result2,
            "TrivialArbiter should always return true, even with different values"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_party_arbiter_with_correct_creator() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create mock addresses for testing
        let creator = test.alice.address();

        // Create a test attestation with the correct recipient (creator)
        let attestation = create_test_attestation(None, Some(creator));

        // Create demand data with the correct creator and TrivialArbiter as base arbiter
        let demand_data = TrustedPartyArbiter::DemandData {
            baseArbiter: test
                .addresses
                .clone()
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .trivial_arbiter,
            baseDemand: Bytes::default(),
            creator,
        };

        // Encode the demand data
        let demand = ArbitersClient::encode_trusted_party_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check statement should return true
        let trusted_party_arbiter = contracts::TrustedPartyArbiter::new(
            test.addresses
                .arbiters_addresses
                .clone()
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .trusted_party_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_party_arbiter
            .checkStatement(attestation.into(), demand, counteroffer)
            .call()
            .await?
            ._0;

        assert!(
            result,
            "TrustedPartyArbiter should return true with correct creator"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_party_arbiter_with_incorrect_creator() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create mock addresses for testing
        let creator = Address::from_slice(&[0x01; 20]);
        let non_creator = Address::from_slice(&[0x02; 20]);

        // Create a test attestation with an incorrect recipient (not the creator)
        let attestation = create_test_attestation(None, Some(non_creator));

        // Create demand data with the correct creator
        let demand_data = TrustedPartyArbiter::DemandData {
            baseArbiter: test
                .addresses
                .clone()
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .trivial_arbiter,
            baseDemand: Bytes::default(),
            creator,
        };

        // Encode the demand data
        let demand = ArbitersClient::encode_trusted_party_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check statement should revert with NotTrustedParty
        let trusted_party_arbiter = contracts::TrustedPartyArbiter::new(
            test.addresses
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .trusted_party_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_party_arbiter
            .checkStatement(attestation.into(), demand, counteroffer)
            .call()
            .await;

        // Expect an error containing "NotTrustedParty"
        assert!(result.is_err(), "Should have failed with incorrect creator");

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_oracle_arbiter_constructor() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        let statement_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Create an attestation with the statement UID
        let attestation = create_test_attestation(Some(statement_uid), None);

        // Create demand data with oracle as bob
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersClient::encode_trusted_oracle_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check statement - should be false initially since no decision has been made
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_oracle_arbiter
            .checkStatement(attestation.into(), demand, counteroffer)
            .call()
            .await?
            ._0;

        // Should be false initially
        assert!(
            !result,
            "TrustedOracleArbiter should initially return false"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_oracle_arbiter_arbitrate() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        let statement_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Create an attestation with the statement UID
        let attestation = create_test_attestation(Some(statement_uid), None);

        // Create demand data with oracle as bob
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersClient::encode_trusted_oracle_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check contract interface
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        // Initially the decision should be false (default value)
        let initial_result = trusted_oracle_arbiter
            .checkStatement(attestation.clone().into(), demand.clone(), counteroffer)
            .call()
            .await?
            ._0;

        assert!(!initial_result, "Decision should initially be false");

        // Make a positive arbitration decision using our client
        let arbitrate_hash = test
            .bob_client
            .arbiters
            .arbitrate_as_trusted_oracle(statement_uid, true)
            .await?
            .transaction_hash;

        // Wait for transaction receipt
        let _receipt = test
            .alice_client
            .public_provider
            .get_transaction_receipt(arbitrate_hash)
            .await?;

        // Now the decision should be true
        let final_result = trusted_oracle_arbiter
            .checkStatement(attestation.into(), demand, counteroffer)
            .call()
            .await?
            ._0;

        assert!(
            final_result,
            "Decision should now be true after arbitration"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_oracle_arbiter_with_different_oracles() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        let statement_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Set up two different oracles
        let oracle1 = test.bob.address();
        let oracle2 = test.alice.address();

        // Oracle 1 (Bob) makes a positive decision
        let arbitrate_hash1 = test
            .bob_client
            .arbiters
            .arbitrate_as_trusted_oracle(statement_uid, true)
            .await?
            .transaction_hash;

        // Wait for transaction receipt
        let _receipt1 = test
            .alice_client
            .public_provider
            .get_transaction_receipt(arbitrate_hash1)
            .await?;

        // Oracle 2 (Alice) makes a negative decision
        let arbitrate_hash2 = test
            .alice_client
            .arbiters
            .arbitrate_as_trusted_oracle(statement_uid, false)
            .await?
            .transaction_hash;

        // Wait for transaction receipt
        let _receipt2 = test
            .alice_client
            .public_provider
            .get_transaction_receipt(arbitrate_hash2)
            .await?;

        // Create the attestation
        let attestation = create_test_attestation(Some(statement_uid), None);
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        // Check with oracle1 (Bob) - should be true
        let demand_data1 = TrustedOracleArbiter::DemandData {
            oracle: oracle1,
            data: bytes!(""),
        };
        let demand1 = ArbitersClient::encode_trusted_oracle_demand(&demand_data1);
        let counteroffer = FixedBytes::<32>::default();

        let result1 = trusted_oracle_arbiter
            .checkStatement(attestation.clone().into(), demand1, counteroffer)
            .call()
            .await?
            ._0;

        assert!(result1, "Decision for Oracle 1 (Bob) should be true");

        // Check with oracle2 (Alice) - should be false
        let demand_data2 = TrustedOracleArbiter::DemandData {
            oracle: oracle2,
            data: bytes!(""),
        };
        let demand2 = ArbitersClient::encode_trusted_oracle_demand(&demand_data2);

        let result2 = trusted_oracle_arbiter
            .checkStatement(attestation.into(), demand2, counteroffer)
            .call()
            .await?
            ._0;

        assert!(!result2, "Decision for Oracle 2 (Alice) should be false");

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_oracle_arbiter_with_no_decision() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a new oracle address that hasn't made a decision
        let new_oracle = Address::from_slice(&[0x42; 20]);
        let statement_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Create the attestation
        let attestation = create_test_attestation(Some(statement_uid), None);

        // Create demand data with the new oracle
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: new_oracle,
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersClient::encode_trusted_oracle_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check with the new oracle - should be false (default value)
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_oracle_arbiter
            .checkStatement(attestation.into(), demand, counteroffer)
            .call()
            .await?
            ._0;

        assert!(
            !result,
            "Decision for an oracle that hasn't made a decision should be false"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_specific_attestation_arbiter_with_correct_uid() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create demand data with matching UID
        let demand_data = SpecificAttestationArbiter::DemandData { uid };

        // Encode demand data
        let demand = ArbitersClient::encode_specific_attestation_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check statement - should return true
        let specific_attestation_arbiter = contracts::SpecificAttestationArbiter::new(
            test.addresses
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .specific_attestation_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = specific_attestation_arbiter
            .checkStatement(attestation.into(), demand, counteroffer)
            .call()
            .await?
            ._0;

        assert!(
            result,
            "SpecificAttestationArbiter should return true with matching UID"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_specific_attestation_arbiter_with_incorrect_uid() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create demand data with non-matching UID
        let different_uid = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let demand_data = SpecificAttestationArbiter::DemandData { uid: different_uid };

        // Encode demand data
        let demand = ArbitersClient::encode_specific_attestation_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check statement should revert with NotDemandedAttestation
        let specific_attestation_arbiter = contracts::SpecificAttestationArbiter::new(
            test.addresses
                .arbiters_addresses
                .ok_or(eyre::eyre!("no arbiter addresses"))?
                .specific_attestation_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = specific_attestation_arbiter
            .checkStatement(attestation.into(), demand, counteroffer)
            .call()
            .await;

        // Should fail with NotDemandedAttestation
        assert!(result.is_err(), "Should have failed with incorrect UID");

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_trusted_party_demand() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test demand data
        let creator = Address::from_slice(&[0x01; 20]);
        let base_arbiter = test
            .addresses
            .arbiters_addresses
            .ok_or(eyre::eyre!("no arbiter addresses"))?
            .trivial_arbiter;

        let demand_data = TrustedPartyArbiter::DemandData {
            baseArbiter: base_arbiter,
            baseDemand: Bytes::from(vec![1, 2, 3]),
            creator,
        };

        // Encode the demand data
        let encoded = ArbitersClient::encode_trusted_party_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersClient::decode_trusted_party_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(
            decoded.baseArbiter, base_arbiter,
            "Base arbiter should match"
        );
        assert_eq!(
            decoded.baseDemand, demand_data.baseDemand,
            "Base demand should match"
        );
        assert_eq!(decoded.creator, creator, "Creator should match");

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_specific_attestation_demand() -> eyre::Result<()> {
        // Setup test environment
        let _test = setup_test_environment().await?;

        // Create a test demand data
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let demand_data = SpecificAttestationArbiter::DemandData { uid };

        // Encode the demand data
        let encoded = ArbitersClient::encode_specific_attestation_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersClient::decode_specific_attestation_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(decoded.uid, uid, "UID should match");

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_trusted_oracle_demand() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test demand data
        let oracle = test.bob.address();
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle,
            data: bytes!(""),
        };

        // Encode the demand data
        let encoded = ArbitersClient::encode_trusted_oracle_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersClient::decode_trusted_oracle_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(decoded.oracle, oracle, "Oracle should match");

        Ok(())
    }

    #[tokio::test]
    async fn test_wait_for_trusted_oracle_arbitration() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        let statement_uid = FixedBytes::<32>::from_slice(&[42u8; 32]);
        let oracle = test.bob.address();

        // Start listening for arbitration events in the background
        let listener_task = tokio::spawn({
            let alice_client = test.alice_client.clone();
            let statement_uid = statement_uid.clone();
            async move {
                alice_client
                    .arbiters
                    .wait_for_trusted_oracle_arbitration(oracle, statement_uid, None)
                    .await
            }
        });

        // Ensure the listener is running
        // tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Make an arbitration decision
        let arbitrate_hash = test
            .bob_client
            .arbiters
            .arbitrate_as_trusted_oracle(statement_uid, true)
            .await?
            .transaction_hash;

        // Wait for transaction receipt
        let _receipt = test
            .alice_client
            .public_provider
            .get_transaction_receipt(arbitrate_hash)
            .await?;

        // Wait for the listener to pick up the event
        let log_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(5), listener_task).await???;

        // Verify the event data
        assert_eq!(log_result.oracle, oracle, "Oracle in event should match");
        assert_eq!(
            log_result.statement, statement_uid,
            "Statement UID in event should match"
        );
        assert!(log_result.decision, "Decision in event should be true");

        Ok(())
    }
}
