use crate::{
    addresses::BASE_SEPOLIA_ADDRESSES,
    contracts,
    extensions::AlkahestExtension,
    types::{PublicProvider, WalletProvider},
    utils,
};
use alloy::{
    primitives::{Address, Bytes, FixedBytes, Log},
    providers::Provider as _,
    rpc::types::{Filter, TransactionReceipt},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolEvent as _, SolValue as _},
};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitersAddresses {
    pub eas: Address,
    pub trusted_party_arbiter: Address,
    pub trivial_arbiter: Address,
    pub specific_attestation_arbiter: Address,
    pub trusted_oracle_arbiter: Address,
    pub intrinsics_arbiter: Address,
    pub intrinsics_arbiter_2: Address,
    pub any_arbiter: Address,
    pub all_arbiter: Address,
    pub uid_arbiter: Address,
    pub recipient_arbiter: Address,
    pub not_arbiter: Address,
    pub attester_arbiter_composing: Address,
    pub attester_arbiter_non_composing: Address,
    pub expiration_time_after_arbiter_composing: Address,
    pub expiration_time_before_arbiter_composing: Address,
    pub expiration_time_equal_arbiter_composing: Address,
    pub recipient_arbiter_composing: Address,
    pub ref_uid_arbiter_composing: Address,
    pub revocable_arbiter_composing: Address,
    pub schema_arbiter_composing: Address,
    pub time_after_arbiter_composing: Address,
    pub time_before_arbiter_composing: Address,
    pub time_equal_arbiter_composing: Address,
    pub uid_arbiter_composing: Address,
    // Payment fulfillment arbiters
    pub erc20_payment_fulfillment_arbiter: Address,
    pub erc721_payment_fulfillment_arbiter: Address,
    pub erc1155_payment_fulfillment_arbiter: Address,
    pub token_bundle_payment_fulfillment_arbiter: Address,
    // Non-composing arbiters
    pub expiration_time_after_arbiter_non_composing: Address,
    pub expiration_time_before_arbiter_non_composing: Address,
    pub expiration_time_equal_arbiter_non_composing: Address,
    pub recipient_arbiter_non_composing: Address,
    pub ref_uid_arbiter_non_composing: Address,
    pub revocable_arbiter_non_composing: Address,
    pub schema_arbiter_non_composing: Address,
    pub time_after_arbiter_non_composing: Address,
    pub time_before_arbiter_non_composing: Address,
    pub time_equal_arbiter_non_composing: Address,
    pub uid_arbiter_non_composing: Address,
    // Confirmation arbiters
    pub confirmation_arbiter: Address,
    pub confirmation_arbiter_composing: Address,
    pub revocable_confirmation_arbiter: Address,
    pub revocable_confirmation_arbiter_composing: Address,
    pub unrevocable_confirmation_arbiter: Address,
}

#[derive(Clone)]
pub struct ArbitersModule {
    signer: PrivateKeySigner,
    public_provider: PublicProvider,
    wallet_provider: WalletProvider,

    pub addresses: ArbitersAddresses,
}

impl Default for ArbitersAddresses {
    fn default() -> Self {
        BASE_SEPOLIA_ADDRESSES.arbiters_addresses
    }
}

sol! {
    contract AttesterArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            address attester;
        }
    }
}

sol! {
    contract ExpirationTimeAfterArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 expirationTime;
        }
    }
}

sol! {
    contract ExpirationTimeBeforeArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 expirationTime;
        }
    }
}

sol! {
    contract ExpirationTimeEqualArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 expirationTime;
        }
    }
}

sol! {
    contract RecipientArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            address recipient;
        }
    }
}

sol! {
    contract RefUidArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            bytes32 refUID;
        }
    }
}

sol! {
    contract RevocableArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            bool revocable;
        }
    }
}

sol! {
    contract SchemaArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            bytes32 schema;
        }
    }
}

sol! {
    contract TimeAfterArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 time;
        }
    }
}

sol! {
    contract TimeBeforeArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 time;
        }
    }
}

sol! {
    contract TimeEqualArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 time;
        }
    }
}

sol! {
    contract UidArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            bytes32 uid;
        }
    }
}

impl AlkahestExtension for ArbitersModule {
    type Config = ArbitersAddresses;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        config: Option<Self::Config>,
    ) -> eyre::Result<Self> {
        Self::new(private_key, rpc_url, config).await
    }
}

sol! {
    contract AttesterArbiterNonComposing {
        struct DemandData {
            address attester;
        }
    }
}

sol! {
    contract ExpirationTimeAfterArbiterNonComposing {
        struct DemandData {
            uint64 expirationTime;
        }
    }
}

sol! {
    contract ExpirationTimeBeforeArbiterNonComposing {
        struct DemandData {
            uint64 expirationTime;
        }
    }
}

sol! {
    contract ExpirationTimeEqualArbiterNonComposing {
        struct DemandData {
            uint64 expirationTime;
        }
    }
}

sol! {
    contract RecipientArbiterNonComposing {
        struct DemandData {
            address recipient;
        }
    }
}

sol! {
    contract RefUidArbiterNonComposing {
        struct DemandData {
            bytes32 refUID;
        }
    }
}

sol! {
    contract RevocableArbiterNonComposing {
        struct DemandData {
            bool revocable;
        }
    }
}

sol! {
    contract SchemaArbiterNonComposing {
        struct DemandData {
            bytes32 schema;
        }
    }
}

sol! {
    contract TimeAfterArbiterNonComposing {
        struct DemandData {
            uint64 time;
        }
    }
}

sol! {
    contract TimeBeforeArbiterNonComposing {
        struct DemandData {
            uint64 time;
        }
    }
}

sol! {
    contract TimeEqualArbiterNonComposing {
        struct DemandData {
            uint64 time;
        }
    }
}

sol! {
    contract UidArbiterNonComposing {
        struct DemandData {
            bytes32 uid;
        }
    }
}

// confirmation arbiters

sol! {
    contract ConfirmationArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
        }
    }
}

sol! {
    contract RevocableConfirmationArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
        }
    }
}

sol! {
    contract UnrevocableArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
        }
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

//logical arbiters

sol! {
    contract MultiArbiter {
        // Shared structure for both AnyArbiter and AllArbiter
        struct DemandData {
            address[] arbiters;
            bytes[] demands;
        }
    }
}

sol! {
    contract NotArbiter {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
        }
    }
}

macro_rules! impl_encode_and_decode {
    ($contract:ident, $encode_fn:ident, $decode_fn:ident) => {
        impl ArbitersModule {
            pub fn $encode_fn(demand: &$contract::DemandData) -> Bytes {
                demand.abi_encode().into()
            }

            pub fn $decode_fn(data: &Bytes) -> eyre::Result<$contract::DemandData> {
                Ok($contract::DemandData::abi_decode(data)?)
            }
        }
    };
}
impl_encode_and_decode!(
    AttesterArbiterComposing,
    encode_attester_arbiter_composing_demand,
    decode_attester_arbiter_composing_demand
);
impl_encode_and_decode!(
    ExpirationTimeAfterArbiterComposing,
    encode_expiration_time_after_arbiter_composing_demand,
    decode_expiration_time_after_arbiter_composing_demand
);
impl_encode_and_decode!(
    ExpirationTimeBeforeArbiterComposing,
    encode_expiration_time_before_arbiter_composing_demand,
    decode_expiration_time_before_arbiter_composing_demand
);
impl_encode_and_decode!(
    ExpirationTimeEqualArbiterComposing,
    encode_expiration_time_equal_arbiter_composing_demand,
    decode_expiration_time_equal_arbiter_composing_demand
);
impl_encode_and_decode!(
    RecipientArbiterComposing,
    encode_recipient_arbiter_composing_demand,
    decode_recipient_arbiter_composing_demand
);
impl_encode_and_decode!(
    RefUidArbiterComposing,
    encode_ref_uid_arbiter_composing_demand,
    decode_ref_uid_arbiter_composing_demand
);
impl_encode_and_decode!(
    RevocableArbiterComposing,
    encode_revocable_arbiter_composing_demand,
    decode_revocable_arbiter_composing_demand
);
impl_encode_and_decode!(
    SchemaArbiterComposing,
    encode_schema_arbiter_composing_demand,
    decode_schema_arbiter_composing_demand
);
impl_encode_and_decode!(
    TimeAfterArbiterComposing,
    encode_time_after_arbiter_composing_demand,
    decode_time_after_arbiter_composing_demand
);
impl_encode_and_decode!(
    TimeBeforeArbiterComposing,
    encode_time_before_arbiter_composing_demand,
    decode_time_before_arbiter_composing_demand
);
impl_encode_and_decode!(
    TimeEqualArbiterComposing,
    encode_time_equal_arbiter_composing_demand,
    decode_time_equal_arbiter_composing_demand
);
impl_encode_and_decode!(
    UidArbiterComposing,
    encode_uid_arbiter_composing_demand,
    decode_uid_arbiter_composing_demand
);
impl_encode_and_decode!(
    AttesterArbiterNonComposing,
    encode_attester_arbiter_non_composing_demand,
    decode_attester_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    ExpirationTimeAfterArbiterNonComposing,
    encode_expiration_time_after_arbiter_non_composing_demand,
    decode_expiration_time_after_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    ExpirationTimeBeforeArbiterNonComposing,
    encode_expiration_time_before_arbiter_non_composing_demand,
    decode_expiration_time_before_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    ExpirationTimeEqualArbiterNonComposing,
    encode_expiration_time_equal_arbiter_non_composing_demand,
    decode_expiration_time_equal_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    RecipientArbiterNonComposing,
    encode_recipient_arbiter_non_composing_demand,
    decode_recipient_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    RefUidArbiterNonComposing,
    encode_ref_uid_arbiter_non_composing_demand,
    decode_ref_uid_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    RevocableArbiterNonComposing,
    encode_revocable_arbiter_non_composing_demand,
    decode_revocable_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    SchemaArbiterNonComposing,
    encode_schema_arbiter_non_composing_demand,
    decode_schema_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    TimeAfterArbiterNonComposing,
    encode_time_after_arbiter_non_composing_demand,
    decode_time_after_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    TimeBeforeArbiterNonComposing,
    encode_time_before_arbiter_non_composing_demand,
    decode_time_before_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    TimeEqualArbiterNonComposing,
    encode_time_equal_arbiter_non_composing_demand,
    decode_time_equal_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    UidArbiterNonComposing,
    encode_uid_arbiter_non_composing_demand,
    decode_uid_arbiter_non_composing_demand
);
impl_encode_and_decode!(
    ConfirmationArbiterComposing,
    encode_confirmation_arbiter_composing_demand,
    decode_confirmation_arbiter_composing_demand
);
impl_encode_and_decode!(
    RevocableConfirmationArbiterComposing,
    encode_revocable_confirmation_arbiter_composing_demand,
    decode_revocable_confirmation_arbiter_composing_demand
);
impl_encode_and_decode!(
    UnrevocableArbiterComposing,
    encode_unrevocable_arbiter_composing_demand,
    decode_unrevocable_arbiter_composing_demand
);
impl_encode_and_decode!(
    TrustedPartyArbiter,
    encode_trusted_party_arbiter_demand,
    decode_trusted_party_arbiter_demand
);
impl_encode_and_decode!(
    SpecificAttestationArbiter,
    encode_specific_attestation_arbiter_demand,
    decode_specific_attestation_arbiter_demand
);
impl_encode_and_decode!(
    TrustedOracleArbiter,
    encode_trusted_oracle_arbiter_demand,
    decode_trusted_oracle_arbiter_demand
);
impl_encode_and_decode!(
    IntrinsicsArbiter2,
    encode_intrinsics_arbiter2_demand,
    decode_intrinsics_arbiter2_demand
);
impl_encode_and_decode!(
    MultiArbiter,
    encode_multi_arbiter_demand,
    decode_multi_arbiter_demand
);
impl_encode_and_decode!(
    NotArbiter,
    encode_not_arbiter_demand,
    decode_not_arbiter_demand
);

impl ArbitersModule {
    pub async fn new(
        signer: PrivateKeySigner,
        rpc_url: impl ToString + Clone,
        addresses: Option<ArbitersAddresses>,
    ) -> eyre::Result<Self> {
        let public_provider = utils::get_public_provider(rpc_url.clone()).await?;
        let wallet_provider = utils::get_wallet_provider(signer.clone(), rpc_url.clone()).await?;

        Ok(ArbitersModule {
            signer: signer,
            public_provider: public_provider.clone(),
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    pub async fn arbitrate_as_trusted_oracle(
        &self,
        obligation: FixedBytes<32>,
        decision: bool,
    ) -> eyre::Result<TransactionReceipt> {
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            self.addresses.trusted_oracle_arbiter,
            &self.wallet_provider,
        );

        let receipt = trusted_oracle_arbiter
            .arbitrate(obligation, decision)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn wait_for_trusted_oracle_arbitration(
        &self,
        oracle: Address,
        obligation: FixedBytes<32>,
        from_block: Option<u64>,
    ) -> eyre::Result<Log<contracts::TrustedOracleArbiter::ArbitrationMade>> {
        let filter = Filter::new()
            .from_block(from_block.unwrap_or(0))
            .address(self.addresses.trusted_oracle_arbiter)
            .event_signature(contracts::TrustedOracleArbiter::ArbitrationMade::SIGNATURE_HASH)
            .topic1(obligation)
            .topic2(oracle.into_word());

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
    use crate::extensions::HasArbiters;
    use alloy::{
        primitives::{Address, Bytes, FixedBytes, bytes},
        providers::Provider as _,
        sol,
        sol_types::SolValue,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        clients::arbiters::{
            ArbitersModule, IntrinsicsArbiter2, MultiArbiter, RecipientArbiterComposing,
            SpecificAttestationArbiter, TrustedOracleArbiter, TrustedPartyArbiter,
            UidArbiterComposing,
        },
        contracts,
        utils::setup_test_environment,
    };

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
            test.addresses.arbiters_addresses.trivial_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trivial_arbiter
            .checkObligation(attestation.clone().into(), demand.clone(), counteroffer)
            .call()
            .await?;

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
            .checkObligation(attestation2.into(), demand2, counteroffer2)
            .call()
            .await?;

        // Should still return true
        assert!(
            result2,
            "TrivialArbiter should always return true, even with different values"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_party_arbiter_with_incorrect_creator_original() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let attestation = create_test_attestation(None, None);

        // Create demand data with the correct creator
        let demand_data = TrustedPartyArbiter::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.clone().trivial_arbiter,
            baseDemand: Bytes::from(vec![]),
            creator: test.alice.address(),
        };

        // Encode demand data
        let demand = ArbitersModule::encode_trusted_party_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check obligation should revert with NotTrustedParty
        let trusted_party_arbiter = contracts::TrustedPartyArbiter::new(
            test.addresses.arbiters_addresses.trusted_party_arbiter,
            &test.bob_client.wallet_provider,
        );

        // Call with Bob as the sender (different from demand_data.creator which is Alice)
        let result = trusted_party_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await;

        // We expect this to revert because Bob is not the creator
        assert!(
            result.is_err(),
            "TrustedPartyArbiter should revert with incorrect creator"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_recipient_arbiter_with_incorrect_recipient() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation with Bob as recipient
        let bob_address = test.bob.address();
        let attestation = create_test_attestation(None, Some(bob_address));

        // Create demand data expecting Alice as recipient
        let alice_address = test.alice.address();
        let demand_data = RecipientArbiterComposing::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.clone().trivial_arbiter,
            baseDemand: Bytes::from(vec![]),
            recipient: alice_address, // Different from attestation.recipient which is Bob
        };

        // Encode demand data
        let demand = ArbitersModule::encode_recipient_arbiter_composing_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Create RecipientArbiter contract instance
        let recipient_arbiter = contracts::RecipientArbiter::new(
            test.addresses.arbiters_addresses.recipient_arbiter,
            &test.alice_client.public_provider,
        );

        // Call check_obligation - should revert with RecipientMismatched
        let result = recipient_arbiter
            .checkObligation(attestation.clone().into(), demand, counteroffer)
            .call()
            .await;

        // We expect this to revert because recipient mismatch
        assert!(
            result.is_err(),
            "RecipientArbiter should revert with incorrect recipient"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_recipient_arbiter_with_correct_recipient() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let recipient = test.alice.address();
        let attestation = create_test_attestation(None, Some(recipient));

        // Create demand data with the correct recipient and TrivialArbiter as base arbiter
        let demand_data = RecipientArbiterComposing::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.clone().trivial_arbiter,
            baseDemand: Bytes::from(vec![]),
            recipient,
        };

        // Encode demand data
        let demand = ArbitersModule::encode_recipient_arbiter_composing_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check obligation should return true
        let recipient_arbiter = contracts::RecipientArbiter::new(
            test.addresses.arbiters_addresses.recipient_arbiter,
            &test.alice_client.public_provider,
        );

        // Call check_obligation
        let result = recipient_arbiter
            .checkObligation(attestation.clone().into(), demand, counteroffer)
            .call()
            .await?;

        assert!(
            result,
            "RecipientArbiter should return true with correct recipient"
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
            baseArbiter: test.addresses.clone().arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::default(),
            creator,
        };

        // Encode the demand data
        let demand = ArbitersModule::encode_trusted_party_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check obligation should revert with NotTrustedParty
        let trusted_party_arbiter = contracts::TrustedPartyArbiter::new(
            test.addresses.arbiters_addresses.trusted_party_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_party_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
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

        let obligation_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Create an attestation with the obligation UID
        let attestation = create_test_attestation(Some(obligation_uid), None);

        // Create demand data with oracle as bob
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check obligation - should be false initially since no decision has been made
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses.arbiters_addresses.trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_oracle_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await?;

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

        let obligation_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Create an attestation with the obligation UID
        let attestation = create_test_attestation(Some(obligation_uid), None);

        // Create demand data with oracle as bob
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check contract interface
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses.arbiters_addresses.trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        // Initially the decision should be false (default value)
        let initial_result = trusted_oracle_arbiter
            .checkObligation(attestation.clone().into(), demand.clone(), counteroffer)
            .call()
            .await?;

        assert!(!initial_result, "Decision should initially be false");

        // Make a positive arbitration decision using our client
        let arbitrate_hash = test
            .bob_client
            .arbiters()
            .arbitrate_as_trusted_oracle(obligation_uid, true)
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
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await?;

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

        let obligation_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Set up two different oracles
        let oracle1 = test.bob.address();
        let oracle2 = test.alice.address();

        // Oracle 1 (Bob) makes a positive decision
        let arbitrate_hash1 = test
            .bob_client
            .arbiters()
            .arbitrate_as_trusted_oracle(obligation_uid, true)
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
            .arbiters()
            .arbitrate_as_trusted_oracle(obligation_uid, false)
            .await?
            .transaction_hash;

        // Wait for transaction receipt
        let _receipt2 = test
            .alice_client
            .public_provider
            .get_transaction_receipt(arbitrate_hash2)
            .await?;

        // Create the attestation
        let attestation = create_test_attestation(Some(obligation_uid), None);
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses.arbiters_addresses.trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        // Check with oracle1 (Bob) - should be true
        let demand_data1 = TrustedOracleArbiter::DemandData {
            oracle: oracle1,
            data: bytes!(""),
        };
        let demand1 = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data1);
        let counteroffer = FixedBytes::<32>::default();

        let result1 = trusted_oracle_arbiter
            .checkObligation(attestation.clone().into(), demand1, counteroffer)
            .call()
            .await?;

        assert!(result1, "Decision for Oracle 1 (Bob) should be true");

        // Check with oracle2 (Alice) - should be false
        let demand_data2 = TrustedOracleArbiter::DemandData {
            oracle: oracle2,
            data: bytes!(""),
        };
        let demand2 = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data2);

        let result2 = trusted_oracle_arbiter
            .checkObligation(attestation.into(), demand2, counteroffer)
            .call()
            .await?;

        assert!(!result2, "Decision for Oracle 2 (Alice) should be false");

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_oracle_arbiter_with_no_decision() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a new oracle address that hasn't made a decision
        let new_oracle = Address::from_slice(&[0x42; 20]);
        let obligation_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Create the attestation
        let attestation = create_test_attestation(Some(obligation_uid), None);

        // Create demand data with the new oracle
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: new_oracle,
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check with the new oracle - should be false (default value)
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses.arbiters_addresses.trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_oracle_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await?;

        assert!(
            !result,
            "Decision for an oracle that hasn't made a decision should be false"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_specific_attestation_arbiter_with_incorrect_uid_original() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create demand data with non-matching UID
        let different_uid = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let demand_data = SpecificAttestationArbiter::DemandData { uid: different_uid };

        // Encode the demand data
        let encoded = ArbitersModule::encode_specific_attestation_arbiter_demand(&demand_data);

        // Check obligation should revert with NotDemandedAttestation
        let specific_attestation_arbiter = contracts::SpecificAttestationArbiter::new(
            test.addresses
                .arbiters_addresses
                .specific_attestation_arbiter,
            &test.alice_client.public_provider,
        );

        let result = specific_attestation_arbiter
            .checkObligation(attestation.clone().into(), encoded, FixedBytes::<32>::ZERO)
            .call()
            .await;

        assert!(
            result.is_err(),
            "SpecificAttestationArbiter should revert with incorrect UID"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_uid_arbiter_with_incorrect_uid() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create demand data with non-matching UID
        let different_uid = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let trivial_arbiter = test.addresses.arbiters_addresses.clone().trivial_arbiter;
        let demand_data = UidArbiterComposing::DemandData {
            baseArbiter: trivial_arbiter,
            baseDemand: Bytes::default(),
            uid: different_uid,
        };

        // Encode the demand data
        let encoded = ArbitersModule::encode_uid_arbiter_composing_demand(&demand_data);

        // Check obligation should revert with UidMismatched
        let uid_arbiter_address = test.addresses.arbiters_addresses.clone().uid_arbiter;
        let uid_arbiter = contracts::extended_uid_arbiters::composing::UidArbiterComposing::new(
            uid_arbiter_address,
            &test.alice_client.public_provider,
        );

        let result = uid_arbiter
            .checkObligation(attestation.clone().into(), encoded, FixedBytes::<32>::ZERO)
            .call()
            .await;

        assert!(
            result.is_err(),
            "UidArbiter should revert with incorrect UID"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_uid_arbiter_with_correct_uid() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create demand data with matching UID and use trivialArbiter as the baseArbiter
        let trivial_arbiter = test.addresses.arbiters_addresses.clone().trivial_arbiter;
        let demand_data = UidArbiterComposing::DemandData {
            baseArbiter: trivial_arbiter,
            baseDemand: Bytes::default(),
            uid,
        };

        // Encode the demand data
        let encoded = ArbitersModule::encode_uid_arbiter_composing_demand(&demand_data);

        // Check obligation - should return true
        let uid_arbiter_address = test.addresses.arbiters_addresses.clone().uid_arbiter;
        let uid_arbiter = contracts::extended_uid_arbiters::composing::UidArbiterComposing::new(
            uid_arbiter_address,
            &test.alice_client.public_provider,
        );
        let result = uid_arbiter
            .checkObligation(attestation.clone().into(), encoded, FixedBytes::<32>::ZERO)
            .call()
            .await?;

        assert!(result, "UidArbiter should return true with matching UID");

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
        let demand = ArbitersModule::encode_specific_attestation_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check obligation should revert with NotDemandedAttestation
        let specific_attestation_arbiter = contracts::SpecificAttestationArbiter::new(
            test.addresses
                .arbiters_addresses
                .specific_attestation_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = specific_attestation_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
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
        let base_arbiter = test.addresses.arbiters_addresses.trivial_arbiter;

        let demand_data = TrustedPartyArbiter::DemandData {
            baseArbiter: base_arbiter,
            baseDemand: Bytes::from(vec![1, 2, 3]),
            creator,
        };

        // Encode the demand data
        let encoded = ArbitersModule::encode_trusted_party_arbiter_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_trusted_party_arbiter_demand(&encoded)?;

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
    async fn test_encode_and_decode_specific_attestation_arbiter_demand() -> eyre::Result<()> {
        // Setup test environment
        let _test = setup_test_environment().await?;

        // Create a test demand data
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let demand_data = SpecificAttestationArbiter::DemandData { uid };

        // Encode the demand data
        let encoded = ArbitersModule::encode_specific_attestation_arbiter_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_specific_attestation_arbiter_demand(&encoded)?;

        // Verify the data was encoded and decoded correctly
        assert_eq!(decoded.uid, uid, "UID did not round-trip correctly");

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_uid_arbiter_composing_demand() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test demand data
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let trivial_arbiter = test.addresses.arbiters_addresses.clone().trivial_arbiter;
        let demand_data = UidArbiterComposing::DemandData {
            baseArbiter: trivial_arbiter,
            baseDemand: Bytes::default(),
            uid,
        };

        // Encode the demand data
        let encoded = ArbitersModule::encode_uid_arbiter_composing_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_uid_arbiter_composing_demand(&encoded)?;

        // Verify the data was encoded and decoded correctly
        assert_eq!(decoded.uid, uid, "UID did not round-trip correctly");

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_recipient_arbiter_demand() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test demand data
        let base_arbiter = test.addresses.arbiters_addresses.trivial_arbiter;
        let base_demand = Bytes::from(vec![1, 2, 3]);
        let recipient = test.alice.address();

        let demand_data = RecipientArbiterComposing::DemandData {
            baseArbiter: base_arbiter,
            baseDemand: base_demand.clone(),
            recipient,
        };

        // Encode the demand data
        let encoded = ArbitersModule::encode_recipient_arbiter_composing_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_recipient_arbiter_composing_demand(&encoded)?;

        // Verify the data was encoded and decoded correctly
        assert_eq!(
            decoded.baseArbiter, base_arbiter,
            "Base arbiter did not round-trip correctly"
        );
        assert_eq!(
            decoded.baseDemand, base_demand,
            "Base demand did not round-trip correctly"
        );
        assert_eq!(
            decoded.recipient, recipient,
            "Recipient did not round-trip correctly"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_trusted_oracle_arbiter_demand() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test demand data
        let oracle = test.bob.address();
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle,
            data: bytes!(""),
        };

        // Encode the demand data
        let encoded = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_trusted_oracle_arbiter_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(decoded.oracle, oracle, "Oracle should match");

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_wait_for_trusted_oracle_arbitration() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        let obligation_uid = FixedBytes::<32>::from_slice(&[42u8; 32]);
        let oracle = test.bob.address();

        // Start listening for arbitration events in the background
        let listener_task = tokio::spawn({
            let alice_client = test.alice_client.clone();
            let obligation_uid = obligation_uid.clone();
            async move {
                alice_client
                    .extensions
                    .arbiters()
                    .wait_for_trusted_oracle_arbitration(oracle, obligation_uid, None)
                    .await
            }
        });

        // Ensure the listener is running
        // tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Make an arbitration decision
        let arbitrate_hash = test
            .bob_client
            .extensions
            .arbiters()
            .arbitrate_as_trusted_oracle(obligation_uid, true)
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
            log_result.obligation, obligation_uid,
            "Obligation UID in event should match"
        );
        assert!(log_result.decision, "Decision in event should be true");

        Ok(())
    }

    #[tokio::test]
    async fn test_intrinsics_arbiter() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a valid non-expired attestation
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create a valid attestation (not expired, not revoked)
        let valid_attestation = contracts::IEAS::Attestation {
            uid: FixedBytes::<32>::from_slice(&[1u8; 32]),
            schema: FixedBytes::<32>::from_slice(&[2u8; 32]),
            time: now.into(),
            expirationTime: (now + 3600).into(), // expires in 1 hour
            revocationTime: 0u64.into(),         // not revoked
            refUID: FixedBytes::<32>::default(),
            recipient: Address::default(),
            attester: Address::default(),
            revocable: true,
            data: Bytes::default(),
        };

        // Create an expired attestation
        let expired_attestation = contracts::IEAS::Attestation {
            expirationTime: (now - 3600).into(), // expired 1 hour ago
            ..valid_attestation.clone()
        };

        // Create a revoked attestation
        let revoked_attestation = contracts::IEAS::Attestation {
            revocationTime: (now - 3600).into(), // revoked 1 hour ago
            ..valid_attestation.clone()
        };

        // Test with IntrinsicsArbiter
        let intrinsics_arbiter = contracts::IntrinsicsArbiter::new(
            test.addresses.arbiters_addresses.intrinsics_arbiter,
            &test.alice_client.wallet_provider,
        );

        // Valid attestation should pass
        let result_valid = intrinsics_arbiter
            .checkObligation(
                valid_attestation.into(),
                Bytes::default(),
                FixedBytes::<32>::default(),
            )
            .call()
            .await?;
        assert!(
            result_valid,
            "Valid attestation should pass intrinsic checks"
        );

        // Expired attestation should fail
        let result_expired = intrinsics_arbiter
            .checkObligation(
                expired_attestation.into(),
                Bytes::default(),
                FixedBytes::<32>::default(),
            )
            .call()
            .await;

        assert!(
            result_expired.is_err(),
            "Expired attestation should fail intrinsic checks"
        );

        // Revoked attestation should fail
        let result_revoked = intrinsics_arbiter
            .checkObligation(
                revoked_attestation.into(),
                Bytes::default(),
                FixedBytes::<32>::default(),
            )
            .call()
            .await;

        assert!(
            result_revoked.is_err(),
            "Revoked attestation should fail intrinsic checks"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_intrinsics_arbiter_2() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Define schemas
        let schema1 = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let schema2 = FixedBytes::<32>::from_slice(&[2u8; 32]);

        // Create a valid attestation with schema1
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let valid_attestation = contracts::IEAS::Attestation {
            uid: FixedBytes::<32>::from_slice(&[1u8; 32]),
            schema: schema1,
            time: now.into(),
            expirationTime: (now + 3600).into(), // expires in 1 hour
            revocationTime: 0u64.into(),         // not revoked
            refUID: FixedBytes::<32>::default(),
            recipient: Address::default(),
            attester: Address::default(),
            revocable: true,
            data: Bytes::default(),
        };

        // Test with IntrinsicsArbiter2
        let intrinsics_arbiter2 = contracts::IntrinsicsArbiter2::new(
            test.addresses.arbiters_addresses.intrinsics_arbiter_2,
            &test.alice_client.wallet_provider,
        );

        // Create demand with matching schema
        let matching_demand = IntrinsicsArbiter2::DemandData { schema: schema1 };
        let encoded_matching_demand =
            ArbitersModule::encode_intrinsics_arbiter2_demand(&matching_demand);

        // Create demand with non-matching schema
        let non_matching_demand = IntrinsicsArbiter2::DemandData { schema: schema2 };
        let encoded_non_matching_demand =
            ArbitersModule::encode_intrinsics_arbiter2_demand(&non_matching_demand);

        // Test with matching schema - should pass
        let result_matching = intrinsics_arbiter2
            .checkObligation(
                valid_attestation.clone().into(),
                encoded_matching_demand,
                FixedBytes::<32>::default(),
            )
            .call()
            .await?;
        assert!(
            result_matching,
            "Attestation with matching schema should pass"
        );

        // Test with non-matching schema - should fail
        let result_non_matching = intrinsics_arbiter2
            .checkObligation(
                valid_attestation.into(),
                encoded_non_matching_demand,
                FixedBytes::<32>::default(),
            )
            .call()
            .await;

        assert!(
            result_non_matching.is_err(),
            "Attestation with non-matching schema should fail"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_any_arbiter() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Get arbiter addresses
        let addresses = test.addresses.arbiters_addresses;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create different demand data for different arbiters

        // SpecificAttestationArbiter with matching UID (will return true)
        let specific_matching = SpecificAttestationArbiter::DemandData { uid };
        let specific_matching_encoded =
            ArbitersModule::encode_specific_attestation_arbiter_demand(&specific_matching);

        // SpecificAttestationArbiter with non-matching UID (will return false/error)
        let non_matching_uid = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let specific_non_matching = SpecificAttestationArbiter::DemandData {
            uid: non_matching_uid,
        };
        let specific_non_matching_encoded =
            ArbitersModule::encode_specific_attestation_arbiter_demand(&specific_non_matching);

        // Set up AnyArbiter with two arbiters
        let any_arbiter =
            contracts::AnyArbiter::new(addresses.any_arbiter, &test.alice_client.wallet_provider);

        // Test case 1: One true, one false - should return true
        let any_demand_data1 = MultiArbiter::DemandData {
            arbiters: vec![
                addresses.trivial_arbiter,              // Always returns true
                addresses.specific_attestation_arbiter, // Will return false with non-matching UID
            ],
            demands: vec![
                Bytes::default(),                      // Empty data for TrivialArbiter
                specific_non_matching_encoded.clone(), // Non-matching UID for SpecificAttestationArbiter
            ],
        };

        let any_demand1 = ArbitersModule::encode_multi_arbiter_demand(&any_demand_data1);
        let result_any1 = any_arbiter
            .checkObligation(
                attestation.clone().into(),
                any_demand1,
                FixedBytes::<32>::default(),
            )
            .call()
            .await?;

        assert!(
            result_any1,
            "AnyArbiter should return true if any arbiter returns true"
        );

        // Test case 2: Both false - should return false
        let any_demand_data2 = MultiArbiter::DemandData {
            arbiters: vec![
                addresses.specific_attestation_arbiter, // Will return false with non-matching UID
                addresses.specific_attestation_arbiter, // Will return false with non-matching UID
            ],
            demands: vec![
                specific_non_matching_encoded.clone(), // Non-matching UID
                specific_non_matching_encoded,         // Non-matching UID
            ],
        };

        let any_demand2 = ArbitersModule::encode_multi_arbiter_demand(&any_demand_data2);
        let result_any2 = any_arbiter
            .checkObligation(
                attestation.clone().into(),
                any_demand2,
                FixedBytes::<32>::default(),
            )
            .call()
            .await;

        // Should fail since both arbiters would fail
        assert!(
            result_any2.is_err() || !result_any2.unwrap(),
            "AnyArbiter should return false if all arbiters return false"
        );

        // Test case 3: All true - should return true
        let any_demand_data3 = MultiArbiter::DemandData {
            arbiters: vec![
                addresses.trivial_arbiter,              // Always returns true
                addresses.specific_attestation_arbiter, // Will return true with matching UID
            ],
            demands: vec![
                Bytes::default(),          // Empty data for TrivialArbiter
                specific_matching_encoded, // Matching UID for SpecificAttestationArbiter
            ],
        };

        let any_demand3 = ArbitersModule::encode_multi_arbiter_demand(&any_demand_data3);
        let result_any3 = any_arbiter
            .checkObligation(attestation.into(), any_demand3, FixedBytes::<32>::default())
            .call()
            .await?;

        assert!(
            result_any3,
            "AnyArbiter should return true if all arbiters return true"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_all_arbiter() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Get arbiter addresses
        let addresses = test.addresses.arbiters_addresses;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create different demand data for different arbiters

        // SpecificAttestationArbiter with matching UID (will return true)
        let specific_matching = SpecificAttestationArbiter::DemandData { uid };
        let specific_matching_encoded =
            ArbitersModule::encode_specific_attestation_arbiter_demand(&specific_matching);

        // SpecificAttestationArbiter with non-matching UID (will return false/error)
        let non_matching_uid = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let specific_non_matching = SpecificAttestationArbiter::DemandData {
            uid: non_matching_uid,
        };
        let specific_non_matching_encoded =
            ArbitersModule::encode_specific_attestation_arbiter_demand(&specific_non_matching);

        // Set up AllArbiter
        let all_arbiter =
            contracts::AllArbiter::new(addresses.all_arbiter, &test.alice_client.wallet_provider);

        // Test case 1: One true, one false - should return false
        let all_demand_data1 = MultiArbiter::DemandData {
            arbiters: vec![
                addresses.trivial_arbiter,              // Always returns true
                addresses.specific_attestation_arbiter, // Will return false with non-matching UID
            ],
            demands: vec![
                Bytes::default(),                      // Empty data for TrivialArbiter
                specific_non_matching_encoded.clone(), // Non-matching UID for SpecificAttestationArbiter
            ],
        };

        let all_demand1 = ArbitersModule::encode_multi_arbiter_demand(&all_demand_data1);
        let result_all1 = all_arbiter
            .checkObligation(
                attestation.clone().into(),
                all_demand1,
                FixedBytes::<32>::default(),
            )
            .call()
            .await;

        // Should fail since one arbiter would fail
        assert!(
            result_all1.is_err(),
            "AllArbiter should return false if any arbiter returns false"
        );

        // Test case 2: All true - should return true
        let all_demand_data2 = MultiArbiter::DemandData {
            arbiters: vec![
                addresses.trivial_arbiter,              // Always returns true
                addresses.specific_attestation_arbiter, // Will return true with matching UID
            ],
            demands: vec![
                Bytes::default(),          // Empty data for TrivialArbiter
                specific_matching_encoded, // Matching UID for SpecificAttestationArbiter
            ],
        };

        let all_demand2 = ArbitersModule::encode_multi_arbiter_demand(&all_demand_data2);
        let result_all2 = all_arbiter
            .checkObligation(
                attestation.clone().into(),
                all_demand2,
                FixedBytes::<32>::default(),
            )
            .call()
            .await?;

        assert!(
            result_all2,
            "AllArbiter should return true if all arbiters return true"
        );

        // Test case 3: Empty arbiters list - should return true (vacuously true)
        let all_demand_data3 = MultiArbiter::DemandData {
            arbiters: vec![],
            demands: vec![],
        };

        let all_demand3 = ArbitersModule::encode_multi_arbiter_demand(&all_demand_data3);
        let result_all3 = all_arbiter
            .checkObligation(attestation.into(), all_demand3, FixedBytes::<32>::default())
            .call()
            .await?;

        assert!(
            result_all3,
            "AllArbiter should return true with empty arbiters list"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_intrinsics_arbiter2_demand() -> eyre::Result<()> {
        // Create a test demand data
        let schema = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let demand_data = IntrinsicsArbiter2::DemandData { schema };

        // Encode the demand data
        let encoded = ArbitersModule::encode_intrinsics_arbiter2_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_intrinsics_arbiter2_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(decoded.schema, schema, "Schema should match");

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_multi_demand() -> eyre::Result<()> {
        // Set up test environment
        let test = setup_test_environment().await?;

        // Get arbiter addresses
        let addresses = test.addresses.arbiters_addresses;

        // Create a test demand data
        let arbiters = vec![
            addresses.trivial_arbiter,
            addresses.specific_attestation_arbiter,
        ];
        let demands = vec![Bytes::default(), Bytes::from(vec![1, 2, 3])];

        let demand_data = MultiArbiter::DemandData { arbiters, demands };

        // Encode the demand data
        let encoded = ArbitersModule::encode_multi_arbiter_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_multi_arbiter_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(
            decoded.arbiters.len(),
            demand_data.arbiters.len(),
            "Number of arbiters should match"
        );
        assert_eq!(
            decoded.demands.len(),
            demand_data.demands.len(),
            "Number of demands should match"
        );

        for i in 0..decoded.arbiters.len() {
            assert_eq!(
                decoded.arbiters[i], demand_data.arbiters[i],
                "Arbiter address should match"
            );
            assert_eq!(
                decoded.demands[i], demand_data.demands[i],
                "Demand data should match"
            );
        }

        Ok(())
    }
}
