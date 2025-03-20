use alloy::primitives::{address, Address};
use alloy::primitives::{Bytes, FixedBytes};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue as _;

use crate::addresses::FILECOIN_CALIBRATION_ADDRESSES;
use crate::contracts::IEAS::Attestation;
use crate::contracts::{self, IEAS};
use crate::types::ArbiterData;
use crate::{types::WalletProvider, utils};

#[derive(Debug, Clone)]
pub struct AttestationAddresses {
    pub eas: Address,
    pub eas_schema_registry: Address,
    pub barter_utils: Address,
    pub escrow_obligation: Address,
    pub escrow_obligation_2: Address,
}

#[derive(Clone)]
pub struct AttestationClient {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    pub addresses: AttestationAddresses,
}

impl Default for AttestationAddresses {
    fn default() -> Self {
        FILECOIN_CALIBRATION_ADDRESSES
            .attestation_addresses
            .unwrap()
    }
}

impl AttestationClient {
    /// Creates a new AttestationClient instance.
    ///
    /// # Arguments
    /// * `private_key` - The private key for signing transactions
    /// * `rpc_url` - The RPC endpoint URL
    /// * `addresses` - Optional custom contract addresses
    pub async fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<AttestationAddresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider =
            utils::get_wallet_provider(private_key.clone(), rpc_url.clone()).await?;

        Ok(AttestationClient {
            signer: private_key.to_string().parse()?,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    /// Decodes AttestationEscrowObligation.StatementData from bytes.
    ///
    /// # Arguments
    /// * `statement_data` - The statement data
    ///
    /// # Returns
    /// * `Result<contracts::AttestationEscrowObligation::StatementData>` - The decoded statement data
    pub fn decode_escrow_statement(
        statement_data: Bytes,
    ) -> eyre::Result<contracts::AttestationEscrowObligation::StatementData> {
        let statement_data = contracts::AttestationEscrowObligation::StatementData::abi_decode(
            statement_data.as_ref(),
            true,
        )?;
        return Ok(statement_data);
    }

    /// Decodes AttestationEscrowObligation2.StatementData from bytes.
    ///
    /// # Arguments
    /// * `statement_data` - The statement data
    ///
    /// # Returns
    /// * `Result<contracts::AttestationEscrowObligation2::StatementData>` - The decoded statement data
    pub fn decode_escrow_statement_2(
        statement_data: Bytes,
    ) -> eyre::Result<contracts::AttestationEscrowObligation2::StatementData> {
        let statement_data = contracts::AttestationEscrowObligation2::StatementData::abi_decode(
            statement_data.as_ref(),
            true,
        )?;
        return Ok(statement_data);
    }

    /// Retrieves an attestation by its UID.
    ///
    /// # Arguments
    /// * `uid` - The unique identifier of the attestation
    pub async fn get_attestation(&self, uid: FixedBytes<32>) -> eyre::Result<Attestation> {
        let eas_contract = contracts::IEAS::new(self.addresses.eas, &self.wallet_provider);

        let attestation = eas_contract.getAttestation(uid).call().await?._0;
        Ok(attestation)
    }

    /// Registers a new schema in the EAS Schema Registry.
    ///
    /// # Arguments
    /// * `schema` - The schema string defining the attestation structure
    /// * `resolver` - The address of the resolver contract
    /// * `revocable` - Whether attestations using this schema can be revoked
    pub async fn register_schema(
        &self,
        schema: String,
        resolver: Address,
        revocable: bool,
    ) -> eyre::Result<TransactionReceipt> {
        let schema_registry_contract = contracts::ISchemaRegistry::new(
            self.addresses.eas_schema_registry,
            &self.wallet_provider,
        );

        let receipt = schema_registry_contract
            .register(schema, resolver, revocable)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates a new attestation using the EAS contract.
    ///
    /// # Arguments
    /// * `attestation` - The attestation request data
    pub async fn attest(
        &self,
        attestation: IEAS::AttestationRequest,
    ) -> eyre::Result<TransactionReceipt> {
        let eas_contract = contracts::IEAS::new(self.addresses.eas, &self.wallet_provider);

        let receipt = eas_contract
            .attest(attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Collects payment from an attestation escrow by providing a fulfillment attestation.
    /// This function is used with the original AttestationEscrowObligation contract.
    ///
    /// # Arguments
    /// * `buy_attestation` - The UID of the escrow attestation
    /// * `fulfillment` - The UID of the fulfillment attestation
    pub async fn collect_payment(
        &self,
        buy_attestation: FixedBytes<32>,
        fulfillment: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let escrow_contract = contracts::AttestationEscrowObligation::new(
            self.addresses.escrow_obligation,
            &self.wallet_provider,
        );

        let receipt = escrow_contract
            .collectPayment(buy_attestation, fulfillment)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Collects payment from an attestation escrow by providing a fulfillment attestation.
    /// This function is used with AttestationEscrowObligation2 and creates a validation
    /// attestation referencing the original attestation.
    ///
    /// # Arguments
    /// * `buy_attestation` - The UID of the escrow attestation
    /// * `fulfillment` - The UID of the fulfillment attestation
    pub async fn collect_payment_2(
        &self,
        buy_attestation: FixedBytes<32>,
        fulfillment: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let escrow_contract = contracts::AttestationEscrowObligation2::new(
            self.addresses.escrow_obligation_2,
            &self.wallet_provider,
        );

        let receipt = escrow_contract
            .collectPayment(buy_attestation, fulfillment)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow using an attestation as the escrowed item.
    /// This function uses the original AttestationEscrowObligation contract where the full attestation
    /// data is stored in the escrow statement. When collecting payment, this contract creates a new
    /// attestation as the collection event, requiring the contract to have attestation rights.
    ///
    /// # Arguments
    /// * `attestation` - The attestation data to be escrowed
    /// * `demand` - The arbiter and demand data for the escrow
    /// * `expiration` - Optional expiration time for the escrow (default: 0 = no expiration)
    pub async fn create_escrow(
        &self,
        attestation: IEAS::AttestationRequest,
        demand: ArbiterData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let attestation_escrow_obligation_contract = contracts::AttestationEscrowObligation::new(
            self.addresses.escrow_obligation,
            &self.wallet_provider,
        );

        let receipt = attestation_escrow_obligation_contract
            .makeStatement(
                contracts::AttestationEscrowObligation::StatementData {
                    attestation: attestation.into(),
                    arbiter: demand.arbiter,
                    demand: demand.demand,
                },
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow using an attestation UID as reference.
    /// This function uses AttestationEscrowObligation2 which references the attestation by UID
    /// instead of storing the full attestation data, making it more gas efficient. When collecting
    /// payment, this contract creates a validation attestation that references the original attestation,
    /// allowing it to work with any schema implementation without requiring attestation rights.
    ///
    /// # Arguments
    /// * `attestation` - The UID of the attestation to be escrowed
    /// * `demand` - The arbiter and demand data for the escrow
    /// * `expiration` - Optional expiration time for the escrow (default: 0 = no expiration)
    pub async fn create_escrow_2(
        &self,
        attestation: FixedBytes<32>,
        demand: ArbiterData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let attestation_escrow_obligation_2_contract = contracts::AttestationEscrowObligation2::new(
            self.addresses.escrow_obligation_2,
            &self.wallet_provider,
        );

        let receipt = attestation_escrow_obligation_2_contract
            .makeStatement(
                contracts::AttestationEscrowObligation2::StatementData {
                    attestationUid: attestation,
                    arbiter: demand.arbiter,
                    demand: demand.demand,
                },
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an attestation and immediately escrows it in a single transaction.
    /// This is a convenience function that combines createAttestation and createEscrow.
    ///
    /// # Arguments
    /// * `attestation` - The attestation data to create and escrow
    /// * `demand` - The escrow parameters including arbiter and demand
    /// * `expiration` - Optional expiration time for the escrow
    pub async fn attest_and_create_escrow(
        &self,
        attestation: IEAS::AttestationRequest,
        demand: ArbiterData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::AttestationBarterUtils::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .attestAndCreateEscrow(
                attestation.into(),
                demand.arbiter,
                demand.demand,
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }
}
