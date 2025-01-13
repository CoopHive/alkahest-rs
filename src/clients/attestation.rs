use alloy::primitives::FixedBytes;
use alloy::primitives::{address, Address};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;

use crate::contracts::{self, IEAS};
use crate::types::ArbiterData;
use crate::{types::WalletProvider, utils};

#[derive(Debug, Clone)]
pub struct AttestationAddresses {
    eas: Address,
    eas_schema_registry: Address,
    barter_utils: Address,
    escrow_obligation: Address,
    escrow_obligation_2: Address,
}

pub struct AttestationClient {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    addresses: AttestationAddresses,
}

impl Default for AttestationAddresses {
    fn default() -> Self {
        Self {
            eas: address!("4200000000000000000000000000000000000021"),
            eas_schema_registry: address!("4200000000000000000000000000000000000020"),
            barter_utils: address!("3A40F65D2589a43Dc057bf820D8626F87D95307c"),
            escrow_obligation: address!("248cd93922eBDf962c9ea10286E6566C75081948"),
            escrow_obligation_2: address!("702fab66515b3313dFd41E7CE70C2aF0033E2356"),
        }
    }
}

impl AttestationClient {
    pub fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<AttestationAddresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(private_key.clone(), rpc_url.clone())?;

        Ok(AttestationClient {
            signer: private_key.to_string().parse()?,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

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
