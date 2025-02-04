use alloy::primitives::FixedBytes;
use alloy::primitives::{address, Address};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;

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
        Self {
            eas: address!("0x4200000000000000000000000000000000000021"),
            eas_schema_registry: address!("0x4200000000000000000000000000000000000020"),
            barter_utils: address!("0x3C905a7121fb72a4D69Ca8860a93530A88E92f87"),
            escrow_obligation: address!("0x63E8031DA08f6852Abe7bDc4C056903C7863cb7c"),
            escrow_obligation_2: address!("0x4200637A112ba709Fe4a5fe315128879a8Bf4082"),
        }
    }
}

impl AttestationClient {
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

    pub async fn get_attestation(&self, uid: FixedBytes<32>) -> eyre::Result<Attestation> {
        let eas_contract = contracts::IEAS::new(self.addresses.eas, &self.wallet_provider);

        let attestation = eas_contract.getAttestation(uid).call().await?._0;
        Ok(attestation)
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
