use alloy::primitives::{address, Address, Bytes, FixedBytes};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue as _;

use crate::contracts::{self};
use crate::types::{ArbiterData, TokenBundleData};
use crate::{types::WalletProvider, utils};

#[derive(Debug, Clone)]
pub struct TokenBundleAddresses {
    pub eas: Address,
    pub barter_utils: Address,
    pub escrow_obligation: Address,
    pub payment_obligation: Address,
}

/// Client for interacting with token bundle trading and escrow functionality.
///
/// This client provides methods for:
/// - Trading token bundles for other token bundles
/// - Creating escrow arrangements with custom demands
/// - Managing token bundle payments
/// - Collecting payments from fulfilled trades
#[derive(Clone)]
pub struct TokenBundleClient {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    pub addresses: TokenBundleAddresses,
}

impl Default for TokenBundleAddresses {
    fn default() -> Self {
        Self {
            eas: address!("0x4200000000000000000000000000000000000021"),
            barter_utils: address!("0x013C2c98Be06b48f271BdF0469eFa6e89d37BA7A"),
            escrow_obligation: address!("0xc282ec5E2585dc1696471adf4A9f5b3a151359c9"),
            payment_obligation: address!("0x797C365B6A1300c13001a6D0FDF2ea0684b5BCcD"),
        }
    }
}

impl TokenBundleClient {
    /// Creates a new TokenBundleClient instance.
    ///
    /// # Arguments
    /// * `private_key` - The private key for signing transactions
    /// * `rpc_url` - The RPC endpoint URL
    /// * `addresses` - Optional custom contract addresses, uses defaults if None
    ///
    /// # Returns
    /// * `Result<Self>` - The initialized client instance
    pub async fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<TokenBundleAddresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider =
            utils::get_wallet_provider(private_key.clone(), rpc_url.clone()).await?;

        Ok(TokenBundleClient {
            signer: private_key.to_string().parse()?,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    /// Decodes TokenBundleEscrowObligation.StatementData from bytes.
    ///
    /// # Arguments
    /// * `statement_data` - The statement data
    ///
    /// # Returns
    /// * `Result<contracts::TokenBundleEscrowObligation::StatementData>` - The decoded statement data
    pub fn decode_escrow_statement(
        statement_data: Bytes,
    ) -> eyre::Result<contracts::TokenBundleEscrowObligation::StatementData> {
        let statement_data = contracts::TokenBundleEscrowObligation::StatementData::abi_decode(
            statement_data.as_ref(),
            true,
        )?;
        return Ok(statement_data);
    }

    /// Decodes TokenBundlePaymentObligation.StatementData from bytes.
    ///
    /// # Arguments
    ///
    /// * `statement_data` - The statement data
    ///
    /// # Returns
    ///
    /// * `eyre::Result<contracts::TokenBundlePaymentObligation::StatementData>` - The decoded statement data
    pub fn decode_payment_statement(
        statement_data: Bytes,
    ) -> eyre::Result<contracts::TokenBundlePaymentObligation::StatementData> {
        let statement_data = contracts::TokenBundlePaymentObligation::StatementData::abi_decode(
            statement_data.as_ref(),
            true,
        )?;
        return Ok(statement_data);
    }

    /// Collects payment from a fulfilled trade.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    /// * `fulfillment` - The attestation UID of the fulfillment
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn collect_payment(
        &self,
        buy_attestation: FixedBytes<32>,
        fulfillment: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let escrow_contract = contracts::token_bundle::TokenBundleEscrowObligation::new(
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

    /// Collects expired escrow funds after expiration time has passed.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the expired escrow
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn collect_expired(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let escrow_contract = contracts::token_bundle::TokenBundleEscrowObligation::new(
            self.addresses.escrow_obligation,
            &self.wallet_provider,
        );

        let receipt = escrow_contract
            .collectExpired(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow arrangement with token bundles for a custom demand.
    ///
    /// # Arguments
    /// * `price` - The token bundle data for payment
    /// * `item` - The arbiter and demand data
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn buy_with_bundle(
        &self,
        price: TokenBundleData,
        item: ArbiterData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let escrow_obligation_contract = contracts::token_bundle::TokenBundleEscrowObligation::new(
            self.addresses.escrow_obligation,
            &self.wallet_provider,
        );

        let receipt = escrow_obligation_contract
            .makeStatement((price, item).into(), expiration)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Makes a direct payment with token bundles.
    ///
    /// # Arguments
    /// * `price` - The token bundle data for payment
    /// * `payee` - The address of the payment recipient
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn pay_with_bundle(
        &self,
        price: TokenBundleData,
        payee: Address,
    ) -> eyre::Result<TransactionReceipt> {
        let payment_obligation_contract =
            contracts::token_bundle::TokenBundlePaymentObligation::new(
                self.addresses.payment_obligation,
                &self.wallet_provider,
            );

        let receipt = payment_obligation_contract
            .makeStatement((price, payee).into())
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow to trade token bundles for other token bundles.
    ///
    /// # Arguments
    /// * `bid` - The token bundle data being offered
    /// * `ask` - The token bundle data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn buy_bundle_for_bundle(
        &self,
        bid: TokenBundleData,
        ask: TokenBundleData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::TokenBundleBarterUtils::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let zero_arbiter = ArbiterData {
            arbiter: Address::ZERO,
            demand: Bytes::new(),
        };

        let receipt = barter_utils_contract
            .buyBundleForBundle(
                (bid, zero_arbiter).into(),
                (ask, self.signer.address()).into(),
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Fulfills an existing bundle-for-bundle trade escrow.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn pay_bundle_for_bundle(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::TokenBundleBarterUtils::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .payBundleForBundle(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }
}
