use alloy::primitives::{address, Address, FixedBytes};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;

use crate::contracts::{self};
use crate::{types::WalletProvider, utils};

pub struct TokenBundleAddresses {
    eas: Address,
    barter_utils: Address,
    escrow_obligation: Address,
    payment_obligation: Address,
}

pub struct TokenBundleClient {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    addresses: TokenBundleAddresses,
}

impl Default for TokenBundleAddresses {
    fn default() -> Self {
        Self {
            eas: address!("4200000000000000000000000000000000000021"),
            barter_utils: address!("3A40F65D2589a43Dc057bf820D8626F87D95307c"),
            escrow_obligation: address!("248cd93922eBDf962c9ea10286E6566C75081948"),
            payment_obligation: address!("702fab66515b3313dFd41E7CE70C2aF0033E2356"),
        }
    }
}

impl TokenBundleClient {
    pub fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<TokenBundleAddresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(private_key.clone(), rpc_url.clone())?;

        Ok(TokenBundleClient {
            signer: private_key.to_string().parse()?,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    pub async fn buy_bundle_for_bundle(
        &self,
        bid: contracts::TokenBundleEscrowObligation::StatementData,
        ask: contracts::TokenBundlePaymentObligation::StatementData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::TokenBundleBarterUtils::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .buyBundleForBundle(bid, ask, expiration)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

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
