use alloy::primitives::{address, Address, FixedBytes};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;

use crate::contracts::{self};
use crate::types::{
    ApprovalPurpose, ArbiterData, Erc1155Data, Erc20Data, Erc721Data, TokenBundleData,
};
use crate::{types::WalletProvider, utils};

#[derive(Debug, Clone)]
pub struct Erc721Addresses {
    pub eas: Address,
    pub barter_utils: Address,
    pub escrow_obligation: Address,
    pub payment_obligation: Address,
}

#[derive(Clone)]
pub struct Erc721Client {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    addresses: Erc721Addresses,
}

impl Default for Erc721Addresses {
    fn default() -> Self {
        Self {
            eas: address!("4200000000000000000000000000000000000021"),
            barter_utils: address!("AfBaacEA69961C892797ceA7A8457dBA57568Ebb"),
            escrow_obligation: address!("868e59ecd79067087Cac7447061b1436eD6C9417"),
            payment_obligation: address!("0F13f5c62D88BE6C85205A1A010511BF54269615"),
        }
    }
}

impl Erc721Client {
    pub fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<Erc721Addresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(private_key.clone(), rpc_url.clone())?;

        Ok(Erc721Client {
            signer: private_key.to_string().parse()?,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    pub async fn approve(
        &self,
        token: Erc721Data,
        purpose: ApprovalPurpose,
    ) -> eyre::Result<TransactionReceipt> {
        let erc721_contract = contracts::IERC721::new(token.address, &self.wallet_provider);

        let to = match purpose {
            ApprovalPurpose::Escrow => self.addresses.escrow_obligation,
            ApprovalPurpose::Payment => self.addresses.payment_obligation,
        };

        let receipt = erc721_contract
            .approve(to, token.id)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn approve_all(
        &self,
        token_contract: Address,
        purpose: ApprovalPurpose,
    ) -> eyre::Result<TransactionReceipt> {
        let erc721_contract = contracts::IERC721::new(token_contract, &self.wallet_provider);

        let to = match purpose {
            ApprovalPurpose::Escrow => self.addresses.escrow_obligation,
            ApprovalPurpose::Payment => self.addresses.payment_obligation,
        };

        let receipt = erc721_contract
            .setApprovalForAll(to, true)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn revoke_all(
        &self,
        token_contract: Address,
        purpose: ApprovalPurpose,
    ) -> eyre::Result<TransactionReceipt> {
        let erc721_contract = contracts::IERC721::new(token_contract, &self.wallet_provider);

        let to = match purpose {
            ApprovalPurpose::Escrow => self.addresses.escrow_obligation,
            ApprovalPurpose::Payment => self.addresses.payment_obligation,
        };

        let receipt = erc721_contract
            .setApprovalForAll(to, false)
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
        let escrow_contract = contracts::ERC721EscrowObligation::new(
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

    pub async fn collect_expired(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let escrow_contract = contracts::ERC721EscrowObligation::new(
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

    pub async fn buy_with_erc721(
        &self,
        price: Erc721Data,
        item: ArbiterData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let escrow_obligation_contract = contracts::ERC721EscrowObligation::new(
            self.addresses.escrow_obligation,
            &self.wallet_provider,
        );

        let receipt = escrow_obligation_contract
            .makeStatement(
                contracts::ERC721EscrowObligation::StatementData {
                    token: price.address,
                    tokenId: price.id,
                    arbiter: item.arbiter,
                    demand: item.demand,
                },
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn pay_with_erc721(
        &self,
        price: Erc721Data,
        payee: Address,
    ) -> eyre::Result<TransactionReceipt> {
        let payment_obligation_contract = contracts::ERC721PaymentObligation::new(
            self.addresses.payment_obligation,
            &self.wallet_provider,
        );

        let receipt = payment_obligation_contract
            .makeStatement(contracts::ERC721PaymentObligation::StatementData {
                token: price.address,
                tokenId: price.id,
                payee,
            })
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_erc_721_for_erc_721(
        &self,
        bid: Erc721Data,
        ask: Erc721Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::ERC721BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);

        let receipt = barter_utils_contract
            .buyErc721ForErc721(bid.address, bid.id, ask.address, ask.id, expiration)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn pay_erc_721_for_erc_721(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::ERC721BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);

        let receipt = barter_utils_contract
            .payErc721ForErc721(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_erc20_with_erc721(
        &self,
        bid: Erc721Data,
        ask: Erc20Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::erc721_barter_cross_token::ERC721BarterCrossToken::new(
                self.addresses.barter_utils,
                &self.wallet_provider,
            );

        let receipt = barter_utils_contract
            .buyErc20WithErc721(bid.address, bid.id, ask.address, ask.value, expiration)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_erc1155_with_erc721(
        &self,
        bid: Erc721Data,
        ask: Erc1155Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::erc721_barter_cross_token::ERC721BarterCrossToken::new(
                self.addresses.barter_utils,
                &self.wallet_provider,
            );

        let receipt = barter_utils_contract
            .buyErc1155WithErc721(
                bid.address,
                bid.id,
                ask.address,
                ask.id,
                ask.value,
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_bundle_with_erc721(
        &self,
        bid: Erc721Data,
        ask: TokenBundleData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::erc721_barter_cross_token::ERC721BarterCrossToken::new(
                self.addresses.barter_utils,
                &self.wallet_provider,
            );

        let receipt = barter_utils_contract
            .buyBundleWithErc721(
                bid.address,
                bid.id,
                (ask, self.signer.address()).into(),
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }
}
