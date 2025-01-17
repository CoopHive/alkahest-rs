use alloy::primitives::{address, Address, FixedBytes};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;

use crate::contracts::{self};
use crate::types::{
    ApprovalPurpose, ArbiterData, Erc1155Data, Erc20Data, Erc721Data, TokenBundleData,
};
use crate::{types::WalletProvider, utils};

#[derive(Debug, Clone)]
pub struct Erc1155Addresses {
    pub eas: Address,
    pub barter_utils: Address,
    pub escrow_obligation: Address,
    pub payment_obligation: Address,
}

#[derive(Clone)]
pub struct Erc1155Client {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    addresses: Erc1155Addresses,
}

impl Default for Erc1155Addresses {
    fn default() -> Self {
        Self {
            eas: address!("4200000000000000000000000000000000000021"),
            barter_utils: address!("12D8bF4F01bF011859f6184ffDe3f01f4F568Fe8"),
            escrow_obligation: address!("93B7D9cdD97887a8f7603c77F12938bf3d1331F6"),
            payment_obligation: address!("1395A7b129503E23eDAa7823b5F5994D65a26BF0"),
        }
    }
}

impl Erc1155Client {
    pub fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<Erc1155Addresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(private_key.clone(), rpc_url.clone())?;

        Ok(Erc1155Client {
            signer: private_key.to_string().parse()?,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    pub async fn approve_all(
        &self,
        token_contract: Address,
        purpose: ApprovalPurpose,
    ) -> eyre::Result<TransactionReceipt> {
        let erc1155_contract = contracts::IERC1155::new(token_contract, &self.wallet_provider);

        let to = match purpose {
            ApprovalPurpose::Escrow => self.addresses.escrow_obligation,
            ApprovalPurpose::Payment => self.addresses.payment_obligation,
        };

        let receipt = erc1155_contract
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
        let erc1155_contract = contracts::IERC1155::new(token_contract, &self.wallet_provider);

        let to = match purpose {
            ApprovalPurpose::Escrow => self.addresses.escrow_obligation,
            ApprovalPurpose::Payment => self.addresses.payment_obligation,
        };

        let receipt = erc1155_contract
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
        let escrow_contract = contracts::ERC1155EscrowObligation::new(
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
        let escrow_contract = contracts::ERC1155EscrowObligation::new(
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

    pub async fn buy_with_erc1155(
        &self,
        price: Erc1155Data,
        item: ArbiterData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let escrow_obligation_contract = contracts::ERC1155EscrowObligation::new(
            self.addresses.escrow_obligation,
            &self.wallet_provider,
        );

        let receipt = escrow_obligation_contract
            .makeStatement(
                contracts::ERC1155EscrowObligation::StatementData {
                    token: price.address,
                    tokenId: price.id,
                    amount: price.value,
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

    pub async fn pay_with_erc1155(
        &self,
        price: Erc1155Data,
        payee: Address,
    ) -> eyre::Result<TransactionReceipt> {
        let payment_obligation_contract = contracts::ERC1155PaymentObligation::new(
            self.addresses.payment_obligation,
            &self.wallet_provider,
        );

        let receipt = payment_obligation_contract
            .makeStatement(contracts::ERC1155PaymentObligation::StatementData {
                token: price.address,
                tokenId: price.id,
                amount: price.value,
                payee,
            })
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_erc1155_for_erc1155(
        &self,
        bid: Erc1155Data,
        ask: Erc1155Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::ERC1155BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);

        let receipt = barter_utils_contract
            .buyErc1155ForErc1155(
                bid.address,
                bid.id,
                bid.value,
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

    pub async fn pay_erc1155_for_erc1155(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::ERC1155BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);

        let receipt = barter_utils_contract
            .payErc1155ForErc1155(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_erc20_with_erc1155(
        &self,
        bid: Erc1155Data,
        ask: Erc20Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::erc1155_barter_cross_token::ERC1155BarterCrossToken::new(
                self.addresses.barter_utils,
                &self.wallet_provider,
            );

        let receipt = barter_utils_contract
            .buyErc20WithErc1155(
                bid.address,
                bid.id,
                bid.value,
                ask.address,
                ask.value,
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_erc721_with_erc1155(
        &self,
        bid: Erc1155Data,
        ask: Erc721Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::erc1155_barter_cross_token::ERC1155BarterCrossToken::new(
                self.addresses.barter_utils,
                &self.wallet_provider,
            );

        let receipt = barter_utils_contract
            .buyErc721WithErc1155(
                bid.address,
                bid.id,
                bid.value,
                ask.address,
                ask.id,
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_bundle_with_erc1155(
        &self,
        bid: Erc1155Data,
        ask: TokenBundleData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::erc1155_barter_cross_token::ERC1155BarterCrossToken::new(
                self.addresses.barter_utils,
                &self.wallet_provider,
            );

        let receipt = barter_utils_contract
            .buyBundleWithErc1155(
                bid.address,
                bid.id,
                bid.value,
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
