use alloy::primitives::{address, Address, Bytes, FixedBytes};
use alloy::primitives::{Address, Bytes, FixedBytes, address};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue as _;

use crate::addresses::FILECOIN_CALIBRATION_ADDRESSES;
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

/// Client for interacting with ERC1155 token trading and escrow functionality.
///
/// This client provides methods for:
/// - Trading ERC1155 tokens for other ERC1155, ERC20, and ERC721 tokens
/// - Creating escrow arrangements with custom demands
/// - Managing token approvals
/// - Collecting payments from fulfilled trades
#[derive(Clone)]
pub struct Erc1155Client {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    pub addresses: Erc1155Addresses,
}

impl Default for Erc1155Addresses {
    fn default() -> Self {
        FILECOIN_CALIBRATION_ADDRESSES.erc1155_addresses.unwrap()
    }
}

impl Erc1155Client {
    /// Creates a new ERC1155Client instance.
    ///
    /// # Arguments
    /// * `private_key` - The private key for signing transactions
    /// * `rpc_url` - The RPC endpoint URL
    /// * `addresses` - Optional custom contract addresses, uses defaults if None
    ///
    /// # Returns
    /// * `Result<Self>` - The initialized client instance
    pub async fn new(
        signer: PrivateKeySigner,
        rpc_url: impl ToString + Clone,
        addresses: Option<Erc1155Addresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(signer.clone(), rpc_url.clone()).await?;

        Ok(Erc1155Client {
            signer,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    /// Decodes ERC1155EscrowObligation.StatementData from bytes.
    ///
    /// # Arguments
    /// * `statement_data` - The statement data
    ///
    /// # Returns
    /// * `Result<contracts::ERC1155EscrowObligation::StatementData>` - The decoded statement data
    pub fn decode_escrow_statement(
        statement_data: Bytes,
    ) -> eyre::Result<contracts::ERC1155EscrowObligation::StatementData> {
        let statement_data = contracts::ERC1155EscrowObligation::StatementData::abi_decode(
            statement_data.as_ref(),
            true,
        )?;
        return Ok(statement_data);
    }

    /// Decodes ERC1155PaymentObligation.StatementData from bytes.
    ///
    /// # Arguments
    ///
    /// * `statement_data` - The statement data
    ///
    /// # Returns
    ///
    /// * `eyre::Result<contracts::ERC1155PaymentObligation::StatementData>` - The decoded statement data
    pub fn decode_payment_statement(
        statement_data: Bytes,
    ) -> eyre::Result<contracts::ERC1155PaymentObligation::StatementData> {
        let statement_data = contracts::ERC1155PaymentObligation::StatementData::abi_decode(
            statement_data.as_ref(),
            true,
        )?;
        return Ok(statement_data);
    }

    /// Approves all tokens from a contract for trading.
    ///
    /// # Arguments
    /// * `token_contract` - The ERC1155 contract address
    /// * `purpose` - Whether the approval is for payment or escrow
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
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

    /// Revokes approval for all tokens from a contract.
    ///
    /// # Arguments
    /// * `token_contract` - The ERC1155 contract address
    /// * `purpose` - Whether to revoke payment or escrow approval
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
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

    /// Creates an escrow arrangement with ERC1155 tokens for a custom demand.
    ///
    /// # Arguments
    /// * `price` - The ERC1155 token data for payment
    /// * `item` - The arbiter and demand data
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
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

    /// Makes a direct payment with ERC1155 tokens.
    ///
    /// # Arguments
    /// * `price` - The ERC1155 token data for payment
    /// * `payee` - The address of the payment recipient
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
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

    /// Creates an escrow to trade ERC1155 tokens for other ERC1155 tokens.
    ///
    /// # Arguments
    /// * `bid` - The ERC1155 token data being offered
    /// * `ask` - The ERC1155 token data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
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

    /// Fulfills an existing ERC1155-for-ERC1155 trade escrow.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
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

    /// Creates an escrow to trade ERC1155 tokens for ERC20 tokens.
    ///
    /// # Arguments
    /// * `bid` - The ERC1155 token data being offered
    /// * `ask` - The ERC20 token data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
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

    /// Fulfills an existing ERC1155-for-ERC20 trade escrow.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn pay_erc1155_for_erc20(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::erc1155_barter_cross_token::ERC1155BarterCrossToken::new(
                self.addresses.barter_utils,
                &self.wallet_provider,
            );

        let receipt = barter_utils_contract
            .payErc1155ForErc20(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow to trade ERC1155 tokens for ERC721 tokens.
    ///
    /// # Arguments
    /// * `bid` - The ERC1155 token data being offered
    /// * `ask` - The ERC721 token data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
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

    /// Fulfills an existing ERC1155-for-ERC721 trade escrow.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn pay_erc1155_for_erc721(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::erc1155_barter_cross_token::ERC1155BarterCrossToken::new(
                self.addresses.barter_utils,
                &self.wallet_provider,
            );

        let receipt = barter_utils_contract
            .payErc1155ForErc721(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow to trade ERC1155 tokens for a bundle of tokens.
    ///
    /// # Arguments
    /// * `bid` - The ERC1155 token data being offered
    /// * `ask` - The token bundle data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
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

    /// Fulfills an existing ERC1155-for-bundle trade escrow.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn pay_erc1155_for_bundle(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::erc1155_barter_cross_token::ERC1155BarterCrossToken::new(
                self.addresses.barter_utils,
                &self.wallet_provider,
            );

        let receipt = barter_utils_contract
            .payErc1155ForBundle(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }
}
