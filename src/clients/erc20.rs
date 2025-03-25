use std::time::{SystemTime, UNIX_EPOCH};

use alloy::dyn_abi::Eip712Domain;
use alloy::providers::Provider as _;
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::{Signature, Signer};
use alloy::sol_types::SolValue as _;
use alloy::{
    primitives::{Address, Bytes, FixedBytes, U256},
    sol_types::SolValue,
};

use crate::addresses::FILECOIN_CALIBRATION_ADDRESSES;
use crate::contracts::{self, ERC20Permit};
use crate::types::{
    ApprovalPurpose, ArbiterData, Erc20Data, Erc721Data, Erc1155Data, TokenBundleData,
};
use crate::{types::WalletProvider, utils};

#[derive(Debug, Clone)]
pub struct Erc20Addresses {
    pub eas: Address,
    pub barter_utils: Address,
    pub escrow_obligation: Address,
    pub payment_obligation: Address,
}

/// Client for interacting with ERC20 token trading and escrow functionality.
///
/// This client provides methods for:
/// - Trading ERC20 tokens for other ERC20, ERC721, and ERC1155 tokens
/// - Creating escrow arrangements with custom demands
/// - Managing token approvals and permits
/// - Collecting payments from fulfilled trades
#[derive(Clone)]
pub struct Erc20Client {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    pub addresses: Erc20Addresses,
}

impl Default for Erc20Addresses {
    fn default() -> Self {
        FILECOIN_CALIBRATION_ADDRESSES.erc20_addresses.unwrap()
    }
}

impl Erc20Client {
    /// Creates a new ERC20Client instance.
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
        addresses: Option<Erc20Addresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(signer.clone(), rpc_url.clone()).await?;

        Ok(Erc20Client {
            signer,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    /// Gets a permit signature for token approval.
    ///
    /// # Arguments
    /// * `spender` - The address being approved to spend tokens
    /// * `token` - The token data including address and amount
    /// * `deadline` - The timestamp until which the permit is valid
    ///
    /// # Returns
    /// * `Result<Signature>` - The permit signature
    async fn get_permit_signature(
        &self,
        spender: Address,
        token: &Erc20Data,
        deadline: U256,
    ) -> eyre::Result<Signature> {
        use alloy::sol;

        // Define the Permit type using the sol! macro
        sol! {
            struct Permit {
                address owner;
                address spender;
                uint256 value;
                uint256 nonce;
                uint256 deadline;
            }
        }

        let token_contract = ERC20Permit::new(token.address, &self.wallet_provider);
        let owner = self.signer.address();

        // Get token name and nonce
        let (name, nonce, chain_id) = tokio::try_join!(
            async { Ok::<_, eyre::Error>(token_contract.name().call().await?._0) },
            async { Ok(token_contract.nonces(owner).call().await?._0) },
            async { Ok(self.wallet_provider.get_chain_id().await?) },
        )?;

        // Create the EIP-712 domain
        let domain = Eip712Domain {
            name: Some(name.into()),
            version: Some("1".into()),
            chain_id: Some(chain_id.try_into()?),
            verifying_contract: Some(token.address),
            salt: None,
        };

        // Create the permit data
        let permit = Permit {
            owner,
            spender,
            value: token.value,
            nonce,
            deadline,
        };

        // Sign the typed data according to EIP-712
        let signature = self.signer.sign_typed_data(&permit, &domain).await?;

        Ok(signature)
    }

    /// Decodes ERC20EscrowObligation.StatementData from bytes.
    ///
    /// # Arguments
    /// * `statement_data` - The statement data
    ///
    /// # Returns
    /// * `Result<contracts::ERC20EscrowObligation::StatementData>` - The decoded statement data
    pub fn decode_escrow_statement(
        statement_data: Bytes,
    ) -> eyre::Result<contracts::ERC20EscrowObligation::StatementData> {
        let statement_data = contracts::ERC20EscrowObligation::StatementData::abi_decode(
            statement_data.as_ref(),
            true,
        )?;
        return Ok(statement_data);
    }

    /// Decodes ERC20PaymentObligation.StatementData from bytes.
    ///
    /// # Arguments
    ///
    /// * `statement_data` - The statement data
    ///
    /// # Returns
    ///
    /// * `eyre::Result<contracts::ERC20PaymentObligation::StatementData>` - The decoded statement data
    pub fn decode_payment_statement(
        statement_data: Bytes,
    ) -> eyre::Result<contracts::ERC20PaymentObligation::StatementData> {
        let statement_data = contracts::ERC20PaymentObligation::StatementData::abi_decode(
            statement_data.as_ref(),
            true,
        )?;
        return Ok(statement_data);
    }

    /// Approves token spending for payment or escrow purposes.
    ///
    /// # Arguments
    /// * `token` - The token data including address and amount
    /// * `purpose` - Whether the approval is for payment or escrow
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn approve(
        &self,
        token: &Erc20Data,
        purpose: ApprovalPurpose,
    ) -> eyre::Result<TransactionReceipt> {
        let to = match purpose {
            ApprovalPurpose::Payment => self.addresses.payment_obligation,
            ApprovalPurpose::Escrow => self.addresses.escrow_obligation,
        };

        let token_contract = ERC20Permit::new(token.address, &self.wallet_provider);
        let receipt = token_contract
            .approve(to, token.value)
            .send()
            .await?
            .get_receipt()
            .await?;
        Ok(receipt)
    }

    /// Approves token spending if current allowance is less than required amount.
    ///
    /// # Arguments
    /// * `token` - The token data including address and amount
    /// * `purpose` - Whether the approval is for payment or escrow
    ///
    /// # Returns
    /// * `Result<Option<TransactionReceipt>>` - The transaction receipt if approval was needed
    pub async fn approve_if_less(
        &self,
        token: &Erc20Data,
        purpose: ApprovalPurpose,
    ) -> eyre::Result<Option<TransactionReceipt>> {
        let to = match purpose {
            ApprovalPurpose::Payment => self.addresses.payment_obligation,
            ApprovalPurpose::Escrow => self.addresses.escrow_obligation,
        };

        let token_contract = ERC20Permit::new(token.address, &self.wallet_provider);
        let current_allowance = token_contract
            .allowance(self.signer.address(), to)
            .call()
            .await?
            ._0;

        if current_allowance > token.value {
            return Ok(None);
        }

        let receipt = token_contract
            .approve(to, token.value)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(Some(receipt))
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
        let escrow_contract = contracts::ERC20EscrowObligation::new(
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
        let escrow_contract = contracts::ERC20EscrowObligation::new(
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

    /// Creates an escrow arrangement with ERC20 tokens for a custom demand.
    ///
    /// # Arguments
    /// * `price` - The ERC20 token data for payment
    /// * `item` - The arbiter and demand data
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn buy_with_erc20(
        &self,
        price: &Erc20Data,
        item: &ArbiterData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let escrow_obligation_contract = contracts::ERC20EscrowObligation::new(
            self.addresses.escrow_obligation,
            &self.wallet_provider,
        );

        let receipt = escrow_obligation_contract
            .makeStatement(
                contracts::ERC20EscrowObligation::StatementData {
                    token: price.address,
                    amount: price.value,
                    arbiter: item.arbiter,
                    demand: item.demand.clone(),
                },
                expiration,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Makes a direct payment with ERC20 tokens.
    ///
    /// # Arguments
    /// * `price` - The ERC20 token data for payment
    /// * `payee` - The address of the payment recipient
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn pay_with_erc20(
        &self,
        price: &Erc20Data,
        payee: Address,
    ) -> eyre::Result<TransactionReceipt> {
        let payment_obligation_contract = contracts::ERC20PaymentObligation::new(
            self.addresses.payment_obligation,
            &self.wallet_provider,
        );

        let receipt = payment_obligation_contract
            .makeStatement(contracts::ERC20PaymentObligation::StatementData {
                token: price.address,
                amount: price.value,
                payee,
            })
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Makes a direct payment with ERC20 tokens using permit signature.
    ///
    /// # Arguments
    /// * `price` - The ERC20 token data for payment
    /// * `payee` - The address of the payment recipient
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    /// Makes a direct payment with ERC20 tokens using permit signature.
    ///
    /// # Arguments
    /// * `price` - The ERC20 token data for payment
    /// * `payee` - The address of the payment recipient
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn permit_and_pay_with_erc20(
        &self,
        price: &Erc20Data,
        payee: Address,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.payment_obligation,
                price,
                deadline.try_into()?,
            )
            .await?;

        let barter_utils_contract =
            contracts::ERC20BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);
        let receipt = barter_utils_contract
            .permitAndPayWithErc20(
                price.address,
                price.value,
                payee,
                deadline.try_into()?,
                27 + permit.v() as u8,
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow to trade ERC20 tokens for other ERC20 tokens.
    ///
    /// # Arguments
    /// * `bid` - The ERC20 token data being offered
    /// * `ask` - The ERC20 token data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn buy_erc20_for_erc20(
        &self,
        bid: &Erc20Data,
        ask: &Erc20Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::ERC20BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);
        let receipt = barter_utils_contract
            .buyErc20ForErc20(bid.address, bid.value, ask.address, ask.value, expiration)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow to trade ERC20 tokens for other ERC20 tokens using permit signature.
    ///
    /// # Arguments
    /// * `bid` - The ERC20 token data being offered
    /// * `ask` - The ERC20 token data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn permit_and_buy_erc20_for_erc20(
        &self,
        bid: &Erc20Data,
        ask: &Erc20Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;

        let permit = self
            .get_permit_signature(self.addresses.escrow_obligation, bid, deadline.try_into()?)
            .await?;

        let barter_utils_contract =
            contracts::ERC20BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);

        let receipt = barter_utils_contract
            .permitAndBuyErc20ForErc20(
                bid.address,
                bid.value,
                ask.address,
                ask.value,
                expiration,
                deadline.try_into()?,
                27 + permit.v() as u8,
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Fulfills an existing ERC20-for-ERC20 trade escrow.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn pay_erc20_for_erc20(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract =
            contracts::ERC20BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);
        let receipt = barter_utils_contract
            .payErc20ForErc20(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Fulfills an existing ERC20-for-ERC20 trade escrow using permit signature.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    /// Fulfills an existing ERC20-for-ERC20 trade escrow using permit signature.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn permit_and_pay_erc20_for_erc20(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let eas_contract = contracts::IEAS::new(self.addresses.eas, &self.wallet_provider);
        let barter_utils_contract =
            contracts::ERC20BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);

        let buy_attestation_data = eas_contract
            .getAttestation(buy_attestation)
            .call()
            .await?
            ._0;
        let buy_attestation_data = contracts::ERC20EscrowObligation::StatementData::abi_decode(
            buy_attestation_data.data.as_ref(),
            true,
        )?;
        let demand_data = contracts::ERC20PaymentObligation::StatementData::abi_decode(
            buy_attestation_data.demand.as_ref(),
            true,
        )?;

        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.payment_obligation,
                &Erc20Data {
                    address: demand_data.token,
                    value: demand_data.amount,
                },
                deadline.try_into()?,
            )
            .await?;

        let receipt = barter_utils_contract
            .permitAndPayErc20ForErc20(
                buy_attestation,
                deadline.try_into()?,
                27 + permit.v() as u8,
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow to trade ERC20 tokens for an ERC721 token.
    ///
    /// # Arguments
    /// * `bid` - The ERC20 token data being offered
    /// * `ask` - The ERC721 token data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn buy_erc721_for_erc20(
        &self,
        bid: &Erc20Data,
        ask: &Erc721Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .buyErc721WithErc20(bid.address, bid.value, ask.address, ask.id, expiration)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow to trade ERC20 tokens for ERC721 tokens using permit signature.
    ///
    /// # Arguments
    /// * `bid` - The ERC20 token data being offered
    /// * `ask` - The ERC721 token data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn permit_and_buy_erc721_for_erc20(
        &self,
        bid: &Erc20Data,
        ask: &Erc721Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(self.addresses.escrow_obligation, bid, deadline.try_into()?)
            .await?;

        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .permitAndBuyErc721WithErc20(
                bid.address,
                bid.value,
                ask.address,
                ask.id,
                expiration,
                deadline.try_into()?,
                27 + permit.v() as u8,
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Fulfills an existing ERC721-for-ERC20 trade escrow.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn pay_erc20_for_erc721(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .payErc20ForErc721(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Fulfills an existing ERC721-for-ERC20 trade escrow using permit signature.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn permit_and_pay_erc20_for_erc721(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let eas_contract = contracts::IEAS::new(self.addresses.eas, &self.wallet_provider);
        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let buy_attestation_data = eas_contract
            .getAttestation(buy_attestation)
            .call()
            .await?
            ._0;
        let buy_attestation_data = contracts::ERC721EscrowObligation::StatementData::abi_decode(
            buy_attestation_data.data.as_ref(),
            true,
        )?;
        let demand_data = contracts::ERC20PaymentObligation::StatementData::abi_decode(
            buy_attestation_data.demand.as_ref(),
            true,
        )?;

        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.payment_obligation,
                &Erc20Data {
                    address: demand_data.token,
                    value: demand_data.amount,
                },
                deadline.try_into()?,
            )
            .await?;

        let receipt = barter_utils_contract
            .permitAndPayErc20ForErc721(
                buy_attestation,
                deadline.try_into()?,
                27 + permit.v() as u8,
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow to trade ERC20 tokens for an ERC1155 token.
    ///
    /// # Arguments
    /// * `bid` - The ERC20 token data being offered
    /// * `ask` - The ERC1155 token data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn buy_erc1155_for_erc20(
        &self,
        bid: &Erc20Data,
        ask: &Erc1155Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .buyErc1155WithErc20(
                bid.address,
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

    /// Creates an escrow to trade ERC20 tokens for ERC1155 tokens using permit signature.
    ///
    /// # Arguments
    /// * `bid` - The ERC20 token data being offered
    /// * `ask` - The ERC1155 token data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn permit_and_buy_erc1155_for_erc20(
        &self,
        bid: &Erc20Data,
        ask: &Erc1155Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(self.addresses.escrow_obligation, bid, deadline.try_into()?)
            .await?;

        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .permitAndBuyErc1155WithErc20(
                bid.address,
                bid.value,
                ask.address,
                ask.id,
                ask.value,
                expiration,
                deadline.try_into()?,
                27 + permit.v() as u8,
                permit.r().into(),
                permit.s().into(),
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
    pub async fn pay_erc20_for_erc1155(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .payErc20ForErc1155(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Fulfills an existing ERC1155-for-ERC20 trade escrow using permit signature.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn permit_and_pay_erc20_for_erc1155(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let eas_contract = contracts::IEAS::new(self.addresses.eas, &self.wallet_provider);
        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let buy_attestation_data = eas_contract
            .getAttestation(buy_attestation)
            .call()
            .await?
            ._0;
        let buy_attestation_data = contracts::ERC1155EscrowObligation::StatementData::abi_decode(
            buy_attestation_data.data.as_ref(),
            true,
        )?;
        let demand_data = contracts::ERC20PaymentObligation::StatementData::abi_decode(
            buy_attestation_data.demand.as_ref(),
            true,
        )?;

        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.payment_obligation,
                &Erc20Data {
                    address: demand_data.token,
                    value: demand_data.amount,
                },
                deadline.try_into()?,
            )
            .await?;

        let receipt = barter_utils_contract
            .permitAndPayErc20ForErc1155(
                buy_attestation,
                deadline.try_into()?,
                permit.v().into(),
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Creates an escrow to trade ERC20 tokens for a bundle of tokens.
    ///
    /// # Arguments
    /// * `bid` - The ERC20 token data being offered
    /// * `ask` - The token bundle data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn buy_bundle_for_erc20(
        &self,
        bid: &Erc20Data,
        ask: &TokenBundleData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .buyBundleWithErc20(
                bid.address,
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

    /// Creates an escrow to trade ERC20 tokens for a bundle of tokens using permit signature.
    ///
    /// # Arguments
    /// * `bid` - The ERC20 token data being offered
    /// * `ask` - The token bundle data being requested
    /// * `expiration` - The expiration timestamp
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn permit_and_buy_bundle_for_erc20(
        &self,
        bid: &Erc20Data,
        ask: &TokenBundleData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(self.addresses.escrow_obligation, bid, deadline.try_into()?)
            .await?;

        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .permitAndBuyBundleWithErc20(
                bid.address,
                bid.value,
                (ask, self.signer.address()).into(),
                expiration,
                deadline.try_into()?,
                27 + permit.v() as u8,
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Fulfills an existing bundle-for-ERC20 trade escrow.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn pay_erc20_for_bundle(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let receipt = barter_utils_contract
            .payErc20ForBundle(buy_attestation)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Fulfills an existing bundle-for-ERC20 trade escrow using permit signature.
    ///
    /// # Arguments
    /// * `buy_attestation` - The attestation UID of the buy order
    ///
    /// # Returns
    /// * `Result<TransactionReceipt>` - The transaction receipt
    pub async fn permit_and_pay_erc20_for_bundle(
        &self,
        buy_attestation: FixedBytes<32>,
    ) -> eyre::Result<TransactionReceipt> {
        let eas_contract = contracts::IEAS::new(self.addresses.eas, &self.wallet_provider);
        let barter_utils_contract = contracts::erc20_barter_cross_token::ERC20BarterCrossToken::new(
            self.addresses.barter_utils,
            &self.wallet_provider,
        );

        let buy_attestation_data = eas_contract
            .getAttestation(buy_attestation)
            .call()
            .await?
            ._0;
        let buy_attestation_data =
            contracts::TokenBundleEscrowObligation::StatementData::abi_decode(
                buy_attestation_data.data.as_ref(),
                true,
            )?;
        let demand_data = contracts::ERC20PaymentObligation::StatementData::abi_decode(
            buy_attestation_data.demand.as_ref(),
            true,
        )?;

        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.payment_obligation,
                &Erc20Data {
                    address: demand_data.token,
                    value: demand_data.amount,
                },
                deadline.try_into()?,
            )
            .await?;

        let receipt = barter_utils_contract
            .permitAndPayErc20ForBundle(
                buy_attestation,
                deadline.try_into()?,
                27 + permit.v() as u8,
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use alloy::{
        primitives::{Bytes, FixedBytes, U256},
        sol_types::SolValue,
    };

    use crate::{
        AlkahestClient,
        clients::erc20::Erc20Client,
        contracts::ERC20PaymentObligation,
        fixtures::MockERC20Permit,
        types::{
            ApprovalPurpose, ArbiterData, Erc20Data, Erc721Data, Erc1155Data, TokenBundleData,
        },
        utils::setup_test_environment,
    };

    #[tokio::test]
    async fn test_decode_escrow_statement() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Create sample statement data
        let token_address = test.mock_addresses.erc20_a;
        let amount: U256 = 100.try_into()?;
        let arbiter = test
            .addresses
            .erc20_addresses
            .ok_or(eyre::eyre!("no erc20-related addresses"))?
            .payment_obligation;
        let demand = Bytes::from(vec![1, 2, 3, 4]); // sample demand data

        let escrow_data = crate::contracts::ERC20EscrowObligation::StatementData {
            token: token_address,
            amount,
            arbiter,
            demand: demand.clone(),
        };

        // Encode the data
        let encoded = escrow_data.abi_encode();

        // Decode the data
        let decoded = Erc20Client::decode_escrow_statement(encoded.into())?;

        // Verify decoded data
        assert_eq!(decoded.token, token_address, "Token address should match");
        assert_eq!(decoded.amount, amount, "Amount should match");
        assert_eq!(decoded.arbiter, arbiter, "Arbiter should match");
        assert_eq!(decoded.demand, demand, "Demand should match");

        Ok(())
    }

    #[tokio::test]
    async fn test_decode_payment_statement() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Create sample statement data
        let token_address = test.mock_addresses.erc20_a;
        let amount: U256 = 100.try_into()?;
        let payee = test.alice.address();

        let payment_data = ERC20PaymentObligation::StatementData {
            token: token_address,
            amount,
            payee,
        };

        // Encode the data
        let encoded = payment_data.abi_encode();

        // Decode the data
        let decoded = Erc20Client::decode_payment_statement(encoded.into())?;

        // Verify decoded data
        assert_eq!(decoded.token, token_address, "Token address should match");
        assert_eq!(decoded.amount, amount, "Amount should match");
        assert_eq!(decoded.payee, payee, "Payee should match");

        Ok(())
    }

    #[tokio::test]
    async fn test_approve() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let token = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };

        // Test approve for payment
        let _receipt = test
            .alice_client
            .erc20
            .approve(&token, ApprovalPurpose::Payment)
            .await?;

        // Verify approval for payment obligation
        let payment_allowance = mock_erc20_a
            .allowance(
                test.alice.address(),
                test.addresses
                    .erc20_addresses
                    .clone()
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
            )
            .call()
            .await?
            ._0;

        assert_eq!(
            payment_allowance,
            100.try_into()?,
            "Payment allowance should be set correctly"
        );

        // Test approve for escrow
        let _receipt = test
            .alice_client
            .erc20
            .approve(&token, ApprovalPurpose::Escrow)
            .await?;

        // Verify approval for escrow obligation
        let escrow_allowance = mock_erc20_a
            .allowance(
                test.alice.address(),
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        assert_eq!(
            escrow_allowance,
            100.try_into()?,
            "Escrow allowance should be set correctly"
        );

        Ok(())
    }

    // #[tokio::test]
    // async fn test_approve_if_less() -> eyre::Result<()> {
    //     // test setup
    //     let test = setup_test_environment().await?;

    //     // give alice some erc20 tokens
    //     let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
    //     mock_erc20_a
    //         .transfer(test.alice.address(), 200.try_into()?)
    //         .send()
    //         .await?
    //         .get_receipt()
    //         .await?;

    //     let token = Erc20Data {
    //         address: test.mock_addresses.erc20_a,
    //         value: 100.try_into()?,
    //     };

    //     // First time should approve (no existing allowance)
    //     let receipt_opt = test
    //         .alice_client
    //         .erc20
    //         .approve_if_less(&token, ApprovalPurpose::Payment)
    //         .await?;

    //     assert!(
    //         receipt_opt.is_some(),
    //         "First approval should return receipt"
    //     );

    //     // Verify approval happened
    //     let payment_allowance = mock_erc20_a
    //         .allowance(
    //             test.alice.address(),
    //             test.addresses
    //                 .erc20_addresses
    //                 .clone()
    //                 .ok_or(eyre::eyre!("no erc20-related addresses"))?
    //                 .payment_obligation,
    //         )
    //         .call()
    //         .await?
    //         ._0;

    //     assert_eq!(
    //         payment_allowance,
    //         100.try_into()?,
    //         "Payment allowance should be set correctly"
    //     );

    //     // Second time should not approve (existing allowance is sufficient)
    //     let receipt_opt = test
    //         .alice_client
    //         .erc20
    //         .approve_if_less(&token, ApprovalPurpose::Payment)
    //         .await?;

    //     assert!(receipt_opt.is_none(), "Second approval should not happen");

    //     // Now test with a larger amount
    //     let larger_token = Erc20Data {
    //         address: test.mock_addresses.erc20_a,
    //         value: 150.try_into()?,
    //     };

    //     // This should approve again because we need a higher allowance
    //     let receipt_opt = test
    //         .alice_client
    //         .erc20
    //         .approve_if_less(&larger_token, ApprovalPurpose::Payment)
    //         .await?;

    //     assert!(
    //         receipt_opt.is_some(),
    //         "Third approval with larger amount should return receipt"
    //     );

    //     // Verify new approval amount
    //     let new_payment_allowance = mock_erc20_a
    //         .allowance(
    //             test.alice.address(),
    //             test.addresses
    //                 .erc20_addresses
    //                 .ok_or(eyre::eyre!("no erc20-related addresses"))?
    //                 .payment_obligation,
    //         )
    //         .call()
    //         .await?
    //         ._0;

    //     assert_eq!(
    //         new_payment_allowance,
    //         150.try_into()?,
    //         "New payment allowance should be set correctly"
    //     );

    //     Ok(())
    // }

    #[tokio::test]
    async fn test_buy_with_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let price = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };

        // Create custom arbiter data
        let arbiter = test
            .addresses
            .erc20_addresses
            .clone()
            .ok_or(eyre::eyre!("no erc20-related addresses"))?
            .payment_obligation;
        let demand = Bytes::from(b"custom demand data");
        let item = ArbiterData { arbiter, demand };

        // approve tokens for escrow
        test.alice_client
            .erc20
            .approve(&price, ApprovalPurpose::Escrow)
            .await?;

        // alice creates escrow with custom demand
        let receipt = test
            .alice_client
            .erc20
            .buy_with_erc20(&price, &item, 0)
            .await?;

        // Verify escrow happened
        let alice_balance = mock_erc20_a
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let escrow_balance = mock_erc20_a
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // all tokens in escrow
        assert_eq!(alice_balance, 0.try_into()?);
        assert_eq!(escrow_balance, 100.try_into()?);

        // escrow statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_pay_with_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let price = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };

        // approve tokens for payment
        test.alice_client
            .erc20
            .approve(&price, ApprovalPurpose::Payment)
            .await?;

        // alice makes direct payment to bob
        let receipt = test
            .alice_client
            .erc20
            .pay_with_erc20(&price, test.bob.address())
            .await?;

        // Verify payment happened
        let alice_balance = mock_erc20_a
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let payment_balance = mock_erc20_a
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
            )
            .call()
            .await?
            ._0;

        // all tokens moved to payment contract
        assert_eq!(alice_balance, 0.try_into()?);
        assert_eq!(payment_balance, 100.try_into()?);

        // payment statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_permit_and_pay_with_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let price = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };

        // alice makes direct payment to bob using permit (no pre-approval needed)
        let receipt = test
            .alice_client
            .erc20
            .permit_and_pay_with_erc20(&price, test.bob.address())
            .await?;

        // Verify payment happened
        let alice_balance = mock_erc20_a
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let payment_balance = mock_erc20_a
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
            )
            .call()
            .await?
            ._0;

        // all tokens moved to payment contract
        assert_eq!(alice_balance, 0.try_into()?);
        assert_eq!(payment_balance, 100.try_into()?);

        // payment statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    // Erc20BarterUtils
    #[tokio::test]
    async fn test_buy_erc20_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // begin test
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };
        let ask = Erc20Data {
            address: test.mock_addresses.erc20_b,
            value: 200.try_into()?,
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice makes escrow
        let receipt = test
            .alice_client
            .erc20
            .buy_erc20_for_erc20(&bid, &ask, 0)
            .await?;

        let alice_balance = mock_erc20_a
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;
        let escrow_balance = mock_erc20_a
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // all tokens in escrow
        assert_eq!(alice_balance, 0.try_into()?);
        assert_eq!(escrow_balance, 100.try_into()?);

        // escrow statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_permit_and_buy_erc20_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // begin test
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };
        let ask = Erc20Data {
            address: test.mock_addresses.erc20_b,
            value: 200.try_into()?,
        };

        // alice creates an escrow using permit signature (no pre-approval needed)
        let receipt = test
            .alice_client
            .erc20
            .permit_and_buy_erc20_for_erc20(&bid, &ask, 0)
            .await?;

        let alice_balance = mock_erc20_a
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;
        let escrow_balance = mock_erc20_a
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // all tokens in escrow
        assert_eq!(alice_balance, 0.try_into()?);
        assert_eq!(escrow_balance, 100.try_into()?);

        // escrow statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_pay_erc20_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens for bidding
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // give bob some erc20 tokens for fulfillment
        let mock_erc20_b = MockERC20Permit::new(test.mock_addresses.erc20_b, &test.god_provider);
        mock_erc20_b
            .transfer(test.bob.address(), 200.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // begin test
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };
        let ask = Erc20Data {
            address: test.mock_addresses.erc20_b,
            value: 200.try_into()?,
        };

        // alice approves tokens for escrow and creates buy attestation
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        let buy_receipt = test
            .alice_client
            .erc20
            .buy_erc20_for_erc20(&bid, &ask, 0)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(buy_receipt)?.uid;

        // bob approves tokens for payment
        test.bob_client
            .erc20
            .approve(&ask, ApprovalPurpose::Payment)
            .await?;

        // bob fulfills the buy attestation
        let sell_receipt = test
            .bob_client
            .erc20
            .pay_erc20_for_erc20(buy_attestation)
            .await?;

        // verify token transfers
        let alice_token_b_balance = mock_erc20_b
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let bob_token_a_balance = mock_erc20_a.balanceOf(test.bob.address()).call().await?._0;

        // both sides received the tokens
        assert_eq!(
            alice_token_b_balance,
            200.try_into()?,
            "Alice should have received token B"
        );
        assert_eq!(
            bob_token_a_balance,
            100.try_into()?,
            "Bob should have received token A"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_permit_and_pay_erc20_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens for bidding
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // give bob some erc20 tokens for fulfillment
        let mock_erc20_b = MockERC20Permit::new(test.mock_addresses.erc20_b, &test.god_provider);
        mock_erc20_b
            .transfer(test.bob.address(), 200.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // begin test
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };
        let ask = Erc20Data {
            address: test.mock_addresses.erc20_b,
            value: 200.try_into()?,
        };

        // alice approves tokens for escrow and creates buy attestation
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        let buy_receipt = test
            .alice_client
            .erc20
            .buy_erc20_for_erc20(&bid, &ask, 0)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(buy_receipt)?.uid;

        // bob fulfills the buy attestation with permit
        let sell_receipt = test
            .bob_client
            .erc20
            .permit_and_pay_erc20_for_erc20(buy_attestation)
            .await?;

        // verify token transfers
        let alice_token_b_balance = mock_erc20_b
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let bob_token_a_balance = mock_erc20_a.balanceOf(test.bob.address()).call().await?._0;

        // both sides received the tokens
        assert_eq!(
            alice_token_b_balance,
            200.try_into()?,
            "Alice should have received token B"
        );
        assert_eq!(
            bob_token_a_balance,
            100.try_into()?,
            "Bob should have received token A"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_payment() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens for bidding
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // give bob some erc20 tokens for fulfillment
        let mock_erc20_b = MockERC20Permit::new(test.mock_addresses.erc20_b, &test.god_provider);
        mock_erc20_b
            .transfer(test.bob.address(), 200.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // begin test
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };
        let ask = Erc20Data {
            address: test.mock_addresses.erc20_b,
            value: 200.try_into()?,
        };

        // alice approves tokens for escrow and creates buy attestation
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        let buy_receipt = test
            .alice_client
            .erc20
            .buy_erc20_for_erc20(&bid, &ask, 0)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(buy_receipt)?.uid;

        // bob approves tokens for payment and creates fulfillment
        test.bob_client
            .erc20
            .approve(&ask, ApprovalPurpose::Payment)
            .await?;

        let sell_receipt = test
            .bob_client
            .erc20
            .pay_erc20_for_erc20(buy_attestation)
            .await?;

        let fulfillment = AlkahestClient::get_attested_event(sell_receipt)?.uid;

        // Test collecting payment
        let collect_receipt = test
            .bob_client
            .erc20
            .collect_payment(buy_attestation, fulfillment)
            .await?;

        // verify token transfers
        let alice_token_b_balance = mock_erc20_b
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let bob_token_a_balance = mock_erc20_a.balanceOf(test.bob.address()).call().await?._0;

        // both sides received the tokens
        assert_eq!(
            alice_token_b_balance,
            200.try_into()?,
            "Alice should have received token B"
        );
        assert_eq!(
            bob_token_a_balance,
            100.try_into()?,
            "Bob should have received token A"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_expired() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // give alice some erc20 tokens
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // begin test
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 100.try_into()?,
        };
        let ask = Erc20Data {
            address: test.mock_addresses.erc20_b,
            value: 200.try_into()?,
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice makes escrow with a short expiration
        let expiration = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 1;
        let receipt = test
            .alice_client
            .erc20
            .buy_erc20_for_erc20(&bid, &ask, expiration as u64)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(receipt)?.uid;

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // alice collects expired funds
        let collect_receipt = test
            .alice_client
            .erc20
            .collect_expired(buy_attestation)
            .await?;

        // verify tokens returned to alice
        let alice_balance = mock_erc20_a
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        assert_eq!(
            alice_balance,
            100.try_into()?,
            "Tokens should be returned to Alice"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_buy_erc721_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20, bob gets ERC721
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        let ask = Erc721Data {
            address: test.mock_addresses.erc721_a,
            id: 1.try_into()?,
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice creates purchase offer
        let receipt = test
            .alice_client
            .erc20
            .buy_erc721_for_erc20(&bid, &ask, 0)
            .await?;

        // Verify escrow happened
        let alice_balance = mock_erc20.balanceOf(test.alice.address()).call().await?._0;

        let escrow_balance = mock_erc20
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // tokens in escrow
        assert_eq!(alice_balance, 50.try_into()?);
        assert_eq!(escrow_balance, 50.try_into()?);

        // escrow statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_buy_erc1155_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        let ask = Erc1155Data {
            address: test.mock_addresses.erc1155_a,
            id: 1.try_into()?,
            value: 10.try_into()?,
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice creates purchase offer
        let receipt = test
            .alice_client
            .erc20
            .buy_erc1155_for_erc20(&bid, &ask, 0)
            .await?;

        // Verify escrow happened
        let alice_balance = mock_erc20.balanceOf(test.alice.address()).call().await?._0;

        let escrow_balance = mock_erc20
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // tokens in escrow
        assert_eq!(alice_balance, 50.try_into()?);
        assert_eq!(escrow_balance, 50.try_into()?);

        // escrow statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_buy_bundle_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        // Create bundle data
        let bundle = TokenBundleData {
            erc20s: vec![Erc20Data {
                address: test.mock_addresses.erc20_b,
                value: 20.try_into()?,
            }],
            erc721s: vec![Erc721Data {
                address: test.mock_addresses.erc721_a,
                id: 1.try_into()?,
            }],
            erc1155s: vec![Erc1155Data {
                address: test.mock_addresses.erc1155_a,
                id: 1.try_into()?,
                value: 5.try_into()?,
            }],
        };
        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice creates purchase offer
        let receipt = test
            .alice_client
            .erc20
            .buy_bundle_for_erc20(&bid, &bundle, 0)
            .await?;

        // Verify escrow happened
        let alice_balance = mock_erc20.balanceOf(test.alice.address()).call().await?._0;

        let escrow_balance = mock_erc20
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // tokens in escrow
        assert_eq!(alice_balance, 50.try_into()?);
        assert_eq!(escrow_balance, 50.try_into()?);

        // escrow statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_permit_and_buy_erc721_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20, bob gets ERC721
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        let ask = Erc721Data {
            address: test.mock_addresses.erc721_a,
            id: 1.try_into()?,
        };

        // alice creates purchase offer with permit (no pre-approval needed)
        let receipt = test
            .alice_client
            .erc20
            .permit_and_buy_erc721_for_erc20(&bid, &ask, 0)
            .await?;

        // Verify escrow happened
        let alice_balance = mock_erc20.balanceOf(test.alice.address()).call().await?._0;

        let escrow_balance = mock_erc20
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // tokens in escrow
        assert_eq!(alice_balance, 50.try_into()?);
        assert_eq!(escrow_balance, 50.try_into()?);

        // escrow statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_permit_and_buy_erc1155_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        let ask = Erc1155Data {
            address: test.mock_addresses.erc1155_a,
            id: 1.try_into()?,
            value: 10.try_into()?,
        };

        // alice creates purchase offer with permit (no pre-approval needed)
        let receipt = test
            .alice_client
            .erc20
            .permit_and_buy_erc1155_for_erc20(&bid, &ask, 0)
            .await?;

        // Verify escrow happened
        let alice_balance = mock_erc20.balanceOf(test.alice.address()).call().await?._0;

        let escrow_balance = mock_erc20
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // tokens in escrow
        assert_eq!(alice_balance, 50.try_into()?);
        assert_eq!(escrow_balance, 50.try_into()?);

        // escrow statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_permit_and_buy_bundle_for_erc20() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        // Create bundle data
        let bundle = TokenBundleData {
            erc20s: vec![Erc20Data {
                address: test.mock_addresses.erc20_b,
                value: 20.try_into()?,
            }],
            erc721s: vec![Erc721Data {
                address: test.mock_addresses.erc721_a,
                id: 1.try_into()?,
            }],
            erc1155s: vec![Erc1155Data {
                address: test.mock_addresses.erc1155_a,
                id: 1.try_into()?,
                value: 5.try_into()?,
            }],
        };

        // alice creates purchase offer with permit (no pre-approval needed)
        let receipt = test
            .alice_client
            .erc20
            .permit_and_buy_bundle_for_erc20(&bid, &bundle, 0)
            .await?;

        // Verify escrow happened
        let alice_balance = mock_erc20.balanceOf(test.alice.address()).call().await?._0;

        let escrow_balance = mock_erc20
            .balanceOf(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .escrow_obligation,
            )
            .call()
            .await?
            ._0;

        // tokens in escrow
        assert_eq!(alice_balance, 50.try_into()?);
        assert_eq!(escrow_balance, 50.try_into()?);

        // escrow statement made
        let attested_event = AlkahestClient::get_attested_event(receipt)?;
        assert_ne!(attested_event.uid, FixedBytes::<32>::default());

        Ok(())
    }

    #[tokio::test]
    async fn test_pay_erc20_for_erc721() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20, bob gets ERC721
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let mock_erc721 =
            crate::fixtures::MockERC721::new(test.mock_addresses.erc721_a, &test.god_provider);
        // Mint token ID 1 to Bob
        mock_erc721
            .mint(test.bob.address())
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        let ask = Erc721Data {
            address: test.mock_addresses.erc721_a,
            id: 1.try_into()?,
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice creates purchase offer
        let buy_receipt = test
            .alice_client
            .erc20
            .buy_erc721_for_erc20(&bid, &ask, 0)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(buy_receipt)?.uid;

        // bob approves ERC721 for transfer
        test.bob_client
            .erc721
            .approve(&ask, ApprovalPurpose::Payment)
            .await?;

        // bob fulfills the buy attestation
        let _sell_receipt = test
            .bob_client
            .erc20
            .pay_erc20_for_erc721(buy_attestation)
            .await?;

        // verify token transfers
        let alice_owns_erc721 =
            mock_erc721.ownerOf(1.try_into()?).call().await?._0 == test.alice.address();

        let bob_balance_erc20 = mock_erc20.balanceOf(test.bob.address()).call().await?._0;

        // both sides received the tokens
        assert!(alice_owns_erc721, "Alice should now own the ERC721 token");
        assert_eq!(
            bob_balance_erc20,
            50.try_into()?,
            "Bob should have received the ERC20 tokens"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_permit_and_pay_erc20_for_erc721() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20, bob gets ERC721
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let mock_erc721 =
            crate::fixtures::MockERC721::new(test.mock_addresses.erc721_a, &test.god_provider);
        // Mint token ID 1 to Bob
        mock_erc721
            .mint(test.bob.address())
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        let ask = Erc721Data {
            address: test.mock_addresses.erc721_a,
            id: 1.try_into()?,
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice creates purchase offer
        let buy_receipt = test
            .alice_client
            .erc20
            .buy_erc721_for_erc20(&bid, &ask, 0)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(buy_receipt)?.uid;

        // bob approves ERC721 for transfer
        mock_erc721
            .approve(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
                1.try_into()?,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        // bob fulfills the buy attestation with permit
        let sell_receipt = test
            .bob_client
            .erc20
            .permit_and_pay_erc20_for_erc721(buy_attestation)
            .await?;

        // verify token transfers
        let alice_owns_erc721 =
            mock_erc721.ownerOf(1.try_into()?).call().await?._0 == test.alice.address();

        let bob_balance_erc20 = mock_erc20.balanceOf(test.bob.address()).call().await?._0;

        // both sides received the tokens
        assert!(alice_owns_erc721, "Alice should now own the ERC721 token");
        assert_eq!(
            bob_balance_erc20,
            50.try_into()?,
            "Bob should have received the ERC20 tokens"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_pay_erc20_for_erc1155() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20, bob gets ERC1155
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let mock_erc1155 =
            crate::fixtures::MockERC1155::new(test.mock_addresses.erc1155_a, &test.god_provider);
        // Mint tokens to Bob
        mock_erc1155
            .mint(test.bob.address(), 1.try_into()?, 20.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        let ask = Erc1155Data {
            address: test.mock_addresses.erc1155_a,
            id: 1.try_into()?,
            value: 10.try_into()?,
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice creates purchase offer
        let buy_receipt = test
            .alice_client
            .erc20
            .buy_erc1155_for_erc20(&bid, &ask, 0)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(buy_receipt)?.uid;

        // bob approves ERC1155 for transfer
        mock_erc1155
            .setApprovalForAll(
                test.addresses
                    .erc1155_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
                true,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        // bob fulfills the buy attestation
        let sell_receipt = test
            .bob_client
            .erc20
            .pay_erc20_for_erc1155(buy_attestation)
            .await?;

        // verify token transfers
        let alice_erc1155_balance = mock_erc1155
            .balanceOf(test.alice.address(), 1.try_into()?)
            .call()
            .await?
            ._0;

        let bob_balance_erc20 = mock_erc20.balanceOf(test.bob.address()).call().await?._0;

        // both sides received the tokens
        assert_eq!(
            alice_erc1155_balance,
            10.try_into()?,
            "Alice should have received the ERC1155 tokens"
        );
        assert_eq!(
            bob_balance_erc20,
            50.try_into()?,
            "Bob should have received the ERC20 tokens"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_permit_and_pay_erc20_for_erc1155() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20, bob gets ERC1155
        let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        mock_erc20
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let mock_erc1155 =
            crate::fixtures::MockERC1155::new(test.mock_addresses.erc1155_a, &test.god_provider);
        // Mint tokens to Bob
        mock_erc1155
            .mint(test.bob.address(), 1.try_into()?, 20.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        let ask = Erc1155Data {
            address: test.mock_addresses.erc1155_a,
            id: 1.try_into()?,
            value: 10.try_into()?,
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice creates purchase offer
        let buy_receipt = test
            .alice_client
            .erc20
            .buy_erc1155_for_erc20(&bid, &ask, 0)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(buy_receipt)?.uid;

        // bob approves ERC1155 for transfer
        mock_erc1155
            .setApprovalForAll(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
                true,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        // bob fulfills the buy attestation with permit
        let sell_receipt = test
            .bob_client
            .erc20
            .permit_and_pay_erc20_for_erc1155(buy_attestation)
            .await?;

        // verify token transfers
        let alice_erc1155_balance = mock_erc1155
            .balanceOf(test.alice.address(), 1.try_into()?)
            .call()
            .await?
            ._0;

        let bob_balance_erc20 = mock_erc20.balanceOf(test.bob.address()).call().await?._0;

        // both sides received the tokens
        assert_eq!(
            alice_erc1155_balance,
            10.try_into()?,
            "Alice should have received the ERC1155 tokens"
        );
        assert_eq!(
            bob_balance_erc20,
            50.try_into()?,
            "Bob should have received the ERC20 tokens"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_pay_erc20_for_bundle() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20, bob gets the bundle
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        let mock_erc20_b = MockERC20Permit::new(test.mock_addresses.erc20_b, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        mock_erc20_b
            .transfer(test.bob.address(), 20.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let mock_erc721 =
            crate::fixtures::MockERC721::new(test.mock_addresses.erc721_a, &test.god_provider);
        mock_erc721
            .mint(test.bob.address())
            .send()
            .await?
            .get_receipt()
            .await?;

        let mock_erc1155 =
            crate::fixtures::MockERC1155::new(test.mock_addresses.erc1155_a, &test.god_provider);
        mock_erc1155
            .mint(test.bob.address(), 1.try_into()?, 20.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        // Create bundle data
        let bundle = TokenBundleData {
            erc20s: vec![Erc20Data {
                address: test.mock_addresses.erc20_b,
                value: 20.try_into()?,
            }],
            erc721s: vec![Erc721Data {
                address: test.mock_addresses.erc721_a,
                id: 1.try_into()?,
            }],
            erc1155s: vec![Erc1155Data {
                address: test.mock_addresses.erc1155_a,
                id: 1.try_into()?,
                value: 5.try_into()?,
            }],
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice creates purchase offer
        let buy_receipt = test
            .alice_client
            .erc20
            .buy_bundle_for_erc20(&bid, &bundle, 0)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(buy_receipt)?.uid;

        // bob approves all tokens for transfer
        mock_erc20_b
            .approve(
                test.addresses
                    .erc20_addresses
                    .clone()
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
                20.try_into()?,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        mock_erc721
            .approve(
                test.addresses
                    .erc20_addresses
                    .clone()
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
                1.try_into()?,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        mock_erc1155
            .setApprovalForAll(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
                true,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        // bob fulfills the buy attestation
        let sell_receipt = test
            .bob_client
            .erc20
            .pay_erc20_for_bundle(buy_attestation)
            .await?;

        // verify token transfers
        let alice_erc20_b_balance = mock_erc20_b
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let alice_owns_erc721 =
            mock_erc721.ownerOf(1.try_into()?).call().await?._0 == test.alice.address();

        let alice_erc1155_balance = mock_erc1155
            .balanceOf(test.alice.address(), 1.try_into()?)
            .call()
            .await?
            ._0;

        let bob_balance_erc20_a = mock_erc20_a.balanceOf(test.bob.address()).call().await?._0;

        // both sides received the tokens
        assert_eq!(
            alice_erc20_b_balance,
            20.try_into()?,
            "Alice should have received the ERC20 B tokens"
        );
        assert!(alice_owns_erc721, "Alice should own the ERC721 token");
        assert_eq!(
            alice_erc1155_balance,
            5.try_into()?,
            "Alice should have received the ERC1155 tokens"
        );
        assert_eq!(
            bob_balance_erc20_a,
            50.try_into()?,
            "Bob should have received the ERC20 A tokens"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_permit_and_pay_erc20_for_bundle() -> eyre::Result<()> {
        // test setup
        let test = setup_test_environment().await?;

        // Set up tokens - alice gets ERC20, bob gets the bundle
        let mock_erc20_a = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
        let mock_erc20_b = MockERC20Permit::new(test.mock_addresses.erc20_b, &test.god_provider);
        mock_erc20_a
            .transfer(test.alice.address(), 100.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        mock_erc20_b
            .transfer(test.bob.address(), 20.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        let mock_erc721 =
            crate::fixtures::MockERC721::new(test.mock_addresses.erc721_a, &test.god_provider);
        mock_erc721
            .mint(test.bob.address())
            .send()
            .await?
            .get_receipt()
            .await?;

        let mock_erc1155 =
            crate::fixtures::MockERC1155::new(test.mock_addresses.erc1155_a, &test.god_provider);
        mock_erc1155
            .mint(test.bob.address(), 1.try_into()?, 20.try_into()?)
            .send()
            .await?
            .get_receipt()
            .await?;

        // Create a purchase offer
        let bid = Erc20Data {
            address: test.mock_addresses.erc20_a,
            value: 50.try_into()?,
        };

        // Create bundle data
        let bundle = TokenBundleData {
            erc20s: vec![Erc20Data {
                address: test.mock_addresses.erc20_b,
                value: 20.try_into()?,
            }],
            erc721s: vec![Erc721Data {
                address: test.mock_addresses.erc721_a,
                id: 1.try_into()?,
            }],
            erc1155s: vec![Erc1155Data {
                address: test.mock_addresses.erc1155_a,
                id: 1.try_into()?,
                value: 5.try_into()?,
            }],
        };

        // alice approves tokens for escrow
        test.alice_client
            .erc20
            .approve(&bid, ApprovalPurpose::Escrow)
            .await?;

        // alice creates purchase offer
        let buy_receipt = test
            .alice_client
            .erc20
            .buy_bundle_for_erc20(&bid, &bundle, 0)
            .await?;

        let buy_attestation = AlkahestClient::get_attested_event(buy_receipt)?.uid;

        // bob approves all tokens for transfer
        mock_erc20_b
            .approve(
                test.addresses
                    .erc20_addresses
                    .clone()
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
                20.try_into()?,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        mock_erc721
            .approve(
                test.addresses
                    .erc20_addresses
                    .clone()
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
                1.try_into()?,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        mock_erc1155
            .setApprovalForAll(
                test.addresses
                    .erc20_addresses
                    .ok_or(eyre::eyre!("no erc20-related addresses"))?
                    .payment_obligation,
                true,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        // bob fulfills the buy attestation with permit
        let sell_receipt = test
            .bob_client
            .erc20
            .permit_and_pay_erc20_for_bundle(buy_attestation)
            .await?;

        // verify token transfers
        let alice_erc20_b_balance = mock_erc20_b
            .balanceOf(test.alice.address())
            .call()
            .await?
            ._0;

        let alice_owns_erc721 =
            mock_erc721.ownerOf(1.try_into()?).call().await?._0 == test.alice.address();

        let alice_erc1155_balance = mock_erc1155
            .balanceOf(test.alice.address(), 1.try_into()?)
            .call()
            .await?
            ._0;

        let bob_balance_erc20_a = mock_erc20_a.balanceOf(test.bob.address()).call().await?._0;

        // both sides received the tokens
        assert_eq!(
            alice_erc20_b_balance,
            20.try_into()?,
            "Alice should have received the ERC20 B tokens"
        );
        assert!(alice_owns_erc721, "Alice should own the ERC721 token");
        assert_eq!(
            alice_erc1155_balance,
            5.try_into()?,
            "Alice should have received the ERC1155 tokens"
        );
        assert_eq!(
            bob_balance_erc20_a,
            50.try_into()?,
            "Bob should have received the ERC20 A tokens"
        );

        Ok(())
    }
}
