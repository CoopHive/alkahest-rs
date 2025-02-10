use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{address, keccak256, Address, FixedBytes, U256};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::{Signature, Signer};
use alloy::sol_types::SolValue;

use crate::contracts::{self, ERC20Permit};
use crate::types::{
    ApprovalPurpose, ArbiterData, Erc1155Data, Erc20Data, Erc721Data, TokenBundleData,
};
use crate::{types::WalletProvider, utils};

#[derive(Debug, Clone)]
pub struct Erc20Addresses {
    pub eas: Address,
    pub barter_utils: Address,
    pub escrow_obligation: Address,
    pub payment_obligation: Address,
}

#[derive(Clone)]
pub struct Erc20Client {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    pub addresses: Erc20Addresses,
}

impl Default for Erc20Addresses {
    fn default() -> Self {
        Self {
            eas: address!("0x4200000000000000000000000000000000000021"),
            barter_utils: address!("0xeb7daF691b03A906c563c3aa7FD6b8eFef55D13f"),
            escrow_obligation: address!("0xa34CD115800aA79758Ee5A781a4A3C02915c8602"),
            payment_obligation: address!("0x97128f9ea2cB1C1b49b778Db7df9fd921901B89c"),
        }
    }
}

impl Erc20Client {
    pub async fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<Erc20Addresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider =
            utils::get_wallet_provider(private_key.clone(), rpc_url.clone()).await?;

        Ok(Erc20Client {
            signer: private_key.to_string().parse()?,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    async fn get_permit_signature(
        &self,
        spender: Address,
        token: Erc20Data,
        deadline: U256,
    ) -> eyre::Result<Signature> {
        let token_contract = ERC20Permit::new(token.address, &self.wallet_provider);

        let permit_type_hash = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
        );
        let owner = self.signer.address();

        let (nonce, domain_separator) = tokio::try_join!(
            async { Ok::<_, eyre::Error>(token_contract.nonces(owner).call().await?._0) },
            async { Ok(token_contract.DOMAIN_SEPARATOR().call().await?._0) }
        )?;

        let struct_hash = keccak256(
            (
                permit_type_hash,
                owner,
                spender,
                token.value,
                nonce,
                deadline,
            )
                .abi_encode(),
        );

        let digest = keccak256((&[0x19, 0x01], domain_separator, struct_hash).abi_encode_packed());
        let signature = self.signer.sign_hash(&digest).await?;

        Ok(signature)
    }

    pub async fn approve(
        &self,
        token: Erc20Data,
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

    pub async fn approve_if_less(
        &self,
        token: Erc20Data,
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

    pub async fn buy_with_erc20(
        &self,
        price: Erc20Data,
        item: ArbiterData,
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

    pub async fn permit_and_buy_with_erc20(
        &self,
        price: Erc20Data,
        item: ArbiterData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.escrow_obligation,
                price.clone(),
                deadline.try_into()?,
            )
            .await?;

        let barter_utils_contract =
            contracts::ERC20BarterUtils::new(self.addresses.barter_utils, &self.wallet_provider);

        let receipt = barter_utils_contract
            .permitAndBuyWithErc20(
                price.address,
                price.value,
                item.arbiter,
                item.demand,
                expiration,
                deadline.try_into()?,
                if permit.v() { 27 } else { 28 },
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn pay_with_erc20(
        &self,
        price: Erc20Data,
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

    pub async fn permit_and_pay_with_erc20(
        &self,
        price: Erc20Data,
        payee: Address,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.payment_obligation,
                price.clone(),
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
                if permit.v() { 27 } else { 28 },
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_erc20_for_erc20(
        &self,
        bid: Erc20Data,
        ask: Erc20Data,
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

    pub async fn permit_and_buy_erc20_for_erc20(
        &self,
        bid: Erc20Data,
        ask: Erc20Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.escrow_obligation,
                bid.clone(),
                deadline.try_into()?,
            )
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
                if permit.v() { 27 } else { 28 },
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

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
                Erc20Data {
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
                if permit.v() { 27 } else { 28 },
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_erc721_for_erc20(
        &self,
        bid: Erc20Data,
        ask: Erc721Data,
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

    pub async fn permit_and_buy_erc721_for_erc20(
        &self,
        bid: Erc20Data,
        ask: Erc721Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.escrow_obligation,
                bid.clone(),
                deadline.try_into()?,
            )
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
                if permit.v() { 27 } else { 28 },
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

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
                Erc20Data {
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
                if permit.v() { 27 } else { 28 },
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn buy_erc1155_for_erc20(
        &self,
        bid: Erc20Data,
        ask: Erc1155Data,
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

    pub async fn permit_and_buy_erc1155_for_erc20(
        &self,
        bid: Erc20Data,
        ask: Erc1155Data,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.escrow_obligation,
                bid.clone(),
                deadline.try_into()?,
            )
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
                if permit.v() { 27 } else { 28 },
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

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
                Erc20Data {
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

    pub async fn buy_bundle_for_erc20(
        &self,
        bid: Erc20Data,
        ask: TokenBundleData,
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

    pub async fn permit_and_buy_bundle_for_erc20(
        &self,
        bid: Erc20Data,
        ask: TokenBundleData,
        expiration: u64,
    ) -> eyre::Result<TransactionReceipt> {
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let permit = self
            .get_permit_signature(
                self.addresses.escrow_obligation,
                bid.clone(),
                deadline.try_into()?,
            )
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
                if permit.v() { 27 } else { 28 },
                permit.r().into(),
                permit.s().into(),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

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
                Erc20Data {
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
                if permit.v() { 27 } else { 28 },
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
    use std::env;

    use crate::{
        contracts,
        types::{ApprovalPurpose, ArbiterData, Erc20Data},
        AlkahestClient,
    };

    use alloy::{
        primitives::{address, FixedBytes},
        sol,
        sol_types::SolValue,
    };
    use eyre::Result;

    #[tokio::test]
    async fn test_trade_erc20_for_erc20() -> Result<()> {
        let client_buyer = AlkahestClient::new(
            env::var("PRIVKEY_ALICE")?.as_str(),
            env::var("RPC_URL")?.as_str(),
            None,
        )
        .await?;

        let client_seller = AlkahestClient::new(
            env::var("PRIVKEY_BOB")?.as_str(),
            env::var("RPC_URL")?.as_str(),
            None,
        )
        .await?;

        let usdc = address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e");
        let eurc = address!("0x808456652fdb597867f38412077A9182bf77359F");

        client_buyer
            .erc20
            .approve(
                Erc20Data {
                    address: usdc,
                    value: 10.try_into()?,
                },
                ApprovalPurpose::Escrow,
            )
            .await?;

        // buy 10 eurc for 10 usdc
        let receipt = client_buyer
            .erc20
            .buy_erc20_for_erc20(
                Erc20Data {
                    address: usdc,
                    value: 10.try_into()?,
                },
                Erc20Data {
                    address: eurc,
                    value: 10.try_into()?,
                },
                0,
            )
            .await?;

        let attested = AlkahestClient::get_attested_event(receipt)?;
        println!("{:?}", attested);

        client_seller
            .erc20
            .approve(
                Erc20Data {
                    address: eurc,
                    value: 10.try_into()?,
                },
                ApprovalPurpose::Payment,
            )
            .await?;

        let receipt = client_seller
            .erc20
            .pay_erc20_for_erc20(attested.uid)
            .await?;
        println!("{:?}", receipt);

        Ok(())
    }

    #[tokio::test]
    async fn test_trade_erc20_for_custom() -> Result<()> {
        let client_buyer = AlkahestClient::new(
            env::var("PRIVKEY_ALICE")?.as_str(),
            env::var("RPC_URL")?.as_str(),
            None,
        )
        .await?;

        let client_seller = AlkahestClient::new(
            env::var("PRIVKEY_BOB")?.as_str(),
            env::var("RPC_URL")?.as_str(),
            None,
        )
        .await?;
        // the example will use JobResultObligation to demand a string to be capitalized
        // but JobResultObligation is generic enough to represent much more (a db query, a Dockerfile...)
        // see https://github.com/CoopHive/alkahest-mocks/blob/main/src/Statements/JobResultObligation.sol
        //
        // for custom cases, you'll have to implement your own arbiter
        //
        // in the example, we'll use TrustedPartyArbiter and TrivialArbiter
        // to make sure the result is from a particular trusted party,
        // without actually validating the result
        // see https://github.com/CoopHive/alkahest-mocks/blob/main/src/Validators/TrustedPartyArbiter.sol
        // and https://github.com/CoopHive/alkahest-mocks/blob/main/src/Validators/TrivialArbiter.sol

        // construct custom demand. note that this could be anything, and is determined by the arbiter.
        // since our base arbiter is TrivialArbiter, which doesn't actually decode DemandData,
        // the format doesn't matter. though the seller and buyer do still have to agree on it
        // so that the seller can properly fulfill the demand.
        sol! {
            struct ResultDemandData {
                string query;
            }
        }
        let base_demand = ResultDemandData {
            query: "hello world".to_string(),
        }
        .abi_encode();

        // we use TrustedPartyArbiter to wrap the base demand. This actually does decode DemandData,
        // and we use the DemandData format it defines,
        // to demand that only our trusted seller can fulfill the demand.
        // if the baseDemand were something other than TrivialArbiter,
        // it would be an additional check on the fulfillment.
        // many arbiters can be stacked according to this pattern.
        sol! {
            struct TrustedPartyDemandData {
                address creator;
                address baseArbiter;
                bytes baseDemand;
            }
        }

        let trival_arbiter = address!("0x8fdbf9C22Ce0B83aFEe8da63F14467663D150b5d");
        let demand = TrustedPartyDemandData {
            creator: client_seller.address,
            baseArbiter: trival_arbiter,
            baseDemand: base_demand.into(),
        }
        .abi_encode();

        // approve escrow contract to spend tokens
        let usdc = address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e");
        client_buyer
            .erc20
            .approve(
                Erc20Data {
                    address: usdc,
                    value: 10.try_into()?,
                },
                ApprovalPurpose::Escrow,
            )
            .await?;

        // make escrow with generic escrow function,
        // passing in TrustedPartyArbiter's address and our custom demand,
        // and no expiration
        let trusted_party_arbiter = address!("0x82FaE516dE4912C382FBF7D9D6d0194b7f532738");
        let escrow = client_buyer
            .erc20
            .buy_with_erc20(
                Erc20Data {
                    address: usdc,
                    value: 10.try_into()?,
                },
                ArbiterData {
                    arbiter: trusted_party_arbiter,
                    demand: demand.into(),
                },
                0,
            )
            .await?;
        let escrow = AlkahestClient::get_attested_event(escrow)?;
        println!("escrow: {escrow:?}");

        // now the seller manually decodes the statement and demand
        // and creates a StringResultObligation
        // and manually collects payment
        let buy_statement = client_seller
            .attestation
            .get_attestation(escrow.uid)
            .await?;
        let buy_statement = contracts::ERC20EscrowObligation::StatementData::abi_decode(
            buy_statement.data.as_ref(),
            true,
        )?;
        let decoded_demand =
            TrustedPartyDemandData::abi_decode(buy_statement.demand.as_ref(), true)?;
        let decoded_base_demand =
            ResultDemandData::abi_decode(decoded_demand.baseDemand.as_ref(), true);

        // uppercase string for the example;
        // this could be anything as agreed upon between buyer and seller
        // (running a Docker job, executing a DB query...)
        // as long as the job "spec" is agreed upon between buyer and seller,
        // and the "query" is contained in the demand
        let result = decoded_base_demand?.query.to_uppercase();
        println!("result: {}", result);

        // manually make result statement
        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            JobResultObligation,
            "src/contracts/JobResultObligation.json"
        );

        // JobResultObligation.StatementData:
        // struct StatementData {
        //     string result;
        // }
        //
        // JobResultObligation.makeStatement
        // function makeStatement(
        //     StatementData calldata data,
        //     bytes32 refUID
        // ) public returns (bytes32)
        let job_result_obligation = address!("0x823a06994B4e817a5127c042dBd2742CcFdF2076");
        let job_result_obligation =
            JobResultObligation::new(job_result_obligation, &client_seller.wallet_provider);

        let result = job_result_obligation
            .makeStatement(
                JobResultObligation::StatementData {
                    result: result.to_string(),
                },
                FixedBytes::<32>::ZERO,
            )
            .send()
            .await?
            .get_receipt()
            .await?;
        let result = AlkahestClient::get_attested_event(result)?;
        println!("result: {result:?}");

        // and collect the payment from escrow
        let collection = client_seller
            .erc20
            .collect_payment(escrow.uid, result.uid)
            .await?;
        println!("collection: {collection:?}");

        // meanwhile, the buyer can wait for fulfillment of her escrow.
        // if called after fulfillment, like in this case, it will
        // return the fulfilling statement immediately
        let fulfillment = client_buyer
            .wait_for_fulfillment(
                client_buyer.erc20.addresses.escrow_obligation,
                escrow.uid,
                None,
            )
            .await?;

        // and extract the result from the fulfillment statement
        let fulfillment = client_buyer
            .attestation
            .get_attestation(fulfillment.fulfillment)
            .await?;

        let result =
            JobResultObligation::StatementData::abi_decode(fulfillment.data.as_ref(), true);
        println!("result: {}", result?.result);

        Ok(())
    }
}
