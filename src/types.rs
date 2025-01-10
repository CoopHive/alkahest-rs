use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{Address, Bytes, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, RootProvider,
    },
    transports::http::{Client, Http},
};

use crate::contracts;

pub type WalletProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<Http<Client>>,
    Http<Client>,
    Ethereum,
>;

pub type PublicProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider<Http<Client>>,
    Http<Client>,
    Ethereum,
>;

pub struct ArbiterData {
    pub arbiter: Address,
    pub demand: Bytes,
}

#[derive(Debug, Clone)]
pub struct Erc20Data {
    pub address: Address,
    pub value: U256,
}

#[derive(Debug, Clone)]
pub struct Erc721Data {
    pub address: Address,
    pub id: U256,
}

#[derive(Debug, Clone)]
pub struct Erc1155Data {
    pub address: Address,
    pub id: U256,
    pub value: U256,
}

#[derive(Debug, Clone)]
pub struct TokenBundleData {
    pub erc20s: Vec<Erc20Data>,
    pub erc721s: Vec<Erc721Data>,
    pub erc1155s: Vec<Erc1155Data>,
}

impl TokenBundleData {
    // Helper function to convert to the common token bundle format
    fn into_bundle_components(
        self,
    ) -> (
        Vec<Address>, // erc20Tokens
        Vec<U256>,    // erc20Amounts
        Vec<Address>, // erc721Tokens
        Vec<U256>,    // erc721TokenIds
        Vec<Address>, // erc1155Tokens
        Vec<U256>,    // erc1155TokenIds
        Vec<U256>,    // erc1155Amounts
    ) {
        (
            self.erc20s.iter().map(|erc20| erc20.address).collect(),
            self.erc20s.iter().map(|erc20| erc20.value).collect(),
            self.erc721s.iter().map(|erc721| erc721.address).collect(),
            self.erc721s.iter().map(|erc721| erc721.id).collect(),
            self.erc1155s
                .iter()
                .map(|erc1155| erc1155.address)
                .collect(),
            self.erc1155s.iter().map(|erc1155| erc1155.id).collect(),
            self.erc1155s.iter().map(|erc1155| erc1155.value).collect(),
        )
    }
}

macro_rules! impl_payment_obligation {
    ($target:path) => {
        impl From<(TokenBundleData, Address)> for $target {
            fn from((bundle, payee): (TokenBundleData, Address)) -> Self {
                let components = bundle.into_bundle_components();
                Self {
                    erc20Tokens: components.0,
                    erc20Amounts: components.1,
                    erc721Tokens: components.2,
                    erc721TokenIds: components.3,
                    erc1155Tokens: components.4,
                    erc1155TokenIds: components.5,
                    erc1155Amounts: components.6,
                    payee,
                }
            }
        }
    };
}

impl From<(TokenBundleData, ArbiterData)>
    for contracts::token_bundle::TokenBundleEscrowObligation::StatementData
{
    fn from((bundle, arbiter_data): (TokenBundleData, ArbiterData)) -> Self {
        let components = bundle.into_bundle_components();

        Self {
            erc20Tokens: components.0,
            erc20Amounts: components.1,
            erc721Tokens: components.2,
            erc721TokenIds: components.3,
            erc1155Tokens: components.4,
            erc1155TokenIds: components.5,
            erc1155Amounts: components.6,
            arbiter: arbiter_data.arbiter,
            demand: arbiter_data.demand,
        }
    }
}

impl_payment_obligation!(contracts::token_bundle::TokenBundlePaymentObligation::StatementData);
impl_payment_obligation!(
    contracts::erc20_barter_cross_token::TokenBundlePaymentObligation::StatementData
);
impl_payment_obligation!(
    contracts::erc721_barter_cross_token::TokenBundlePaymentObligation::StatementData
);
impl_payment_obligation!(
    contracts::erc1155_barter_cross_token::TokenBundlePaymentObligation::StatementData
);

pub enum ApprovalPurpose {
    Escrow,
    Payment,
}
