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

impl From<(TokenBundleData, Address)>
    for contracts::token_bundle::TokenBundlePaymentObligation::StatementData
{
    fn from(data: (TokenBundleData, Address)) -> Self {
        let (price, payee) = data;
        contracts::token_bundle::TokenBundlePaymentObligation::StatementData {
            erc20Tokens: price
                .erc20s
                .clone()
                .into_iter()
                .map(|erc20| erc20.address)
                .collect(),
            erc20Amounts: price.erc20s.into_iter().map(|erc20| erc20.value).collect(),
            erc721Tokens: price
                .erc721s
                .clone()
                .into_iter()
                .map(|erc721| erc721.address)
                .collect(),
            erc721TokenIds: price.erc721s.into_iter().map(|erc721| erc721.id).collect(),
            erc1155Tokens: price
                .erc1155s
                .clone()
                .into_iter()
                .map(|erc1155| erc1155.address)
                .collect(),
            erc1155TokenIds: price
                .erc1155s
                .clone()
                .into_iter()
                .map(|erc1155| erc1155.id)
                .collect(),
            erc1155Amounts: price
                .erc1155s
                .into_iter()
                .map(|erc1155| erc1155.value)
                .collect(),
            payee,
        }
    }
}

impl From<contracts::token_bundle::TokenBundlePaymentObligation::StatementData>
    for contracts::erc20_barter_cross_token::TokenBundlePaymentObligation::StatementData
{
    fn from(data: contracts::token_bundle::TokenBundlePaymentObligation::StatementData) -> Self {
        Self {
            erc20Tokens: data.erc20Tokens,
            erc20Amounts: data.erc20Amounts,
            erc721Tokens: data.erc721Tokens,
            erc721TokenIds: data.erc721TokenIds,
            erc1155Tokens: data.erc1155Tokens,
            erc1155TokenIds: data.erc1155TokenIds,
            erc1155Amounts: data.erc1155Amounts,
            payee: data.payee,
        }
    }
}

impl From<(TokenBundleData, Address)>
    for contracts::erc20_barter_cross_token::TokenBundlePaymentObligation::StatementData
{
    fn from(data: (TokenBundleData, Address)) -> Self {
        let data: contracts::token_bundle::TokenBundlePaymentObligation::StatementData =
            data.into();
        data.into()
    }
}

impl From<(TokenBundleData, ArbiterData)>
    for contracts::token_bundle::TokenBundleEscrowObligation::StatementData
{
    fn from(data: (TokenBundleData, ArbiterData)) -> Self {
        let (price, demand) = data;

        contracts::token_bundle::TokenBundleEscrowObligation::StatementData {
            erc20Tokens: price
                .erc20s
                .clone()
                .into_iter()
                .map(|erc20| erc20.address)
                .collect(),
            erc20Amounts: price.erc20s.into_iter().map(|erc20| erc20.value).collect(),
            erc721Tokens: price
                .erc721s
                .clone()
                .into_iter()
                .map(|erc721| erc721.address)
                .collect(),
            erc721TokenIds: price.erc721s.into_iter().map(|erc721| erc721.id).collect(),
            erc1155Tokens: price
                .erc1155s
                .clone()
                .into_iter()
                .map(|erc1155| erc1155.address)
                .collect(),
            erc1155TokenIds: price
                .erc1155s
                .clone()
                .into_iter()
                .map(|erc1155| erc1155.id)
                .collect(),
            erc1155Amounts: price
                .erc1155s
                .into_iter()
                .map(|erc1155| erc1155.value)
                .collect(),
            arbiter: demand.arbiter,
            demand: demand.demand,
        }
    }
}
