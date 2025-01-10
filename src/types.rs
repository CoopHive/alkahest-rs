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
    sol,
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

pub enum ApprovalPurpose {
    Escrow,
    Payment,
}
