use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, U256},
    providers::{
        Identity, RootProvider,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
    },
};

use crate::contracts::IEAS::Attestation;

pub type WalletProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

pub type PublicProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

#[derive(Debug, Clone)]
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

pub struct DecodedAttestation<T> {
    pub attestation: Attestation,
    pub data: T,
}
