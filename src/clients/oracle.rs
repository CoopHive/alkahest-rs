use alloy::{
    dyn_abi::SolType,
    primitives::{Address, FixedBytes},
    signers::local::PrivateKeySigner,
};

use crate::{
    addresses::FILECOIN_CALIBRATION_ADDRESSES,
    types::{PublicProvider, WalletProvider},
    utils,
};

#[derive(Debug, Clone)]
pub struct OracleAddresses {
    pub trusted_oracle_arbiter: Address,
}

#[derive(Clone)]
pub struct OracleClient {
    _signer: PrivateKeySigner,
    public_provider: PublicProvider,
    wallet_provider: WalletProvider,

    pub addresses: OracleAddresses,
}

impl Default for OracleAddresses {
    fn default() -> Self {
        OracleAddresses {
            trusted_oracle_arbiter: FILECOIN_CALIBRATION_ADDRESSES
                .arbiters_addresses
                .unwrap()
                .trusted_oracle_arbiter,
        }
    }
}

pub enum AddressOrAddresses {
    Address(Address),
    Addresses(Vec<Address>),
}

pub enum Bytes32OrBytes32s {
    Bytes32(FixedBytes<32>),
    Bytes32s(Vec<FixedBytes<32>>),
}

pub struct AttestationFilter {
    pub attester: Option<AddressOrAddresses>,
    pub recipient: Option<AddressOrAddresses>,
    pub schema_uid: Option<Bytes32OrBytes32s>,
    pub uid: Option<Bytes32OrBytes32s>,
    pub ref_uid: Option<Bytes32OrBytes32s>,
}

pub struct AttestationFilterWithoutRefUid {
    pub attester: Option<AddressOrAddresses>,
    pub recipient: Option<AddressOrAddresses>,
    pub schema_uid: Option<Bytes32OrBytes32s>,
    pub uid: Option<Bytes32OrBytes32s>,
}

pub struct FulfillmentParams<T: SolType> {
    pub statement_abi: T,
    pub filter: AttestationFilter,
}

pub struct FulfillmentParamsWithoutRefUid<T: SolType> {
    pub statement_abi: T,
    pub filter: AttestationFilterWithoutRefUid,
}

pub struct EscrowParams<T: SolType> {
    pub demand_abi: T,
    pub filter: AttestationFilter,
}

impl OracleClient {
    pub async fn new(
        signer: PrivateKeySigner,
        rpc_url: impl ToString + Clone,
        addresses: Option<OracleAddresses>,
    ) -> eyre::Result<Self> {
        let public_provider = utils::get_public_provider(rpc_url.clone()).await?;
        let wallet_provider = utils::get_wallet_provider(signer.clone(), rpc_url.clone()).await?;

        Ok(OracleClient {
            _signer: signer,
            public_provider: public_provider.clone(),
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    pub async fn arbitrate_past<
        StatementData: SolType,
        Arbitrate: Fn(StatementData::RustType) -> bool,
    >(
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn arbitrate_past_async<
        StatementData: SolType,
        ArbitrateFut: Future<Output = bool>,
        Arbitrate: Fn(StatementData::RustType) -> ArbitrateFut,
    >(
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn listen_and_arbitrate<
        StatementData: SolType,
        Arbitrate: Fn(StatementData::RustType) -> bool,
    >(
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn listen_and_arbitrate_async<
        StatementData: SolType,
        ArbitrateFut: Future<Output = bool>,
        Arbitrate: Fn(StatementData::RustType) -> ArbitrateFut,
    >(
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn arbitrate_past_for_escrow<
        StatementData: SolType,
        DemandData: SolType,
        Arbitrate: Fn(StatementData::RustType, DemandData::RustType) -> bool,
    >(
        escrow: EscrowParams<DemandData>,
        fulfillment: FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn arbitrate_past_for_escrow_async<
        StatementData: SolType,
        DemandData: SolType,
        ArbitrateFut: Future<Output = bool>,
        Arbitrate: Fn(StatementData::RustType, DemandData::RustType) -> ArbitrateFut,
    >(
        escrow: EscrowParams<DemandData>,
        fulfillment: FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn listen_and_arbitrate_for_escrow<
        StatementData: SolType,
        DemandData: SolType,
        Arbitrate: Fn(StatementData::RustType, DemandData::RustType) -> bool,
    >(
        escrow: EscrowParams<DemandData>,
        fulfillment: FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn listen_and_arbitrate_for_escrow_async<
        StatementData: SolType,
        DemandData: SolType,
        ArbitrateFut: Future<Output = bool>,
        Arbitrate: Fn(StatementData::RustType, DemandData::RustType) -> ArbitrateFut,
    >(
        escrow: EscrowParams<DemandData>,
        fulfillment: FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }
}
