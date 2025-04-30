use alloy::{
    dyn_abi::SolType,
    primitives::{Address, FixedBytes},
    signers::local::PrivateKeySigner,
};

use crate::{
    addresses::BASE_SEPOLIA_ADDRESSES,
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
            trusted_oracle_arbiter: BASE_SEPOLIA_ADDRESSES
                .arbiters_addresses
                .unwrap()
                .trusted_oracle_arbiter,
        }
    }
}

pub struct AttestationFilter {
    pub attester: Option<ValueOrArray<Address>>,
    pub recipient: Option<ValueOrArray<Address>>,
    pub schema_uid: Option<ValueOrArray<FixedBytes<32>>>,
    pub uid: Option<ValueOrArray<FixedBytes<32>>>,
    pub ref_uid: Option<ValueOrArray<FixedBytes<32>>>,
}

pub struct AttestationFilterWithoutRefUid {
    pub attester: Option<ValueOrArray<Address>>,
    pub recipient: Option<ValueOrArray<Address>>,
    pub schema_uid: Option<ValueOrArray<FixedBytes<32>>>,
    pub uid: Option<ValueOrArray<FixedBytes<32>>>,
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
        &self,
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn arbitrate_past_async<
        StatementData: SolType,
        ArbitrateFut: Future<Output = bool>,
        Arbitrate: Fn(StatementData::RustType) -> ArbitrateFut,
    >(
        &self,
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn listen_and_arbitrate<
        StatementData: SolType,
        Arbitrate: Fn(StatementData::RustType) -> bool,
    >(
        &self,
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn listen_and_arbitrate_async<
        StatementData: SolType,
        ArbitrateFut: Future<Output = bool>,
        Arbitrate: Fn(StatementData::RustType) -> ArbitrateFut,
    >(
        &self,
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn arbitrate_past_for_escrow<
        StatementData: SolType,
        DemandData: SolType,
        Arbitrate: Fn(StatementData::RustType, DemandData::RustType) -> bool,
    >(
        &self,
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
        &self,
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
        &self,
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
        &self,
        escrow: EscrowParams<DemandData>,
        fulfillment: FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }
}
