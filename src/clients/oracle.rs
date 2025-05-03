use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    dyn_abi::SolType,
    eips::BlockNumberOrTag,
    primitives::{Address, FixedBytes},
    providers::Provider,
    rpc::types::{Filter, ValueOrArray},
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use futures::future::{join_all, try_join_all};

use crate::{
    addresses::BASE_SEPOLIA_ADDRESSES,
    contracts::{IEAS, TrustedOracleArbiter},
    types::{PublicProvider, WalletProvider},
    utils,
};

#[derive(Debug, Clone)]
pub struct OracleAddresses {
    pub eas: Address,
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
            eas: BASE_SEPOLIA_ADDRESSES.arbiters_addresses.unwrap().eas,
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

impl From<(AttestationFilterWithoutRefUid, ValueOrArray<FixedBytes<32>>)> for AttestationFilter {
    fn from(
        filter_and_ref_uid: (AttestationFilterWithoutRefUid, ValueOrArray<FixedBytes<32>>),
    ) -> Self {
        let (filter, ref_uid) = filter_and_ref_uid;

        Self {
            attester: filter.attester,
            recipient: filter.recipient,
            schema_uid: filter.schema_uid,
            uid: filter.uid,
            ref_uid: Some(ref_uid),
        }
    }
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

    fn make_filter(&self, p: &AttestationFilter) -> Filter {
        let mut filter = Filter::new()
            .address(self.addresses.eas)
            .event_signature(IEAS::Attested::SIGNATURE_HASH)
            .from_block(BlockNumberOrTag::Earliest);

        if let Some(ValueOrArray::Value(a)) = &p.recipient {
            filter = filter.topic1(a.into_word());
        }

        if let Some(ValueOrArray::Array(ads)) = &p.recipient {
            filter = filter.topic1(ads.into_iter().map(|a| a.into_word()).collect::<Vec<_>>());
        }

        if let Some(ValueOrArray::Value(a)) = &p.attester {
            filter = filter.topic2(a.into_word());
        }

        if let Some(ValueOrArray::Array(ads)) = &p.attester {
            filter = filter.topic2(ads.into_iter().map(|a| a.into_word()).collect::<Vec<_>>());
        }

        if let Some(ValueOrArray::Value(schema)) = &p.schema_uid {
            filter = filter.topic3(*schema);
        }

        if let Some(ValueOrArray::Array(schemas)) = &p.schema_uid {
            filter = filter.topic3(schemas.clone());
        }

        filter
    }

    pub async fn arbitrate_past<
        StatementData: SolType,
        Arbitrate: Fn(StatementData::RustType) -> Option<bool>,
    >(
        &self,
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) -> eyre::Result<()> {
        let filter = self.make_filter(&fulfillment.filter);
        let logs = self
            .public_provider
            .get_logs(&filter)
            .await?
            .into_iter()
            .map(|log| log.log_decode::<IEAS::Attested>())
            .collect::<Result<Vec<_>, _>>()?;

        let attestation_futs = logs.into_iter().map(|log| {
            let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
            async move { eas.getAttestation(log.inner.uid).call().await }
        });

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let attestations = try_join_all(attestation_futs)
            .await?
            .into_iter()
            .map(|a| a._0)
            .filter(|a| {
                if let Some(ValueOrArray::Value(ref_uid)) = &fulfillment.filter.ref_uid {
                    if a.refUID != *ref_uid {
                        return false;
                    };
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &fulfillment.filter.ref_uid {
                    if ref_uids.contains(&a.refUID) {
                        return false;
                    };
                }

                if a.expirationTime != 0 && a.expirationTime < now {
                    return false;
                }

                if a.revocationTime != 0 && a.revocationTime < now {
                    return false;
                }

                return true;
            })
            .collect::<Vec<_>>();

        let statements = attestations
            .iter()
            .map(|a| StatementData::abi_decode(&a.data, true))
            .collect::<Result<Vec<_>, _>>()?;

        let decisions = statements
            .into_iter()
            .map(|s| arbitrate(s))
            .collect::<Vec<_>>();

        let arbitration_futs = attestations
            .into_iter()
            .zip(decisions)
            .map(|(attestation, decision)| {
                let trusted_oracle_arbiter = TrustedOracleArbiter::new(
                    self.addresses.trusted_oracle_arbiter,
                    &self.wallet_provider,
                );

                if let Some(decision) = decision {
                    Some(async move {
                        trusted_oracle_arbiter
                            .arbitrate(attestation.uid, decision)
                            .send()
                            .await
                    })
                } else {
                    None
                }
            })
            .flatten()
            .collect::<Vec<_>>();

        let pending_txs = try_join_all(arbitration_futs).await?;
        let receipt_futs = pending_txs
            .into_iter()
            .map(|tx| async move { tx.get_receipt().await });

        let receipts = try_join_all(receipt_futs).await?;

    }

    pub async fn arbitrate_past_async<
        StatementData: SolType,
        ArbitrateFut: Future<Output = Option<bool>>,
        Arbitrate: Fn(StatementData::RustType) -> ArbitrateFut,
    >(
        &self,
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn listen_and_arbitrate<
        StatementData: SolType,
        Arbitrate: Fn(StatementData::RustType) -> Option<bool>,
    >(
        &self,
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }

    pub async fn listen_and_arbitrate_async<
        StatementData: SolType,
        ArbitrateFut: Future<Output = Option<bool>>,
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
        Arbitrate: Fn(StatementData::RustType, DemandData::RustType) -> Option<bool>,
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
        ArbitrateFut: Future<Output = Option<bool>>,
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
        Arbitrate: Fn(StatementData::RustType, DemandData::RustType) -> Option<bool>,
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
        ArbitrateFut: Future<Output = Option<bool>>,
        Arbitrate: Fn(StatementData::RustType, DemandData::RustType) -> ArbitrateFut,
    >(
        &self,
        escrow: EscrowParams<DemandData>,
        fulfillment: FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
    ) {
    }
}
