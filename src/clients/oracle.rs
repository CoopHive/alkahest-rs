use std::{
    collections::HashMap,
    pin::Pin,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::{
    dyn_abi::SolType,
    eips::BlockNumberOrTag,
    primitives::{Address, FixedBytes},
    providers::Provider,
    rpc::types::{Filter, FilterBlockOption, FilterSet, TransactionReceipt, ValueOrArray},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};
use futures::{
    StreamExt as _,
    future::{join_all, try_join_all},
};
use itertools::izip;

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

#[derive(Clone)]
pub struct AttestationFilter {
    pub block_option: Option<FilterBlockOption>,
    pub attester: Option<ValueOrArray<Address>>,
    pub recipient: Option<ValueOrArray<Address>>,
    pub schema_uid: Option<ValueOrArray<FixedBytes<32>>>,
    pub uid: Option<ValueOrArray<FixedBytes<32>>>,
    pub ref_uid: Option<ValueOrArray<FixedBytes<32>>>,
}

#[derive(Clone)]
pub struct AttestationFilterWithoutRefUid {
    pub block_option: Option<FilterBlockOption>,
    pub attester: Option<ValueOrArray<Address>>,
    pub recipient: Option<ValueOrArray<Address>>,
    pub schema_uid: Option<ValueOrArray<FixedBytes<32>>>,
    pub uid: Option<ValueOrArray<FixedBytes<32>>>,
}

impl
    From<(
        AttestationFilterWithoutRefUid,
        Option<ValueOrArray<FixedBytes<32>>>,
    )> for AttestationFilter
{
    fn from(
        filter_and_ref_uid: (
            AttestationFilterWithoutRefUid,
            Option<ValueOrArray<FixedBytes<32>>>,
        ),
    ) -> Self {
        let (filter, ref_uid) = filter_and_ref_uid;

        Self {
            block_option: filter.block_option,
            attester: filter.attester,
            recipient: filter.recipient,
            schema_uid: filter.schema_uid,
            uid: filter.uid,
            ref_uid,
        }
    }
}
#[derive(Clone)]
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

pub struct Decision<T: SolType, U: SolType> {
    pub attestation: IEAS::Attestation,
    pub statement: T::RustType,
    pub demand: Option<U::RustType>,
    pub decision: bool,
    pub receipt: TransactionReceipt,
}

sol! {
    struct ArbiterDemand {
        address oracle;
        bytes demand;
    }
}

pub struct ListenAndArbitrateResult<StatementData: SolType> {
    pub decisions: Vec<Decision<StatementData, ()>>,
    pub subscription_id: FixedBytes<32>,
}
pub struct ListenAndArbitrateNewFulfillmentsResult {
    pub subscription_id: FixedBytes<32>,
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
    pub async fn unsubscribe(&self, local_id: FixedBytes<32>) -> eyre::Result<()> {
        self.public_provider
            .unsubscribe(local_id)
            .await
            .map_err(Into::into)
    }

    fn make_filter(&self, p: &AttestationFilter) -> Filter {
        let mut filter = Filter::new()
            .address(self.addresses.eas)
            .event_signature(IEAS::Attested::SIGNATURE_HASH)
            .from_block(
                p.block_option
                    .as_ref()
                    .and_then(|b| b.get_from_block())
                    .cloned()
                    .unwrap_or(BlockNumberOrTag::Earliest),
            )
            .to_block(
                p.block_option
                    .as_ref()
                    .and_then(|b| b.get_to_block())
                    .cloned()
                    .unwrap_or(BlockNumberOrTag::Latest),
            );

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

    fn make_filter_without_refuid(&self, p: &AttestationFilterWithoutRefUid) -> Filter {
        let mut filter = Filter::new()
            .address(self.addresses.eas)
            .event_signature(IEAS::Attested::SIGNATURE_HASH)
            .from_block(
                p.block_option
                    .as_ref()
                    .and_then(|b| b.get_from_block())
                    .cloned()
                    .unwrap_or(BlockNumberOrTag::Earliest),
            )
            .to_block(
                p.block_option
                    .as_ref()
                    .and_then(|b| b.get_to_block())
                    .cloned()
                    .unwrap_or(BlockNumberOrTag::Latest),
            );

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
        Arbitrate: Fn(&StatementData::RustType) -> Option<bool>,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) -> eyre::Result<Vec<Decision<StatementData, ()>>> {
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

        let decisions = statements.iter().map(|s| arbitrate(s)).collect::<Vec<_>>();

        let mut receipts = Vec::new();
        let trusted_oracle_arbiter =
            TrustedOracleArbiter::new(self.addresses.trusted_oracle_arbiter, &self.wallet_provider);

        for (attestation, decision) in attestations.iter().zip(decisions.iter()) {
            if let Some(decision) = decision {
                let tx = trusted_oracle_arbiter
                    .arbitrate(attestation.uid, *decision)
                    .send()
                    .await?;
                let receipt = tx.get_receipt().await?;
                receipts.push(Some(receipt));
            } else {
                receipts.push(None);
            }
        }

        let result = izip!(attestations, statements, decisions, receipts)
            .filter(|(_, _, d, r)| d.is_some() && r.is_some())
            .map(|(attestation, statement, decision, receipt)| Decision {
                attestation,
                statement,
                demand: None,
                decision: decision.unwrap(),
                receipt: receipt.unwrap(),
            })
            .collect::<Vec<Decision<StatementData, ()>>>();

        Ok(result)
    }

    pub async fn arbitrate_past_async<
        StatementData: SolType,
        ArbitrateFut: Future<Output = Option<bool>>,
        Arbitrate: Fn(&StatementData::RustType) -> ArbitrateFut + Copy,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
    ) -> eyre::Result<Vec<Decision<StatementData, ()>>> {
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

        let decision_futs = statements.iter().map(|s| async move { arbitrate(s).await });
        let decisions = join_all(decision_futs).await;

        let arbitration_futs = attestations
            .iter()
            .zip(decisions.iter())
            .map(|(attestation, decision)| {
                let trusted_oracle_arbiter = TrustedOracleArbiter::new(
                    self.addresses.trusted_oracle_arbiter,
                    &self.wallet_provider,
                );

                if let Some(decision) = decision {
                    Some(async move {
                        trusted_oracle_arbiter
                            .arbitrate(attestation.uid, *decision)
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

        let result = izip!(attestations, statements, decisions, receipts)
            .filter(|(_, _, d, _)| d.is_some())
            .map(|(attestation, statement, decision, receipt)| Decision {
                attestation,
                statement,
                demand: None,
                decision: decision.unwrap(),
                receipt,
            })
            .collect::<Vec<Decision<StatementData, ()>>>();

        Ok(result)
    }

    pub async fn listen_and_arbitrate<
        StatementData: SolType + Clone + Send + 'static,
        Arbitrate: Fn(&StatementData::RustType) -> Option<bool> + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
    ) -> eyre::Result<ListenAndArbitrateResult<StatementData>>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let decisions = self.arbitrate_past(&fulfillment, arbitrate).await?;
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream = sub.into_stream();
        let wallet_provider = self.wallet_provider.clone();
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;
        let fulfillment = fulfillment.clone();

        tokio::spawn(async move {
            let eas = IEAS::new(eas_address, &wallet_provider);
            let arbiter = TrustedOracleArbiter::new(arbiter_address, &wallet_provider);
            let mut stream = stream;

            while let Some(log) = stream.next().await {
                println!("Received log: {:?}", log);

                let Ok(log) = log.log_decode::<IEAS::Attested>() else {
                    continue;
                };
                let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else {
                    continue;
                };
                let attestation = attestation._0;

                if let Some(ValueOrArray::Value(ref_uid)) = &fulfillment.filter.ref_uid {
                    if attestation.refUID != *ref_uid {
                        continue;
                    }
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &fulfillment.filter.ref_uid {
                    if !ref_uids.contains(&attestation.refUID) {
                        continue;
                    }
                }

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if (attestation.expirationTime != 0 && attestation.expirationTime < now)
                    || (attestation.revocationTime != 0 && attestation.revocationTime < now)
                {
                    continue;
                }

                let Ok(statement) = StatementData::abi_decode(&attestation.data, true) else {
                    continue;
                };
                let Some(decision_value) = arbitrate(&statement) else {
                    continue;
                };

                let Ok(tx) = arbiter
                    .arbitrate(attestation.uid, decision_value)
                    .send()
                    .await
                else {
                    continue;
                };
                let Ok(receipt) = tx.get_receipt().await else {
                    continue;
                };

                let decision = Decision {
                    attestation,
                    statement,
                    demand: None,
                    decision: decision_value,
                    receipt,
                };

                tokio::spawn(on_after_arbitrate(&decision));
            }
        });

        Ok(ListenAndArbitrateResult {
            decisions,
            subscription_id: local_id,
        })
    }

    pub async fn listen_and_arbitrate_async<
        StatementData: SolType + Clone + Send + 'static,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&StatementData::RustType) -> ArbitrateFut + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
    ) -> eyre::Result<ListenAndArbitrateResult<StatementData>>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let decisions = self.arbitrate_past_async(fulfillment, arbitrate).await?;
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream = sub.into_stream();

        let wallet_provider = self.wallet_provider.clone();
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;
        let fulfillment = fulfillment.clone();

        tokio::spawn(async move {
            let eas = IEAS::new(eas_address, &wallet_provider);
            let trusted_oracle_arbiter =
                TrustedOracleArbiter::new(arbiter_address, &wallet_provider);
            let mut stream = stream;

            while let Some(log_result) = stream.next().await {
                let Ok(log) = log_result.log_decode::<IEAS::Attested>() else {
                    continue;
                };

                let Ok(attestation_result) = eas.getAttestation(log.inner.uid).call().await else {
                    continue;
                };
                let attestation = attestation_result._0;

                if let Some(ValueOrArray::Value(ref_uid)) = &fulfillment.filter.ref_uid {
                    if attestation.refUID != *ref_uid {
                        continue;
                    }
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &fulfillment.filter.ref_uid {
                    if !ref_uids.contains(&attestation.refUID) {
                        continue;
                    }
                }

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if (attestation.expirationTime != 0 && attestation.expirationTime < now)
                    || (attestation.revocationTime != 0 && attestation.revocationTime < now)
                {
                    continue;
                }

                let Ok(statement) = StatementData::abi_decode(&attestation.data, true) else {
                    continue;
                };

                if let Some(decision_value) = arbitrate(&statement).await {
                    let Ok(tx) = trusted_oracle_arbiter
                        .arbitrate(attestation.uid, decision_value)
                        .send()
                        .await
                    else {
                        continue;
                    };

                    let Ok(receipt) = tx.get_receipt().await else {
                        continue;
                    };

                    let decision = Decision {
                        attestation,
                        statement,
                        demand: None,
                        decision: decision_value,
                        receipt,
                    };

                    tokio::spawn(on_after_arbitrate(&decision));
                }
            }
        });

        Ok(ListenAndArbitrateResult {
            decisions,
            subscription_id: local_id,
        })
    }

    pub async fn listen_and_arbitrate_new_fulfillments<
        StatementData: SolType + Clone + Send + 'static,
        Arbitrate: Fn(&StatementData::RustType) -> Option<bool> + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
    ) -> eyre::Result<ListenAndArbitrateNewFulfillmentsResult>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream = sub.into_stream();

        let wallet_provider = self.wallet_provider.clone(); // Must be Arc or Send + Sync
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;
        let fulfillment = fulfillment.clone();

        tokio::spawn(async move {
            let eas = IEAS::new(eas_address, &wallet_provider);
            let arbiter = TrustedOracleArbiter::new(arbiter_address, &wallet_provider);
            let mut stream = stream;

            while let Some(log) = stream.next().await {
                println!("Received log: {:?}", log);

                let Ok(log) = log.log_decode::<IEAS::Attested>() else {
                    continue;
                };
                let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else {
                    continue;
                };
                let attestation = attestation._0;

                if let Some(ValueOrArray::Value(ref_uid)) = &fulfillment.filter.ref_uid {
                    if attestation.refUID != *ref_uid {
                        continue;
                    }
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &fulfillment.filter.ref_uid {
                    if !ref_uids.contains(&attestation.refUID) {
                        continue;
                    }
                }

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if (attestation.expirationTime != 0 && attestation.expirationTime < now)
                    || (attestation.revocationTime != 0 && attestation.revocationTime < now)
                {
                    continue;
                }

                let Ok(statement) = StatementData::abi_decode(&attestation.data, true) else {
                    continue;
                };
                let Some(decision_value) = arbitrate(&statement) else {
                    continue;
                };

                let Ok(tx) = arbiter
                    .arbitrate(attestation.uid, decision_value)
                    .send()
                    .await
                else {
                    continue;
                };
                let Ok(receipt) = tx.get_receipt().await else {
                    continue;
                };

                let decision = Decision {
                    attestation,
                    statement,
                    demand: None,
                    decision: decision_value,
                    receipt,
                };

                tokio::spawn(on_after_arbitrate(&decision));
            }
        });

        Ok(ListenAndArbitrateNewFulfillmentsResult {
            subscription_id: local_id,
        })
    }

    pub async fn listen_and_arbitrate_new_fulfillments_async<
        StatementData: SolType + Clone + Send + 'static,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&StatementData::RustType) -> ArbitrateFut + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
    ) -> eyre::Result<ListenAndArbitrateNewFulfillmentsResult>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream = sub.into_stream();

        let wallet_provider = self.wallet_provider.clone();
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;
        let fulfillment = fulfillment.clone();

        tokio::spawn(async move {
            let eas = IEAS::new(eas_address, &wallet_provider);
            let trusted_oracle_arbiter =
                TrustedOracleArbiter::new(arbiter_address, &wallet_provider);
            let mut stream = stream;

            while let Some(log_result) = stream.next().await {
                let Ok(log) = log_result.log_decode::<IEAS::Attested>() else {
                    continue;
                };

                let Ok(attestation_result) = eas.getAttestation(log.inner.uid).call().await else {
                    continue;
                };
                let attestation = attestation_result._0;

                if let Some(ValueOrArray::Value(ref_uid)) = &fulfillment.filter.ref_uid {
                    if attestation.refUID != *ref_uid {
                        continue;
                    }
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &fulfillment.filter.ref_uid {
                    if !ref_uids.contains(&attestation.refUID) {
                        continue;
                    }
                }

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if (attestation.expirationTime != 0 && attestation.expirationTime < now)
                    || (attestation.revocationTime != 0 && attestation.revocationTime < now)
                {
                    continue;
                }

                let Ok(statement) = StatementData::abi_decode(&attestation.data, true) else {
                    continue;
                };

                if let Some(decision_value) = arbitrate(&statement).await {
                    let Ok(tx) = trusted_oracle_arbiter
                        .arbitrate(attestation.uid, decision_value)
                        .send()
                        .await
                    else {
                        continue;
                    };

                    let Ok(receipt) = tx.get_receipt().await else {
                        continue;
                    };

                    let decision = Decision {
                        attestation,
                        statement,
                        demand: None,
                        decision: decision_value,
                        receipt,
                    };

                    tokio::spawn(on_after_arbitrate(&decision));
                }
            }
        });

        Ok(ListenAndArbitrateNewFulfillmentsResult {
            subscription_id: local_id,
        })
    }

    pub async fn arbitrate_past_for_escrow<
        StatementData: SolType,
        DemandData: SolType,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> Option<bool>,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
    ) -> eyre::Result<(
        Vec<Decision<StatementData, DemandData>>,
        Vec<IEAS::Attestation>,
        Vec<<DemandData as SolType>::RustType>,
    )>
    where
        DemandData::RustType: Clone,
    {
        let escrow_filter = self.make_filter(&escrow.filter);
        let escrow_logs_fut = async move { self.public_provider.get_logs(&escrow_filter).await };

        let fulfillment_filter: AttestationFilter = (fulfillment.filter.clone(), None).into();
        let fulfillment_filter = self.make_filter(&fulfillment_filter);
        let fulfillment_logs_fut =
            async move { self.public_provider.get_logs(&fulfillment_filter).await };

        let (escrow_logs, fulfillment_logs) =
            tokio::try_join!(escrow_logs_fut, fulfillment_logs_fut)?;

        let escrow_logs = escrow_logs
            .into_iter()
            .map(|log| log.log_decode::<IEAS::Attested>())
            .collect::<Result<Vec<_>, _>>()?;

        let fulfillment_logs = fulfillment_logs
            .into_iter()
            .map(|log| log.log_decode::<IEAS::Attested>())
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_attestation_futs = escrow_logs.into_iter().map(|log| {
            let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
            async move { eas.getAttestation(log.inner.uid).call().await }
        });

        let fulfillment_attestation_futs = fulfillment_logs.into_iter().map(|log| {
            let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
            async move { eas.getAttestation(log.inner.uid).call().await }
        });

        let escrow_attestations_fut = async move { try_join_all(escrow_attestation_futs).await };
        let fulfillment_attestations_fut =
            async move { try_join_all(fulfillment_attestation_futs).await };

        let (escrow_attestations, fulfillment_attestations) =
            tokio::try_join!(escrow_attestations_fut, fulfillment_attestations_fut)?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let escrow_attestations = escrow_attestations
            .into_iter()
            .map(|a| a._0)
            .filter(|a| {
                if let Some(ValueOrArray::Value(ref_uid)) = &escrow.filter.ref_uid {
                    if a.refUID != *ref_uid {
                        return false;
                    };
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &escrow.filter.ref_uid {
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

        let escrow_statements = escrow_attestations
            .iter()
            .map(|a| ArbiterDemand::abi_decode(&a.data, true))
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_demands = escrow_statements
            .iter()
            .map(|s| DemandData::abi_decode(&s.demand, true))
            .collect::<Result<Vec<_>, _>>()?;

        let demands_map: HashMap<_, _> = escrow_attestations
            .iter()
            .zip(escrow_demands.iter())
            .map(|(attestation, demand)| (attestation.uid, demand))
            .collect();

        let fulfillment_attestations = fulfillment_attestations
            .iter()
            .map(|a| a._0.clone())
            .filter(|a| demands_map.contains_key(&a.refUID))
            .collect::<Vec<_>>();

        let fulfillment_statements = fulfillment_attestations
            .iter()
            .map(|a| StatementData::abi_decode(&a.data, true))
            .collect::<Result<Vec<_>, _>>()?;

        let decisions = fulfillment_statements
            .iter()
            .zip(fulfillment_attestations.iter())
            .map(|(statement, attestation)| {
                let demand = demands_map.get(&attestation.refUID)?;
                arbitrate(statement, demand)
            })
            .collect::<Vec<_>>();

        let arbitration_futs = fulfillment_attestations
            .iter()
            .zip(decisions.iter())
            .map(|(attestation, decision)| {
                let trusted_oracle_arbiter = TrustedOracleArbiter::new(
                    self.addresses.trusted_oracle_arbiter,
                    &self.wallet_provider,
                );

                if let Some(decision) = decision {
                    Some(async move {
                        trusted_oracle_arbiter
                            .arbitrate(attestation.uid, *decision)
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

        let result = izip!(
            fulfillment_attestations,
            fulfillment_statements,
            decisions,
            receipts
        )
        .filter(|(_, _, d, _)| d.is_some())
        .map(|(attestation, statement, decision, receipt)| {
            let demand = demands_map.get(&attestation.refUID).map(|&x| x.clone());
            Decision {
                attestation,
                statement,
                demand,
                decision: decision.unwrap(),
                receipt,
            }
        })
        .collect::<Vec<Decision<StatementData, DemandData>>>();

        Ok((result, escrow_attestations, escrow_demands))
    }

    pub async fn arbitrate_past_for_escrow_async<
        StatementData: SolType,
        DemandData: SolType,
        ArbitrateFut: Future<Output = Option<bool>>,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> ArbitrateFut + Copy,
    >(
        &self,
        escrow: EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
    ) -> eyre::Result<(
        Vec<Decision<StatementData, DemandData>>,
        Vec<IEAS::Attestation>,
        Vec<<DemandData as SolType>::RustType>,
    )>
    where
        DemandData::RustType: Clone,
    {
        let escrow_filter = self.make_filter(&escrow.filter);
        let escrow_logs_fut = async move { self.public_provider.get_logs(&escrow_filter).await };

        let fulfillment_filter: AttestationFilter = (fulfillment.filter.clone(), None).into();
        let fulfillment_filter = self.make_filter(&fulfillment_filter);
        let fulfillment_logs_fut =
            async move { self.public_provider.get_logs(&fulfillment_filter).await };

        let (escrow_logs, fulfillment_logs) =
            tokio::try_join!(escrow_logs_fut, fulfillment_logs_fut)?;

        let escrow_logs = escrow_logs
            .into_iter()
            .map(|log| log.log_decode::<IEAS::Attested>())
            .collect::<Result<Vec<_>, _>>()?;

        let fulfillment_logs = fulfillment_logs
            .into_iter()
            .map(|log| log.log_decode::<IEAS::Attested>())
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_attestation_futs = escrow_logs.into_iter().map(|log| {
            let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
            async move { eas.getAttestation(log.inner.uid).call().await }
        });

        let fulfillment_attestation_futs = fulfillment_logs.into_iter().map(|log| {
            let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
            async move { eas.getAttestation(log.inner.uid).call().await }
        });

        let escrow_attestations_fut = async move { try_join_all(escrow_attestation_futs).await };
        let fulfillment_attestations_fut =
            async move { try_join_all(fulfillment_attestation_futs).await };

        let (escrow_attestations, fulfillment_attestations) =
            tokio::try_join!(escrow_attestations_fut, fulfillment_attestations_fut)?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let escrow_attestations = escrow_attestations
            .into_iter()
            .map(|a| a._0)
            .filter(|a| {
                if let Some(ValueOrArray::Value(ref_uid)) = &escrow.filter.ref_uid {
                    if a.refUID != *ref_uid {
                        return false;
                    };
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &escrow.filter.ref_uid {
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

        let escrow_statements = escrow_attestations
            .iter()
            .map(|a| ArbiterDemand::abi_decode(&a.data, true))
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_demands = escrow_statements
            .iter()
            .map(|s| DemandData::abi_decode(&s.demand, true))
            .collect::<Result<Vec<_>, _>>()?;

        let demands_map: HashMap<_, _> = escrow_attestations
            .iter()
            .zip(escrow_demands.iter())
            .map(|(attestation, demand)| (attestation.uid, demand))
            .collect();

        let fulfillment_attestations = fulfillment_attestations
            .iter()
            .map(|a| a._0.clone())
            .filter(|a| demands_map.contains_key(&a.refUID))
            .collect::<Vec<_>>();

        let fulfillment_statements = fulfillment_attestations
            .iter()
            .map(|a| StatementData::abi_decode(&a.data, true))
            .collect::<Result<Vec<_>, _>>()?;

        let decisions_fut = fulfillment_statements
            .iter()
            .zip(fulfillment_attestations.iter())
            .map(|(statement, attestation)| {
                let demand = demands_map.get(&attestation.refUID)?;
                Some(async move { arbitrate(statement, demand).await })
            })
            .flatten()
            .collect::<Vec<_>>();

        let decisions = join_all(decisions_fut).await;

        let arbitration_futs = fulfillment_attestations
            .iter()
            .zip(decisions.iter())
            .map(|(attestation, decision)| {
                let trusted_oracle_arbiter = TrustedOracleArbiter::new(
                    self.addresses.trusted_oracle_arbiter,
                    &self.wallet_provider,
                );

                if let Some(decision) = decision {
                    Some(async move {
                        trusted_oracle_arbiter
                            .arbitrate(attestation.uid, *decision)
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

        let result = izip!(
            fulfillment_attestations,
            fulfillment_statements,
            decisions,
            receipts
        )
        .filter(|(_, _, d, _)| d.is_some())
        .map(|(attestation, statement, decision, receipt)| {
            let demand = demands_map.get(&attestation.refUID).map(|&x| x.clone());
            Decision {
                attestation,
                statement,
                demand,
                decision: decision.unwrap(),
                receipt,
            }
        })
        .collect::<Vec<Decision<StatementData, DemandData>>>();

        Ok((result, escrow_attestations, escrow_demands))
    }

    pub async fn listen_and_arbitrate_for_escrow<
        StatementData: SolType,
        DemandData: SolType,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> Option<bool> + Copy,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, DemandData>) -> OnAfterArbitrateFut + Copy,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
    ) -> eyre::Result<(
        Vec<Decision<StatementData, DemandData>>,
        Vec<IEAS::Attestation>,
    )>
    where
        DemandData::RustType: Clone,
    {
        let (mut decisions, escrow_attestations, escrow_demands) = self
            .arbitrate_past_for_escrow(escrow, fulfillment, arbitrate)
            .await
            .unwrap();

        let mut demands_map: HashMap<_, DemandData::RustType> = escrow_attestations
            .iter()
            .zip(escrow_demands.iter())
            .map(|(attestation, demand)| (attestation.uid, demand.clone()))
            .collect();

        let escrow_filter = self.make_filter(&escrow.filter);

        let escrow_sub = self.public_provider.subscribe_logs(&escrow_filter).await?;
        let mut escrow_stream = escrow_sub.into_stream();

        let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);

        while let Some(log) = escrow_stream.next().await {
            let log = log.log_decode::<IEAS::Attested>()?;

            let attestation = eas.getAttestation(log.inner.uid).call().await?._0;

            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if attestation.expirationTime != 0 && attestation.expirationTime < now {
                continue;
            }
            if attestation.revocationTime != 0 && attestation.revocationTime < now {
                continue;
            }

            let statement = ArbiterDemand::abi_decode(&attestation.data, true)?;
            let demand = DemandData::abi_decode(&statement.demand, true)?;

            demands_map.insert(attestation.uid, demand);
        }

        let fulfillment_filter = self.make_filter_without_refuid(&fulfillment.filter);

        let sub = self
            .public_provider
            .subscribe_logs(&fulfillment_filter)
            .await?;
        let mut stream = sub.into_stream();

        let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
        let trusted_oracle_arbiter =
            TrustedOracleArbiter::new(self.addresses.trusted_oracle_arbiter, &self.wallet_provider);

        while let Some(log) = stream.next().await {
            let log = log.log_decode::<IEAS::Attested>()?;

            let attestation = eas.getAttestation(log.inner.uid).call().await?._0;

            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if attestation.expirationTime != 0 && attestation.expirationTime < now {
                continue;
            }
            if attestation.revocationTime != 0 && attestation.revocationTime < now {
                continue;
            }

            let demand = demands_map.get(&attestation.refUID).map(|x| x.clone());
            if demand.is_none() {
                continue;
            }

            let statement = StatementData::abi_decode(&attestation.data, true)?;
            if let Some(ref demand) = demand {
                let decision = arbitrate(&statement, demand);

                if let Some(decision) = decision {
                    let tx = trusted_oracle_arbiter
                        .arbitrate(attestation.uid, decision)
                        .send()
                        .await?;
                    let receipt = tx.get_receipt().await?;
                    let decision = Decision {
                        attestation,
                        statement,
                        demand: Some(demand.clone()),
                        decision,
                        receipt,
                    };

                    tokio::spawn(on_after_arbitrate(&decision));
                    decisions.push(decision);
                }
            }
        }
        Ok((decisions, escrow_attestations))
    }

    pub async fn listen_and_arbitrate_for_escrow_async<
        StatementData: SolType,
        DemandData: SolType,
        ArbitrateFut: Future<Output = Option<bool>>,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> ArbitrateFut + Copy,
        OnAfterArbitrateFut: Future<Output = ()>,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut + Copy,
    >(
        &self,
        escrow: EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
    ) {
    }
}
