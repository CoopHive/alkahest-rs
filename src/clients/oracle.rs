use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::{
    dyn_abi::SolType,
    eips::BlockNumberOrTag,
    primitives::{Address, FixedBytes},
    providers::Provider,
    pubsub::SubscriptionStream,
    rpc::types::{Filter, FilterBlockOption, Log, TransactionReceipt, ValueOrArray},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};
use futures::{
    StreamExt as _,
    future::{join_all, try_join_all},
};
use itertools::izip;
use tokio::{sync::RwLock, time::Duration};
use tracing;

use crate::{
    addresses::BASE_SEPOLIA_ADDRESSES,
    contracts::{
        IEAS::{self, Attestation},
        TrustedOracleArbiter,
    },
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
#[derive(Debug, Clone)]
pub struct ArbitrateOptions {
    pub require_oracle: bool,
    pub skip_arbitrated: bool,
}

impl Default for ArbitrateOptions {
    fn default() -> Self {
        ArbitrateOptions {
            require_oracle: false,
            skip_arbitrated: false,
        }
    }
}

#[derive(Clone)]
pub struct FulfillmentParams<T: SolType> {
    pub filter: AttestationFilter,
    pub _statement_data: PhantomData<T>,
}

pub struct FulfillmentParamsWithoutRefUid<T: SolType> {
    pub filter: AttestationFilterWithoutRefUid,
    pub _statement_data: PhantomData<T>,
}

pub struct EscrowParams<T: SolType> {
    pub _demand_data: PhantomData<T>,
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
pub struct ListenAndArbitrateForEscrowResult<StatementData: SolType, DemandData: SolType> {
    pub decisions: Vec<Decision<StatementData, DemandData>>,
    pub escrow_attestations: Vec<IEAS::Attestation>,
    pub escrow_subscription_id: FixedBytes<32>,
    pub fulfillment_subscription_id: FixedBytes<32>,
}
pub struct ListenAndArbitrateNewFulfillmentsForEscrowResult {
    pub escrow_attestations: Vec<IEAS::Attestation>,
    pub escrow_subscription_id: FixedBytes<32>,
    pub fulfillment_subscription_id: FixedBytes<32>,
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

    fn make_arbitration_filter(
        address: Address,
        statement: FixedBytes<32>,
        oracle: Address,
    ) -> Filter {
        let mut filter = Filter::new()
            .address(address)
            .event_signature(TrustedOracleArbiter::ArbitrationMade::SIGNATURE_HASH)
            .from_block(BlockNumberOrTag::Earliest)
            .to_block(BlockNumberOrTag::Latest);

        filter = filter.topic1(statement);

        filter = filter.topic2(oracle);

        filter
    }

    async fn filter_unarbitrated_attestations(
        &self,
        attestations: Vec<Attestation>,
        skip_arbitrated: bool,
    ) -> eyre::Result<Vec<Attestation>> {
        if !skip_arbitrated {
            return Ok(attestations);
        }

        let futs = attestations.into_iter().map(|a| {
            let filter = Self::make_arbitration_filter(
                self.addresses.trusted_oracle_arbiter,
                a.uid,
                self._signer.address(),
            );
            async move {
                let logs = self.public_provider.get_logs(&filter).await?;
                Ok::<_, eyre::Error>((a, !logs.is_empty()))
            }
        });

        let results = try_join_all(futs).await?;
        Ok(results
            .into_iter()
            .filter_map(|(a, is_arbitrated)| if is_arbitrated { None } else { Some(a) })
            .collect())
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

    async fn get_attestations_and_statements<StatementData: SolType>(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        options: &ArbitrateOptions,
    ) -> eyre::Result<(Vec<Attestation>, Vec<StatementData::RustType>)> {
        let filter = self.make_filter(&fulfillment.filter);

        let logs = self
            .public_provider
            .get_logs(&filter)
            .await?
            .into_iter()
            .map(|log| log.log_decode::<IEAS::Attested>())
            .collect::<Result<Vec<_>, _>>()?;

        let attestation_futures = logs.into_iter().map(|log| {
            let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
            async move { eas.getAttestation(log.inner.uid).call().await }
        });
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let attestations: Vec<Attestation> = try_join_all(attestation_futures)
            .await?
            .into_iter()
            .filter(|a| {
                match &fulfillment.filter.ref_uid {
                    Some(ValueOrArray::Value(ref_uid)) if a.refUID != *ref_uid => return false,
                    Some(ValueOrArray::Array(ref_uids)) if !ref_uids.contains(&a.refUID) => {
                        return false;
                    }
                    _ => {}
                }
                if (a.expirationTime != 0 && a.expirationTime < now)
                    || (a.revocationTime != 0 && a.revocationTime < now)
                {
                    return false;
                }
                true
            })
            .collect();

        let attestations = if options.require_oracle {
            let oracle_addr = self.addresses.trusted_oracle_arbiter;
            let futs = attestations.into_iter().map(|a| {
                let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
                async move {
                    let escrow_att = eas.getAttestation(a.refUID).call().await?;
                    let demand = ArbiterDemand::abi_decode(&escrow_att.data)?;
                    Ok::<_, eyre::Error>((a, demand.oracle == oracle_addr))
                }
            });

            try_join_all(futs)
                .await?
                .into_iter()
                .filter_map(|(a, is_match)| if is_match { Some(a) } else { None })
                .collect()
        } else {
            attestations
        };

        let attestations = self
            .filter_unarbitrated_attestations(attestations, options.skip_arbitrated)
            .await?;

        let statements = attestations
            .iter()
            .map(|a| StatementData::abi_decode(&a.data))
            .collect::<Result<Vec<_>, _>>()?;

        Ok((attestations, statements))
    }

    pub async fn arbitrate_past<
        StatementData: SolType,
        Arbitrate: Fn(&StatementData::RustType) -> Option<bool>,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: &Arbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<Vec<Decision<StatementData, ()>>> {
        let (attestations, statements) = self
            .get_attestations_and_statements(fulfillment, options)
            .await?;

        let decisions = statements.iter().map(|s| arbitrate(s)).collect::<Vec<_>>();
        let base_nonce = self
            .wallet_provider
            .get_transaction_count(self._signer.address())
            .await?;

        let arbitration_futs = attestations
            .iter()
            .zip(decisions.iter())
            .enumerate()
            .filter_map(|(i, (attestation, decision))| {
                let trusted_oracle_arbiter = TrustedOracleArbiter::new(
                    self.addresses.trusted_oracle_arbiter,
                    &self.wallet_provider,
                );
                let nonce = base_nonce + i as u64;
                if let Some(decision) = decision {
                    Some(async move {
                        trusted_oracle_arbiter
                            .arbitrate(attestation.uid, *decision)
                            .nonce(nonce)
                            .send()
                            .await
                    })
                } else {
                    None
                }
            })
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

    pub async fn arbitrate_past_async<
        StatementData: SolType,
        ArbitrateFut: Future<Output = Option<bool>>,
        Arbitrate: Fn(&StatementData::RustType) -> ArbitrateFut + Copy,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<Vec<Decision<StatementData, ()>>> {
        let (attestations, statements) = self
            .get_attestations_and_statements(fulfillment, options)
            .await?;

        let decision_futs = statements.iter().map(|s| async move { arbitrate(s).await });
        let decisions = join_all(decision_futs).await;

        let base_nonce = self
            .wallet_provider
            .get_transaction_count(self._signer.address())
            .await?;

        let arbitration_futs = attestations
            .iter()
            .zip(decisions.iter())
            .enumerate()
            .filter_map(|(i, (attestation, decision))| {
                let trusted_oracle_arbiter = TrustedOracleArbiter::new(
                    self.addresses.trusted_oracle_arbiter,
                    &self.wallet_provider,
                );
                let nonce = base_nonce + i as u64;
                if let Some(decision) = decision {
                    Some(async move {
                        trusted_oracle_arbiter
                            .arbitrate(attestation.uid, *decision)
                            .nonce(nonce)
                            .send()
                            .await
                    })
                } else {
                    None
                }
            })
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

    async fn spawn_fulfillment_listener<
        StatementData: SolType + Clone + Send + 'static,
        Arbitrate: Fn(&StatementData::RustType) -> Option<bool> + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        stream: SubscriptionStream<Log>,
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) where
        <StatementData as SolType>::RustType: Send,
    {
        let wallet_provider = self.wallet_provider.clone();
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;
        let signer_address = self._signer.address();
        let public_provider = self.public_provider.clone();
        let options = options.clone();
        let arbitrate = arbitrate.clone();
        tokio::spawn(async move {
            let eas = IEAS::new(eas_address, &wallet_provider);
            let arbiter = TrustedOracleArbiter::new(arbiter_address, &wallet_provider);
            let mut stream = stream;

            while let Some(log) = stream.next().await {
                let Ok(log) = log.log_decode::<IEAS::Attested>() else {
                    continue;
                };

                let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else {
                    continue;
                };

                if options.require_oracle {
                    let escrow_att = match eas.getAttestation(attestation.refUID).call().await {
                        Ok(a) => a,
                        Err(_) => continue,
                    };

                    let demand = match ArbiterDemand::abi_decode(&escrow_att.data) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };

                    if demand.oracle != arbiter_address {
                        continue;
                    }
                }

                if options.skip_arbitrated {
                    let filter = Self::make_arbitration_filter(
                        arbiter_address,
                        attestation.uid,
                        signer_address,
                    );
                    let logs_result = public_provider.get_logs(&filter).await;

                    if let Ok(logs) = logs_result {
                        if logs.len() > 0 {
                            continue;
                        }
                    }
                }

                match &fulfillment.filter.ref_uid {
                    Some(ValueOrArray::Value(ref_uid)) if attestation.refUID != *ref_uid => {
                        continue;
                    }
                    Some(ValueOrArray::Array(ref_uids))
                        if !ref_uids.contains(&attestation.refUID) =>
                    {
                        continue;
                    }
                    _ => {}
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

                let Ok(statement) = StatementData::abi_decode(&attestation.data) else {
                    continue;
                };

                let Some(decision_value) = arbitrate(&statement) else {
                    continue;
                };

                let Ok(nonce) = wallet_provider.get_transaction_count(signer_address).await else {
                    continue;
                };

                match arbiter
                    .arbitrate(attestation.uid, decision_value)
                    .nonce(nonce)
                    .send()
                    .await
                {
                    Ok(tx) => {
                        if let Ok(receipt) = tx.get_receipt().await {
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
                    Err(err) => {
                        tracing::error!("Arbitration failed for {}: {}", attestation.uid, err);
                    }
                }
            }
        });
    }

    pub async fn spawn_fulfillment_listener_async<
        StatementData: SolType + Clone + Send + 'static,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&StatementData::RustType) -> ArbitrateFut + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        stream: SubscriptionStream<Log>,
        fulfillment: FulfillmentParams<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) where
        <StatementData as SolType>::RustType: Send,
    {
        let wallet_provider = self.wallet_provider.clone();
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;
        let signer_address = self._signer.address();
        let public_provider = self.public_provider.clone();
        let options = options.clone();
        tokio::spawn(async move {
            let eas = IEAS::new(eas_address, &wallet_provider);
            let arbiter = TrustedOracleArbiter::new(arbiter_address, &wallet_provider);
            let mut stream = stream;

            while let Some(log) = stream.next().await {
                let Ok(log) = log.log_decode::<IEAS::Attested>() else {
                    continue;
                };

                let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else {
                    continue;
                };

                if options.require_oracle {
                    let escrow_att = match eas.getAttestation(attestation.refUID).call().await {
                        Ok(a) => a,
                        Err(_) => continue,
                    };

                    let demand = match ArbiterDemand::abi_decode(&escrow_att.data) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };

                    if demand.oracle != arbiter_address {
                        continue;
                    }
                }

                if options.skip_arbitrated {
                    let filter = Self::make_arbitration_filter(
                        arbiter_address,
                        attestation.uid,
                        signer_address,
                    );
                    let logs_result = public_provider.get_logs(&filter).await;

                    if let Ok(logs) = logs_result {
                        if logs.len() > 0 {
                            continue;
                        }
                    }
                }

                match &fulfillment.filter.ref_uid {
                    Some(ValueOrArray::Value(ref_uid)) if attestation.refUID != *ref_uid => {
                        continue;
                    }
                    Some(ValueOrArray::Array(ref_uids))
                        if !ref_uids.contains(&attestation.refUID) =>
                    {
                        continue;
                    }
                    _ => {}
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

                let Ok(statement) = StatementData::abi_decode(&attestation.data) else {
                    continue;
                };

                let Some(decision_value) = arbitrate(&statement).await else {
                    continue;
                };

                let Ok(nonce) = wallet_provider.get_transaction_count(signer_address).await else {
                    continue;
                };

                match arbiter
                    .arbitrate(attestation.uid, decision_value)
                    .nonce(nonce)
                    .send()
                    .await
                {
                    Ok(tx) => {
                        if let Ok(receipt) = tx.get_receipt().await {
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
                    Err(err) => {
                        tracing::error!("Arbitration failed for {}: {}", attestation.uid, err);
                    }
                }
            }
        });
    }

    pub async fn listen_and_arbitrate<
        StatementData: SolType + Clone + Send + 'static,
        Arbitrate: Fn(&StatementData::RustType) -> Option<bool> + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<ListenAndArbitrateResult<StatementData>>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let decisions = self
            .arbitrate_past(&fulfillment, arbitrate, options)
            .await?;
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream: SubscriptionStream<Log> = sub.into_stream();

        self.spawn_fulfillment_listener(
            stream,
            fulfillment.clone(),
            arbitrate,
            on_after_arbitrate,
            options,
        )
        .await;

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
        options: &ArbitrateOptions,
    ) -> eyre::Result<ListenAndArbitrateResult<StatementData>>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let decisions = self
            .arbitrate_past_async(&fulfillment, arbitrate, options)
            .await?;
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream: SubscriptionStream<Log> = sub.into_stream();

        self.spawn_fulfillment_listener_async(
            stream,
            fulfillment.clone(),
            arbitrate,
            on_after_arbitrate,
            options,
        )
        .await;

        Ok(ListenAndArbitrateResult {
            decisions,
            subscription_id: local_id,
        })
    }

    async fn handle_fulfillment_stream_no_spawn<
        StatementData: SolType,
        Arbitrate: Fn(&StatementData::RustType) -> Option<bool>,
        OnAfterArbitrateFut: Future<Output = ()>,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut,
    >(
        &self,
        mut stream: SubscriptionStream<Log>,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
        timeout: Option<Duration>,
    ) where
        <StatementData as SolType>::RustType: Send,
    {
        let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
        let arbiter =
            TrustedOracleArbiter::new(self.addresses.trusted_oracle_arbiter, &self.wallet_provider);

        loop {
            let next_result = if let Some(timeout_duration) = timeout {
                match tokio::time::timeout(timeout_duration, stream.next()).await {
                    Ok(Some(log)) => Some(log),
                    Ok(None) => None, // Stream ended
                    Err(_) => {
                        tracing::info!("Stream timeout reached after {:?}", timeout_duration);
                        break;
                    }
                }
            } else {
                stream.next().await
            };

            let Some(log) = next_result else {
                break; // Stream ended
            };

            let Ok(log) = log.log_decode::<IEAS::Attested>() else {
                continue;
            };

            let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else {
                continue;
            };

            if options.require_oracle {
                let escrow_att = match eas.getAttestation(attestation.refUID).call().await {
                    Ok(a) => a,
                    Err(_) => continue,
                };

                let demand = match ArbiterDemand::abi_decode(&escrow_att.data) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                if demand.oracle != self.addresses.trusted_oracle_arbiter {
                    continue;
                }
            }

            if options.skip_arbitrated {
                let filter = Self::make_arbitration_filter(
                    self.addresses.trusted_oracle_arbiter,
                    attestation.uid,
                    self._signer.address(),
                );
                let logs_result = self.public_provider.get_logs(&filter).await;

                if let Ok(logs) = logs_result {
                    if logs.len() > 0 {
                        continue;
                    }
                }
            }

            match &fulfillment.filter.ref_uid {
                Some(ValueOrArray::Value(ref_uid)) if attestation.refUID != *ref_uid => {
                    continue;
                }
                Some(ValueOrArray::Array(ref_uids)) if !ref_uids.contains(&attestation.refUID) => {
                    continue;
                }
                _ => {}
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

            let Ok(statement) = StatementData::abi_decode(&attestation.data) else {
                continue;
            };

            let Some(decision_value) = arbitrate(&statement) else {
                continue;
            };

            let Ok(nonce) = self
                .wallet_provider
                .get_transaction_count(self._signer.address())
                .await
            else {
                continue;
            };

            match arbiter
                .arbitrate(attestation.uid, decision_value)
                .nonce(nonce)
                .send()
                .await
            {
                Ok(tx) => {
                    if let Ok(receipt) = tx.get_receipt().await {
                        let decision = Decision {
                            attestation,
                            statement,
                            demand: None,
                            decision: decision_value,
                            receipt,
                        };
                        on_after_arbitrate(&decision).await;
                    }
                }
                Err(err) => {
                    tracing::error!("Arbitration failed for {}: {}", attestation.uid, err);
                }
            }
        }
    }

    pub async fn listen_and_arbitrate_no_spawn<
        StatementData: SolType,
        Arbitrate: Fn(&StatementData::RustType) -> Option<bool>,
        OnAfterArbitrateFut: Future<Output = ()>,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
        timeout: Option<Duration>,
    ) -> eyre::Result<ListenAndArbitrateResult<StatementData>>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let decisions = self
            .arbitrate_past(&fulfillment, &arbitrate, options)
            .await?;
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream: SubscriptionStream<Log> = sub.into_stream();

        self.handle_fulfillment_stream_no_spawn(
            stream,
            fulfillment,
            arbitrate,
            on_after_arbitrate,
            options,
            timeout,
        )
        .await;

        Ok(ListenAndArbitrateResult {
            decisions,
            subscription_id: local_id,
        })
    }

    pub async fn listen_and_arbitrate_new_fulfillments_no_spawn<
        StatementData: SolType,
        Arbitrate: Fn(&StatementData::RustType) -> Option<bool>,
        OnAfterArbitrateFut: Future<Output = ()>,
        OnAfterArbitrate: Fn(&Decision<StatementData, ()>) -> OnAfterArbitrateFut,
    >(
        &self,
        fulfillment: &FulfillmentParams<StatementData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
        timeout: Option<Duration>,
    ) -> eyre::Result<ListenAndArbitrateNewFulfillmentsResult>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream: SubscriptionStream<Log> = sub.into_stream();

        self.handle_fulfillment_stream_no_spawn(
            stream,
            fulfillment,
            arbitrate,
            on_after_arbitrate,
            options,
            timeout,
        )
        .await;

        Ok(ListenAndArbitrateNewFulfillmentsResult {
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
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<ListenAndArbitrateNewFulfillmentsResult>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream = sub.into_stream();

        self.spawn_fulfillment_listener(
            stream,
            fulfillment.clone(),
            arbitrate,
            on_after_arbitrate,
            options,
        )
        .await;

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
        options: &ArbitrateOptions,
    ) -> eyre::Result<ListenAndArbitrateNewFulfillmentsResult>
    where
        <StatementData as SolType>::RustType: Send,
    {
        let filter = self.make_filter(&fulfillment.filter);

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream = sub.into_stream();

        self.spawn_fulfillment_listener_async(
            stream,
            fulfillment.clone(),
            arbitrate,
            on_after_arbitrate,
            options,
        )
        .await;

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
        skip_arbitrated: Option<bool>,
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
            .map(|a| a)
            .filter(|a| {
                if let Some(ValueOrArray::Value(ref_uid)) = &escrow.filter.ref_uid {
                    if a.refUID != *ref_uid {
                        return false;
                    };
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &escrow.filter.ref_uid {
                    if !ref_uids.contains(&a.refUID) {
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
            .map(|a| ArbiterDemand::abi_decode(&a.data))
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_demands = escrow_statements
            .iter()
            .map(|s| DemandData::abi_decode(&s.demand))
            .collect::<Result<Vec<_>, _>>()?;

        let demands_map: HashMap<_, _> = escrow_attestations
            .iter()
            .zip(escrow_demands.iter())
            .map(|(attestation, demand)| (attestation.uid, demand))
            .collect();

        let fulfillment_attestations = fulfillment_attestations
            .iter()
            .map(|a| a.clone())
            .filter(|a| demands_map.contains_key(&a.refUID))
            .collect::<Vec<_>>();

        let fulfillment_attestations = self
            .filter_unarbitrated_attestations(
                fulfillment_attestations,
                skip_arbitrated.unwrap_or(false),
            )
            .await?;

        let fulfillment_statements = fulfillment_attestations
            .iter()
            .map(|a| StatementData::abi_decode(&a.data))
            .collect::<Result<Vec<_>, _>>()?;

        let decisions = fulfillment_statements
            .iter()
            .zip(fulfillment_attestations.iter())
            .map(|(statement, attestation)| {
                let demand = demands_map.get(&attestation.refUID)?;
                arbitrate(statement, demand)
            })
            .collect::<Vec<_>>();

        let base_nonce = self
            .wallet_provider
            .get_transaction_count(self._signer.address())
            .await?;

        let arbitration_futs = fulfillment_attestations
            .iter()
            .zip(decisions.iter())
            .enumerate()
            .filter_map(|(i, (attestation, decision))| {
                let trusted_oracle_arbiter = TrustedOracleArbiter::new(
                    self.addresses.trusted_oracle_arbiter,
                    &self.wallet_provider,
                );
                let nonce = base_nonce + i as u64;
                if let Some(decision) = decision {
                    Some(async move {
                        trusted_oracle_arbiter
                            .arbitrate(attestation.uid, *decision)
                            .nonce(nonce)
                            .send()
                            .await
                    })
                } else {
                    None
                }
            })
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

    pub async fn get_escrows<DemandData: SolType>(
        &self,
        escrow: &EscrowParams<DemandData>,
    ) -> eyre::Result<(
        Vec<IEAS::Attestation>,
        Vec<<DemandData as SolType>::RustType>,
    )>
    where
        DemandData::RustType: Clone,
    {
        let escrow_filter = self.make_filter(&escrow.filter);
        let escrow_logs_fut = async move { self.public_provider.get_logs(&escrow_filter).await };

        let escrow_logs = tokio::try_join!(escrow_logs_fut)?.0;

        let escrow_logs = escrow_logs
            .into_iter()
            .map(|log| log.log_decode::<IEAS::Attested>())
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_attestation_futs = escrow_logs.into_iter().map(|log| {
            let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
            async move { eas.getAttestation(log.inner.uid).call().await }
        });

        let escrow_attestations_fut = async move { try_join_all(escrow_attestation_futs).await };
        let escrow_attestations = tokio::try_join!(escrow_attestations_fut)?.0;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let escrow_attestations = escrow_attestations
            .into_iter()
            .map(|a| a)
            .filter(|a| {
                if let Some(ValueOrArray::Value(ref_uid)) = &escrow.filter.ref_uid {
                    if a.refUID != *ref_uid {
                        return false;
                    };
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &escrow.filter.ref_uid {
                    if !ref_uids.contains(&a.refUID) {
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
            .map(|a| ArbiterDemand::abi_decode(&a.data))
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_demands = escrow_statements
            .iter()
            .map(|s| DemandData::abi_decode(&s.demand))
            .collect::<Result<Vec<_>, _>>()?;

        Ok((escrow_attestations, escrow_demands))
    }

    pub async fn arbitrate_past_for_escrow_async<
        StatementData: SolType,
        DemandData: SolType,
        ArbitrateFut: Future<Output = Option<bool>>,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> ArbitrateFut + Copy,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
        skip_arbitrated: Option<bool>,
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
            .map(|a| a)
            .filter(|a| {
                if let Some(ValueOrArray::Value(ref_uid)) = &escrow.filter.ref_uid {
                    if a.refUID != *ref_uid {
                        return false;
                    };
                }
                if let Some(ValueOrArray::Array(ref_uids)) = &escrow.filter.ref_uid {
                    if !ref_uids.contains(&a.refUID) {
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
            .map(|a| ArbiterDemand::abi_decode(&a.data))
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_demands = escrow_statements
            .iter()
            .map(|s| DemandData::abi_decode(&s.demand))
            .collect::<Result<Vec<_>, _>>()?;

        let demands_map: HashMap<_, _> = escrow_attestations
            .iter()
            .zip(escrow_demands.iter())
            .map(|(attestation, demand)| (attestation.uid, demand))
            .collect();

        let fulfillment_attestations = fulfillment_attestations
            .iter()
            .map(|a| a.clone())
            .filter(|a| demands_map.contains_key(&a.refUID))
            .collect::<Vec<_>>();

        let fulfillment_attestations = self
            .filter_unarbitrated_attestations(
                fulfillment_attestations,
                skip_arbitrated.unwrap_or(false),
            )
            .await?;

        let fulfillment_statements = fulfillment_attestations
            .iter()
            .map(|a| StatementData::abi_decode(&a.data))
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

        let base_nonce = self
            .wallet_provider
            .get_transaction_count(self._signer.address())
            .await?;

        let arbitration_futs = fulfillment_attestations
            .iter()
            .zip(decisions.iter())
            .enumerate()
            .filter_map(|(i, (attestation, decision))| {
                let trusted_oracle_arbiter = TrustedOracleArbiter::new(
                    self.addresses.trusted_oracle_arbiter,
                    &self.wallet_provider,
                );
                let nonce = base_nonce + i as u64;
                if let Some(decision) = decision {
                    Some(async move {
                        trusted_oracle_arbiter
                            .arbitrate(attestation.uid, *decision)
                            .nonce(nonce)
                            .send()
                            .await
                    })
                } else {
                    None
                }
            })
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
        StatementData: SolType + Clone + Send + Sync + 'static,
        DemandData: SolType + Clone + Send + Sync + 'static,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> Option<bool>
            + Send
            + Sync
            + Copy
            + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, DemandData>) -> OnAfterArbitrateFut
            + Send
            + Sync
            + Copy
            + 'static,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        skip_arbitrated: Option<bool>,
    ) -> eyre::Result<ListenAndArbitrateForEscrowResult<StatementData, DemandData>>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <StatementData as SolType>::RustType: Send + 'static,
    {
        let (decisions, escrow_attestations, escrow_demands) = self
            .arbitrate_past_for_escrow(&escrow, &fulfillment, arbitrate, skip_arbitrated)
            .await?;

        let demands_map: Arc<RwLock<HashMap<FixedBytes<32>, DemandData::RustType>>> =
            Arc::new(RwLock::new(
                escrow_attestations
                    .iter()
                    .zip(escrow_demands.iter())
                    .map(|(a, d)| (a.uid, d.clone()))
                    .collect(),
            ));

        let wallet_provider = self.wallet_provider.clone();
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;

        let escrow_subscription_id;
        let fulfillment_subscription_id;

        // Listen for escrow demands
        {
            let demands_map = Arc::clone(&demands_map);
            let filter = self.make_filter(&escrow.filter);
            let sub = self.public_provider.subscribe_logs(&filter).await?;
            escrow_subscription_id = *sub.local_id();

            let mut stream = sub.into_stream();
            let eas_address = eas_address.clone();
            let wallet_provider = wallet_provider.clone();

            tokio::spawn(async move {
                let eas = IEAS::new(eas_address, &wallet_provider);
                while let Some(log) = stream.next().await {
                    if let Ok(log) = log.log_decode::<IEAS::Attested>() {
                        if let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            if attestation.expirationTime != 0 && attestation.expirationTime < now {
                                continue;
                            }
                            if attestation.revocationTime != 0 && attestation.revocationTime < now {
                                continue;
                            }

                            if let Ok(statement) = ArbiterDemand::abi_decode(&attestation.data) {
                                if let Ok(demand) = DemandData::abi_decode(&statement.demand) {
                                    demands_map.write().await.insert(attestation.uid, demand);
                                }
                            }
                        }
                    }
                }
            });
        }

        // Listen for fulfillments
        {
            let demands_map = Arc::clone(&demands_map);
            let filter = self.make_filter_without_refuid(&fulfillment.filter);
            let sub = self.public_provider.subscribe_logs(&filter).await?;
            fulfillment_subscription_id = *sub.local_id();

            let mut stream = sub.into_stream();
            let eas_address = eas_address.clone();
            let wallet_provider = Arc::new(wallet_provider.clone());
            let signer_address = self._signer.address();

            tokio::spawn(async move {
                let eas = IEAS::new(eas_address, &*wallet_provider);
                let arbiter = TrustedOracleArbiter::new(arbiter_address, &*wallet_provider);

                while let Some(log) = stream.next().await {
                    let Ok(log) = log.log_decode::<IEAS::Attested>() else {
                        continue;
                    };
                    let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else {
                        continue;
                    };

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if (attestation.expirationTime != 0 && attestation.expirationTime < now)
                        || (attestation.revocationTime != 0 && attestation.revocationTime < now)
                    {
                        continue;
                    }

                    let Some(demand) = demands_map.read().await.get(&attestation.refUID).cloned()
                    else {
                        continue;
                    };

                    let Ok(statement) = StatementData::abi_decode(&attestation.data) else {
                        continue;
                    };

                    let Some(decision_value) = arbitrate(&statement, &demand) else {
                        continue;
                    };

                    let Ok(nonce) = wallet_provider.get_transaction_count(signer_address).await
                    else {
                        tracing::error!("Failed to get transaction count for {}", signer_address);
                        continue;
                    };

                    match arbiter
                        .arbitrate(attestation.uid, decision_value)
                        .nonce(nonce)
                        .send()
                        .await
                    {
                        Ok(tx) => match tx.get_receipt().await {
                            Ok(receipt) => {
                                let decision = Decision {
                                    attestation,
                                    statement,
                                    demand: None,
                                    decision: decision_value,
                                    receipt,
                                };
                                tokio::spawn(on_after_arbitrate(&decision));
                            }
                            Err(_) => continue,
                        },
                        Err(err) => {
                            tracing::error!("Arbitration failed for {}: {}", attestation.uid, err);
                        }
                    }
                }
            });
        }

        Ok(ListenAndArbitrateForEscrowResult {
            decisions,
            escrow_attestations,
            escrow_subscription_id,
            fulfillment_subscription_id,
        })
    }

    pub async fn listen_and_arbitrate_for_escrow_no_spawn<
        StatementData: SolType,
        DemandData: SolType,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> Option<bool>,
        OnAfterArbitrateFut: Future<Output = ()>,
        OnAfterArbitrate: Fn(&Decision<StatementData, DemandData>) -> OnAfterArbitrateFut,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        skip_arbitrated: Option<bool>,
        timeout: Option<Duration>,
    ) -> eyre::Result<ListenAndArbitrateForEscrowResult<StatementData, DemandData>>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <StatementData as SolType>::RustType: Send + 'static,
    {
        let (decisions, escrow_attestations, escrow_demands) = self
            .arbitrate_past_for_escrow(&escrow, &fulfillment, arbitrate, skip_arbitrated)
            .await?;

        let demands_map: Arc<RwLock<HashMap<FixedBytes<32>, DemandData::RustType>>> =
            Arc::new(RwLock::new(
                escrow_attestations
                    .iter()
                    .zip(escrow_demands.iter())
                    .map(|(a, d)| (a.uid, d.clone()))
                    .collect(),
            ));

        let escrow_filter = self.make_filter(&escrow.filter);
        let fulfillment_filter = self.make_filter_without_refuid(&fulfillment.filter);

        let escrow_sub = self.public_provider.subscribe_logs(&escrow_filter).await?;
        let fulfillment_sub = self
            .public_provider
            .subscribe_logs(&fulfillment_filter)
            .await?;

        let escrow_subscription_id = *escrow_sub.local_id();
        let fulfillment_subscription_id = *fulfillment_sub.local_id();

        let mut escrow_stream = escrow_sub.into_stream();
        let mut fulfillment_stream = fulfillment_sub.into_stream();

        let wallet_provider = Arc::new(self.wallet_provider.clone());
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;
        let eas = IEAS::new(eas_address, &*wallet_provider);
        let arbiter = TrustedOracleArbiter::new(arbiter_address, &*wallet_provider);
        let signer_address = self._signer.address();

        loop {
            tokio::select! {
                maybe_log = escrow_stream.next() => {
                    let Some(log) = maybe_log else { break };
                    let Ok(log) = log.log_decode::<IEAS::Attested>() else { continue };

                    if let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await {
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        if attestation.expirationTime != 0 && attestation.expirationTime < now { continue; }
                        if attestation.revocationTime != 0 && attestation.revocationTime < now { continue; }

                        if let Ok(statement) = ArbiterDemand::abi_decode(&attestation.data) {
                            if let Ok(demand) = DemandData::abi_decode(&statement.demand) {
                                demands_map.write().await.insert(attestation.uid, demand);
                            }
                        }
                    }
                }

                maybe_log = fulfillment_stream.next() => {
                    let Some(log) = maybe_log else { break };
                    let Ok(log) = log.log_decode::<IEAS::Attested>() else { continue };
                    let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else { continue };

                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    if attestation.expirationTime != 0 && attestation.expirationTime < now { continue; }
                    if attestation.revocationTime != 0 && attestation.revocationTime < now { continue; }

                    let Some(demand) = demands_map.read().await.get(&attestation.refUID).cloned() else { continue; };
                    let Ok(statement) = StatementData::abi_decode(&attestation.data) else { continue; };
                    let Some(decision_value) = arbitrate(&statement, &demand) else { continue; };

                    let Ok(nonce) = wallet_provider.get_transaction_count(signer_address).await else {
                        tracing::error!("Failed to get transaction count for {}", signer_address);
                        continue;
                    };

                    match arbiter.arbitrate(attestation.uid, decision_value).nonce(nonce).send().await {
                        Ok(tx) => match tx.get_receipt().await {
                            Ok(receipt) => {
                                let decision = Decision {
                                    attestation,
                                    statement,
                                    demand: None,
                                    decision: decision_value,
                                    receipt,
                                };
                                on_after_arbitrate(&decision).await;
                            },
                            Err(_) => continue,
                        },
                        Err(err) => {
                            tracing::error!("Arbitration failed for {}: {}", attestation.uid, err);
                        }
                    }
                }

                _ = tokio::time::sleep(timeout.unwrap_or(Duration::from_secs(300))) => {
                    tracing::info!("Timeout reached, exiting arbitration loop.");
                    break;
                }
            }
        }

        Ok(ListenAndArbitrateForEscrowResult {
            decisions,
            escrow_attestations,
            escrow_subscription_id,
            fulfillment_subscription_id,
        })
    }

    pub async fn listen_and_arbitrate_for_escrow_async<
        StatementData: SolType,
        DemandData: SolType,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> ArbitrateFut
            + Copy
            + Send
            + Sync
            + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, DemandData>) -> OnAfterArbitrateFut
            + Copy
            + Send
            + Sync
            + 'static,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        skip_arbitrated: Option<bool>,
    ) -> eyre::Result<ListenAndArbitrateForEscrowResult<StatementData, DemandData>>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <StatementData as SolType>::RustType: Send + 'static,
    {
        let (decisions, escrow_attestations, escrow_demands) = self
            .arbitrate_past_for_escrow_async(&escrow, &fulfillment, arbitrate, skip_arbitrated)
            .await?;

        let demands_map: Arc<RwLock<HashMap<FixedBytes<32>, DemandData::RustType>>> =
            Arc::new(RwLock::new(
                escrow_attestations
                    .iter()
                    .zip(escrow_demands.iter())
                    .map(|(a, d)| (a.uid, d.clone()))
                    .collect(),
            ));

        let wallet_provider = self.wallet_provider.clone();
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;

        let escrow_subscription_id;
        let fulfillment_subscription_id;

        // Listen for escrow demands
        {
            let demands_map = Arc::clone(&demands_map);
            let filter = self.make_filter(&escrow.filter);
            let sub = self.public_provider.subscribe_logs(&filter).await?;
            escrow_subscription_id = *sub.local_id();

            let mut stream = sub.into_stream();
            let eas_address = eas_address.clone();
            let wallet_provider = wallet_provider.clone();

            tokio::spawn(async move {
                let eas = IEAS::new(eas_address, &wallet_provider);
                while let Some(log) = stream.next().await {
                    if let Ok(log) = log.log_decode::<IEAS::Attested>() {
                        if let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            if attestation.expirationTime != 0 && attestation.expirationTime < now {
                                continue;
                            }
                            if attestation.revocationTime != 0 && attestation.revocationTime < now {
                                continue;
                            }

                            if let Ok(statement) = ArbiterDemand::abi_decode(&attestation.data) {
                                if let Ok(demand) = DemandData::abi_decode(&statement.demand) {
                                    demands_map.write().await.insert(attestation.uid, demand);
                                }
                            }
                        }
                    }
                }
            });
        }

        // Listen for fulfillments
        {
            let demands_map = Arc::clone(&demands_map);
            let filter = self.make_filter_without_refuid(&fulfillment.filter);
            let sub = self.public_provider.subscribe_logs(&filter).await?;
            fulfillment_subscription_id = *sub.local_id();

            let mut stream = sub.into_stream();
            let eas_address = eas_address.clone();
            let wallet_provider = Arc::new(wallet_provider.clone());
            let signer_address = self._signer.address();

            tokio::spawn(async move {
                let eas = IEAS::new(eas_address, &*wallet_provider);
                let arbiter = TrustedOracleArbiter::new(arbiter_address, &*wallet_provider);

                while let Some(log) = stream.next().await {
                    let Ok(log) = log.log_decode::<IEAS::Attested>() else {
                        continue;
                    };
                    let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else {
                        continue;
                    };

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if (attestation.expirationTime != 0 && attestation.expirationTime < now)
                        || (attestation.revocationTime != 0 && attestation.revocationTime < now)
                    {
                        continue;
                    }

                    let Some(demand) = demands_map.read().await.get(&attestation.refUID).cloned()
                    else {
                        continue;
                    };

                    let Ok(statement) = StatementData::abi_decode(&attestation.data) else {
                        continue;
                    };

                    let Some(decision_value) = arbitrate(&statement, &demand).await else {
                        continue;
                    };

                    let Ok(nonce) = wallet_provider.get_transaction_count(signer_address).await
                    else {
                        tracing::error!("Failed to get transaction count for {}", signer_address);
                        continue;
                    };

                    match arbiter
                        .arbitrate(attestation.uid, decision_value)
                        .nonce(nonce)
                        .send()
                        .await
                    {
                        Ok(tx) => match tx.get_receipt().await {
                            Ok(receipt) => {
                                let decision = Decision {
                                    attestation,
                                    statement,
                                    demand: None,
                                    decision: decision_value,
                                    receipt,
                                };
                                tokio::spawn(on_after_arbitrate(&decision));
                            }
                            Err(_) => continue,
                        },
                        Err(err) => {
                            tracing::error!("Arbitration failed for {}: {}", attestation.uid, err);
                        }
                    }
                }
            });
        }

        Ok(ListenAndArbitrateForEscrowResult {
            decisions,
            escrow_attestations,
            escrow_subscription_id,
            fulfillment_subscription_id,
        })
    }

    pub async fn listen_and_arbitrate_new_fulfillments_for_escrow<
        StatementData: SolType + Clone + Send + Sync + 'static,
        DemandData: SolType + Clone + Send + Sync + 'static,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> Option<bool>
            + Send
            + Sync
            + Copy
            + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, DemandData>) -> OnAfterArbitrateFut
            + Send
            + Sync
            + Copy
            + 'static,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
    ) -> eyre::Result<ListenAndArbitrateNewFulfillmentsForEscrowResult>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <StatementData as SolType>::RustType: Send + 'static,
    {
        let (escrow_attestations, escrow_demands) = self.get_escrows(&escrow).await?;

        let demands_map: Arc<RwLock<HashMap<FixedBytes<32>, DemandData::RustType>>> =
            Arc::new(RwLock::new(
                escrow_attestations
                    .iter()
                    .zip(escrow_demands.iter())
                    .map(|(a, d)| (a.uid, d.clone()))
                    .collect(),
            ));

        let wallet_provider = self.wallet_provider.clone();
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;

        let escrow_subscription_id;
        let fulfillment_subscription_id;

        // Listen for escrow demands
        {
            let demands_map = Arc::clone(&demands_map);
            let filter = self.make_filter(&escrow.filter);
            let sub = self.public_provider.subscribe_logs(&filter).await?;
            escrow_subscription_id = *sub.local_id();

            let mut stream = sub.into_stream();
            let eas_address = eas_address.clone();
            let wallet_provider = wallet_provider.clone();

            tokio::spawn(async move {
                let eas = IEAS::new(eas_address, &wallet_provider);
                while let Some(log) = stream.next().await {
                    if let Ok(log) = log.log_decode::<IEAS::Attested>() {
                        if let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            if attestation.expirationTime != 0 && attestation.expirationTime < now {
                                continue;
                            }
                            if attestation.revocationTime != 0 && attestation.revocationTime < now {
                                continue;
                            }

                            if let Ok(statement) = ArbiterDemand::abi_decode(&attestation.data) {
                                if let Ok(demand) = DemandData::abi_decode(&statement.demand) {
                                    demands_map.write().await.insert(attestation.uid, demand);
                                }
                            }
                        }
                    }
                }
            });
        }

        // Listen for fulfillments
        {
            let demands_map = Arc::clone(&demands_map);
            let filter = self.make_filter_without_refuid(&fulfillment.filter);
            let sub = self.public_provider.subscribe_logs(&filter).await?;
            fulfillment_subscription_id = *sub.local_id();

            let mut stream = sub.into_stream();
            let eas_address = eas_address.clone();
            let wallet_provider = Arc::new(wallet_provider.clone());
            let signer_address = self._signer.address();

            tokio::spawn(async move {
                let eas = IEAS::new(eas_address, &*wallet_provider);
                let arbiter = TrustedOracleArbiter::new(arbiter_address, &*wallet_provider);

                while let Some(log) = stream.next().await {
                    let Ok(log) = log.log_decode::<IEAS::Attested>() else {
                        continue;
                    };
                    let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else {
                        continue;
                    };

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if (attestation.expirationTime != 0 && attestation.expirationTime < now)
                        || (attestation.revocationTime != 0 && attestation.revocationTime < now)
                    {
                        continue;
                    }

                    let Some(demand) = demands_map.read().await.get(&attestation.refUID).cloned()
                    else {
                        continue;
                    };

                    let Ok(statement) = StatementData::abi_decode(&attestation.data) else {
                        continue;
                    };

                    let Some(decision_value) = arbitrate(&statement, &demand) else {
                        continue;
                    };

                    let Ok(nonce) = wallet_provider.get_transaction_count(signer_address).await
                    else {
                        tracing::error!("Failed to get transaction count for {}", signer_address);
                        continue;
                    };

                    match arbiter
                        .arbitrate(attestation.uid, decision_value)
                        .nonce(nonce)
                        .send()
                        .await
                    {
                        Ok(tx) => match tx.get_receipt().await {
                            Ok(receipt) => {
                                let decision = Decision {
                                    attestation,
                                    statement,
                                    demand: None,
                                    decision: decision_value,
                                    receipt,
                                };
                                tokio::spawn(on_after_arbitrate(&decision));
                            }
                            Err(_) => continue,
                        },
                        Err(err) => {
                            tracing::error!("Arbitration failed for {}: {}", attestation.uid, err);
                        }
                    }
                }
            });
        }

        Ok(ListenAndArbitrateNewFulfillmentsForEscrowResult {
            escrow_attestations,
            escrow_subscription_id,
            fulfillment_subscription_id,
        })
    }

    pub async fn listen_and_arbitrate_new_fulfillments_for_escrow_no_spawn<
        StatementData: SolType,
        DemandData: SolType,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> Option<bool>,
        OnAfterArbitrateFut: Future<Output = ()>,
        OnAfterArbitrate: Fn(&Decision<StatementData, DemandData>) -> OnAfterArbitrateFut,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        skip_arbitrated: Option<bool>,
        timeout: Option<Duration>,
    ) -> eyre::Result<ListenAndArbitrateNewFulfillmentsForEscrowResult>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <StatementData as SolType>::RustType: Send + 'static,
    {
        let (escrow_attestations, escrow_demands) = self.get_escrows(&escrow).await?;

        let demands_map: Arc<RwLock<HashMap<FixedBytes<32>, DemandData::RustType>>> =
            Arc::new(RwLock::new(
                escrow_attestations
                    .iter()
                    .zip(escrow_demands.iter())
                    .map(|(a, d)| (a.uid, d.clone()))
                    .collect(),
            ));

        let escrow_filter = self.make_filter(&escrow.filter);
        let fulfillment_filter = self.make_filter_without_refuid(&fulfillment.filter);

        let escrow_sub = self.public_provider.subscribe_logs(&escrow_filter).await?;
        let fulfillment_sub = self
            .public_provider
            .subscribe_logs(&fulfillment_filter)
            .await?;

        let escrow_subscription_id = *escrow_sub.local_id();
        let fulfillment_subscription_id = *fulfillment_sub.local_id();

        let mut escrow_stream = escrow_sub.into_stream();
        let mut fulfillment_stream = fulfillment_sub.into_stream();

        let wallet_provider = Arc::new(self.wallet_provider.clone());
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;
        let eas = IEAS::new(eas_address, &*wallet_provider);
        let arbiter = TrustedOracleArbiter::new(arbiter_address, &*wallet_provider);
        let signer_address = self._signer.address();

        loop {
            tokio::select! {
                maybe_log = escrow_stream.next() => {
                    let Some(log) = maybe_log else { break };
                    let Ok(log) = log.log_decode::<IEAS::Attested>() else { continue };

                    if let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await {
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        if attestation.expirationTime != 0 && attestation.expirationTime < now { continue; }
                        if attestation.revocationTime != 0 && attestation.revocationTime < now { continue; }

                        if let Ok(statement) = ArbiterDemand::abi_decode(&attestation.data) {
                            if let Ok(demand) = DemandData::abi_decode(&statement.demand) {
                                demands_map.write().await.insert(attestation.uid, demand);
                            }
                        }
                    }
                }

                maybe_log = fulfillment_stream.next() => {
                    let Some(log) = maybe_log else { break };
                    let Ok(log) = log.log_decode::<IEAS::Attested>() else { continue };
                    let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else { continue };

                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    if attestation.expirationTime != 0 && attestation.expirationTime < now { continue; }
                    if attestation.revocationTime != 0 && attestation.revocationTime < now { continue; }

                    let Some(demand) = demands_map.read().await.get(&attestation.refUID).cloned() else { continue; };
                    let Ok(statement) = StatementData::abi_decode(&attestation.data) else { continue; };
                    let Some(decision_value) = arbitrate(&statement, &demand) else { continue; };

                    let Ok(nonce) = wallet_provider.get_transaction_count(signer_address).await else {
                        tracing::error!("Failed to get transaction count for {}", signer_address);
                        continue;
                    };

                    match arbiter.arbitrate(attestation.uid, decision_value).nonce(nonce).send().await {
                        Ok(tx) => match tx.get_receipt().await {
                            Ok(receipt) => {
                                let decision = Decision {
                                    attestation,
                                    statement,
                                    demand: None,
                                    decision: decision_value,
                                    receipt,
                                };
                                on_after_arbitrate(&decision).await;
                            },
                            Err(_) => continue,
                        },
                        Err(err) => {
                            tracing::error!("Arbitration failed for {}: {}", attestation.uid, err);
                        }
                    }
                }

                _ = tokio::time::sleep(timeout.unwrap_or(Duration::from_secs(300))) => {
                    tracing::info!("Timeout reached, exiting arbitration loop.");
                    break;
                }
            }
        }

        Ok(ListenAndArbitrateNewFulfillmentsForEscrowResult {
            escrow_attestations,
            escrow_subscription_id,
            fulfillment_subscription_id,
        })
    }

    pub async fn listen_and_arbitrate_new_fulfillments_for_escrow_async<
        StatementData: SolType,
        DemandData: SolType,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&StatementData::RustType, &DemandData::RustType) -> ArbitrateFut
            + Copy
            + Send
            + Sync
            + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<StatementData, DemandData>) -> OnAfterArbitrateFut
            + Copy
            + Send
            + Sync
            + 'static,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParamsWithoutRefUid<StatementData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
    ) -> eyre::Result<ListenAndArbitrateNewFulfillmentsForEscrowResult>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <StatementData as SolType>::RustType: Send + 'static,
    {
        let (escrow_attestations, escrow_demands) = self.get_escrows(&escrow).await?;

        let demands_map: Arc<RwLock<HashMap<FixedBytes<32>, DemandData::RustType>>> =
            Arc::new(RwLock::new(
                escrow_attestations
                    .iter()
                    .zip(escrow_demands.iter())
                    .map(|(a, d)| (a.uid, d.clone()))
                    .collect(),
            ));

        let wallet_provider = self.wallet_provider.clone();
        let eas_address = self.addresses.eas;
        let arbiter_address = self.addresses.trusted_oracle_arbiter;

        let escrow_subscription_id;
        let fulfillment_subscription_id;

        // Listen for escrow demands
        {
            let demands_map = Arc::clone(&demands_map);
            let filter = self.make_filter(&escrow.filter);
            let sub = self.public_provider.subscribe_logs(&filter).await?;
            escrow_subscription_id = *sub.local_id();

            let mut stream = sub.into_stream();
            let eas_address = eas_address.clone();
            let wallet_provider = wallet_provider.clone();

            tokio::spawn(async move {
                let eas = IEAS::new(eas_address, &wallet_provider);
                while let Some(log) = stream.next().await {
                    if let Ok(log) = log.log_decode::<IEAS::Attested>() {
                        if let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            if attestation.expirationTime != 0 && attestation.expirationTime < now {
                                continue;
                            }
                            if attestation.revocationTime != 0 && attestation.revocationTime < now {
                                continue;
                            }

                            if let Ok(statement) = ArbiterDemand::abi_decode(&attestation.data) {
                                if let Ok(demand) = DemandData::abi_decode(&statement.demand) {
                                    demands_map.write().await.insert(attestation.uid, demand);
                                }
                            }
                        }
                    }
                }
            });
        }

        // Listen for fulfillments
        {
            let demands_map = Arc::clone(&demands_map);
            let filter = self.make_filter_without_refuid(&fulfillment.filter);
            let sub = self.public_provider.subscribe_logs(&filter).await?;
            fulfillment_subscription_id = *sub.local_id();

            let mut stream = sub.into_stream();
            let eas_address = eas_address.clone();
            let wallet_provider = Arc::new(wallet_provider.clone());
            let signer_address = self._signer.address();

            tokio::spawn(async move {
                let eas = IEAS::new(eas_address, &*wallet_provider);
                let arbiter = TrustedOracleArbiter::new(arbiter_address, &*wallet_provider);

                while let Some(log) = stream.next().await {
                    let Ok(log) = log.log_decode::<IEAS::Attested>() else {
                        continue;
                    };
                    let Ok(attestation) = eas.getAttestation(log.inner.uid).call().await else {
                        continue;
                    };

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if (attestation.expirationTime != 0 && attestation.expirationTime < now)
                        || (attestation.revocationTime != 0 && attestation.revocationTime < now)
                    {
                        continue;
                    }

                    let Some(demand) = demands_map.read().await.get(&attestation.refUID).cloned()
                    else {
                        continue;
                    };

                    let Ok(statement) = StatementData::abi_decode(&attestation.data) else {
                        continue;
                    };

                    let Some(decision_value) = arbitrate(&statement, &demand).await else {
                        continue;
                    };

                    let Ok(nonce) = wallet_provider.get_transaction_count(signer_address).await
                    else {
                        tracing::error!("Failed to get transaction count for {}", signer_address);
                        continue;
                    };

                    match arbiter
                        .arbitrate(attestation.uid, decision_value)
                        .nonce(nonce)
                        .send()
                        .await
                    {
                        Ok(tx) => match tx.get_receipt().await {
                            Ok(receipt) => {
                                let decision = Decision {
                                    attestation,
                                    statement,
                                    demand: None,
                                    decision: decision_value,
                                    receipt,
                                };
                                tokio::spawn(on_after_arbitrate(&decision));
                            }
                            Err(_) => continue,
                        },
                        Err(err) => {
                            tracing::error!("Arbitration failed for {}: {}", attestation.uid, err);
                        }
                    }
                }
            });
        }

        Ok(ListenAndArbitrateNewFulfillmentsForEscrowResult {
            escrow_attestations,
            escrow_subscription_id,
            fulfillment_subscription_id,
        })
    }
}
