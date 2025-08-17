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
    extensions::AlkahestExtension,
    types::{PublicProvider, WalletProvider},
    utils,
};

#[derive(Debug, Clone)]
pub struct OracleAddresses {
    pub eas: Address,
    pub trusted_oracle_arbiter: Address,
}

#[derive(Clone)]
pub struct OracleModule {
    _signer: PrivateKeySigner,
    public_provider: PublicProvider,
    wallet_provider: WalletProvider,

    pub addresses: OracleAddresses,
}

impl Default for OracleAddresses {
    fn default() -> Self {
        OracleAddresses {
            eas: BASE_SEPOLIA_ADDRESSES.arbiters_addresses.eas,
            trusted_oracle_arbiter: BASE_SEPOLIA_ADDRESSES
                .arbiters_addresses
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

#[derive(Debug, Clone)]
pub struct ArbitrateOptions {
    pub require_oracle: bool,
    pub skip_arbitrated: bool,
    pub require_request: bool,
    pub only_new: bool,
}

impl Default for ArbitrateOptions {
    fn default() -> Self {
        ArbitrateOptions {
            require_oracle: false,
            skip_arbitrated: false,
            require_request: false,
            only_new: false,
        }
    }
}

// Trait for abstracting over sync and async arbitration strategies
trait ArbitrationStrategy<ObligationData: SolType> {
    type Future: std::future::Future<Output = Option<bool>> + Send;

    fn arbitrate(&self, obligation: &ObligationData::RustType) -> Self::Future;
}

// Escrow arbitration strategy trait for two-argument arbitration
trait EscrowArbitrationStrategy<ObligationData: SolType, DemandData: SolType> {
    type Future: std::future::Future<Output = Option<bool>> + Send;

    fn arbitrate(
        &self,
        obligation: &ObligationData::RustType,
        demand: &DemandData::RustType,
    ) -> Self::Future;
}

// Sync arbitration strategy
struct SyncArbitration<F> {
    func: F,
}

impl<F> SyncArbitration<F> {
    fn new(func: F) -> Self {
        Self { func }
    }
}

impl<ObligationData, F> ArbitrationStrategy<ObligationData> for SyncArbitration<F>
where
    ObligationData: SolType,
    F: Fn(&ObligationData::RustType) -> Option<bool> + Copy,
{
    type Future = std::future::Ready<Option<bool>>;

    fn arbitrate(&self, obligation: &ObligationData::RustType) -> Self::Future {
        std::future::ready((self.func)(obligation))
    }
}

// Sync escrow arbitration strategy
#[derive(Clone)]
struct SyncEscrowArbitration<F> {
    func: F,
}

impl<F: Copy> Copy for SyncEscrowArbitration<F> {}

impl<F> SyncEscrowArbitration<F> {
    fn new(func: F) -> Self {
        Self { func }
    }
}

impl<ObligationData, DemandData, F> EscrowArbitrationStrategy<ObligationData, DemandData>
    for SyncEscrowArbitration<F>
where
    ObligationData: SolType,
    DemandData: SolType,
    F: Fn(&ObligationData::RustType, &DemandData::RustType) -> Option<bool> + Copy,
{
    type Future = std::future::Ready<Option<bool>>;

    fn arbitrate(
        &self,
        obligation: &ObligationData::RustType,
        demand: &DemandData::RustType,
    ) -> Self::Future {
        std::future::ready((self.func)(obligation, demand))
    }
}

// Async arbitration strategy
struct AsyncArbitration<F> {
    func: F,
}

impl<F> AsyncArbitration<F> {
    fn new(func: F) -> Self {
        Self { func }
    }
}

impl<ObligationData, F, Fut> ArbitrationStrategy<ObligationData> for AsyncArbitration<F>
where
    ObligationData: SolType,
    F: Fn(&ObligationData::RustType) -> Fut + Copy,
    Fut: std::future::Future<Output = Option<bool>> + Send,
{
    type Future = Fut;

    fn arbitrate(&self, obligation: &ObligationData::RustType) -> Self::Future {
        (self.func)(obligation)
    }
}

// Async escrow arbitration strategy
#[derive(Clone)]
struct AsyncEscrowArbitration<F> {
    func: F,
}

impl<F: Copy> Copy for AsyncEscrowArbitration<F> {}

impl<F> AsyncEscrowArbitration<F> {
    fn new(func: F) -> Self {
        Self { func }
    }
}

impl AlkahestExtension for OracleModule {
    type Config = OracleAddresses;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        config: Option<Self::Config>,
    ) -> eyre::Result<Self> {
        Self::new(private_key, rpc_url, config).await
    }
}

impl<ObligationData, DemandData, F, Fut> EscrowArbitrationStrategy<ObligationData, DemandData>
    for AsyncEscrowArbitration<F>
where
    ObligationData: SolType,
    DemandData: SolType,
    F: Fn(&ObligationData::RustType, &DemandData::RustType) -> Fut + Copy,
    Fut: std::future::Future<Output = Option<bool>> + Send,
{
    type Future = Fut;

    fn arbitrate(
        &self,
        obligation: &ObligationData::RustType,
        demand: &DemandData::RustType,
    ) -> Self::Future {
        (self.func)(obligation, demand)
    }
}

#[derive(Clone)]
pub struct FulfillmentParams<T: SolType> {
    pub filter: AttestationFilter,
    pub _obligation_data: PhantomData<T>,
}

pub struct EscrowParams<T: SolType> {
    pub _demand_data: PhantomData<T>,
    pub filter: AttestationFilter,
}

pub struct Decision<T: SolType, U: SolType> {
    pub attestation: IEAS::Attestation,
    pub obligation: T::RustType,
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

pub struct ListenAndArbitrateResult<ObligationData: SolType> {
    pub decisions: Vec<Decision<ObligationData, ()>>,
    pub subscription_id: FixedBytes<32>,
}

pub struct ListenAndArbitrateForEscrowResult<ObligationData: SolType, DemandData: SolType> {
    pub decisions: Vec<Decision<ObligationData, DemandData>>,
    pub escrow_attestations: Vec<IEAS::Attestation>,
    pub escrow_subscription_id: FixedBytes<32>,
    pub fulfillment_subscription_id: FixedBytes<32>,
}

impl OracleModule {
    pub async fn new(
        signer: PrivateKeySigner,
        rpc_url: impl ToString + Clone,
        addresses: Option<OracleAddresses>,
    ) -> eyre::Result<Self> {
        let public_provider = utils::get_public_provider(rpc_url.clone()).await?;
        let wallet_provider = utils::get_wallet_provider(signer.clone(), rpc_url.clone()).await?;

        Ok(OracleModule {
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

    pub async fn request_arbitration(
        &self,
        obligation_uid: FixedBytes<32>,
        oracle: Address,
    ) -> eyre::Result<TransactionReceipt> {
        let trusted_oracle_arbiter =
            TrustedOracleArbiter::new(self.addresses.trusted_oracle_arbiter, &self.wallet_provider);

        let nonce = self
            .wallet_provider
            .get_transaction_count(self._signer.address())
            .await?;

        let tx = trusted_oracle_arbiter
            .requestArbitration(obligation_uid, oracle)
            .nonce(nonce)
            .send()
            .await?;

        let receipt = tx.get_receipt().await?;
        Ok(receipt)
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

    fn make_event_filter(
        address: Address,
        event_signature: FixedBytes<32>,
        obligation: Option<FixedBytes<32>>,
        oracle: Option<Address>,
    ) -> Filter {
        let mut filter = Filter::new()
            .address(address)
            .event_signature(event_signature)
            .from_block(BlockNumberOrTag::Earliest)
            .to_block(BlockNumberOrTag::Latest);

        if let Some(obligation) = obligation {
            filter = filter.topic1(obligation);
        }
        if let Some(oracle) = oracle {
            filter = filter.topic2(oracle);
        }

        filter
    }

    async fn filter_unarbitrated_attestations(
        &self,
        attestations: Vec<Attestation>,
    ) -> eyre::Result<Vec<Attestation>> {
        let futs = attestations.into_iter().map(|a| {
            let filter = Self::make_event_filter(
                self.addresses.trusted_oracle_arbiter,
                TrustedOracleArbiter::ArbitrationMade::SIGNATURE_HASH,
                Some(a.uid),
                Some(self._signer.address()),
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

    async fn filter_requested_attestations(
        &self,
        attestations: Vec<Attestation>,
    ) -> eyre::Result<Vec<Attestation>> {
        let futs = attestations.into_iter().map(|a| {
            let filter = Self::make_event_filter(
                self.addresses.trusted_oracle_arbiter,
                TrustedOracleArbiter::ArbitrationRequested::SIGNATURE_HASH,
                Some(a.uid),
                Some(self._signer.address()),
            );
            async move {
                let logs = self.public_provider.get_logs(&filter).await?;
                Ok::<_, eyre::Error>((a, !logs.is_empty()))
            }
        });

        let results = try_join_all(futs).await?;
        Ok(results
            .into_iter()
            .filter_map(|(a, is_requested)| if is_requested { Some(a) } else { None })
            .collect())
    }

    async fn get_attestations_and_obligations<ObligationData: SolType>(
        &self,
        fulfillment: &FulfillmentParams<ObligationData>,
        options: &ArbitrateOptions,
    ) -> eyre::Result<(Vec<Attestation>, Vec<ObligationData::RustType>)> {
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

        let attestations = if options.skip_arbitrated {
            self.filter_unarbitrated_attestations(attestations).await?
        } else {
            attestations
        };

        let attestations = if options.require_request {
            self.filter_requested_attestations(attestations).await?
        } else {
            attestations
        };

        let obligations = attestations
            .iter()
            .map(|a| ObligationData::abi_decode(&a.data))
            .collect::<Result<Vec<_>, _>>()?;

        Ok((attestations, obligations))
    }

    async fn arbitrate_past_internal<ObligationData: SolType>(
        &self,
        _fulfillment: &FulfillmentParams<ObligationData>,
        decisions: Vec<Option<bool>>,
        attestations: Vec<Attestation>,
        obligations: Vec<ObligationData::RustType>,
    ) -> eyre::Result<Vec<Decision<ObligationData, ()>>> {
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

        let result = izip!(attestations, obligations, decisions, receipts)
            .filter(|(_, _, d, _)| d.is_some())
            .map(|(attestation, obligation, decision, receipt)| Decision {
                attestation,
                obligation: obligation,
                demand: None,
                decision: decision.unwrap(),
                receipt,
            })
            .collect::<Vec<Decision<ObligationData, ()>>>();

        Ok(result)
    }

    async fn arbitrate_past<
        ObligationData: SolType,
        Strategy: ArbitrationStrategy<ObligationData>,
    >(
        &self,
        fulfillment: &FulfillmentParams<ObligationData>,
        strategy: Strategy,
        options: &ArbitrateOptions,
    ) -> eyre::Result<Vec<Decision<ObligationData, ()>>>
    where
        Strategy::Future: Send,
    {
        let (attestations, obligations) = self
            .get_attestations_and_obligations(fulfillment, options)
            .await?;

        let decision_futs = obligations.iter().map(|s| strategy.arbitrate(s));
        let decisions = join_all(decision_futs).await;

        self.arbitrate_past_internal(fulfillment, decisions, attestations, obligations)
            .await
    }

    pub async fn arbitrate_past_sync<
        ObligationData: SolType,
        Arbitrate: Fn(&ObligationData::RustType) -> Option<bool> + Copy,
    >(
        &self,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: &Arbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<Vec<Decision<ObligationData, ()>>> {
        let strategy = SyncArbitration::new(*arbitrate);
        self.arbitrate_past(fulfillment, strategy, options).await
    }

    pub async fn arbitrate_past_async<
        ObligationData: SolType,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&ObligationData::RustType) -> ArbitrateFut + Copy,
    >(
        &self,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: Arbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<Vec<Decision<ObligationData, ()>>> {
        let strategy = AsyncArbitration::new(arbitrate);
        self.arbitrate_past(fulfillment, strategy, options).await
    }

    async fn spawn_fulfillment_listener<
        ObligationData: SolType + Clone + Send + 'static,
        Strategy: ArbitrationStrategy<ObligationData> + Send + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<ObligationData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        stream: SubscriptionStream<Log>,
        fulfillment: FulfillmentParams<ObligationData>,
        strategy: Strategy,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) where
        <ObligationData as SolType>::RustType: Send,
        Strategy::Future: Send,
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
                let attestation = if options.require_request {
                    let Ok(arbitration_log) =
                        log.log_decode::<TrustedOracleArbiter::ArbitrationRequested>()
                    else {
                        continue;
                    };
                    // Get the attestation using the obligation UID from the event
                    let Ok(attestation) = eas
                        .getAttestation(arbitration_log.inner.obligation)
                        .call()
                        .await
                    else {
                        continue;
                    };
                    attestation
                } else {
                    let Ok(attested_log) = log.log_decode::<IEAS::Attested>() else {
                        continue;
                    };
                    let Ok(attestation) = eas.getAttestation(attested_log.inner.uid).call().await
                    else {
                        continue;
                    };
                    attestation
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
                    let filter = Self::make_event_filter(
                        arbiter_address,
                        TrustedOracleArbiter::ArbitrationMade::SIGNATURE_HASH,
                        Some(attestation.uid),
                        Some(signer_address),
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

                let Ok(obligation) = ObligationData::abi_decode(&attestation.data) else {
                    continue;
                };

                let Some(decision_value) = strategy.arbitrate(&obligation).await else {
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
                                obligation: obligation,
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

    async fn spawn_fulfillment_listener_sync<
        ObligationData: SolType + Clone + Send + 'static,
        Arbitrate: Fn(&ObligationData::RustType) -> Option<bool> + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<ObligationData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        stream: SubscriptionStream<Log>,
        fulfillment: FulfillmentParams<ObligationData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) where
        <ObligationData as SolType>::RustType: Send,
    {
        let strategy = SyncArbitration::new(*arbitrate);
        self.spawn_fulfillment_listener(stream, fulfillment, strategy, on_after_arbitrate, options)
            .await;
    }

    pub async fn spawn_fulfillment_listener_async<
        ObligationData: SolType + Clone + Send + 'static,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&ObligationData::RustType) -> ArbitrateFut + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<ObligationData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        stream: SubscriptionStream<Log>,
        fulfillment: FulfillmentParams<ObligationData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) where
        <ObligationData as SolType>::RustType: Send,
    {
        let strategy = AsyncArbitration::new(arbitrate);
        self.spawn_fulfillment_listener(stream, fulfillment, strategy, on_after_arbitrate, options)
            .await;
    }

    async fn handle_fulfillment_stream_no_spawn<
        ObligationData: SolType,
        Arbitrate: Fn(&ObligationData::RustType) -> Option<bool>,
        OnAfterArbitrateFut: Future<Output = ()>,
        OnAfterArbitrate: Fn(&Decision<ObligationData, ()>) -> OnAfterArbitrateFut,
    >(
        &self,
        mut stream: SubscriptionStream<Log>,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
        timeout: Option<Duration>,
    ) where
        <ObligationData as SolType>::RustType: Send,
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

            let attestation = if options.require_request {
                let Ok(arbitration_log) =
                    log.log_decode::<TrustedOracleArbiter::ArbitrationRequested>()
                else {
                    continue;
                };
                let Ok(attestation) = eas
                    .getAttestation(arbitration_log.inner.obligation)
                    .call()
                    .await
                else {
                    continue;
                };
                attestation
            } else {
                let Ok(attested_log) = log.log_decode::<IEAS::Attested>() else {
                    continue;
                };
                let Ok(attestation) = eas.getAttestation(attested_log.inner.uid).call().await
                else {
                    continue;
                };
                attestation
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
                let filter = Self::make_event_filter(
                    self.addresses.trusted_oracle_arbiter,
                    TrustedOracleArbiter::ArbitrationMade::SIGNATURE_HASH,
                    Some(attestation.uid),
                    Some(self._signer.address()),
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

            let Ok(obligation) = ObligationData::abi_decode(&attestation.data) else {
                continue;
            };

            let Some(decision_value) = arbitrate(&obligation) else {
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
                            obligation: obligation,
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

    pub async fn listen_and_arbitrate_sync<
        ObligationData: SolType + Clone + Send + 'static,
        Arbitrate: Fn(&ObligationData::RustType) -> Option<bool> + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<ObligationData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<ListenAndArbitrateResult<ObligationData>>
    where
        <ObligationData as SolType>::RustType: Send,
    {
        let decisions = if options.only_new {
            Vec::new()
        } else {
            self.arbitrate_past_sync(&fulfillment, arbitrate, options)
                .await?
        };
        let filter = if options.require_request {
            Self::make_event_filter(
                self.addresses.trusted_oracle_arbiter,
                TrustedOracleArbiter::ArbitrationRequested::SIGNATURE_HASH,
                None,
                Some(self._signer.address()),
            )
        } else {
            self.make_filter(&fulfillment.filter)
        };
        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let local_id = *sub.local_id();
        let stream: SubscriptionStream<Log> = sub.into_stream();

        self.spawn_fulfillment_listener_sync(
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
        ObligationData: SolType + Clone + Send + 'static,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&ObligationData::RustType) -> ArbitrateFut + Copy + Send + Sync + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<ObligationData, ()>) -> OnAfterArbitrateFut + Copy + Send + Sync + 'static,
    >(
        &self,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<ListenAndArbitrateResult<ObligationData>>
    where
        <ObligationData as SolType>::RustType: Send,
    {
        let decisions = if options.only_new {
            Vec::new()
        } else {
            self.arbitrate_past_async(&fulfillment, arbitrate, options)
                .await?
        };

        let filter = if options.require_request {
            Self::make_event_filter(
                self.addresses.trusted_oracle_arbiter,
                TrustedOracleArbiter::ArbitrationRequested::SIGNATURE_HASH,
                None,
                Some(self._signer.address()),
            )
        } else {
            self.make_filter(&fulfillment.filter)
        };

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

    pub async fn listen_and_arbitrate_no_spawn<
        ObligationData: SolType,
        Arbitrate: Fn(&ObligationData::RustType) -> Option<bool>,
        OnAfterArbitrateFut: Future<Output = ()>,
        OnAfterArbitrate: Fn(&Decision<ObligationData, ()>) -> OnAfterArbitrateFut,
    >(
        &self,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
        timeout: Option<Duration>,
    ) -> eyre::Result<ListenAndArbitrateResult<ObligationData>>
    where
        <ObligationData as SolType>::RustType: Send,
    {
        let decisions = if options.only_new {
            Vec::new()
        } else {
            self.arbitrate_past_sync(&fulfillment, &arbitrate, options)
                .await?
        };
        let filter = if options.require_request {
            Self::make_event_filter(
                self.addresses.trusted_oracle_arbiter,
                TrustedOracleArbiter::ArbitrationRequested::SIGNATURE_HASH,
                None,
                Some(self._signer.address()),
            )
        } else {
            self.make_filter(&fulfillment.filter)
        };

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

    async fn arbitrate_past_for_escrow<
        ObligationData: SolType,
        DemandData: SolType,
        Strategy: EscrowArbitrationStrategy<ObligationData, DemandData>,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParams<ObligationData>,
        strategy: Strategy,
        options: &ArbitrateOptions,
    ) -> eyre::Result<(
        Vec<Decision<ObligationData, DemandData>>,
        Vec<IEAS::Attestation>,
        Vec<<DemandData as SolType>::RustType>,
    )>
    where
        DemandData::RustType: Clone,
        Strategy::Future: Send,
    {
        let escrow_filter = self.make_filter(&escrow.filter);
        let escrow_logs_fut = async move { self.public_provider.get_logs(&escrow_filter).await };

        let fulfillment_filter: AttestationFilter = fulfillment.filter.clone();
        let fulfillment_filter = if options.require_request {
            Self::make_event_filter(
                self.addresses.trusted_oracle_arbiter,
                TrustedOracleArbiter::ArbitrationRequested::SIGNATURE_HASH,
                None,
                Some(self._signer.address()),
            )
        } else {
            self.make_filter(&fulfillment_filter)
        };
        let fulfillment_logs_fut =
            async move { self.public_provider.get_logs(&fulfillment_filter).await };

        let (escrow_logs, fulfillment_logs) =
            tokio::try_join!(escrow_logs_fut, fulfillment_logs_fut)?;

        let escrow_logs = escrow_logs
            .into_iter()
            .map(|log| log.log_decode::<IEAS::Attested>())
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_attestation_futs = escrow_logs.into_iter().map(|log| {
            let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
            async move { eas.getAttestation(log.inner.uid).call().await }
        });
        let escrow_attestations_fut = async move { try_join_all(escrow_attestation_futs).await };

        let fulfillment_logs = if options.require_request {
            fulfillment_logs
                .into_iter()
                .map(|log| {
                    log.log_decode::<TrustedOracleArbiter::ArbitrationRequested>()
                        .map(|decoded| decoded.inner.obligation)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            fulfillment_logs
                .into_iter()
                .map(|log| {
                    log.log_decode::<IEAS::Attested>()
                        .map(|decoded| decoded.inner.uid)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let fulfillment_attestation_futs = fulfillment_logs.into_iter().map(|uid| {
            let eas = IEAS::new(self.addresses.eas, &self.wallet_provider);
            async move { eas.getAttestation(uid).call().await }
        });

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

        let escrow_obligations = escrow_attestations
            .iter()
            .map(|a| ArbiterDemand::abi_decode(&a.data))
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_demands = escrow_obligations
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

        let fulfillment_attestations = if options.skip_arbitrated {
            self.filter_unarbitrated_attestations(fulfillment_attestations)
                .await?
        } else {
            fulfillment_attestations
        };

        let fulfillment_obligations = fulfillment_attestations
            .iter()
            .map(|a| ObligationData::abi_decode(&a.data))
            .collect::<Result<Vec<_>, _>>()?;

        let decision_futs = fulfillment_obligations
            .iter()
            .zip(fulfillment_attestations.iter())
            .filter_map(|(obligation, attestation)| {
                demands_map
                    .get(&attestation.refUID)
                    .map(|demand| strategy.arbitrate(obligation, demand))
            });
        let decisions = join_all(decision_futs).await;

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
            fulfillment_obligations,
            decisions,
            receipts
        )
        .filter(|(_, _, d, _)| d.is_some())
        .map(|(attestation, obligation, decision, receipt)| {
            let demand = demands_map.get(&attestation.refUID).map(|&x| x.clone());
            Decision {
                attestation,
                obligation: obligation,
                demand,
                decision: decision.unwrap(),
                receipt,
            }
        })
        .collect::<Vec<Decision<ObligationData, DemandData>>>();

        Ok((result, escrow_attestations, escrow_demands))
    }

    pub async fn arbitrate_past_for_escrow_sync<
        ObligationData: SolType,
        DemandData: SolType,
        Arbitrate: Fn(&ObligationData::RustType, &DemandData::RustType) -> Option<bool> + Copy,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: Arbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<(
        Vec<Decision<ObligationData, DemandData>>,
        Vec<IEAS::Attestation>,
        Vec<<DemandData as SolType>::RustType>,
    )>
    where
        DemandData::RustType: Clone,
    {
        let strategy = SyncEscrowArbitration::new(arbitrate);
        self.arbitrate_past_for_escrow(escrow, fulfillment, strategy, options)
            .await
    }

    pub async fn arbitrate_past_for_escrow_async<
        ObligationData: SolType,
        DemandData: SolType,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&ObligationData::RustType, &DemandData::RustType) -> ArbitrateFut + Copy,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: Arbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<(
        Vec<Decision<ObligationData, DemandData>>,
        Vec<IEAS::Attestation>,
        Vec<<DemandData as SolType>::RustType>,
    )>
    where
        DemandData::RustType: Clone,
    {
        let strategy = AsyncEscrowArbitration::new(arbitrate);
        self.arbitrate_past_for_escrow(escrow, fulfillment, strategy, options)
            .await
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

        let escrow_obligations = escrow_attestations
            .iter()
            .map(|a| ArbiterDemand::abi_decode(&a.data))
            .collect::<Result<Vec<_>, _>>()?;

        let escrow_demands = escrow_obligations
            .iter()
            .map(|s| DemandData::abi_decode(&s.demand))
            .collect::<Result<Vec<_>, _>>()?;

        Ok((escrow_attestations, escrow_demands))
    }

    async fn listen_and_arbitrate_for_escrow<
        ObligationData: SolType + Clone + Send + Sync + 'static,
        DemandData: SolType + Clone + Send + Sync + 'static,
        Strategy: EscrowArbitrationStrategy<ObligationData, DemandData> + Send + Sync + Copy + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<ObligationData, DemandData>) -> OnAfterArbitrateFut
            + Send
            + Sync
            + Copy
            + 'static,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParams<ObligationData>,
        strategy: Strategy,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<ListenAndArbitrateForEscrowResult<ObligationData, DemandData>>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <ObligationData as SolType>::RustType: Send + 'static,
        Strategy::Future: Send,
    {
        let (decisions, escrow_attestations, escrow_demands) = if options.only_new {
            let (escrow_attestations, escrow_demands) = self.get_escrows(&escrow).await?;
            (Vec::new(), escrow_attestations, escrow_demands)
        } else {
            self.arbitrate_past_for_escrow(escrow, fulfillment, strategy, options)
                .await?
        };

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

                            if let Ok(obligation) = ArbiterDemand::abi_decode(&attestation.data) {
                                if let Ok(demand) = DemandData::abi_decode(&obligation.demand) {
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
            let public_provider = self.public_provider.clone();
            let demands_map = Arc::clone(&demands_map);
            let filter = if options.require_request {
                Self::make_event_filter(
                    self.addresses.trusted_oracle_arbiter,
                    TrustedOracleArbiter::ArbitrationRequested::SIGNATURE_HASH,
                    None,
                    Some(self._signer.address()),
                )
            } else {
                self.make_filter(&fulfillment.filter)
            };
            let sub = self.public_provider.subscribe_logs(&filter).await?;
            fulfillment_subscription_id = *sub.local_id();
            let mut stream = sub.into_stream();
            let eas_address = eas_address.clone();
            let wallet_provider = Arc::new(wallet_provider.clone());
            let signer_address = self._signer.address();
            let options = options.clone();

            tokio::spawn(async move {
                let eas = IEAS::new(eas_address, &*wallet_provider);
                let arbiter = TrustedOracleArbiter::new(arbiter_address, &*wallet_provider);

                while let Some(log) = stream.next().await {
                    let attestation = if options.require_request {
                        let Ok(arbitration_log) =
                            log.log_decode::<TrustedOracleArbiter::ArbitrationRequested>()
                        else {
                            continue;
                        };
                        let Ok(attestation) = eas
                            .getAttestation(arbitration_log.inner.obligation)
                            .call()
                            .await
                        else {
                            continue;
                        };
                        attestation
                    } else {
                        let Ok(attested_log) = log.log_decode::<IEAS::Attested>() else {
                            continue;
                        };
                        let Ok(attestation) =
                            eas.getAttestation(attested_log.inner.uid).call().await
                        else {
                            continue;
                        };
                        attestation
                    };

                    if options.skip_arbitrated {
                        let filter = Self::make_event_filter(
                            arbiter_address,
                            TrustedOracleArbiter::ArbitrationMade::SIGNATURE_HASH,
                            Some(attestation.uid),
                            None,
                        );
                        let logs_result = public_provider.get_logs(&filter).await;

                        if let Ok(logs) = logs_result {
                            if logs.len() > 0 {
                                continue;
                            }
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

                    let Some(demand) = demands_map.read().await.get(&attestation.refUID).cloned()
                    else {
                        continue;
                    };

                    let Ok(obligation) = ObligationData::abi_decode(&attestation.data) else {
                        continue;
                    };

                    let Some(decision_value) = strategy.arbitrate(&obligation, &demand).await
                    else {
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
                                    obligation: obligation,
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

    pub async fn listen_and_arbitrate_for_escrow_sync<
        ObligationData: SolType + Clone + Send + Sync + 'static,
        DemandData: SolType + Clone + Send + Sync + 'static,
        Arbitrate: Fn(&ObligationData::RustType, &DemandData::RustType) -> Option<bool>
            + Send
            + Sync
            + Copy
            + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<ObligationData, DemandData>) -> OnAfterArbitrateFut
            + Send
            + Sync
            + Copy
            + 'static,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<ListenAndArbitrateForEscrowResult<ObligationData, DemandData>>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <ObligationData as SolType>::RustType: Send + 'static,
    {
        let strategy = SyncEscrowArbitration::new(arbitrate);
        self.listen_and_arbitrate_for_escrow(
            escrow,
            fulfillment,
            strategy,
            on_after_arbitrate,
            options,
        )
        .await
    }

    pub async fn listen_and_arbitrate_for_escrow_async<
        ObligationData: SolType + Clone + Send + Sync + 'static,
        DemandData: SolType + Clone + Send + Sync + 'static,
        ArbitrateFut: Future<Output = Option<bool>> + Send,
        Arbitrate: Fn(&ObligationData::RustType, &DemandData::RustType) -> ArbitrateFut
            + Copy
            + Send
            + Sync
            + 'static,
        OnAfterArbitrateFut: Future<Output = ()> + Send + 'static,
        OnAfterArbitrate: Fn(&Decision<ObligationData, DemandData>) -> OnAfterArbitrateFut
            + Copy
            + Send
            + Sync
            + 'static,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,
    ) -> eyre::Result<ListenAndArbitrateForEscrowResult<ObligationData, DemandData>>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <ObligationData as SolType>::RustType: Send + 'static,
    {
        let strategy = AsyncEscrowArbitration::new(arbitrate);
        self.listen_and_arbitrate_for_escrow(
            escrow,
            fulfillment,
            strategy,
            on_after_arbitrate,
            options,
        )
        .await
    }

    pub async fn listen_and_arbitrate_for_escrow_no_spawn<
        ObligationData: SolType,
        DemandData: SolType,
        Arbitrate: Fn(&ObligationData::RustType, &DemandData::RustType) -> Option<bool>,
        OnAfterArbitrateFut: Future<Output = ()>,
        OnAfterArbitrate: Fn(&Decision<ObligationData, DemandData>) -> OnAfterArbitrateFut,
    >(
        &self,
        escrow: &EscrowParams<DemandData>,
        fulfillment: &FulfillmentParams<ObligationData>,
        arbitrate: &Arbitrate,
        on_after_arbitrate: OnAfterArbitrate,
        options: &ArbitrateOptions,

        timeout: Option<Duration>,
    ) -> eyre::Result<ListenAndArbitrateForEscrowResult<ObligationData, DemandData>>
    where
        <DemandData as SolType>::RustType: Clone + Send + Sync + 'static,
        <ObligationData as SolType>::RustType: Send + 'static,
    {
        let (decisions, escrow_attestations, escrow_demands) = if options.only_new {
            let (escrow_attestations, escrow_demands) = self.get_escrows(&escrow).await?;
            (Vec::new(), escrow_attestations, escrow_demands)
        } else {
            self.arbitrate_past_for_escrow_sync(&escrow, &fulfillment, arbitrate, &options)
                .await?
        };

        let demands_map: Arc<RwLock<HashMap<FixedBytes<32>, DemandData::RustType>>> =
            Arc::new(RwLock::new(
                escrow_attestations
                    .iter()
                    .zip(escrow_demands.iter())
                    .map(|(a, d)| (a.uid, d.clone()))
                    .collect(),
            ));

        let escrow_filter = self.make_filter(&escrow.filter);
        let fulfillment_filter = self.make_filter(&fulfillment.filter);

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

                        if let Ok(obligation) = ArbiterDemand::abi_decode(&attestation.data) {
                            if let Ok(demand) = DemandData::abi_decode(&obligation.demand) {
                                demands_map.write().await.insert(attestation.uid, demand);
                            }
                        }
                    }
                }

                maybe_log = fulfillment_stream.next() => {
                    let Some(log) = maybe_log else { break };
                    let attestation = if options.require_request {
                        let Ok(arbitration_log) =
                            log.log_decode::<TrustedOracleArbiter::ArbitrationRequested>()
                        else {
                            continue;
                        };
                        let Ok(attestation) = eas
                            .getAttestation(arbitration_log.inner.obligation)
                            .call()
                            .await
                        else {
                            continue;
                        };
                        attestation
                    } else {
                        let Ok(attested_log) = log.log_decode::<IEAS::Attested>() else {
                            continue;
                        };
                        let Ok(attestation) =
                            eas.getAttestation(attested_log.inner.uid).call().await
                        else {
                            continue;
                        };
                        attestation
                    };

                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    if attestation.expirationTime != 0 && attestation.expirationTime < now { continue; }
                    if attestation.revocationTime != 0 && attestation.revocationTime < now { continue; }

                    let Some(demand) = demands_map.read().await.get(&attestation.refUID).cloned() else { continue; };
                    let Ok(obligation) = ObligationData::abi_decode(&attestation.data) else { continue; };
                    let Some(decision_value) = arbitrate(&obligation, &demand) else { continue; };

                    let Ok(nonce) = wallet_provider.get_transaction_count(signer_address).await else {
                        tracing::error!("Failed to get transaction count for {}", signer_address);
                        continue;
                    };

                    match arbiter.arbitrate(attestation.uid, decision_value).nonce(nonce).send().await {
                        Ok(tx) => match tx.get_receipt().await {
                            Ok(receipt) => {
                                let decision = Decision {
                                    attestation,
                                    obligation,
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
}
