use super::{
    XdsService,
    auth::unauthenticated_status,
    drop_events, fetch,
    heartbeat::upsert_heartbeat,
    internal_status,
    policy_stream::{PolicyStreamTask, spawn_policy_stream_task},
    proto::{
        DropEvent, DropEventResponse, FetchGeoPrefixesRequest, FetchGeoPrefixesResponse,
        FetchPolicyRequest, FetchPolicyResponse, HeartbeatRequest, HeartbeatResponse, PolicyUpdate,
        StreamPolicyRequest, firewall_xds_server::FirewallXds,
    },
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

#[tonic::async_trait]
impl FirewallXds for XdsService {
    type StreamPolicyStream = ReceiverStream<std::result::Result<PolicyUpdate, Status>>;

    async fn fetch_policy(
        &self,
        request: Request<FetchPolicyRequest>,
    ) -> std::result::Result<Response<FetchPolicyResponse>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        Ok(Response::new(
            fetch::fetch_policy_response(self, request.into_inner()).await?,
        ))
    }

    async fn fetch_geo_prefixes(
        &self,
        request: Request<FetchGeoPrefixesRequest>,
    ) -> std::result::Result<Response<FetchGeoPrefixesResponse>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        Ok(Response::new(
            fetch::fetch_geo_prefixes_response(self, request.into_inner()).await?,
        ))
    }

    async fn stream_policy(
        &self,
        request: Request<StreamPolicyRequest>,
    ) -> std::result::Result<Response<Self::StreamPolicyStream>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        let (tx, rx) = mpsc::channel(8);
        spawn_policy_stream_task(PolicyStreamTask {
            db: self.db.clone(),
            interval: self.push_interval,
            drop_events: self.drop_events.clone(),
            runtime_trusted_cidrs: self.runtime_trusted_cidrs.clone(),
            temp_ban_cleanup: self.temp_ban_cleanup.clone(),
            request: request.into_inner(),
            tx,
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn report_heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> std::result::Result<Response<HeartbeatResponse>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        let request = request.into_inner();
        if self.standby {
            return Ok(Response::new(HeartbeatResponse { accepted: true }));
        }
        upsert_heartbeat(&self.db, request)
            .await
            .map_err(internal_status)?;
        Ok(Response::new(HeartbeatResponse { accepted: true }))
    }

    async fn report_drop_events(
        &self,
        request: Request<Streaming<DropEvent>>,
    ) -> std::result::Result<Response<DropEventResponse>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        let accepted = drop_events::accept_reported_drop_events(
            &self.db,
            &self.drop_events,
            &self.geo_lookup,
            &self.threat_lookup,
            request.into_inner(),
        )
        .await?;
        Ok(Response::new(DropEventResponse { accepted }))
    }
}
