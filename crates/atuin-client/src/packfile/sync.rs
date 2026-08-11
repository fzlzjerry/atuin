//! Syncs a packed history range in both directions: ship a manifest's blob to the remote, and
//! expand a remote manifest back into the local store.
//!
//! # Uploading
//!
//! [`upload_packed`] takes a `packfile` manifest record, reads the history run it covers,
//! compresses + encrypts it with the pack codec (bound to the manifest's identity), and PUTs
//! the blob to the presigned URL the server hands back. The manifest record itself is authored by
//! the packer and synced separately; this only ships the bytes.
//!
//! # Downloading
//!
//! [`download_packed`] takes a remote `packfile` manifest, fetches its packfile blob, unpacks it back
//! into the individual history records for the manifest's `"start".."end"` range, re-encrypts each
//! one with the local key, and pushes them into the local record store.

use atuin_common::encryption::paseto_v4;
use atuin_domain::record::{EncryptedData, Record, RecordId};
use futures::future::{join_all, try_join_all};
use thiserror::Error;

use crate::{api_client::Client, history::HISTORY_TAG, record::sqlite_store::SqliteStore};

use super::record::{LoadingError, PackBodyError, PackManifestRecordView, UnpackError};

/// Maximum packfile uploads to run concurrently within one batch.
const UPLOAD_CONCURRENCY: usize = 8;

/// Maximum packfile downloads to run concurrently within one batch.
const DOWNLOAD_CONCURRENCY: usize = 8;

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("failed to load the packfile manifest: {0}")]
    PackManifest(#[from] LoadingError),

    #[error(transparent)]
    Body(#[from] PackBodyError),

    #[error("packfile upload failed: {0}")]
    Api(eyre::Report),
}

/// Build and upload the packfile blob for a single `packfile` manifest record.
///
/// The manifest gives both the source range (`start_idx..=end_idx`) and the identity
/// (its own `id`/`idx`/`host`) that the blob's encryption is bound to. The referenced records must
/// already be on the server -- `create_packfile` packfiles ids the server already knows -- so this
/// runs after the loose records for the range have synced.
///
/// Takes an already-parsed [`PackManifestRecordView`]; the caller builds it (and classifies a
/// parse failure -- see [`upload_packed_many`]).
///
/// Returns the server's packfile id.
pub(crate) async fn upload_packed(
    view: PackManifestRecordView<'_>,
    store: &SqliteStore,
    key: &paseto_v4::Key,
    client: &Client,
) -> Result<RecordId, UploadError> {
    // `pack_body` loads the covered history, decrypts it, and packs it on the blocking pool -- so
    // this stays fully async and never serializes with the other packfiles in the same
    // `try_join_all` batch. It hands back the ids the packfile covers, which `create_packfile` needs.
    let (blob, ids) = view.pack_body(store, key).await?;

    let (url, packfile_id) = client
        .create_packfile(view.id(), &ids, blob.len())
        .await
        .map_err(UploadError::Api)?;
    client
        .put_packfile(&url, blob)
        .await
        .map_err(UploadError::Api)?;

    Ok(packfile_id)
}

/// Build and upload the packfile blobs for many `packfile` manifest records.
///
/// The manifests are shipped in bounded concurrent batches of [`UPLOAD_CONCURRENCY`]: each packfile
/// is independent (it carries its own history range and manifest identity), so they need no
/// ordering between them. Returns the server packfile ids in input order. The first failure aborts
/// and propagates -- any packfiles already shipped are harmless, since a re-run re-ships the range.
pub async fn upload_packed_many(
    manifests: &[Record<EncryptedData>],
    store: &SqliteStore,
    key: &paseto_v4::Key,
    client: &Client,
) -> Result<Vec<RecordId>, UploadError> {
    let mut packfile_ids = Vec::with_capacity(manifests.len());
    for batch in manifests.chunks(UPLOAD_CONCURRENCY) {
        // Parsing the manifest into a view happens here so a parse failure surfaces as a
        // `PackManifest` error, which `try_join_all` propagates like any other upload failure.
        let ids = try_join_all(batch.iter().map(|manifest| async move {
            let view = PackManifestRecordView::new(manifest)?;
            upload_packed(view, store, key, client).await
        }))
        .await?;
        packfile_ids.extend(ids);
    }
    Ok(packfile_ids)
}

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("failed to load the packfile manifest: {0}")]
    PackManifest(#[from] LoadingError),

    #[error("packfile download failed: {0}")]
    Api(eyre::Report),

    #[error(transparent)]
    Unpack(#[from] UnpackError),

    #[error("failed to store the unpacked history: {0}")]
    Store(eyre::Report),
}

impl DownloadError {
    /// Whether this fault is PERMANENT -- intrinsic to this one manifest/packfile and identical on
    /// retry -- so [`download_packed_many`] skips-and-warns it instead of aborting the batch. A
    /// TRANSIENT/systemic fault returns `false` and propagates, failing the tick so it retries
    /// cleanly.
    fn is_permanent(&self) -> bool {
        match self {
            // Parse-time: unknown version / malformed body / inverted range. Fails at
            // `PackManifestData::try_from` before any I/O -- retry never fixes it.
            DownloadError::PackManifest(_) => true,
            // Post-download codec/AEAD/msgpack failure: dominated by permanent causes (a
            // version-skewed future packfile codec, a wrong key, or server-side corruption), none
            // fixed by retry. Propagating would brick the tick, which is what this skip prevents.
            DownloadError::Unpack(_) => true,
            // Transport (connect refused / 5xx / timeout) and local sqlite are not this manifest's
            // fault; the latter is systemic and must never be masked as a per-manifest skip.
            DownloadError::Api(_) | DownloadError::Store(_) => false,
        }
    }
}

/// Fetch, unpack, and locally store the history covered by a single `packfile` manifest.
///
/// Takes an already-parsed [`PackManifestRecordView`]; the caller builds it (and classifies a
/// parse failure -- see [`download_packed_many`]).
///
/// Returns the ids of the history records the manifest's range covers, whether they were just
/// inserted or were already present locally.
pub(crate) async fn download_packed(
    view: PackManifestRecordView<'_>,
    store: &SqliteStore,
    key: &paseto_v4::Key,
    client: &Client,
) -> Result<Vec<RecordId>, DownloadError> {
    // Skip if we already have the whole range (history is contiguous, packfiles are prefixes).
    let head = store
        .last(view.host_id(), HISTORY_TAG)
        .await
        .map_err(DownloadError::Store)?;
    if let Some(head) = head
        && head.idx >= view.range().end_idx
    {
        // Range already available locally. Return the IDs.
        let existing = view
            .load_encrypted_packed_records(store)
            .await
            .map_err(DownloadError::Store)?;
        return Ok(existing.map(|r| r.id).collect());
    }

    let blob = client.get_packfile(view.id());

    let decrypted = view.unpack_body(blob, key).await?;

    let encrypted: Vec<Record<EncryptedData>> = decrypted
        .into_iter()
        .map(|record| record.encrypt(key))
        .collect();
    let ids: Vec<RecordId> = encrypted.iter().map(|record| record.id).collect();

    store
        .push_batch(encrypted.iter())
        .await
        .map_err(DownloadError::Store)?;

    Ok(ids)
}

/// Expand many `packfile` manifests, in bounded concurrent batches.
///
/// A PERMANENT per-manifest fault (an unknown-version / malformed / inverted-range manifest, or an
/// un-unpackable packfile -- see [`DownloadError::is_permanent`]) is skipped-and-warned so one bad
/// manifest never bricks the whole tick: the other manifests still expand and the caller gets
/// `Ok` with the ids it could resolve. A TRANSIENT/systemic fault (transport error, local sqlite)
/// still propagates as `Err`, failing the tick so it retries cleanly next sync.
///
/// A skip is lossless for re-indexing: only actually-persisted HISTORY ids are ever returned, and
/// a skipped manifest is `PACKFILE_TAG` (never indexed into `history.db`), so returning fewer ids
/// keeps the id-driven rebuild exactly correct.
pub async fn download_packed_many(
    manifests: &[Record<EncryptedData>],
    store: &SqliteStore,
    key: &paseto_v4::Key,
    client: &Client,
) -> Result<Vec<RecordId>, DownloadError> {
    let mut ids = Vec::new();
    for batch in manifests.chunks(DOWNLOAD_CONCURRENCY) {
        // `join_all` (not `try_join_all`) so a per-manifest failure never cancels its in-flight
        // siblings: every download in the chunk runs to completion, then we fold the results.
        // Parsing the manifest into a view happens here so a parse failure surfaces as a
        // `PackManifest` error per manifest -- PERMANENT, hence skipped-and-warned below.
        let results = join_all(batch.iter().map(|manifest| async move {
            let view = PackManifestRecordView::new(manifest)?;
            download_packed(view, store, key, client).await
        }))
        .await;
        for (manifest, result) in batch.iter().zip(results) {
            match result {
                Ok(record_ids) => ids.extend(record_ids),
                Err(e) if e.is_permanent() => warn!(
                    manifest_id = %manifest.id,
                    host = %manifest.host.id,
                    idx = manifest.idx,
                    "skipping unexpandable packfile manifest: {e}"
                ),
                Err(e) => return Err(e),
            }
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use atuin_common::encryption::paseto_v4;
    use atuin_common::utils::uuid_v7;
    use atuin_domain::record::{DecryptedData, Host, HostId, Record};
    use rstest::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::api_client::{AuthToken, Client};
    use crate::history::HISTORY_TAG;
    use crate::packfile::{PACKFILE_TAG, try_pack};
    use crate::record::sqlite_store::SqliteStore;
    use crate::settings::test_local_timeout;

    /// A single fixed encryption key. The specific bytes are arbitrary in these tests -- each one
    /// packs and unpacks with the same key -- so one shared value keeps setup uniform.
    #[fixture]
    fn key() -> paseto_v4::Key {
        paseto_v4::Key::from([7u8; 32])
    }

    /// A [`Client`] pointed at a wiremock server, authenticated with a dummy token.
    fn mock_client(addr: &url::Url) -> Client {
        Client::new(addr.clone(), AuthToken::Token("t".into()), 30, 30, &HashMap::new()).unwrap()
    }

    /// A fresh in-memory record store.
    async fn memory_store() -> SqliteStore {
        SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap()
    }

    /// Push a contiguous run of `count` encrypted HISTORY records (idx `0..count`).
    async fn seed_history(store: &SqliteStore, host: HostId, key: &paseto_v4::Key, count: u64) {
        for idx in 0..count {
            let record = Record::builder()
                .host(Host::new(host))
                .version("v1".into())
                .tag(HISTORY_TAG.to_owned())
                .idx(idx)
                .data(DecryptedData(format!("command number {idx}").into_bytes()))
                .build()
                .encrypt(key);
            store.push(&record).await.unwrap();
        }
    }

    /// Building the view rejects an inverted plaintext range (`start_idx > end_idx`) regardless of
    /// sync direction -- the precondition every `upload_packed`/`download_packed` caller relies on,
    /// so the covered-record count never underflows and no upload or fetch runs.
    #[rstest]
    #[case::far_apart(100, 5)]
    #[case::adjacent(6, 5)]
    #[case::extreme(u64::MAX, 0)]
    fn an_inverted_range_is_rejected_when_building_the_view(
        #[case] start_idx: u64,
        #[case] end_idx: u64,
    ) {
        use crate::packfile::record::{PACKFILE_VERSION, PackManifestDataV1};

        let host = HostId(uuid_v7());

        // A corrupt/tampered manifest whose plaintext range is inverted (start_idx > end_idx). The
        // packer never emits this, so craft the record directly.
        let data = EncryptedData::try_from(&PackManifestDataV1 { start_idx, end_idx }).unwrap();
        let manifest = Record::builder()
            .host(Host::new(host))
            .version(PACKFILE_VERSION.to_owned())
            .tag(PACKFILE_TAG.to_owned())
            .idx(0)
            .data(data)
            .build();

        assert!(
            PackManifestRecordView::new(&manifest).is_err(),
            "inverted manifest range must be rejected, not underflow the count"
        );
    }

    #[rstest]
    #[tokio::test]
    async fn uploads_the_packed_range(key: paseto_v4::Key) {
        let host = HostId(uuid_v7());
        let store = memory_store().await;

        // Seed history, then let the packer author a manifest over it.
        seed_history(&store, host, &key, 5).await;
        try_pack(&store, host, 5, HISTORY_TAG).await.unwrap();
        let manifest = store
            .last(host, PACKFILE_TAG)
            .await
            .unwrap()
            .expect("packer should have written a manifest");

        // Mock the two-step upload: create_packfile -> presigned URL, then the PUT.
        let server = MockServer::start().await;
        let packfile_id = RecordId(uuid_v7());
        Mock::given(method("POST"))
            .and(path("/api/v0/packfiles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "upload_url": format!("{}/upload/abc", server.uri()),
                "packfile_id": packfile_id.0.to_string(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/upload/abc"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let addr: url::Url = server.uri().parse().unwrap();
        let client = mock_client(&addr);

        let view = PackManifestRecordView::new(&manifest).unwrap();
        let got = upload_packed(view, &store, &key, &client).await.unwrap();

        // `.expect(1)` on both mocks verifies create_packfile + put_packfile each fired once.
        assert_eq!(got, packfile_id);
    }

    #[rstest]
    #[tokio::test]
    async fn download_packed_populates_history_from_the_packfile(key: paseto_v4::Key) {
        let host = HostId(uuid_v7());

        // The UPLOADER's store: seed history, author a manifest, build the blob it would ship.
        let up = memory_store().await;
        seed_history(&up, host, &key, 5).await;
        try_pack(&up, host, 5, HISTORY_TAG).await.unwrap();
        let manifest = up.last(host, PACKFILE_TAG).await.unwrap().unwrap();
        let (blob, _ids) = PackManifestRecordView::new(&manifest)
            .unwrap()
            .pack_body(&up, &key)
            .await
            .unwrap();

        // Mock the download: manifest id -> download_url -> blob bytes.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v0/packfiles/{}", manifest.id.0)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "download_url": format!("{}/download/abc", server.uri()),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/download/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        // The DOWNLOADER's fresh store.
        let down = memory_store().await;
        let addr: url::Url = server.uri().parse().unwrap();
        let client = mock_client(&addr);

        let view = PackManifestRecordView::new(&manifest).unwrap();
        let ids = download_packed(view, &down, &key, &client).await.unwrap();
        assert_eq!(ids.len(), 5, "all five history records populated");

        // History is present locally and decrypts to the same commands.
        let got = down.next(host, HISTORY_TAG, 0, 5).await.unwrap();
        assert_eq!(got.len(), 5);
        let first = got[0].clone().decrypt(&key).unwrap();
        assert_eq!(first.data.0, b"command number 0");
    }

    #[rstest]
    #[tokio::test]
    async fn download_packed_returns_range_ids_when_already_local(key: paseto_v4::Key) {
        let host = HostId(uuid_v7());
        let up = memory_store().await;
        seed_history(&up, host, &key, 5).await;
        try_pack(&up, host, 5, HISTORY_TAG).await.unwrap();
        let manifest = up.last(host, PACKFILE_TAG).await.unwrap().unwrap();

        // Downloader that already HAS the history the manifest covers.
        let down = memory_store().await;
        seed_history(&down, host, &key, 5).await;
        let expected_ids: Vec<RecordId> = down
            .next(host, HISTORY_TAG, 0, 5)
            .await
            .unwrap()
            .iter()
            .map(|record| record.id)
            .collect();
        assert_eq!(expected_ids.len(), 5, "sanity: seeded ids captured");

        // No server needed: the skip must happen before any network call.
        let sync_addr: url::Url = "http://127.0.0.1:1/".parse().unwrap();
        let client = Client::new(
            sync_addr.clone(),
            AuthToken::Token("t".into()),
            1,
            1,
            &HashMap::new(),
        )
        .unwrap();

        let view = PackManifestRecordView::new(&manifest).unwrap();
        let ids = download_packed(view, &down, &key, &client).await.unwrap();

        // Range already present -> no fetch, but the covered ids are still returned so the
        // id-driven history.db rebuild can re-index them (see download_packed's doc comment).
        assert_eq!(
            ids, expected_ids,
            "range already local -> covered ids returned anyway, for re-indexing"
        );
    }

    /// A PERMANENT per-manifest fault -- an unknown-version / malformed / inverted-range manifest
    /// that fails at `PackManifestData::try_from` before any network I/O -- must be skipped-and-warned
    /// so a sibling manifest AFTER it in the same batch still expands. The bad manifest is placed
    /// FIRST: on the old `try_join_all`, the first error cancels the whole batch, so the valid
    /// sibling never expands and this test is RED.
    #[rstest]
    #[case::unknown_version(EncryptedData {
        raw: "999{}".into(),
        cek: String::new(),
    })]
    #[case::malformed_body(EncryptedData {
        raw: "001{not json".into(),
        cek: String::new(),
    })]
    #[case::inverted_range(
        EncryptedData::try_from(&crate::packfile::record::PackManifestDataV1 {
            start_idx: 100,
            end_idx: 5,
        })
        .unwrap()
    )]
    #[tokio::test]
    async fn download_packed_many_skips_a_permanent_manifest_and_expands_the_valid_one(
        key: paseto_v4::Key,
        #[case] bad_data: EncryptedData,
    ) {
        use crate::packfile::record::PACKFILE_VERSION;

        let host = HostId(uuid_v7());

        // A VALID packfile for `host` over three history records, built exactly like
        // `download_packed_populates_history_from_the_packfile`.
        let up = memory_store().await;
        seed_history(&up, host, &key, 3).await;
        try_pack(&up, host, 3, HISTORY_TAG).await.unwrap();
        let good = up.last(host, PACKFILE_TAG).await.unwrap().unwrap();
        let (blob, _ids) = PackManifestRecordView::new(&good)
            .unwrap()
            .pack_body(&up, &key)
            .await
            .unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v0/packfiles/{}", good.id.0)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "download_url": format!("{}/download/abc", server.uri()),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/download/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        // A PERMANENT manifest carrying the case's bad body: it fails at `PackManifestData::try_from`
        // (unknown version / malformed JSON / inverted range) before any network I/O, so it needs
        // no mock of its own.
        let bad = Record::builder()
            .host(Host::new(host))
            .version(PACKFILE_VERSION.to_owned())
            .tag(PACKFILE_TAG.to_owned())
            .idx(0)
            .data(bad_data)
            .build();

        let down = memory_store().await;
        let addr: url::Url = server.uri().parse().unwrap();
        let client = mock_client(&addr);

        // `bad` FIRST proves the valid sibling after it still expands.
        let ids = download_packed_many(&[bad, good], &down, &key, &client)
            .await
            .expect("a permanent per-manifest fault must be skipped, not abort the batch");
        assert_eq!(
            ids.len(),
            3,
            "the valid sibling's three records still expand"
        );

        let got = down.next(host, HISTORY_TAG, 0, 3).await.unwrap();
        assert_eq!(
            got.len(),
            3,
            "the valid packfile's history is present locally"
        );
    }

    /// GUARD: a TRANSIENT/systemic fault (here a connection-refused packfile GET) must still
    /// propagate and fail the tick -- it must NOT be masked as a per-manifest skip. Passes before
    /// AND after the refactor, proving we did not over-skip.
    #[rstest]
    #[tokio::test]
    async fn download_packed_many_propagates_a_transient_api_error(key: paseto_v4::Key) {
        let host = HostId(uuid_v7());

        // A VALID manifest that parses to V1 over a non-empty range.
        let manifest = Record::builder()
            .host(Host::new(host))
            .version(crate::packfile::record::PACKFILE_VERSION.to_owned())
            .tag(PACKFILE_TAG.to_owned())
            .idx(0)
            .data(
                EncryptedData::try_from(&crate::packfile::record::PackManifestDataV1 {
                    start_idx: 0,
                    end_idx: 2,
                })
                .unwrap(),
            )
            .build();

        // FRESH store: the range is NOT already local, so download_packed reaches the packfile fetch.
        let down = memory_store().await;

        // A client pointed at a dead address with short timeouts: the packfile GET fails with a
        // transport error (connection refused), which is TRANSIENT and must propagate.
        let sync_addr: url::Url = "http://127.0.0.1:1/".parse().unwrap();
        let client = Client::new(
            sync_addr.clone(),
            AuthToken::Token("t".into()),
            1,
            1,
            &HashMap::new(),
        )
        .unwrap();

        let result = download_packed_many(&[manifest], &down, &key, &client).await;
        assert!(
            matches!(result, Err(DownloadError::Api(_))),
            "a transient transport fault must propagate, not be skipped: {result:?}"
        );
    }
}
