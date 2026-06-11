//! Server-side handling for signed user-source `PieceTextEdit` changes.
//!
//! `PieceTextEdit` is a normal signed [`ChangelogEntry`]: it flows through the
//! same generic [`SpaceState::handle_change`](super::SpaceState::handle_change)
//! pipeline as every other user-source op (signature, sigref, timestamp,
//! parent, CLC, apply, changelog append, FF proof). There is no dedicated
//! `PieceTextEdit` transport, request, or response type — the inserted buffer
//! ciphertexts ride in the existing `ChangeRequest.values_sidecar`.
//!
//! # Sidecar spike (Commit 3, run before integration)
//!
//! The plan asked three questions before reusing `ChangeRequest.values_sidecar`
//! instead of adding a dedicated `PieceTextEditRequest.inserted_bodies` field.
//! The answers, which justify the generic path:
//!
//! 1. *Can `PieceTextEdit` reuse `values_sidecar` without losing inserted-body
//!    ordering?* Yes. `values_sidecar` is a `repeated bytes` field, which is
//!    ordered on the wire exactly like the oracle's dedicated `inserted_bodies`
//!    field. For a `PieceTextEdit` the server interprets `values_sidecar` as the
//!    ordered inserted-body list (1:1 with the manifest's `Insert` ops, in
//!    order) and binds each body to its manifest entry positionally via the
//!    shared [`validate_piece_text_inserted_bodies`] helper. Order is preserved
//!    end-to-end because the server does not pre-hash the list into a map before
//!    the positional bind.
//!
//! 2. *Is body order actually needed once each body is named by hash in the
//!    manifest?* The manifest names each body by
//!    `ciphertext_value_hash = hashstore_hash(stored_form)`, where `stored_form`
//!    is the base64-JSON on-merk value — not `hashstore_hash(raw_body)`. So a
//!    raw body cannot be looked up by its manifest hash without first wrapping
//!    and re-hashing it. Positional order is therefore the simplest correct
//!    binding, and it is also what lets the server check
//!    `body.len() == manifest.ciphertext_len` per position. After
//!    materialisation the resulting [`HashedValues`] map is keyed by the
//!    stored-form hash and order no longer matters for storage.
//!
//! 3. *Can duplicate body values be handled when the sidecar becomes a hash
//!    map?* Yes. Duplicate raw bodies wrap to identical stored forms, hence
//!    identical `ciphertext_value_hash`, and collapse to a single entry in the
//!    materialised map. Each manifest `Insert` still validates against its own
//!    (identical) body positionally, and every referencing piece resolves the
//!    one stored value. No data loss.
//!
//! Conclusion: generic sidecars are correct; no dedicated `PieceTextEditRequest`
//! is introduced. The only intentional delta from the oracle is the transport
//! shape (generic `ChangeRequest` instead of a dedicated request); the inserted
//! body bytes themselves are identical (raw ciphertext, in manifest order).

use std::collections::BTreeSet;

use base64::Engine as _;
use encrypted_spaces_backend::merk_storage::stored_value;
use encrypted_spaces_changelog_core::changelog::{ChangelogEntry, ChangelogError, HashedValues};
use encrypted_spaces_changelog_core::piece_text::{
    validate_piece_text_inserted_bodies, InsertedBufferManifest, PieceTextEditEnvelopeV1,
    PieceTextEditItemManifest, ValidatedPieceTextInsertedBody,
};
use encrypted_spaces_crypto::encryption::ciphertext_key_id;
use encrypted_spaces_key_manager::SimpleKeyId;

use super::ServerError;

/// Materialise the inserted PieceText buffer bodies carried in a
/// `ChangeRequest.values_sidecar` into hash-store values keyed by the manifest's
/// `ciphertext_value_hash`.
///
/// `inserted_bodies` is the raw `values_sidecar` (ordered, 1:1 with the
/// manifest's `Insert` ops). Each body is validated against its manifest entry
/// (count, size, length, key-id header, hash) and re-encoded into the on-merk
/// stored form so that `_piecetext_buffers.contents` resolves identically to any other
/// hash-backed column.
pub(super) fn inserted_body_values(
    entry: &ChangelogEntry,
    inserted_bodies: &[Vec<u8>],
) -> Result<HashedValues, ServerError> {
    let envelope = PieceTextEditEnvelopeV1::decode_from_entry(entry)
        .map_err(|e| ServerError::Generic(format!("Invalid PieceTextEdit change: {e}")))?;

    let validated = validate_piece_text_inserted_bodies(&envelope, inserted_bodies, |i, body| {
        // The wire body is the raw ciphertext (with key-id header) so the server
        // can validate it. `_piecetext_buffers.contents` is materialised exactly like any
        // other hash-backed column: the hash-store value is the column's on-merk
        // stored value (`value_to_bytes(String(base64(ciphertext)))`) and the
        // merk cell holds `hashstore_hash` of that. Storing the raw ciphertext
        // would make reads resolve to bytes that `bytes_to_value` cannot decode
        // into the encrypted string the SDK then decrypts.
        if ciphertext_key_id::<SimpleKeyId>(body).is_none() {
            return Err(ChangelogError::Generic(format!(
                "PieceTextEdit inserted body {i} has invalid ciphertext key-id header"
            )));
        }
        let stored = stored_value::value_to_bytes(&serde_json::Value::String(
            base64::engine::general_purpose::STANDARD.encode(body),
        ))
        .map_err(|e| {
            ChangelogError::Generic(format!(
                "PieceTextEdit inserted body {i}: failed to encode stored value: {e}"
            ))
        })?;
        Ok(ValidatedPieceTextInsertedBody {
            value_hash: encrypted_spaces_storage_encoding::hashstore_hash(&stored),
            value: stored,
        })
    })
    .map_err(|e| ServerError::Generic(e.to_string()))?;

    Ok(validated
        .into_iter()
        .map(|body| (body.value_hash, body.value))
        .collect())
}

/// Collect the `ciphertext_value_hash` of every inserted buffer named by the
/// signed manifest, after confirming each one's material is supplied in this
/// change's sidecar, genuine, and a well-formed stored PieceText ciphertext.
///
/// These are the only hash-store values a `PieceTextEdit` is allowed to
/// reference. For every referenced hash this requires that:
///
/// - its material is present in this change's `available` sidecar — a
///   `PieceTextEdit` *introduces* new buffer bodies, so the submitter must
///   supply them even if an identical hash already happens to be stored. This
///   is what lets the response/broadcast echo (`change.hashed_values`) carry the
///   complete inserted-buffer material for every new `_piecetext_buffers.contents`
///   reference; resolving silently from the store would apply an edit whose
///   broadcast omits the material peers need;
/// - the supplied material actually hashes to the manifest's
///   `ciphertext_value_hash` (the binding the signer committed to); and
/// - the supplied material is a valid `_piecetext_buffers.contents` stored value — a
///   base64 JSON string whose decoded raw ciphertext matches the manifest's
///   `ciphertext_len` and carries a valid key-id header
///   ([`validate_stored_ciphertext`]).
///
/// This makes the *direct* `SpaceState::handle_change` path (`LocalTransport`,
/// tests, other in-process callers) self-defending: it cannot commit a
/// `_piecetext_buffers.contents` hash with no supplied material, with material that does
/// not match the signed manifest, or with material that is not a usable stored
/// ciphertext — even though those callers bypass the network transport's
/// [`inserted_body_values`] materialisation. The hash binding alone is *not*
/// enough: the signer chooses `ciphertext_value_hash`, so they could sign
/// `hashstore_hash(garbage)` and supply `garbage`; the stored-form content check
/// rejects that. The returned set is also what `validate_hashed_values_references`
/// uses to reject any sidecar value the manifest does not name.
pub(super) fn referenced_buffer_hashes(
    entry: &ChangelogEntry,
    available: &HashedValues,
) -> Result<BTreeSet<[u8; 32]>, ServerError> {
    let envelope = PieceTextEditEnvelopeV1::decode_from_entry(entry)
        .map_err(|e| ServerError::Generic(format!("Invalid PieceTextEdit change: {e}")))?;

    let mut referenced = BTreeSet::new();
    for op in &envelope.edit.ops {
        let PieceTextEditItemManifest::Insert { inserted, .. } = op else {
            continue;
        };
        let hash = inserted.ciphertext_value_hash;
        let material = available.get(&hash).ok_or_else(|| {
            ServerError::Generic(format!(
                "PieceTextEdit references inserted buffer {} with no material supplied in the sidecar",
                hex::encode(hash)
            ))
        })?;
        if encrypted_spaces_storage_encoding::hashstore_hash(material) != hash {
            return Err(ServerError::Generic(format!(
                "PieceTextEdit inserted buffer material does not match manifest hash {}",
                hex::encode(hash)
            )));
        }
        validate_stored_ciphertext(material, inserted)?;
        referenced.insert(hash);
    }
    Ok(referenced)
}

/// Validate that a materialised `_piecetext_buffers.contents` value is a usable stored
/// PieceText ciphertext for the given manifest entry.
///
/// `material` is the on-merk stored form: `value_to_bytes(String(base64(ct)))`.
/// This decodes it back to the raw ciphertext and re-runs the same checks the
/// network transport applies to the raw body in [`inserted_body_values`] —
/// `ciphertext_len` and a valid key-id header — so the direct path cannot store
/// bytes that reads/decryption would later choke on.
fn validate_stored_ciphertext(
    material: &[u8],
    inserted: &InsertedBufferManifest,
) -> Result<(), ServerError> {
    let value = stored_value::bytes_to_value(material).map_err(|e| {
        ServerError::Generic(format!(
            "PieceTextEdit inserted buffer material is not a decodable stored value: {e}"
        ))
    })?;
    let encoded = value.as_str().ok_or_else(|| {
        ServerError::Generic(
            "PieceTextEdit inserted buffer material is not a stored string value".to_string(),
        )
    })?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| {
            ServerError::Generic(format!(
                "PieceTextEdit inserted buffer material is not valid base64: {e}"
            ))
        })?;
    if raw.len() != inserted.ciphertext_len as usize {
        return Err(ServerError::Generic(format!(
            "PieceTextEdit inserted buffer ciphertext is {} bytes, but manifest claims {}",
            raw.len(),
            inserted.ciphertext_len
        )));
    }
    if ciphertext_key_id::<SimpleKeyId>(&raw).is_none() {
        return Err(ServerError::Generic(
            "PieceTextEdit inserted buffer ciphertext has an invalid key-id header".to_string(),
        ));
    }
    Ok(())
}
