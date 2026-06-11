//! Shared PieceText coordinate resolution over either an in-memory planner
//! snapshot or authenticated tree reads.

use crate::piece_text::BufferCoord;
use crate::piece_text_planner::{ClampDirection, PieceRow, ResolvePurpose};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolveEndpoint {
    Head,
    Tail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolveCoreResult {
    DocumentStart {
        head_id: i64,
    },
    InRow {
        row: PieceRow,
        offset: u32,
    },
    ClampedToRow {
        row: PieceRow,
        start_row_id: i64,
        direction: ClampDirection,
        hops: u32,
    },
    ClampedBeforeHead {
        head_id: i64,
        start_row_id: i64,
        direction: ClampDirection,
        hops: u32,
    },
    ClampedAfterTail {
        tail_id: i64,
        start_row_id: i64,
        direction: ClampDirection,
        hops: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolveCoreOutput {
    pub result: ResolveCoreResult,
    pub candidate_count: usize,
}

pub(crate) trait ResolveSource {
    type Error;

    fn list_number(&self) -> i64;
    fn candidate_row_ids(&mut self, buffer_id: i64) -> Result<Vec<i64>, Self::Error>;
    fn read_row(&mut self, row_id: i64) -> Result<PieceRow, Self::Error>;
    fn read_endpoint(&mut self, endpoint: ResolveEndpoint) -> Result<i64, Self::Error>;

    fn invalid_coordinate(&self, message: String) -> Self::Error;
    fn unknown_coordinate(
        &self,
        coord: BufferCoord,
        purpose: ResolvePurpose,
        reason: String,
    ) -> Self::Error;
    fn invariant(&self, message: String) -> Self::Error;
}

pub(crate) fn resolve_coord_core<S: ResolveSource>(
    source: &mut S,
    coord: BufferCoord,
    purpose: ResolvePurpose,
) -> Result<ResolveCoreOutput, S::Error> {
    if coord == BufferCoord::DOCUMENT_START {
        return Ok(ResolveCoreOutput {
            result: ResolveCoreResult::DocumentStart {
                head_id: source.read_endpoint(ResolveEndpoint::Head)?,
            },
            candidate_count: 0,
        });
    }
    if coord.buffer_id <= 0 {
        return Err(source.invalid_coordinate(format!(
            "non-DOCUMENT_START coordinate must reference buffer_id > 0, got {}",
            coord.buffer_id
        )));
    }

    let row_ids = source.candidate_row_ids(coord.buffer_id)?;
    let candidate_count = row_ids.len();
    let mut candidates = Vec::with_capacity(candidate_count);
    for row_id in row_ids {
        let row = source.read_row(row_id)?;
        if row.list_number != source.list_number() {
            return Err(source.invariant(format!(
                "piece-text coord buffer_id={} resolves to _piecetext_pieces row {} in list {} but caller requested list {}",
                coord.buffer_id,
                row.id,
                row.list_number,
                source.list_number()
            )));
        }
        if row.coord.len_bytes == 0 {
            return Err(source.invariant(format!(
                "_piecetext_pieces row {} has zero len_bytes",
                row.id
            )));
        }
        row.coord
            .start_byte
            .checked_add(row.coord.len_bytes)
            .ok_or_else(|| {
                source.invariant(format!("_piecetext_pieces row {} range overflows", row.id))
            })?;
        candidates.push(row);
    }
    verify_candidate_ranges_disjoint(source, coord.buffer_id, &candidates)?;

    let mut interior_match: Option<PieceRow> = None;
    let mut predecessor_match: Option<PieceRow> = None;
    let mut successor_match: Option<PieceRow> = None;

    for row in candidates {
        let end = row
            .coord
            .start_byte
            .checked_add(row.coord.len_bytes)
            .ok_or_else(|| {
                source.invariant(format!("_piecetext_pieces row {} range overflows", row.id))
            })?;
        if row.coord.start_byte < coord.byte_pos && coord.byte_pos < end {
            if interior_match.is_some() {
                return Err(source.invariant(format!(
                    "piece-text coord contradiction: multiple _piecetext_pieces rows strictly contain buffer coord {:?}",
                    coord
                )));
            }
            interior_match = Some(row);
        } else if end == coord.byte_pos {
            if predecessor_match.is_some() {
                return Err(source.invariant(format!(
                    "piece-text coord contradiction: multiple _piecetext_pieces rows end at buffer coord {:?}",
                    coord
                )));
            }
            predecessor_match = Some(row);
        } else if row.coord.start_byte == coord.byte_pos {
            if successor_match.is_some() {
                return Err(source.invariant(format!(
                    "piece-text coord contradiction: multiple _piecetext_pieces rows start at buffer coord {:?}",
                    coord
                )));
            }
            successor_match = Some(row);
        }
    }

    let matched = interior_match
        .or(predecessor_match)
        .or(successor_match)
        .ok_or_else(|| {
            source.unknown_coordinate(
                coord,
                purpose,
                "no live or tombstoned piece covers this byte coordinate".to_string(),
            )
        })?;
    let offset = coord
        .byte_pos
        .checked_sub(matched.coord.start_byte)
        .ok_or_else(|| {
            source.invariant(format!(
                "matched _piecetext_pieces row {} starts after coord {:?}",
                matched.id, coord
            ))
        })?;

    let result = if matched.coord.tombstone {
        clamp_tombstones(source, matched, purpose)?
    } else {
        ResolveCoreResult::InRow {
            row: matched,
            offset,
        }
    };

    Ok(ResolveCoreOutput {
        result,
        candidate_count,
    })
}

fn verify_candidate_ranges_disjoint<S: ResolveSource>(
    source: &S,
    buffer_id: i64,
    rows: &[PieceRow],
) -> Result<(), S::Error> {
    let mut spans = Vec::with_capacity(rows.len());
    for row in rows {
        let end = row
            .coord
            .start_byte
            .checked_add(row.coord.len_bytes)
            .ok_or_else(|| {
                source.invariant(format!("_piecetext_pieces row {} range overflows", row.id))
            })?;
        spans.push((row.coord.start_byte, end, row.id));
    }
    spans.sort_unstable_by_key(|(start, end, id)| (*start, *end, *id));

    for pair in spans.windows(2) {
        let (left_start, left_end, left_id) = pair[0];
        let (right_start, right_end, right_id) = pair[1];
        if left_end > right_start {
            return Err(source.invariant(format!(
                "piece-text coord contradiction: _piecetext_pieces rows {left_id} [{left_start}, {left_end}) and {right_id} [{right_start}, {right_end}) overlap for buffer_id {buffer_id}"
            )));
        }
    }
    Ok(())
}

fn clamp_tombstones<S: ResolveSource>(
    source: &mut S,
    start_row: PieceRow,
    purpose: ResolvePurpose,
) -> Result<ResolveCoreResult, S::Error> {
    let direction = purpose.clamp_direction();
    let start_row_id = start_row.id;
    let mut current = start_row;
    let mut hops: u32 = 0;

    loop {
        if !current.coord.tombstone {
            return Ok(ResolveCoreResult::ClampedToRow {
                row: current,
                start_row_id,
                direction,
                hops,
            });
        }
        hops = hops.checked_add(1).ok_or_else(|| {
            source.invariant("tombstone clamp hop counter overflowed".to_string())
        })?;

        let neighbour_id = match direction {
            ClampDirection::Backward => current.prev_id,
            ClampDirection::Forward => current.next_id,
        };
        if neighbour_id == 0 {
            // A 0 prev/next pointer *claims* this row is the chain endpoint. The
            // indexed path never authenticates the whole linked list, so it must
            // not trust that claim from a `buffer_id`-indexed row: bind it to the
            // head/tail key. (The in-memory planner already proves
            // `prev_id == 0` <=> head via full-snapshot validation, so this is a
            // redundant no-op there and the load-bearing local check here.)
            return match direction {
                ClampDirection::Backward => {
                    let head_id = source.read_endpoint(ResolveEndpoint::Head)?;
                    if current.id != head_id {
                        return Err(source.invariant(format!(
                            "tombstone clamp contradiction: row {} has prev_id 0 but is not the document head {}",
                            current.id, head_id
                        )));
                    }
                    Ok(ResolveCoreResult::ClampedBeforeHead {
                        head_id,
                        start_row_id,
                        direction,
                        hops,
                    })
                }
                ClampDirection::Forward => {
                    let tail_id = source.read_endpoint(ResolveEndpoint::Tail)?;
                    if current.id != tail_id {
                        return Err(source.invariant(format!(
                            "tombstone clamp contradiction: row {} has next_id 0 but is not the document tail {}",
                            current.id, tail_id
                        )));
                    }
                    Ok(ResolveCoreResult::ClampedAfterTail {
                        tail_id,
                        start_row_id,
                        direction,
                        hops,
                    })
                }
            };
        }

        let neighbour = source.read_row(neighbour_id)?;
        if neighbour.list_number != source.list_number() {
            return Err(source.invariant(format!(
                "tombstone clamp contradiction: row {} is in list {} but clamp walk for list {} reached it",
                neighbour.id,
                neighbour.list_number,
                source.list_number()
            )));
        }

        match direction {
            ClampDirection::Backward => {
                if neighbour.next_id != current.id {
                    return Err(source.invariant(format!(
                        "tombstone clamp contradiction: row {}.next_id={} but expected {}",
                        neighbour.id, neighbour.next_id, current.id
                    )));
                }
            }
            ClampDirection::Forward => {
                if neighbour.prev_id != current.id {
                    return Err(source.invariant(format!(
                        "tombstone clamp contradiction: row {}.prev_id={} but expected {}",
                        neighbour.id, neighbour.prev_id, current.id
                    )));
                }
            }
        }
        current = neighbour;
    }
}
