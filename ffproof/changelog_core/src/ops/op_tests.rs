//! Tests exercising advanced OpReader / OpVerifier patterns that go beyond
//! the current Insert/Update ops.
//!
//! These tests verify:
//! - **Adaptive reads**: read → inspect result → issue a second read whose key
//!   depends on the first result.
//! - **Multiple writes**: a single op producing more than one `WriteOp`.
//! - **Verifier rejection of unknown users**: the verifier's `VerifierReader`
//!   correctly surfaces an empty-results read as an error.
//! - **assert_all_consumed**: leftover proven reads are caught as errors.

#[cfg(test)]
mod tests {
    use crate::changelog::{ChangelogEntry, ChangelogError, KvData, LogMessage, OpType};
    use crate::ops::{
        OpContext, OpReader, OpVerifier, OpVerifyResult, ProverReader, VerifierReader,
    };
    use crate::{users_row_key, ProvenRead, ReadOp, WriteOp};
    use encrypted_spaces_storage_encoding::keys::{
        acl_rule_key, column_key, column_key_placeholder, schema_columns_key, schema_id_mode_key,
        schema_indexes_key, schema_list_columns_key, schema_next_id_key,
    };
    use encrypted_spaces_storage_encoding::stored_value::value_to_bytes;

    fn user_status_key(uid: u32) -> Vec<u8> {
        column_key("_users", uid as i64, "status")
    }

    /// No-ACL context for tests that don't need access control.
    fn no_acl() -> OpContext {
        OpContext {
            current_change_id: 0,
            action_name: None,
            ..Default::default()
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    fn make_entry(uid: u32, key: &[u8]) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Insert,
                tree_path: vec![],
                entries: vec![KvData {
                    key: key.to_vec(),
                    value: vec![0xAA; 32],
                }],
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    /// Dummy resolver for ProverReader tests — returns non-empty results for
    /// any key read, so op logic can proceed past existence checks.
    fn dummy_resolver(op: &ReadOp) -> Result<ProvenRead, ChangelogError> {
        Ok(ProvenRead {
            op: op.clone(),
            results: vec![(vec![0xDE, 0xAD], vec![0xBE, 0xEF])],
        })
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 1. Adaptive reads: second read key depends on first read's result
    // ═════════════════════════════════════════════════════════════════════════

    /// Test op: reads a "pointer" key, then reads whatever key the pointer
    /// value contains.  This exercises the adaptive-read pattern.
    const ADAPTIVE_POINTER_KEY: &[u8] = b"ptr";

    struct AdaptiveTestOp;

    impl OpVerifier for AdaptiveTestOp {
        fn extract_and_validate(
            entry: &ChangelogEntry,
            reader: &mut dyn OpReader,
            _ctx: &OpContext,
        ) -> Result<OpVerifyResult, ChangelogError> {
            let pointer_read = reader.read(ReadOp::Key(ADAPTIVE_POINTER_KEY.to_vec()))?;
            if pointer_read.results.is_empty() {
                return Err(ChangelogError::Generic(
                    "adaptive: pointer key not found".to_string(),
                ));
            }

            let target_key = pointer_read.results[0].1.clone();

            let target_read = reader.read(ReadOp::Key(target_key.clone()))?;
            if target_read.results.is_empty() {
                return Err(ChangelogError::Generic(format!(
                    "adaptive: target key {} not found",
                    hex::encode(&target_key)
                )));
            }

            let user_read = reader.read(ReadOp::Prefix(users_row_key(entry.uid)))?;
            if user_read.results.is_empty() {
                return Err(ChangelogError::Generic(format!(
                    "adaptive: user {} not found",
                    entry.uid
                )));
            }

            Ok(OpVerifyResult {
                write_steps: vec![WriteOp::Put {
                    key: target_key,
                    value: entry.message.entries[0].value.clone(),
                }],
            })
        }
    }

    #[test]
    fn test_adaptive_read_with_prover_reader() {
        // Resolver simulates a tree where:
        //   "ptr"  → value "real_key"
        //   "real_key" → value "real_data"
        //   users_row_key(1) → value "user_data"
        let resolver = |op: &ReadOp| -> Result<ProvenRead, ChangelogError> {
            match op {
                ReadOp::Key(k) if k == b"ptr" => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![(b"ptr".to_vec(), b"real_key".to_vec())],
                }),
                ReadOp::Key(k) if k == b"real_key" => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![(b"real_key".to_vec(), b"real_data".to_vec())],
                }),
                ReadOp::Prefix(k) if *k == users_row_key(1) => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![(users_row_key(1), b"user_data".to_vec())],
                }),
                _ => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![],
                }),
            }
        };

        let entry = make_entry(1, b"tbl");

        let mut reader = ProverReader::new(resolver);
        let result = AdaptiveTestOp::extract_and_validate(&entry, &mut reader, &no_acl());
        assert!(result.is_ok(), "adaptive read should succeed: {result:?}");

        // Verify the prover logged all three reads in order
        assert_eq!(reader.logged_reads.len(), 3);
        assert_eq!(reader.logged_reads[0], ReadOp::Key(b"ptr".to_vec()));
        assert_eq!(reader.logged_reads[1], ReadOp::Key(b"real_key".to_vec()));
        assert_eq!(reader.logged_reads[2], ReadOp::Prefix(users_row_key(1)));
    }

    #[test]
    fn test_adaptive_read_with_verifier_reader() {
        let entry = make_entry(1, b"tbl");

        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(b"ptr".to_vec()),
                results: vec![(b"ptr".to_vec(), b"real_key".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(b"real_key".to_vec()),
                results: vec![(b"real_key".to_vec(), b"real_data".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Prefix(users_row_key(1)),
                results: vec![(users_row_key(1), b"user_data".to_vec())],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let result = AdaptiveTestOp::extract_and_validate(&entry, &mut reader, &no_acl());
        assert!(result.is_ok(), "verifier should accept: {result:?}");
        assert!(reader.assert_all_consumed().is_ok());
    }

    #[test]
    fn test_adaptive_read_pointer_not_found() {
        let entry = make_entry(1, b"tbl");

        let reads = vec![ProvenRead {
            op: ReadOp::Key(b"ptr".to_vec()),
            results: vec![],
        }];
        let mut reader = VerifierReader::new(&reads);

        let err = AdaptiveTestOp::extract_and_validate(&entry, &mut reader, &no_acl());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("pointer key not found"), "unexpected: {msg}");
    }

    #[test]
    fn test_adaptive_read_prover_verifier_agreement() {
        let entry = make_entry(1, b"tbl");

        let resolver = |op: &ReadOp| -> Result<ProvenRead, ChangelogError> {
            match op {
                ReadOp::Key(k) if k == b"ptr" => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![(b"ptr".to_vec(), b"target".to_vec())],
                }),
                ReadOp::Key(k) if k == b"target" => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![(b"target".to_vec(), b"data".to_vec())],
                }),
                ReadOp::Prefix(k) if *k == users_row_key(1) => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![(users_row_key(1), b"u".to_vec())],
                }),
                _ => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![],
                }),
            }
        };

        // Step 1: Prover discovers reads
        let mut prover = ProverReader::new(resolver);
        let prover_result = AdaptiveTestOp::extract_and_validate(&entry, &mut prover, &no_acl());
        assert!(prover_result.is_ok());

        // Build verifier proven reads from what the prover discovered
        let proven_reads: Vec<ProvenRead> = prover
            .logged_reads
            .iter()
            .map(|read_op| {
                // Re-resolve against the same data
                match read_op {
                    ReadOp::Key(k) if k == b"ptr" => ProvenRead {
                        op: read_op.clone(),
                        results: vec![(b"ptr".to_vec(), b"target".to_vec())],
                    },
                    ReadOp::Key(k) if k == b"target" => ProvenRead {
                        op: read_op.clone(),
                        results: vec![(b"target".to_vec(), b"data".to_vec())],
                    },
                    ReadOp::Prefix(k) if *k == users_row_key(1) => ProvenRead {
                        op: read_op.clone(),
                        results: vec![(users_row_key(1), b"u".to_vec())],
                    },
                    _ => ProvenRead {
                        op: read_op.clone(),
                        results: vec![],
                    },
                }
            })
            .collect();

        let mut verifier = VerifierReader::new(&proven_reads);
        let verifier_result =
            AdaptiveTestOp::extract_and_validate(&entry, &mut verifier, &no_acl());
        assert!(verifier_result.is_ok());
        assert!(verifier.assert_all_consumed().is_ok());

        // Both should produce the same write steps
        let pw = prover_result.unwrap().write_steps;
        let vw = verifier_result.unwrap().write_steps;
        assert_eq!(pw, vw);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 2. Multiple writes: one op producing multiple WriteOp entries
    // ═════════════════════════════════════════════════════════════════════════

    const MULTI_WRITE_KEYS: &[&[u8]] = &[b"key_a", b"key_b", b"key_c"];

    struct MultiWriteTestOp;

    impl OpVerifier for MultiWriteTestOp {
        fn extract_and_validate(
            entry: &ChangelogEntry,
            reader: &mut dyn OpReader,
            _ctx: &OpContext,
        ) -> Result<OpVerifyResult, ChangelogError> {
            let user_read = reader.read(ReadOp::Prefix(users_row_key(entry.uid)))?;
            if user_read.results.is_empty() {
                return Err(ChangelogError::Generic(format!(
                    "multi-write: user {} not found",
                    entry.uid
                )));
            }

            let write_steps = MULTI_WRITE_KEYS
                .iter()
                .map(|k| WriteOp::Put {
                    key: k.to_vec(),
                    value: entry.message.entries[0].value.clone(),
                })
                .collect();

            Ok(OpVerifyResult { write_steps })
        }
    }

    #[test]
    fn test_multi_write_produces_multiple_steps() {
        let entry = make_entry(1, b"tbl");

        let mut reader = ProverReader::new(dummy_resolver);
        let result = MultiWriteTestOp::extract_and_validate(&entry, &mut reader, &no_acl());
        let result = result.expect("multi-write should succeed");
        assert_eq!(result.write_steps.len(), 3);

        for (i, op) in result.write_steps.iter().enumerate() {
            assert_eq!(crate::ops::write_op_key(op), MULTI_WRITE_KEYS[i]);
        }
    }

    #[test]
    fn test_multi_write_verifier_agreement() {
        let entry = make_entry(1, b"tbl");

        // Prover
        let mut prover = ProverReader::new(dummy_resolver);
        let prover_result = MultiWriteTestOp::extract_and_validate(&entry, &mut prover, &no_acl())
            .expect("prover multi-write");

        // Verifier
        let reads = vec![ProvenRead {
            op: ReadOp::Prefix(users_row_key(1)),
            results: vec![(users_row_key(1), b"u".to_vec())],
        }];
        let mut verifier = VerifierReader::new(&reads);
        let verifier_result =
            MultiWriteTestOp::extract_and_validate(&entry, &mut verifier, &no_acl())
                .expect("verifier multi-write");
        assert!(verifier.assert_all_consumed().is_ok());

        assert_eq!(prover_result.write_steps, verifier_result.write_steps);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 3. Read-then-conditional-write: read determines *which* keys to write
    // ═════════════════════════════════════════════════════════════════════════

    /// An op that reads a "members" prefix, then writes an update to each
    /// member found.  This exercises prefix reads + variable-length writes.
    const FANOUT_MEMBERS_PREFIX: &[u8] = b"members/";

    struct FanOutTestOp;

    impl OpVerifier for FanOutTestOp {
        fn extract_and_validate(
            entry: &ChangelogEntry,
            reader: &mut dyn OpReader,
            _ctx: &OpContext,
        ) -> Result<OpVerifyResult, ChangelogError> {
            let user_read = reader.read(ReadOp::Prefix(users_row_key(entry.uid)))?;
            if user_read.results.is_empty() {
                return Err(ChangelogError::Generic(format!(
                    "fanout: user {} not found",
                    entry.uid
                )));
            }

            let members = reader.read(ReadOp::Prefix(FANOUT_MEMBERS_PREFIX.to_vec()))?;

            if members.results.is_empty() {
                return Err(ChangelogError::Generic(format!(
                    "fanout: no members found under prefix {}",
                    hex::encode(FANOUT_MEMBERS_PREFIX)
                )));
            }

            let write_steps = members
                .results
                .iter()
                .map(|(k, _v)| WriteOp::Put {
                    key: k.clone(),
                    value: entry.message.entries[0].value.clone(),
                })
                .collect();

            Ok(OpVerifyResult { write_steps })
        }
    }

    #[test]
    fn test_fanout_prefix_read_drives_writes() {
        let entry = make_entry(1, b"tbl");

        let resolver = |op: &ReadOp| -> Result<ProvenRead, ChangelogError> {
            match op {
                ReadOp::Prefix(p) if p == b"members/" => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![
                        (b"members/alice".to_vec(), b"a".to_vec()),
                        (b"members/bob".to_vec(), b"b".to_vec()),
                        (b"members/carol".to_vec(), b"c".to_vec()),
                    ],
                }),
                _ => Ok(ProvenRead {
                    op: op.clone(),
                    results: vec![(vec![], vec![])],
                }),
            }
        };

        let mut prover = ProverReader::new(resolver);
        let result = FanOutTestOp::extract_and_validate(&entry, &mut prover, &no_acl())
            .expect("fanout should succeed");

        // Should produce 3 writes (one per member)
        assert_eq!(result.write_steps.len(), 3);
        assert_eq!(prover.logged_reads.len(), 2); // user read + prefix read

        // Verify write keys match the discovered members
        let write_keys: Vec<&[u8]> = result
            .write_steps
            .iter()
            .map(crate::ops::write_op_key)
            .collect();
        assert_eq!(
            write_keys,
            vec![
                b"members/alice".as_slice(),
                b"members/bob".as_slice(),
                b"members/carol".as_slice(),
            ]
        );
    }

    #[test]
    fn test_fanout_verifier_replays_correctly() {
        let entry = make_entry(1, b"tbl");

        let reads = vec![
            ProvenRead {
                op: ReadOp::Prefix(users_row_key(1)),
                results: vec![(users_row_key(1), b"u".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Prefix(b"members/".to_vec()),
                results: vec![
                    (b"members/alice".to_vec(), b"a".to_vec()),
                    (b"members/bob".to_vec(), b"b".to_vec()),
                ],
            },
        ];
        let mut verifier = VerifierReader::new(&reads);

        let result = FanOutTestOp::extract_and_validate(&entry, &mut verifier, &no_acl())
            .expect("verifier fanout");
        assert!(verifier.assert_all_consumed().is_ok());
        assert_eq!(result.write_steps.len(), 2);
    }

    #[test]
    fn test_fanout_empty_prefix_fails() {
        let entry = make_entry(1, b"tbl");

        let reads = vec![
            ProvenRead {
                op: ReadOp::Prefix(users_row_key(1)),
                results: vec![(users_row_key(1), b"u".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Prefix(b"members/".to_vec()),
                results: vec![],
            },
        ];
        let mut verifier = VerifierReader::new(&reads);

        let err = FanOutTestOp::extract_and_validate(&entry, &mut verifier, &no_acl());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("no members found"), "unexpected: {msg}");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 4. Verifier rejects unknown user (verifier-side UID check)
    // ═════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verifier_rejects_unknown_user_insert() {
        use crate::ops::InsertOp;

        let uid = 42;
        let entry_col = column_key_placeholder("t", "name");
        let _proof_col = column_key("t", 5, "name");
        let entry = make_entry(uid, &entry_col);

        // Verifier has a proven read for the user status key, but results are empty
        // (user not found in _users table).  The verifier reads id_mode and
        // next_id first; seed both before reaching the user check.
        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(schema_id_mode_key("t")),
                results: vec![(schema_id_mode_key("t"), vec![0u8])],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key("t")),
                results: vec![(schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk),
                results: vec![], // <-- no user row
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let err = InsertOp::extract_and_validate(&entry, &mut reader, &no_acl());
        assert!(err.is_err(), "verifier should reject unknown user");
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("not found in users table"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_verifier_rejects_unknown_user_update() {
        use crate::ops::UpdateOp;

        let uid = 77;
        let col = column_key("t", 5, "name");
        let entry = make_entry(uid, &col);

        let sk = user_status_key(uid);
        let reads = vec![ProvenRead {
            op: ReadOp::Key(sk),
            results: vec![], // <-- no user row
        }];
        let mut reader = VerifierReader::new(&reads);

        let err = UpdateOp::extract_and_validate(&entry, &mut reader, &no_acl());
        assert!(err.is_err(), "verifier should reject unknown user");
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("not found in users table"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_verifier_rejects_unknown_user_adaptive() {
        let uid = 5;
        let entry = make_entry(uid, b"tbl");

        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(b"ptr".to_vec()),
                results: vec![(b"ptr".to_vec(), b"target".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(b"target".to_vec()),
                results: vec![(b"target".to_vec(), b"data".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Prefix(users_row_key(uid)),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let err = AdaptiveTestOp::extract_and_validate(&entry, &mut reader, &no_acl());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("user 5 not found"), "unexpected error: {msg}");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 5. assert_all_consumed catches extra proven reads
    // ═════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_extra_proven_reads_rejected() {
        use crate::ops::InsertOp;

        let uid = 1;
        let entry_col = column_key_placeholder("t", "name");
        let _proof_col = column_key("t", 5, "name");
        let entry = make_entry(uid, &entry_col);
        // Schema with only "name" so insert is column-complete
        let schema_one_col = b"name".to_vec();

        // Provide reads in InsertOp order plus one extra at the end.
        let sk = user_status_key(uid);
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(schema_id_mode_key("t")),
                results: vec![(schema_id_mode_key("t"), vec![0u8])],
            },
            ProvenRead {
                op: ReadOp::Key(schema_next_id_key("t")),
                results: vec![(schema_next_id_key("t"), 5i64.to_be_bytes().to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(sk.clone()),
                results: vec![(sk, value_to_bytes(&serde_json::json!(1)).unwrap())],
            },
            ProvenRead {
                op: ReadOp::Key(schema_columns_key("t")),
                results: vec![(schema_columns_key("t"), schema_one_col)],
            },
            ProvenRead {
                op: ReadOp::Key(schema_list_columns_key("t")),
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Key(acl_rule_key("t", "write")),
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Key(schema_indexes_key("t")),
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Key(b"extra_key".to_vec()),
                results: vec![(b"extra_key".to_vec(), b"extra".to_vec())],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        // extract_and_validate succeeds (it consumes id_mode + user + columns + list_columns + indexes + next_id)
        let result = InsertOp::extract_and_validate(&entry, &mut reader, &no_acl());
        assert!(result.is_ok());

        // But assert_all_consumed should fail
        let err = reader.assert_all_consumed();
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("1 proven read(s) remaining unconsumed"),
            "unexpected: {msg}"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 6. Mismatched read order between prover and verifier
    // ═════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verifier_rejects_wrong_read_order() {
        let entry = make_entry(1, b"tbl");

        let reads = vec![
            ProvenRead {
                op: ReadOp::Prefix(users_row_key(1)),
                results: vec![(users_row_key(1), b"u".to_vec())],
            },
            ProvenRead {
                op: ReadOp::Key(b"ptr".to_vec()),
                results: vec![(b"ptr".to_vec(), b"target".to_vec())],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        let err = AdaptiveTestOp::extract_and_validate(&entry, &mut reader, &no_acl());
        assert!(err.is_err(), "wrong read order should be rejected");
    }
}
