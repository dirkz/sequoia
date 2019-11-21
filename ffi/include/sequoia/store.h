#ifndef SEQUOIA_STORE_H
#define SEQUOIA_STORE_H

#include <sequoia/core.h>

/*/
/// Keys used for communications.
/*/
const char *SQ_REALM_CONTACTS = "org.sequoia-pgp.contacts";

/*/
/// Keys used for signing software updates.
/*/
const char *SQ_REALM_SOFTWARE_UPDATES = "org.sequoia-pgp.software-updates";

/*/
/// A public key mapping.
/*/
typedef struct sq_mapping *sq_mapping_t;

/*/
/// Frees a sq_mapping_t.
/*/
void sq_mapping_free (sq_mapping_t mapping);

/*/
/// Represents an entry in a Mapping.
///
/// Mappings map labels to TPKs.  A `Binding` represents a pair in this
/// relation.  We make this explicit because we associate metadata
/// with these pairs.
/*/
typedef struct sq_binding *sq_binding_t;

/*/
/// Frees a sq_binding_t.
/*/
void sq_binding_free (sq_binding_t binding);

/*/
/// Represents a key in a mapping.
///
/// A `Key` is a handle to a stored TPK.  We make this explicit
/// because we associate metadata with TPKs.
/*/
typedef struct sq_key *sq_key_t;

/*/
/// Frees a sq_key_t.
/*/
void sq_key_free (sq_key_t key);

/*/
/// Represents a log entry.
/*/
struct sq_log {
  /*/
  /// Records the time of the entry.
  /*/
  uint64_t timestamp;

  /*/
  /// Relates the entry to a mapping.
  ///
  /// May be `NULL`.
  /*/
  sq_mapping_t mapping;

  /*/
  /// Relates the entry to a binding.
  ///
  /// May be `NULL`.
  /*/
  sq_binding_t binding;

  /*/
  /// Relates the entry to a key.
  ///
  /// May be `NULL`.
  /*/
  sq_key_t key;

  /*/
  /// Relates the entry to some object.
  ///
  /// This is a human-readable description of what this log entry is
  /// mainly concerned with.
  /*/
  char *slug;

  /*/
  /// Holds the log message.
  /*/
  char *status;

  /*/
  /// Holds the error message, if any.
  ///
  /// May be `NULL`.
  /*/
  char *error;
};
typedef struct sq_log *sq_log_t;

/*/
/// Frees a sq_log_t.
/*/
void sq_log_free (sq_log_t log);

/*/
/// Counter and timestamps.
/*/
struct sq_stamps {
  /*/
  /// Counts how many times this has been used.
  /*/
  uint64_t count;

  /*/
  /// Records the time when this has been used first.
  /*/
  time_t first;

  /*/
  /// Records the time when this has been used last.
  /*/
  time_t last;
};

/*/
/// Represents binding or key stats.
/*/
struct sq_stats {
  /*/
  /// Records the time this item was created.
  /*/
  time_t created;

  /*/
  /// Records the time this item was last updated.
  /*/
  time_t updated;

  /*/
  /// Records counters and timestamps of encryptions.
  /*/
  struct sq_stamps encryption;

  /*/
  /// Records counters and timestamps of verifications.
  /*/
  struct sq_stamps verification;
};
typedef struct sq_stats *sq_stats_t;

/*/
/// Frees a sq_stats_t.
/*/
void sq_stats_free (sq_stats_t stats);

/*/
/// Iterates over mappings.
/*/
typedef struct sq_mapping_iter *sq_mapping_iter_t;

/*/
/// Returns the next mapping.
///
/// Returns `NULL` on exhaustion.  If `realmp` is not `NULL`, the
/// mapping's realm is stored there.  If `namep` is not `NULL`, the
/// mapping's name is stored there.  If `policyp` is not `NULL`, the
/// mapping's network policy is stored there.
/*/
sq_mapping_t sq_mapping_iter_next (sq_mapping_iter_t iter,
			       char **realmp,
			       char **namep,
			       uint8_t *policyp);


/*/
/// Frees a sq_mapping_iter_t.
/*/
void sq_mapping_iter_free (sq_mapping_iter_t iter);

/*/
/// Iterates over bindings in a mapping.
/*/
typedef struct sq_binding_iter *sq_binding_iter_t;

/*/
/// Returns the next binding.
///
/// Returns `NULL` on exhaustion.  If `labelp` is not `NULL`, the
/// bindings label is stored there.  If `fpp` is not `NULL`, the
/// bindings fingerprint is stored there.
/*/
sq_binding_t sq_binding_iter_next (sq_binding_iter_t iter,
				   char **labelp,
				   pgp_fingerprint_t *fpp);

/*/
/// Frees a sq_binding_iter_t.
/*/
void sq_binding_iter_free (sq_binding_iter_t iter);

/*/
/// Iterates over keys in the common key pool.
/*/
typedef struct sq_key_iter *sq_key_iter_t;

/*/
/// Returns the next key.
///
/// Returns `NULL` on exhaustion.  If `fpp` is not `NULL`, the keys
/// fingerprint is stored there.
/*/
sq_key_t sq_key_iter_next (sq_key_iter_t iter,
			   pgp_fingerprint_t *fpp);

/*/
/// Frees a sq_key_iter_t.
/*/
void sq_key_iter_free (sq_key_iter_t iter);

/*/
/// Iterates over logs.
/*/
typedef struct sq_log_iter *sq_log_iter_t;

/*/
/// Returns the next log entry.
///
/// Returns `NULL` on exhaustion.
/*/
sq_log_t sq_log_iter_next (sq_log_iter_t iter);

/*/
/// Frees a sq_log_iter_t.
/*/
void sq_log_iter_free (sq_log_iter_t iter);

/*/
/// Lists all log entries.
/*/
sq_log_iter_t sq_store_server_log (sq_context_t ctx);

/*/
/// Lists all keys in the common key pool.
/*/
sq_key_iter_t sq_store_list_keys (sq_context_t ctx);

/*/
/// Opens a mapping.
///
/// Opens a mapping with the given name in the given realm.  If the
/// mapping does not exist, it is created.  Mappings are handles for
/// objects maintained by a background service.  The background
/// service associates state with this name.
///
/// The mapping updates TPKs in compliance with the network policy
/// of the context that created the mapping in the first place.
/// Opening the mapping with a different network policy is
/// forbidden.
/*/
sq_mapping_t sq_mapping_open (sq_context_t ctx, const char *realm, const char *name);

/*/
/// Adds a key identified by fingerprint to the mapping.
/*/
sq_binding_t sq_mapping_add (sq_context_t ctx, sq_mapping_t mapping,
			   const char *label, pgp_fingerprint_t fp);

/*/
/// Imports a key into the mapping.
/*/
pgp_tpk_t sq_mapping_import (sq_context_t ctx, sq_mapping_t mapping,
			  const char *label, pgp_tpk_t tpk);

/*/
/// Returns the binding for the given label.
/*/
sq_binding_t sq_mapping_lookup (sq_context_t ctx, sq_mapping_t mapping,
			      const char *label);

/*/
/// Looks up a key in the common key pool by KeyID.
/*/
sq_key_t sq_store_lookup_by_keyid (sq_context_t ctx, pgp_keyid_t keyid);

/*/
/// Looks up a key in the common key pool by (Sub)KeyID.
/*/
sq_key_t sq_store_lookup_by_subkeyid (sq_context_t ctx, pgp_keyid_t keyid);

/*/
/// Deletes this mapping.
///
/// Consumes `mapping`.  Returns != 0 on error.
/*/
pgp_status_t sq_mapping_delete (sq_mapping_t mapping);

/*/
/// Lists all bindings.
/*/
sq_binding_iter_t sq_mapping_iter (sq_context_t ctx, sq_mapping_t mapping);

/*/
/// Lists all log entries related to this mapping.
/*/
sq_log_iter_t sq_mapping_log (sq_context_t ctx, sq_mapping_t mapping);

/*/
/// Returns the `sq_stats_t` of this binding.
/*/
sq_stats_t sq_binding_stats (sq_context_t ctx, sq_binding_t binding);

/*/
/// Returns the `sq_key_t` of this binding.
/*/
sq_key_t sq_binding_key (sq_context_t ctx, sq_binding_t binding);

/*/
/// Returns the `pgp_tpk_t` of this binding.
/*/
pgp_tpk_t sq_binding_tpk (sq_context_t ctx, sq_binding_t binding);

/*/
/// Updates this binding with the given TPK.
///
/// If the new key `tpk` matches the current key, i.e. they have
/// the same fingerprint, both keys are merged and normalized.
/// The returned key contains all packets known to Sequoia, and
/// should be used instead of `tpk`.
///
/// If the new key does not match the current key, but carries a
/// valid signature from the current key, it replaces the current
/// key.  This provides a natural way for key rotations.
///
/// If the new key does not match the current key, and it does not
/// carry a valid signature from the current key, an
/// `Error::Conflict` is returned, and you have to resolve the
/// conflict, either by ignoring the new key, or by using
/// `sq_binding_rotate` to force a rotation.
/*/
pgp_tpk_t sq_binding_import (sq_context_t ctx, sq_binding_t binding,
			    pgp_tpk_t tpk);

/*/
/// Forces a keyrotation to the given TPK.
///
/// The current key is replaced with the new key `tpk`, even if
/// they do not have the same fingerprint.  If a key with the same
/// fingerprint as `tpk` is already in the store, is merged with
/// `tpk` and normalized.  The returned key contains all packets
/// known to Sequoia, and should be used instead of `tpk`.
///
/// Use this function to resolve conflicts returned from
/// `sq_binding_import`.  Make sure that you have authenticated
/// `tpk` properly.  How to do that depends on your thread model.
/// You could simply ask Alice to call her communication partner
/// Bob and confirm that he rotated his keys.
/*/
pgp_tpk_t sq_binding_rotate (sq_context_t ctx, sq_binding_t binding,
			    pgp_tpk_t tpk);

/*/
/// Deletes this binding.
///
/// Consumes `binding`.  Returns != 0 on error.
/*/
pgp_status_t sq_binding_delete (sq_context_t ctx, sq_binding_t binding);

/*/
/// Lists all log entries related to this binding.
/*/
sq_log_iter_t sq_binding_log (sq_context_t ctx, sq_binding_t binding);

/*/
/// Returns the `sq_stats_t` of this key.
/*/
sq_stats_t sq_key_stats (sq_context_t ctx, sq_key_t key);

/*/
/// Returns the `pgp_tpk_t` of this key.
/*/
pgp_tpk_t sq_key_tpk (sq_context_t ctx, sq_key_t key);

/*/
/// Updates this stored key with the given TPK.
///
/// If the new key `tpk` matches the current key, i.e. they have
/// the same fingerprint, both keys are merged and normalized.
/// The returned key contains all packets known to Sequoia, and
/// should be used instead of `tpk`.
///
/// If the new key does not match the current key,
/// `Error::Conflict` is returned.
/*/
pgp_tpk_t sq_key_import (sq_context_t ctx, sq_key_t key,
			pgp_tpk_t tpk);

/*/
/// Lists all log entries related to this key.
/*/
sq_log_iter_t sq_key_log (sq_context_t ctx, sq_key_t key);

#endif
