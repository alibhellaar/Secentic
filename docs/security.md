# Security model

Secentic is a security product, so its own security is part of the deliverable. This page
explains what it protects, whom it trusts, which attacks it defends against (each tied to the
test that proves it), and what is not yet covered.

## Principles

1. **Constrain actions, not reasoning.** Assume an agent's reasoning can be manipulated; make
   sure its actions are still bounded by identity, delegated authority, policy and enforcement.
2. **Fail closed.** Missing configuration, unknown keys or unavailable components lead to
   refusal, never to a permissive fallback.
3. **Deterministic enforcement.** Security decisions come from rules that can be explained and
   audited. ML or LLM output may inform, never decide.
4. **Separate identities.** Humans (administrators) and agents authenticate differently, and
   neither credential works for the other's endpoints.
5. **Invariants live in the database.** Rules like "one record per agent" and "one active key"
   are database constraints, so concurrent requests cannot break them.

## Assets

| Asset | Why it matters |
|---|---|
| Agent private keys | Whoever holds one can act as that agent. They never leave the agent. |
| The admin token | Full control over the inventory and every agent's keys. |
| The inventory | Reveals which agents exist, who owns them and their state. |
| Delegations | Define everything each agent is allowed to do, and on whose authority. |
| The tool registry and policy | Decide which tools agents can reach and which actions need a person. |
| The decision log | The record of what every agent asked to do and what the gateway answered. |
| Agent public keys and their bindings | Decide which key speaks for which agent. |

## Trust boundaries

| Party | Trusted to | Not trusted to |
|---|---|---|
| Administrator (holds the admin token) | Approve agents, confirm owners, bind and revoke keys, record delegations on behalf of the humans named as delegators | — |
| Agent with an active, approved key | Act as itself, within the authority delegated to it, through the tools assigned to it | Claim an owner, register keys for others, read the inventory, grant itself authority or tools, change the policy, read the decision log |
| Tools and MCP servers | Do what their reviewed definition says | Be used before review, change their definition and stay trusted |
| Unauthenticated caller | Register a *new* agent (which waits for review) | Anything about existing agents |
| The network | — | Integrity or freshness of agent requests (signatures and nonces cover these) |

## Threats and defences

| # | Threat | Defence | Proven by |
|---|---|---|---|
| T1 | A shadow agent activates itself by claiming an owner | Self-registration always waits for an administrator | `test_register_new_agent` |
| T2 | An impostor re-registers as an existing agent | Only the agent's enrolled key can re-register it | `test_another_key_cannot_take_over_an_enrolled_agent` |
| T3 | An attacker attaches their key to someone else's pending agent, then acts as it after approval | Keys are self-enrolled only when a registration creates the agent | `test_cannot_attach_a_key_to_someone_elses_pending_agent` |
| T4 | An attacker self-enrols a key on an approved agent that has none | Existing agents get keys only from an administrator | `test_cannot_self_enrol_a_key_on_an_approved_agent` |
| T5 | Enrolling a public key the attacker does not hold | Registration must be signed by the key being enrolled | `test_cannot_enrol_a_public_key_you_do_not_hold` |
| T6 | A weak (small-order) key whose signatures anyone can forge | Such keys are refused everywhere | `test_small_order_keys_refused`, `test_forged_signature_for_identity_point_key_refused` |
| T7 | Tampering with a signed request | Signature covers method, path, query, body, time and nonce | `test_tampered_query_rejected`, `test_tampered_body_rejected` |
| T8 | Replaying a captured request | Timestamp window plus single-use nonces | `test_replayed_request_rejected`, `test_stale_timestamp_rejected` |
| T9 | Replaying at the very edge of the timestamp window | Nonces are kept twice as long as the window | `test_replay_at_the_edge_of_the_window_rejected` |
| T10 | Using a stolen key | Administrator revocation, effective immediately | `test_revoked_key_stops_working_and_agent_can_be_recovered` |
| T11 | Using an old key after rotation | Rotated keys stop working at once | `test_rotation_switches_keys` |
| T12 | Rotating someone's identity to a key the attacker cannot prove | Rotation needs a proof signed by the new key | `test_rotation_requires_proof_of_the_new_key` |
| T13 | Re-binding a retired or compromised key | A public key can be bound only once | `test_rotation_back_to_an_old_key_rejected` |
| T14 | Learning an agent's owner or status, or faking its liveness, via unsigned registration | One identical 409 for every rejected repeat; `last_seen` moves only on verified requests | `test_unsigned_reregistration_reveals_nothing_and_does_not_refresh_last_seen`, `test_last_seen_moves_only_on_verified_requests` |
| T15 | Squatting another team's agent name | Administrator rejects the pending registration, freeing the name | `test_reject_pending_registration_frees_the_name` |
| T16 | An agent using administrator endpoints | Separate credentials | `test_agent_keys_do_not_grant_admin_access` |
| T17 | Admin endpoints exposed by a missing or placeholder token | Fail closed below 16 characters | `test_admin_endpoints_fail_closed_without_configured_token`, `test_admin_endpoints_refuse_a_guessable_token` |
| T18 | A disabled or unapproved agent acting | Only `active` agents authenticate | `test_disabled_agent_cannot_authenticate`, `test_pending_agent_cannot_authenticate` |
| T19 | Races producing duplicate agents or two active keys | Database constraints; conflicts become 409 | `test_unique_constraint_race_becomes_409` |
| T20 | An agent using authority nobody gave it (inherited or assumed permissions) | Deny unless a delegation in force lists the action and resource | `test_delegation_grants_exactly_what_it_lists`, `test_agent_without_delegations_has_no_authority` |
| T21 | Blanket grants (`*`, `crm:acc*`) handing an agent far more than the task needs | Wildcards only at the end after `/` or `:`; no action wildcards | `test_blanket_or_malformed_resource_grants_refused`, `test_wildcard_or_malformed_actions_refused` |
| T22 | Escaping a prefix grant with `..` or encoded characters (`crm:accounts/../admin`, `crm:../admin`) | Restricted resource alphabet, no `.`/`..` segments between `/` or `:`, in grants and in checks | `test_path_traversal_cannot_escape_a_grant`, `test_check_authority_fails_closed_on_invalid_input` |
| T23 | A prefix grant reaching a similarly named resource (`crm:accounts-archive`) | Prefix patterns must end in a separator | `test_prefix_pattern_does_not_reach_sibling_resources` |
| T24 | Using authority after it ended or before it began | Mandatory expiry (at most 30 days), state checked at every decision | `test_scheduled_and_expired_delegations_do_not_grant`, `test_delegation_window_rules` |
| T25 | Using authority after it was withdrawn | Revocation is immediate and permanent | `test_revoked_delegation_stops_granting` |
| T26 | An agent granting itself authority | Delegations are created only through the control plane | `test_agent_cannot_grant_itself_authority` |
| T27 | Authority reaching an unapproved or disabled agent | Pending agents cannot receive it; only active agents can use it | `test_pending_agent_cannot_receive_authority`, `test_disabled_agent_has_no_authority` |
| T28 | Filling the database or tying up the server with huge requests through the open registration endpoint | 64 KiB body limit (also for chunked uploads); 200/500-character text limits | `test_oversized_body_refused`, `test_oversized_body_without_content_length_refused`, `test_text_length_limits` |
| T29 | Crashing requests with hostile input: NUL characters (PostgreSQL rejects them), times outside the representable range, deeply nested JSON | Control characters and malformed IDs refused before any database access; out-of-range times refused; 422 responses never echo nested input | `test_control_characters_refused_in_registration`, `test_control_characters_refused_in_admin_input`, `test_malformed_ids_in_paths_not_found`, `test_out_of_range_check_time_refused`, `test_deeply_nested_json_refused_without_server_error` |
| T30 | An agent using a tool nobody registered, or one it was not given | Only registered tools assigned to the agent pass the gateway | `test_denied_actions_say_why`, `test_tool_not_assigned_to_the_agent` |
| T31 | Using a tool known to be malicious | Blocked tools are always denied and cannot be assigned | `test_blocked_tool_is_denied_even_if_assigned`, `test_assignment_refused_for_pending_agents_blocked_or_unknown_tools` |
| T32 | Asking a tool for something it does not do (capability confusion) | The tool must list the action among its capabilities | `test_denied_actions_say_why` |
| T33 | A reviewed MCP server or tool changing what it does afterwards (rug pull) | Any change to a trusted tool's definition resets it to unknown, so every use needs approval again | `test_changing_a_trusted_tool_resets_its_trust`, `test_rug_pull_turns_allow_into_require_approval` |
| T34 | A look-alike tool shadowing a trusted one | Tool names are unique and lowercase | `test_tool_names_are_unique`, `test_malformed_tool_names_refused` |
| T35 | Using unreviewed or suspicious tools without a person noticing | Untrusted tools always need approval | `test_untrusted_tool_needs_approval` |
| T36 | A prompt-injected agent acting outside its authority (e.g. mailing data out) | Every action passes the gateway; nothing undelegated is allowed | `test_prompt_injected_agent_cannot_send_data_out` |
| T37 | A policy mistake granting authority | Policies can only deny or require approval; the most restrictive outcome wins | `test_policy_cannot_allow_what_was_not_delegated`, `test_most_restrictive_of_trust_and_policy_wins`, `test_malformed_rules_refused` |
| T38 | A misspelt rule condition silently matching everything | Unknown fields are refused | `test_malformed_rules_refused` |
| T39 | An internal failure turning into an ALLOW | The gateway fails closed (503 = deny) | `test_gateway_fails_closed_when_the_policy_is_corrupt`, `test_gateway_fails_closed_on_any_internal_error` |
| T40 | Agents changing the registry or policy, or reading the decision log | Control-plane only | `test_agents_cannot_manage_the_registry`, `test_agents_cannot_change_policy`, `test_agents_cannot_read_the_log_or_simulate` |
| T41 | Dodging a policy rule with another spelling of a resource (`crm:accounts//secret`) | Resources must be in normal form: no empty segments | `test_non_canonical_resource_cannot_slip_past_a_policy_rule`, `test_blanket_or_malformed_resource_grants_refused` |
| T42 | A thief with a stolen key rotating it away while it is being revoked | Rotation retires the old key only if it is still active; otherwise 409 and nothing changes | `test_revocation_during_a_rotation_is_not_overwritten` |
| T43 | Trusting a tool definition nobody reviewed (it changed while the reviewer looked) | Approval names the reviewed `definition_hash`; changed definitions are refused | `test_trusting_requires_the_reviewed_definition`, `test_a_review_of_an_older_definition_cannot_trust_a_newer_one` |
| T44 | Agents probing the registry or reading block reasons for tools they were not given | Assignment checked first; unregistered and unassigned tools get the same answer | `test_agents_cannot_probe_tools_they_were_not_given` |
| T45 | Learning whether a key exists or was revoked without being able to sign | Unknown keys and bad signatures get the same answer; key status only after a valid signature | `test_unknown_key_rejected`, `test_key_status_is_not_revealed_without_a_valid_signature` |
| T46 | Two different agents sharing a fingerprint (`billing\|prod` in `eu` and `billing` in `prod\|eu`) | Unambiguous fingerprint encoding | `test_names_containing_the_old_separator_do_not_collide` |
| T47 | Look-alike names (a trailing non-breaking space, zero-width or bidirectional characters) squatting or disguising a record | Visible, single-line text only | `test_invisible_or_line_breaking_characters_refused` |
| T48 | A disabled agent appearing alive by re-registering | Signed re-registration of an inactive or disabled agent is refused | `test_disabled_agent_cannot_refresh_itself_by_re_registering` |
| T49 | A tool updated to an unreviewed definition at the moment it is approved, ending up trusted | Updates and approvals each apply only if the tool is unchanged since they read it | `test_an_approval_racing_an_update_cannot_trust_the_new_definition` |
| T50 | An administrator revoking a stolen key the thief already rotated away, believing the agent safe | Only the active key can be revoked; the refusal names the key in use | `test_revoking_a_key_that_was_rotated_away_names_the_key_in_use` |
| T51 | A squatter whose registration was rejected coming back with the same key | Keys of rejected registrations are retired for good | `test_rejected_registration_key_can_never_be_enrolled_again` |
| T52 | Look-alike names that differ only in Unicode spelling (`ﬀ`/`ff`, full-width letters, decomposed accents) | Names compared by NFKC with case folding, in the inventory and in policy rules | `test_names_are_compared_by_one_unicode_rule` |
| T53 | Making every denial slower by piling up delegation history | Denials search only the latest delegations for an explanation | `test_denial_explanations_search_only_recent_history` |
| T54 | An unprotected twin of an admin route (`/agents` vs `/agents/`) | Each route is declared once; trailing slashes are stripped before routing | `test_every_route_is_declared_once`, `test_trailing_slash_is_ignored_without_a_redirect` |
| T55 | Dodging a policy rule by changing case (`crm:accounts/Secret`) | Policy patterns match actions and resources ignoring case; grants stay exact | `test_changing_case_cannot_slip_past_a_policy_rule` |
| T56 | Using a tool on another system's data (reading delegated CRM records through a web search tool) | Tools declare the resources they work on; the gateway refuses others | `test_a_tool_cannot_be_used_on_another_systems_resources` |
| T57 | Invisible or blank-looking names that slipped past a hand-made list (U+061C, U+180E, tag characters, U+3164, U+2800) | Forbidden characters derived from Unicode categories and default-ignorable ranges | `test_invisible_or_line_breaking_characters_refused` |
| T58 | Agents the first M1 version auto-activated on a claimed owner staying active after an upgrade | The upgrade sends them back to review | `test_upgrade_sends_agents_the_first_version_auto_activated_back_to_review` |
| T59 | A rejection undoing a concurrent approval (or an approval failing with 500 after a rejection) | Approve and reject apply only while the agent is pending | `test_reject_cannot_undo_a_concurrent_approval`, `test_approval_after_a_concurrent_rejection_is_404`, `test_a_stale_approval_cannot_reactivate_a_disabled_agent` |
| T60 | A forged or broken signature on a registration silently ignored | A signed registration without its key is refused unless an existing agent's enrolled key made it | `test_signed_registration_of_a_new_agent_without_its_key_is_refused` |
| T61 | Oversized signature headers reaching the database and decoder | Key ID and signature headers are format-checked first | `test_signature_headers_are_bounded` |
| T62 | Dodging a policy rule by swapping separators (`crm:accounts:secret`) | Every resource is normalised to one spelling before anything compares it | `test_swapping_separators_cannot_slip_past_a_policy_rule` |
| T63 | Redirecting a captured signature to another endpoint through a crafted `Host` header | The signed path and query are the ones the router serves, not a URL rebuilt from `Host` | `test_a_signature_cannot_be_redirected_through_the_host_header`, `test_the_signed_path_does_not_depend_on_request_url` |
| T64 | A database failure during authentication answering 500 instead of failing closed | Database errors anywhere answer 503 | `test_database_errors_during_authentication_fail_closed` |
| T65 | A look-alike environment (`prоd`, Cyrillic `о`) escaping every rule on `prod` | Environments are plain ASCII names | `test_environments_are_plain_ascii_names` |
| T66 | Locking an agent out: a retried rotation whose first attempt was applied discarding the only working key | The SDK hands back the new key (`RotationInterrupted`) | `test_retrying_a_rotation_that_was_applied_keeps_the_new_key` |
| T67 | Half-finished changes committed as a side effect of spending a nonce | Spending a nonce with anything else pending is refused | `test_spending_a_nonce_never_commits_other_changes` |
| T68 | The demo writing a private key into an existing world-readable file | The key file is made owner-only before writing | `test_demo_saves_its_private_key_readable_by_the_owner_only` |
| T69 | Stalling every agent: each signed request holding two database connections, exhausting the pool under load | The nonce is spent on the request's own connection | `test_a_signed_request_needs_one_database_connection` |
| T70 | Misleading answers about the past: a revoked delegation counted as revoked before it was | Revocations count from `revoked_at` | `test_questions_about_the_past_see_a_revocation_only_from_when_it_happened`, `test_state_filter_in_the_database_matches_state_at` |
| T71 | Agents from older versions with surrounding spaces escaping rules that name them | Inventory and rules compare names with one function | `test_rules_compare_names_exactly_as_the_inventory_does` |
| T72 | A key bound during a rejection deleted without being retired, so it could be enrolled again | The keys retired are exactly the rows deleted | `test_a_key_bound_during_a_rejection_is_retired_too` |
| T73 | A second revocation overwriting the first one's time and reason | Revocation applies only to an active delegation; otherwise 409 | `test_two_revocations_at_once_keep_the_first` |
| T74 | Backdated delegations making historical checks claim authority that did not exist yet | `starts_at` cannot be in the past | `test_delegations_cannot_be_backdated` |
| T75 | Spellings of one resource or action falling under a grant yet escaping a rule or approval | One canonical spelling for resources, lower-case actions, everywhere | `test_requests_are_decided_and_recorded_in_the_one_spelling`, `test_delegations_are_stored_and_checked_in_the_one_spelling` |
| T76 | Replaying a re-registration to tell it apart from other refusals | A replay gets the same 401 as every other unverifiable signed registration | `test_re_registration_signed_with_the_enrolled_key_needs_no_public_key` |
| T77 | Crashing requests with a lone surrogate (`\ud800`): valid JSON, refused correctly, but echoing it in the 422 failed with a 500 | Invalid input is echoed only if it is valid text | `test_lone_surrogates_are_refused_without_server_error` |
| T78 | Probing which agent names exist with signed registrations that leave no record | One answer for every unverifiable signed registration, whether or not the name exists | `test_signed_registrations_reveal_nothing_about_which_names_exist` |
| T79 | Crashing the open registration endpoint with input a JSON response cannot carry (a body that is not UTF-8, `NaN`, `Infinity`) | The 422 echoes only numbers, booleans and valid text | `test_invalid_input_json_cannot_carry_is_refused_without_server_error` |
| T80 | An agent told to stop (503) for an action the decision log records as allowed | The answer is built from the record before it is stored; nothing is read back | `test_the_agent_is_told_what_the_decision_log_says` |
| T81 | Keys left pointing at deleted agents on SQLite, which did not enforce foreign keys | Foreign keys are enforced on SQLite too | `test_a_key_cannot_be_bound_to_an_agent_rejected_meanwhile`, `test_sqlite_enforces_foreign_keys` |
| T82 | Replays making each request repeat the purge of expired nonces | The purge commits on its own | `test_a_replay_neither_undoes_nor_repeats_the_purge` |
| T83 | A delegation window nobody meant: a number string read as a Unix time, or a loose timestamp form | Strict RFC 3339 timestamps, published in the schema | `test_timestamps_must_be_rfc_3339`, `test_timestamp_pattern_matches_its_validator` |

T41–T76 and T78–T83 were found by code review, T77 by the probes of the test campaign. T28 and T29 were found by fuzzing the API with Schemathesis and by targeted probes; after the
fixes, neither found any server error on SQLite or PostgreSQL.

The race defences were also checked against a live server on SQLite and PostgreSQL: of 8
simultaneous registrations of one name, or 8 simultaneous rotations by one agent, exactly one
succeeded and the rest were refused, with no server errors. On SQLite, of 10 simultaneous copies of
one signed request, exactly one was accepted.

## Residual risks

Known gaps, with the planned or possible mitigation:

| Risk | Mitigation |
|---|---|
| **First come, first served registration.** Whoever registers a name first holds it until reviewed. An administrator who approves without checking the key with the operator could approve an impostor. | Reviewers confirm `active_key_id` out of band; squatted names are freed with `DELETE /agents/{id}`. Admin-issued one-time enrollment tokens would remove the gap. |
| **One shared admin token.** No per-person accountability, no expiry. | SSO/OIDC is out of FYP scope; audit logging (M11) will record administrative actions. |
| **No transport security in the app.** The admin token is a bearer secret. | Deploy behind HTTPS (a reverse proxy). |
| **No rate limiting.** The open registration endpoint can be flooded with pending registrations. | Rate limit at the proxy; add application limits later. |
| **Private key storage is the operator's job.** The SDK writes unencrypted PEM. | Restrict file permissions or use a secrets manager; hardware-backed keys are future work. |
| **Keys never expire on their own.** | Operators rotate; a maximum key age could be added. |
| **No audit trail yet.** Key and status changes keep only their latest state. | M11 (hash-chained audit log). |
| **No schema migrations.** | Add Alembic before schemas start changing under real data. |
| **Delegators are not authenticated.** An administrator records who delegates; Secentic cannot prove that person agreed. | Individual logins for people, so delegators sign their own grants; audit logging (M11). |
| **No model of what the delegator may do.** Someone could delegate authority they do not hold themselves. | Connect to the organisation's permission system in future work. |
| **Look-alike agent names in policy rules.** Agent names may use any script, so `billing-bot` written with a Cyrillic letter is a different agent that a rule naming `billing-bot` does not match. | The reviewer approves each agent and sees its name; rules for sensitive cases should select by environment (plain ASCII), tool or resource. Matching Unicode confusables (UTS #39) is future work. |
| **The gateway is cooperative.** Agents (through the SDK) ask before acting and must obey; an agent that calls a tool directly is not stopped. | Route tool and MCP traffic through a gateway proxy, so tools accept only calls it forwards (future work). |
| **REQUIRE APPROVAL has no workflow yet.** It means "do not proceed". | The human approval workflow (M8, FYP-II). |
| **The decision log is an ordinary table.** | Hash chaining and export (M11). |
| **Policy conditions are positive only** (no "except", no time-of-day). | Richer conditions and risk signals (M7). |

## Reporting a problem

Found a weakness? Open an issue in the repository (or tell the team directly if it is sensitive),
and add a row to the table above once it is fixed, with the test that proves it.
