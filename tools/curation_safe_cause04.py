"""Own04 bounded source-identity diagnostics; no acquisition, controller or targets."""
from __future__ import annotations
import ast,hashlib,json,os,stat,sys,types
from pathlib import Path
LIMIT=16384
PURPOSE='PRODUCER04_LINUX_INPUT_CURATION'
STAGES=('bootstrap','host','source','caller-context','disk-ledger','commontransport-enter','commontransport-return','inputreceipt-write','public-originals','metadata','deny','native','signature','graph','terminal')
CONTEXT_KEYS=('projectId','repository','checkout','controller','contract','profile','sourcePins','admission','capsEvidence','expectedSourceCommit','expectedSourceTree','rowStartedMonotonicNs','deadlineMonotonicNs','supervisorPID','supervisorStartIdentity')
# Frozen d9c CTX_KEYS has exactly15 names; retain that observed interface unchanged.
ENV_NAMES=('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_REF','GITHUB_WORKSPACE','GITHUB_EVENT_NAME','GITHUB_EVENT_PATH','GITHUB_JOB','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_ENVIRONMENT','RUNNER_OS','RUNNER_NAME','ImageOS','ImageVersion','RUNNER_TEMP')
CLASSES=('AdmissionError','Denied','CapError','Hold','WorkspaceError','PublicHold')
ERRNOS=frozenset((1,2,5,9,12,13,17,20,21,22,24,28,32,35,60,104,110,111))
FROZEN={'check_dotnet11': 'd9c690d8c82825b018c04089c279036829d3baf2534c2634bba84910c415a37d', 'qualification_input_guard': '7420b08d78d3b1476be41385d179a42212a2a7e1a965a8d8ea3b67bb14da7925', 'materialize_qualification_linux': '5f0dbb951cbe615d8c6dd9edbb63b11143cc457319bdcc9000ea9a486f660fb8', 'sdk11_ci_facts': '6bb0fe5199377dfdb0caed76cf274bcef631205648d9dbf0d67e1f43433e9a7e', 'sdk11_ci_runtime': 'd64ba8ffdf1d7ee0743d29cfb4fbdb8e9fe8c3c58428a7557cdabc7aec8f244f', 'linux_qualification_job': '0d63594368cb6839145d4b1798730fe8fab05f6a94d86834f3a82d52475e7227', 'curation_linux_method': 'a2ed7e4bb9d643f02819907e27af0a1145e966f383f487d306b79372720f9451', 'curation_advisory_source04': '8c6313a4ae0dbb43db71b1de92624180c5fc79678a2ae50bea6cb3556c485e51'}
CODE_LITERALS={'caller': ('CONSUMER900_DEADLINE', 'CONSUMER_ADMISSION_REQUIRED', 'CONSUMER_OUTPUT_EXISTS', 'CONTROLLED_STAGE_NOT_COMPLETED', 'CURATION900_DEADLINE', 'CURATION_EVENT_EXCLUSIVE', 'CURATION_EXCLUSIVE_LINUX_PURPOSE', 'CURATION_FAILURE_PROOF_LINK', 'CURATION_GATE_ARGUMENT_PAIR', 'CURATION_INPUT_GRAPH_RESULTS_REQUIRED', 'CURATION_LINUX_ONLY', 'CURATION_PROOF8M_OVERFLOW', 'CURATION_PROOF_EXISTS', 'CURATION_REPORT_BOUND', 'EXACT_ONE_PRODUCT_ARCHIVE', 'EXACT_ONE_PRODUCT_ROOT', 'EXISTING_PRODUCT_PWSH_REQUIRED', 'FIXED_CONSUMER_ROLE', 'FIXED_OBSERVER_HOST', 'FIXED_STAGE_REQUIRED', 'FRESH_PRIVATE_RUNNER_ROOT', 'HELD_WORKER_PREEXEC_IDENTITY', 'NAMED_UBUNTU_HOST_REQUIRED', 'NAMED_WINDOWS_HOST_REQUIRED', 'NETWORK_EXACT_HELD_GENERATION', 'NETWORK_STOPPED_HANDSHAKE', 'OWN04_ACCEPTED_FACT_IDENTITY', 'OWN04_ACTUAL_HELD_WORKER', 'OWN04_COMMON_SOURCE_IDENTITY', 'OWN04_CURRENT_SOURCE_PROFILE_HASH', 'OWN04_NET11_LOCKS_NOT_CLOSED', 'OWN04_NORMAL_CATALOG_IDENTITY', 'OWN04_ORIGINAL_PRODUCT_INPUTS_PENDING', 'OWN04_SOURCE_PROFILE_IDENTITY', 'OWN04_SOURCE_PROFILE_NOT_ADMITTED', 'OWN04_WINDOWS_NORMAL_INPUT_DENIED', 'OWNED_AGGREGATE_TERMINAL', 'OWNED_CURATION_NONZERO_OR_NO_TRANSITION', 'OWNED_DENY_PARENT_FAILED', 'OWNED_DENY_PARENT_RESULT', 'OWNED_DENY_TYPED_FAILURE', 'OWNED_LAUNCHER_LOG_CAP', 'OWNED_NETWORK_STAGE540', 'OWNED_WORKER840_DEADLINE', 'OWN_CONSUMER_CONTROL_REQUIRED', 'OWN_CONSUMER_DENIAL_REQUIRED', 'OWN_UNIT_MUST_BE_ABSENT', 'PRIVILEGED_METHOD_SOURCE_PIN', 'PUBLIC_INPUT_TOKEN_CONFIG_FORBIDDEN', 'PUBLIC_INPUT_TRANSPORT_REQUIRED', 'PYTHON_BOOTSTRAP_CHANGED', 'PYTHON_BOOTSTRAP_IDENTITY', 'SDK_HELD_IMAGE_IDENTITY', 'STARTUP60_EXPIRED', 'STOPPED_WORKER_IDENTITY', 'STOPPED_WORKER_STARTUP_HOLD', 'SYSTEMD_FIXED_ARGV_PATH', 'TYPED_CURATION_TERMINAL_REQUIRED', 'WORKER_KERNEL_READBACK', 'WORKER_NOT_STOPPED'), 'curation': ('ACTUAL_ALLOCATION_UNIT', 'ACTUAL_PRIVATE_SCRATCH_CAP', 'ACTUAL_PRIVATE_SCRATCH_LEDGER', 'ACTUAL_SCRATCH_INODES', 'BOUNDED_POLICY_DUPLICATE', 'BOUNDED_POLICY_FILE', 'BOUNDED_POLICY_JSON', 'BOUNDED_POLICY_NONFINITE', 'CAPSULE_API_STATUS', 'CAPSULE_BODY_BOUND', 'CAPSULE_CONSUMER_SOURCE', 'CAPSULE_ENTRY_FRAME', 'CAPSULE_ENTRY_HASH', 'CAPSULE_ENTRY_SIZE', 'CAPSULE_EXACT_STORAGE_HOP', 'CAPSULE_EXACT_THREE_ENTRIES', 'CAPSULE_IDENTITY', 'CAPSULE_ORIGINAL420', 'CAPSULE_OWN_TOKEN_SCOPE', 'CAPSULE_RESPONSE_FRAME', 'CAPSULE_RETAINED_LINEAGE', 'CAPSULE_TOKEN_FILE', 'CAPSULE_TOKEN_FORMAT', 'CAPSULE_TOKEN_INODE_BINDING', 'CAPSULE_TOKEN_INODE_CHANGED', 'CAPSULE_WHOLE_HASH_OR_SIZE', 'CONFIG_ROUNDTRIP', 'CURATION_ACTUAL_HELD_WORKER', 'CURATION_CURRENT_LEASE_BRIDGE', 'CURATION_DISPATCH_NONCE', 'CURATION_EVENT_HANDOFF_SCHEMA', 'CURATION_EVENT_LEASE_INTENT', 'CURATION_EVENT_SELECTOR', 'CURATION_EXACT_RUN', 'CURATION_FIXED_CALLER', 'CURATION_FIXED_PURPOSE', 'CURATION_GATE_HEAD', 'CURATION_GATE_IDENTITIES', 'CURATION_GATE_POLICY', 'CURATION_GATE_RUN', 'CURATION_GATE_SCHEMA', 'CURATION_GATE_STATE_PURPOSE', 'CURATION_GATE_VALUE_TYPES', 'CURATION_INTENT_SOURCE', 'CURATION_MANUAL_EXACT_SOURCE', 'CURATION_NUGET_PACKAGING_BINARY', 'CURATION_OWNER_SCRATCH_LIMIT', 'CURATION_PROOF_LINK', 'CURATION_ROOT_INTENT_HASH', 'CURATION_SINGLE_EVENT_INTENT', 'CURATION_SOURCE_TREE', 'CURRENT_CMS_BOUND', 'CURRENT_CMS_BYTES', 'CURRENT_REPOSITORY_SIGNER_MISSING', 'CURRENT_UTC_MONOTONIC_ANCHOR', 'DENY_RESPONSE_IDENTITY', 'DISK_LEDGER_INPUT', 'DURABLE_CONSUMED_FILE_CHANGED', 'DURABLE_CONSUMED_METADATA_REQUIRED', 'DURABLE_FILE_BOUND_OR_TYPE', 'DURABLE_FILE_CHANGED_DURING_READ', 'DURABLE_FIXED_PATH_REQUIRED', 'DURABLE_FOUR_LOCKS_AND_CONFIG_REQUIRED', 'DURABLE_LEDGER_REQUIRED', 'DURABLE_LOCK_SCHEMA', 'DURABLE_ORIGINAL_CHANGED', 'DURABLE_PATH_LINK', 'DURABLE_PROOF_RESERVE_IDENTITY', 'DURABLE_REQUIRED_FILE_MISSING', 'DURABLE_UNEXPECTED_PATH', 'EXACT_SDK_ROOT_BUNDLES', 'EXACT_SDK_RUNTIME_SERVICING_MISSING', 'EXACT_SEVEN_OPERATIONS', 'FINITE_COMPLETE_PAGES', 'FINITE_DUPLICATE_OR_COUNT', 'FINITE_OFFICIAL_ORIGIN', 'FINITE_URI_PATH', 'FINITE_URI_TEXT', 'FINITE_VULNERABILITY_NAMESPACE', 'FIXED_TIME_FRESH_HTTPS_BINDING', 'GRAPH_ACTUAL_NUPKG_METADATA', 'GRAPH_AUDIT_REQUIRED', 'GRAPH_CHECKOUT_OUTPUT_FORBIDDEN', 'GRAPH_DEPENDENCY_SCHEMA', 'GRAPH_FLAVOR', 'GRAPH_LOCK_SCHEMA', 'GRAPH_NEW_DEPENDENCY', 'GRAPH_NORMALIZED_CONTENT_HASH', 'GRAPH_PRIVATE_ROOT', 'GRAPH_PROJECT_EDGE', 'GRAPH_REQUIRED_PROJECT_REFERENCE', 'GRAPH_TFM', 'LATER_SERVICING_REQUIRES_POLICY_HOLD', 'METHOD_HELPER_SOURCE_IDENTITY', 'OFFICIAL_PEER_SOCKET_UNOBSERVED', 'OFFICIAL_RESOURCE_AMBIGUOUS', 'OFFICIAL_RESOURCE_MISSING', 'OFFICIAL_RESOURCE_VERSION', 'ORIGINAL_CLOCK_OR_STAGE_EXPIRED', 'ORIGINAL_DENY540', 'ORIGINAL_DURABLE840', 'ORIGINAL_GRAPH810', 'ORIGINAL_METADATA420', 'ORIGINAL_METADATA_AND_PROOF8M_OVERFLOW', 'ORIGINAL_NOTICE_DATA_BOUND', 'ORIGINAL_NOTICE_DATA_HASH', 'ORIGINAL_SIGNATURE630', 'OWN_LOOPBACK_PORT', 'OWN_PRIVATE_CONFIG_PATH', 'OWN_SDK_ALLOCATION_SCOPE', 'PKI_AGGREGATE_BOUND', 'POLICY_BYTES_IDENTITY', 'PRIVATE_SCRATCH_TYPE_OWNER', 'PUBLIC_INPUT_GATE', 'PUBLIC_INPUT_HELPER_SOURCE', 'PUBLIC_INPUT_PROFILE', 'RETENTION_INPUT', 'SDK_AUDIT_CONSUMPTION_NOT_PROVEN', 'SDK_CHILD_GROUP_NOT_NATURALLY_TERMINAL', 'SDK_OWNED_CHILD_TERMINAL_UNKNOWN', 'SDK_REPORT_BOUND', 'SDK_STDERR_OR_REPORT_UNKNOWN', 'SDK_TARGET_CURRENT_CGROUP', 'SDK_TARGET_DEADLINE_AFTER_TERMINAL', 'SDK_TARGET_DEADLINE_OR_REPORT_BOUND', 'SDK_TARGET_NONZERO', 'SDK_WARNING_OR_AUDIT_ERROR', 'SERVICE_RESOURCES', 'SERVICING_CHANNEL_NOT_SUPPORTED', 'SERVICING_RELEASES', 'STATIC_ADAPTER_TERMINAL_UNKNOWN', 'STATIC_ADAPTER_UNEXPECTED_REQUEST', 'STATIC_CLOSED_ROUTE', 'STATIC_RETENTION_BOUND', 'STATIC_ROUTE_COUNT', 'STATIC_ROUTE_TYPES', 'SUPPORTED_OFFICIAL_RESOURCE_MISSING', 'UNEXPECTED_EFFECTIVE_SYSTEM_CODESIGN_STORE', 'UNSUPPORTED_SCRATCH_ALLOCATION_MODEL', 'VERIFY_EXIT_NOT_ZERO', 'VERIFY_HASH_BASE64', 'VERIFY_HASH_CANONICAL', 'VERIFY_HASH_SCHEMA', 'VERIFY_IDENTITY_ORDER', 'VERIFY_ISSUE_REQUIRES_HOLD', 'VERIFY_LOG_BOUND', 'VERIFY_LOG_CONTROL', 'VERIFY_LOG_ENCODING', 'VERIFY_RAW_BINDING', 'VERIFY_SINGLE_IDENTITY_HASH_BLOCK', 'VULNERABILITY_FUTURE_TIME', 'VULNERABILITY_UPDATED_TIME'), 'safe-cause': ('CURATION_HTTP_DIAGNOSTIC_SHAPE', 'CURATION_PARENT_WORKSPACE_MISMATCH', 'CURATION_PARENT_WORKSPACE_MISSING', 'CURATION_SAFE_CAUSE_BOUND', 'CURATION_SAFE_ROOT_REQUIRED'), 'check_dotnet11': ('ARCHIVE_DUPLICATE_MEMBER', 'ARCHIVE_LIMIT_EXCEEDED', 'ARCHIVE_LINK_UNSUPPORTED', 'ARCHIVE_PATH_INVALID', 'ARCHIVE_SPECIAL_UNSUPPORTED', 'INPUT_IDENTITY_MISMATCH', 'NATIVE_TARGET_UNSUPPORTED', 'NORMAL_ABSOLUTE_DEADLINE', 'NORMAL_ACCEPTANCE_SOURCE_BYTES', 'NORMAL_ACTUAL_OWN_CAPS', 'NORMAL_ADMISSION_HOST_RID', 'NORMAL_ALIAS_IDENTITY', 'NORMAL_BINDING_NOT_TRACKED', 'NORMAL_BINDING_SOURCE_CHANGED', 'NORMAL_BLOCKING_OUTER_SUPERVISOR', 'NORMAL_CAPPED_CALLER_CONTROLLER', 'NORMAL_CAPS_CHANGED', 'NORMAL_CATALOG_CONTRACT', 'NORMAL_CATALOG_SOURCE_BYTES', 'NORMAL_CATALOG_STATE', 'NORMAL_CLEANUP_SCOPE', 'NORMAL_CONTEXT_SHAPE', 'NORMAL_CURRENT_CHECKOUT', 'NORMAL_CURRENT_EXECUTION', 'NORMAL_CURRENT_HOST', 'NORMAL_CURRENT_SOURCE', 'NORMAL_CURRENT_SOURCE_FILE', 'NORMAL_CURRENT_WORKER_IDENTITY', 'NORMAL_DEADLINE_EVIDENCE', 'NORMAL_EVENT_SOURCE', 'NORMAL_FACT_AUTHORITY', 'NORMAL_FACT_SOURCE_BYTES', 'NORMAL_FINITE_UNIT_DEADLINE', 'NORMAL_FOREIGN_MODULE', 'NORMAL_FRESH_OWNER', 'NORMAL_FRESH_SCOPE', 'NORMAL_HELD_BEFORE_EXEC', 'NORMAL_INPUT_FILE', 'NORMAL_INPUT_RID', 'NORMAL_INPUT_STATE', 'NORMAL_INSPECT_SCOPE', 'NORMAL_JSON_CONSTANT', 'NORMAL_JSON_DUPLICATE', 'NORMAL_KERNEL_OUTER_DEADLINE', 'NORMAL_LIBRARY_SOURCE', 'NORMAL_LINUX_MAIN_WORKER_REQUIRED', 'NORMAL_MEMBER_IDENTITY', 'NORMAL_MEMBER_POSTIMAGE', 'NORMAL_NAMESPACE_COUNTS', 'NORMAL_ORIGINAL_DEADLINE', 'NORMAL_OUTER_DEADLINE_EXPIRED', 'NORMAL_OUTER_SUPERVISOR_IDENTITY', 'NORMAL_OWN_ADMISSION', 'NORMAL_OWN_BOOTSTRAP_IDENTITY', 'NORMAL_OWN_BOOTSTRAP_IMAGE', 'NORMAL_OWN_CAP_EVIDENCE', 'NORMAL_OWN_CGROUP', 'NORMAL_OWN_CPU_V2', 'NORMAL_OWN_EVIDENCE_SCOPE', 'NORMAL_OWN_MEMBERSHIP', 'NORMAL_OWN_PROFILE', 'NORMAL_OWN_PROFILE_BUDGET', 'NORMAL_OWN_PROFILE_LIMITS', 'NORMAL_OWN_SOURCE_PINS', 'NORMAL_OWN_SOURCE_PROFILE_HASH', 'NORMAL_OWN_UNIT', 'NORMAL_PERIODIC_TIMER_UNSUPPORTED', 'NORMAL_PRODUCER_ACCEPTANCE', 'NORMAL_PRODUCER_HISTORY', 'NORMAL_RAW_BODY_HASH', 'NORMAL_RAW_HEADER_IDENTITY', 'NORMAL_RAW_IDENTITY', 'NORMAL_RAW_SIZE', 'NORMAL_RECEIPT_CAP', 'NORMAL_RID_FACT_MISSING', 'NORMAL_RID_NOT_ACCEPTED', 'NORMAL_SCHEMA_SOURCE_BYTES', 'NORMAL_SOURCE_MODE', 'NORMAL_SOURCE_NOT_CLEAN', 'NORMAL_SOURCE_OR_HOST_TOOL_FAILED', 'NORMAL_SOURCE_PINS_NOT_TRACKED', 'NORMAL_SOURCE_PIN_TABLE', 'NORMAL_TOOL_OUTPUT_CAP', 'NORMAL_TRANSPORT_IDENTITY', 'NORMAL_TYPED_LAYOUT', 'NORMAL_WINDOWS_DENIED', 'OUTPUT_SCOPE_INVALID', 'SDK_CATALOG_NOT_QUALIFIED', 'SDK_MEMBER_MISMATCH', 'SDK_TRANSPORT_REDIRECT_REJECTED'), 'qualification_input_guard': ('ARCHIVE_DUPLICATE_MEMBER', 'ARCHIVE_LIMIT_EXCEEDED', 'ARCHIVE_LINK_UNSUPPORTED', 'ARCHIVE_PATH_INVALID', 'ARCHIVE_SPECIAL_UNSUPPORTED', 'INPUT_IDENTITY_MISMATCH', 'NATIVE_TARGET_UNSUPPORTED', 'OUTPUT_SCOPE_INVALID', 'SDK_MEMBER_MISMATCH'), 'materialize_qualification_linux': ('ARCHIVE_LIMIT_EXCEEDED', 'CI_LINUX_HEADER_SET', 'CI_LINUX_LAYOUT_IDENTITY', 'CI_LINUX_OWNERSHIP', 'CI_LINUX_TRAILING_DATA', 'COPY_BODY_INVALID', 'COPY_BODY_MISMATCH', 'COPY_DEST_INVALID', 'COPY_DEST_NOT_FRESH', 'COPY_INODE_INVALID', 'COPY_LAYOUT_INVALID', 'COPY_LINK_HEADER_MISMATCH', 'COPY_LINK_INVALID', 'COPY_LINK_SET_INVALID', 'COPY_MODE_INVALID', 'COPY_POSTIMAGE_MISMATCH', 'COPY_RAW_HEADER_MISMATCH', 'COPY_TARGET_ESCAPE', 'COPY_TARGET_MISMATCH', 'COPY_TARGET_NOT_REGULAR', 'COPY_TYPE_INVALID'), 'sdk11_ci_facts': ('CONSUMER_ADMISSION_REQUIRED', 'CONSUMER_CURRENT_EXECUTION_REQUIRED', 'CONSUMER_FACT_IDENTITY', 'CONSUMER_HOST_CLASS_MISMATCH', 'CONSUMER_RID_MISMATCH', 'CONSUMER_SOURCE_CONTRACT', 'CONSUMER_TREE_IDENTITY', 'Q_ACTUAL_CAP_REQUIRED', 'Q_CAP_PROFILE', 'Q_CATALOG_IDENTITY', 'Q_CATALOG_MEMBERS', 'Q_CATALOG_RID', 'Q_CATALOG_STATE', 'Q_CPU_V2_BEFORE_SDK', 'Q_FACT_ARCHIVE', 'Q_FACT_DENIAL_MODES', 'Q_FACT_KIND', 'Q_FACT_TREE', 'Q_HOST_CAP_UID_GID', 'Q_HOST_CLASS', 'Q_HOST_IMAGE', 'Q_HOST_INSTANCE', 'Q_HOST_OS', 'Q_PREEXEC_MEMBERSHIP', 'Q_SOURCE_IDENTITY', 'Q_TERMINAL_REQUIRED', 'Q_TRANSFERABLE_READY_FORBIDDEN'), 'sdk11_ci_runtime': ('ARCHIVE_BYTE_LIMIT', 'ARCHIVE_HASH_IDENTITY', 'ARCHIVE_HTTP_IDENTITY', 'ARCHIVE_REDIRECT_FORBIDDEN', 'ARCHIVE_STAGE_TIMEOUT', 'CHILD_OUTPUT_CAP', 'CI_ORDINARY_PROFILE_IDENTITY', 'CI_PROFILE_IDENTITY', 'CI_QUALIFICATION_MODE', 'CI_QUALIFICATION_STAGE_BUDGET', 'CI_WINDOWS_ONLY_PROFILE', 'CONSUMER_EVENT_SCOPE', 'CPU_AFFINITY', 'CPU_AFFINITY_RESTORE', 'CPU_CPUID_ALLOCATION', 'CPU_CPUID_LEAF', 'CPU_CPUID_RX_POLICY', 'CPU_GROUP_SCOPE_UNSUPPORTED', 'FACT_SCHEMA_SOURCE', 'FAILURE_SUMMARY32K_LIMIT', 'FINAL900_DEADLINE', 'FIXED_FAILURE_RID', 'INPUT_FILE_IDENTITY', 'LOCAL_WSL_SDK_TARGETS_EXCLUDED', 'NATIVE_ELF_AMD64_REQUIRED', 'NATIVE_IMPORT_MISSING', 'NATIVE_PE_AMD64_REQUIRED', 'NATIVE_PUBLISHER_REQUIRED', 'OUTER_STAGE_BUDGET_EXPIRED', 'PROOF8MIB_LIMIT', 'PYTHON_STDLIB_CLOSURE_LIMIT', 'PYTHON_STDLIB_EXTERNAL', 'PYTHON_VERSION_IDENTITY', 'Q_BOOTSTRAP_GIT', 'Q_CATALOG_SOURCE_SHA', 'Q_CPU_V2_BEFORE_SDK', 'Q_DENIAL_MODE_PROOF', 'Q_FULL_MEMBER_MANIFEST', 'Q_HOST_CLASS', 'Q_HOST_IMAGE', 'Q_HOST_OS', 'Q_QUALIFICATION_EVENT', 'Q_SOURCE_IDENTITY', 'SDK_AGGREGATE480_EXPIRED', 'SDK_COMPILER', 'SDK_ENTRY_HELD_IDENTITY', 'SDK_HELLO', 'SDK_INFO', 'SDK_LIST', 'SDK_RUNTIME', 'SDK_VERSION', 'STARTUP60_EXPIRED', 'TRUSTED_BOOTSTRAP_TOOL_MISSING', 'UNSAFE_RUNTIME_ENVIRONMENT', 'WINDOWS_HOST_OBSERVATION_SCHEMA', 'WINDOWS_HOST_OBSERVATION_SHAPE'), 'linux_qualification_job': ('ACTUAL_KERNEL_CAPS', 'ACTUAL_OWNED_CGROUP', 'ACTUAL_RUNNER_UID_GID', 'CHILD_ACTUAL_LIMIT_READBACK', 'CHILD_CGROUP_MISMATCH', 'CHILD_NONZERO_OR_DEADLINE', 'CHILD_NOT_STOPPED', 'OWNED_CHILD_GROUP_NOT_TERMINAL', 'OWNED_CHILD_REAP_TIMEOUT', 'OWNED_CHILD_STOP_BEFORE_EXEC', 'OWN_CI_SPEC'), 'curation_linux_method': ('AIA_CERT_OUTSIDE_DECLARED_POOL_OR_SDK_ANCHORS', 'BPF_FIXED_NATIVE_CGROUP', 'BPF_QUERY_UNSUPPORTED_OR_FAILED', 'CERTIFICATE_AKI', 'CERTIFICATE_BOUND', 'CERTIFICATE_EXTENSIONS', 'CERTIFICATE_FRAME', 'CERTIFICATE_SERIAL_VALIDITY', 'CERTIFICATE_TBS', 'CHAIN_ISSUER_AMBIGUOUS_OR_MISSING', 'CHAIN_LOOP_OR_BOUND', 'CMS_ATTRIBUTE_FRAME', 'CMS_BOUND', 'CMS_CERTIFICATE_CHOICE', 'CMS_CONTAINERS', 'CMS_FRAME', 'CMS_NODE_DEPTH_BOUND', 'CMS_ROLE_IDENTITY', 'CMS_SID_AMBIGUOUS_OR_MISSING', 'CMS_SID_FRAME', 'CMS_SID_KIND', 'CMS_SIGNEDDATA', 'CRL_AKI_REQUIRED', 'CRL_BOUND', 'CRL_CHAIN_COVERAGE_MISSING', 'CRL_DUPLICATE_ISSUER_DISAGREES', 'CRL_EXTENSIONS', 'CRL_FRAME', 'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED', 'CRL_NEXT_UPDATE_REQUIRED', 'CRL_NOT_CURRENT', 'CRL_TBS', 'CURRENT_CERTIFICATE_VALIDITY', 'CURRENT_CRLS_REQUIRED', 'CURRENT_UNIX_TIME', 'DENY_BOUND_OFFICIAL_PEER', 'DENY_CAPS_READBACK', 'DENY_EXACT_GENERATION', 'DENY_EXACT_UNIT_READBACK', 'DENY_KERNEL_FILTER_NOT_NEW_OR_UNSUPPORTED', 'DENY_KERNEL_PROOF_REQUIRED', 'DENY_LOOPBACK_HTTP', 'DENY_LOOPBACK_POSITIVE', 'DENY_ORIGINAL_STAGE540', 'DENY_OWN_ADAPTER_PORT', 'DENY_POLICY_READBACK', 'DENY_PROPERTY_FORMAT', 'DENY_REQUEST_BYTES', 'DENY_REQUEST_CANONICAL_IDENTITY', 'DENY_REQUEST_FILE', 'DENY_REQUEST_PRIVATE_OWNER', 'DENY_SET_FAILED', 'DENY_SHOW_FAILED', 'DENY_TIMEOUT_OR_UNREACHABLE_NOT_PROOF', 'DENY_WITNESS_GENERATION', 'DENY_WITNESS_TIME', 'DER_CHILD_BOUND', 'DER_CONSTRUCTED', 'DER_EXTENSION', 'DER_EXTENSION_DUPLICATE', 'DER_FRAME', 'DER_HIGH_TAG', 'DER_LENGTH', 'DER_NONMINIMAL', 'DER_OID', 'DER_TIME', 'DN_ATTRIBUTE_UNSUPPORTED', 'DN_ENCODING', 'DN_ESCAPING_UNSUPPORTED', 'DN_MULTIVALUED_UNSUPPORTED', 'EXACT_ORIGINAL_CERTIFICATE_POOL', 'EXACT_STOPPED_GENERATION', 'FINITE_OPENSSL_COMMAND_BUDGET', 'FIXED_OS_IMAGE', 'LEAF_NOT_ORIGINAL', 'OPENSSL3_VERSION_UNRECOGNIZED', 'OPENSSL_ACTUAL_LIBCRYPTO_MAPPING_UNOBSERVED', 'OPENSSL_CHAIN_INCOMPLETE', 'OPENSSL_CHAIN_REQUIRED', 'OPENSSL_COMBINED_REPORT_BOUND', 'OPENSSL_CONSTRUCTED_CHAIN_MISMATCH', 'OPENSSL_CURRENT_CGROUP_DRIFT', 'OPENSSL_DN_ATTRIBUTE', 'OPENSSL_DN_ESCAPE', 'OPENSSL_DN_FRAME', 'OPENSSL_EXPECTED_LEAF_RESULT', 'OPENSSL_EXTRA_OR_UNKNOWN_OUTPUT', 'OPENSSL_ORIGINAL_STAGE', 'OPENSSL_OWNED_CHILD_TERMINAL_UNKNOWN', 'OPENSSL_REPORT_BOUND', 'OPENSSL_REPORT_ENCODING', 'OPENSSL_TIME_OR_REPORT_BOUND', 'OPENSSL_VERIFY_EXIT_OR_REPORT', 'OPENSSL_VERIFY_REQUIRES_CURRENT_DENY', 'OPENSSL_VERSION_ONCE', 'OS_IMAGE_CHANGED', 'OS_IMAGE_ELF', 'OS_IMAGE_READ_LENGTH', 'OS_IMAGE_RESOLUTION', 'OS_OPENSSL_BINARY_LIBCRYPTO_UNAVAILABLE', 'OWN_PID_CAPS', 'OWN_PID_CGROUP', 'OWN_UNIT_IDENTITY', 'PREFETCH_EXTERNAL_SOCKET_STILL_CONNECTED', 'PREFETCH_UNKNOWN_SOCKET_FD', 'ROOT_BUNDLE_BASE64', 'ROOT_BUNDLE_BOUND', 'ROOT_BUNDLE_FRAME', 'ROOT_OWNED_OS_IMAGE', 'SOCKET_FD_INHERITANCE', 'TRUSTED_CURATION_PARENT_REQUIRED', 'TSA_LEAF_PATH_BOUND', 'TSA_ROLE_BOUND'), 'curation_advisory_source04': ('ADVISORY_COMPLETE_SNAPSHOT', 'ADVISORY_EXACT_RANGE', 'ADVISORY_RANGE', 'CURRENT_ADVISORY_MATCH', 'METADATA_BODY_BOUND', 'METADATA_CALLER_ORIGIN_BINDING', 'METADATA_CHILD_OUTPUT_UNEXPECTED', 'METADATA_CHILD_RECEIPT_IDENTITY', 'METADATA_CHILD_RESULT_BOUND', 'METADATA_CHILD_WIRE_BOUND', 'METADATA_CHILD_WIRE_HASH', 'METADATA_CLOSED_ONCE', 'METADATA_COMBINED_BYTES_CAP', 'METADATA_DUPLICATE_KEY', 'METADATA_ENCODING', 'METADATA_FRESHNESS', 'METADATA_GZIP_BOUND_OR_MEMBER', 'METADATA_GZIP_EOF', 'METADATA_GZIP_PROGRESS', 'METADATA_HTTP_DATE', 'METADATA_HTTP_FRAMING', 'METADATA_HTTP_STATUS_OR_URL', 'METADATA_JSON_INVALID', 'METADATA_LENGTH', 'METADATA_LENGTH_MISMATCH', 'METADATA_NAMESPACE', 'METADATA_NONFINITE', 'METADATA_ORIGIN', 'METADATA_OWN_CHILD_CGROUP', 'METADATA_OWN_CHILD_FAILED', 'METADATA_OWN_CHILD_IDENTITY', 'METADATA_OWN_CHILD_TERMINAL', 'METADATA_OWN_MAIN_ALARM_REQUIRED', 'METADATA_PERIODIC_ALARM_UNSUPPORTED', 'METADATA_PHASE_IDENTITY', 'METADATA_REDIRECT', 'METADATA_REQUEST10_DEADLINE', 'METADATA_REQUEST_FILE', 'METADATA_REQUEST_FILE_HASH', 'METADATA_REQUEST_OUTPUT_SCOPE', 'METADATA_REQUEST_SOURCE', 'METADATA_REQUEST_SPEC_BOUND', 'METADATA_URL', 'METADATA_URL_ALLOWLIST', 'METADATA_URL_NOT_IN_INDEX', 'ORIGINAL_BODY_BUDGET', 'SELECTED_VERSION_NOT_STABLE', 'UNSUPPORTED_ADVISORY_VERSION', 'VULNERABILITY_INDEX_AMBIGUOUS', 'VULNERABILITY_INDEX_SHAPE', 'VULNERABILITY_PAGE_PARTITION', 'VULNERABILITY_PAGE_SHAPE'), 'public-input': ('PUBLIC_BODY_BUDGET', 'PUBLIC_CHILD', 'PUBLIC_CHILD_IDENTITY', 'PUBLIC_DEADLINE', 'PUBLIC_FILE_CHANGED', 'PUBLIC_FRAME', 'PUBLIC_HASH', 'PUBLIC_IO', 'PUBLIC_MAIN_ALARM', 'PUBLIC_MANIFEST', 'PUBLIC_MODE', 'PUBLIC_PATH', 'PUBLIC_PERIODIC_ALARM', 'PUBLIC_POLICY', 'PUBLIC_RESULT', 'PUBLIC_SIZE', 'PUBLIC_SOURCE', 'PUBLIC_STATUS', 'PUBLIC_TOKEN_CONFIG')}
class WorkspaceError(RuntimeError):pass
def require_workspace(environ,checkout):
 value=environ.get('GITHUB_WORKSPACE')
 if type(value) is not str or not value:raise WorkspaceError('CURATION_PARENT_WORKSPACE_MISSING')
 if value!=str(Path(checkout).resolve()):raise WorkspaceError('CURATION_PARENT_WORKSPACE_MISMATCH')
 return value
def forward_environment(environ,checkout):
 require_workspace(environ,checkout)
 return ['--setenv='+k+'='+environ[k] for k in ENV_NAMES if k in environ]
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def digest(b):return hashlib.sha256(b).hexdigest()
def value_digest(v):
 if type(v) is str and len(v)<=8192 or type(v) is int and abs(v)<10**24 or v is None or type(v) is bool:return digest(canonical(v))
 return 'UNKNOWN_OR_REDACTED'
def context_shape(ctx):
 if type(ctx) is not dict:return {'state':'UNKNOWN_NOT_AVAILABLE'}
 rows=[{'key':k,'present':k in ctx,'type':('str' if type(ctx.get(k)) is str else 'int' if type(ctx.get(k)) is int else 'UNKNOWN_OR_REDACTED'),'valueSHA256':value_digest(ctx[k]) if k in ctx else 'UNKNOWN_NOT_AVAILABLE'} for k in CONTEXT_KEYS]
 return {'state':'STRUCTURAL_CONTEXT_ONLY','keys':rows,'expectedKeyCount':len(CONTEXT_KEYS),'keySetExact':set(ctx)==set(CONTEXT_KEYS),'knownValuesSHA256':digest(canonical(rows))}
def _codes(code):
 result={code}
 for v in code.co_consts:
  if isinstance(v,types.CodeType):result.update(_codes(v))
 return result
class Trace:
 def __init__(self):
  self.bindings={};self.frames={};self.classes={WorkspaceError:'safe-cause'};self.nodes=[];self.seen=set();self.mapped=[];self.chainOmitted=False;self.framesOmitted=False;self.stageHistory=[];self.stageOverflow=False;self.context={'state':'UNKNOWN_NOT_AVAILABLE'};self.identities={};self.clock={};self.caps={};self.saved={};self.httpOperations=[];self.transport={'entered':False,'returned':False,'inputReceiptWritten':False,'HTTPStarted':'UNKNOWN','success':'UNKNOWN','bytes':'UNKNOWN'}
 def bind(self,module,expected,symbol):
  if symbol not in CODE_LITERALS:return False
  path=Path(module.__file__).resolve();raw=path.read_bytes()
  if len(raw)>1048576 or digest(raw)!=expected:return False
  compiled=_codes(compile(raw,str(path),'exec',dont_inherit=True,optimize=sys.flags.optimize));names={}
  def visit(obj):
   if isinstance(obj,types.FunctionType) and obj.__globals__ is module.__dict__ and obj.__code__ in compiled and Path(obj.__code__.co_filename).resolve()==path:
    for code in _codes(obj.__code__):names[code]=(symbol,code.co_name,len(raw.splitlines()))
   elif isinstance(obj,type) and obj.__module__==module.__name__:
    for val in vars(obj).values():
     if isinstance(val,(staticmethod,classmethod)):val=val.__func__
     if isinstance(val,types.FunctionType):visit(val)
  for obj in list(vars(module).values()):visit(obj)
  self.frames.update(names);self.bindings[symbol]={'sha256':expected}
  for name in CLASSES:
   cls=vars(module).get(name)
   if isinstance(cls,type) and cls.__module__==module.__name__ and any(isinstance(n,ast.ClassDef) and n.name==name for n in ast.parse(raw).body):self.classes[cls]=symbol
  return True
 def bind_loaded(self,tools):
  tools=Path(tools).resolve()
  for module in list(sys.modules.values()):
   if not isinstance(module,types.ModuleType):continue
   name=vars(module).get('__file__')
   if type(name) is not str:continue
   p=Path(name)
   if p.parent.resolve()!=tools or p.stem not in FROZEN:continue
   self.bind(module,FROZEN[p.stem],p.stem)
 def observe_http(self,value):
  keys={'inputIndex','operation','category','status','elapsedNs','bodyBytesRead'}
  if type(value) is not dict or set(value)!=keys or type(value['inputIndex']) is not int or not 0<=value['inputIndex']<=2 or value['operation']!='PUBLIC_ORIGINAL_GET' or value['category'] not in ('HTTP_STATUS','TIMEOUT','URL_ERROR','OS_ERROR','SOURCE_FRAME_OR_HASH_HOLD','UNKNOWN_OR_REDACTED') or not(value['status']=='UNKNOWN' or type(value['status']) is int and 100<=value['status']<=599) or type(value['elapsedNs']) is not int or not 0<=value['elapsedNs']<=10**15 or not(value['bodyBytesRead']=='UNKNOWN' or type(value['bodyBytesRead']) is int and 0<=value['bodyBytesRead']<=536936448) or len(self.httpOperations)>=3:raise WorkspaceError('CURATION_HTTP_DIAGNOSTIC_SHAPE')
  self.httpOperations.append(dict(value))
 def mark(self,stage,context=None,spec=None,identities=None,caps=None,now=None):
  if stage not in STAGES:return
  self.currentStage=stage
  if not self.stageHistory or self.stageHistory[-1]!=stage:
   if len(self.stageHistory)<16:self.stageHistory.append(stage)
   else:self.stageOverflow=True
  if context is not None:self.context=context_shape(context)
  if type(spec) is dict:
   for key in ('startTick','supervisorPID'):
    v=spec.get(key)
    if type(v) is int and 0<=v<10**24:self.clock[key]=v
   if type(spec.get('startTick')) is int:self.clock['originalRowEndTick']=spec['startTick']+900000;self.clock['originalWorkerEndTick']=spec['startTick']+840000
  if type(now) is int and 0<=now<10**24:self.clock['observedTick']=now
  if type(identities) is dict:
   for key,length in (('sourceHEAD',40),('sourceTree',40),('profileSHA256',64),('commonSHA256',64),('schemaSHA256',64)):
    v=identities.get(key)
    if type(v) is str and len(v)==length and all(c in '0123456789abcdef' for c in v):self.identities[key]=v
   for key in ('runId','attempt'):
    v=identities.get(key)
    if type(v) is str and 0<len(v)<=20 and all(c in '0123456789' for c in v):self.identities[key]=v
  if type(caps) is dict:
   for key in ('memoryMax','tasksMax','effectiveCpuCores','swapMax'):
    v=caps.get(key)
    if type(v) is int and 0<=v<=10**12 or type(v) is float and 0<=v<=10**12:self.caps[key]=v
  if stage=='commontransport-enter':self.transport['entered']=True
  elif stage=='commontransport-return':self.transport['returned']=True
  elif stage=='inputreceipt-write':self.transport['inputReceiptWritten']=True
 def capture(self,exc,secondary=False):
  if self.nodes and not secondary:return
  role='secondary' if self.nodes else 'primary';node=exc;steps=0
  while isinstance(node,BaseException) and id(node) not in self.seen:
   if len(self.nodes)>=3:self.chainOmitted=True;break
   self.seen.add(id(node));steps+=1;cls=type(node);origin=self.classes.get(cls);kind=cls.__name__ if origin is not None else cls.__name__ if cls in (OSError,FileNotFoundError,PermissionError,TimeoutError,ValueError,KeyError,TypeError,RuntimeError) else 'UNKNOWN_OR_REDACTED';code='UNKNOWN_OR_REDACTED';args=BaseException.args.__get__(node);tb=BaseException.__traceback__.__get__(node);symbols=set();walk=0
   while tb is not None and walk<64:
    walk+=1;entry=self.frames.get(tb.tb_frame.f_code)
    if entry is not None and type(tb.tb_lineno) is int and 0<tb.tb_lineno<=entry[2]:
     symbols.add(entry[0])
     if len(self.mapped)<10:self.mapped.append({'node':len(self.nodes),'module':entry[0],'function':entry[1],'line':tb.tb_lineno})
     else:self.framesOmitted=True
    else:self.framesOmitted=True
    tb=tb.tb_next
   if tb is not None:self.framesOmitted=True
   if origin is not None and len(args)==1 and type(args[0]) is str and any(args[0] in CODE_LITERALS.get(s,()) for s in symbols|{origin}):code=args[0]
   errno=None
   if cls in (OSError,FileNotFoundError,PermissionError,TimeoutError):
    n=OSError.errno.__get__(node)
    if type(n) is int and n in ERRNOS:errno=n
   self.nodes.append({'role':role,'exceptionType':kind,'source':origin or 'UNKNOWN_OR_REDACTED','code':code,'errno':errno});role='cause-or-context' if not secondary else 'secondary-cause-or-context'
   cause=BaseException.__cause__.__get__(node);context=BaseException.__context__.__get__(node);node=cause if cause is not None else context
  if isinstance(node,BaseException):self.chainOmitted=True
 def record(self):
  value={'schema':'producer04-safe-original-cause/v1','state':'ORIGINAL_TYPED_CAUSE_ONLY_NOT_ADMISSION','purpose':PURPOSE,'nodes':self.nodes,'frames':self.mapped,'chainOmittedOrCycle':self.chainOmitted,'framesOmittedOrForeign':self.framesOmitted,'stageHistory':self.stageHistory,'currentStage':getattr(self,'currentStage','bootstrap'),'stageOverflow':self.stageOverflow,'context':self.context,'sourceIdentities':self.identities,'originalClock':self.clock,'observedCaps':self.caps,'transport':self.transport,'httpOperations':self.httpOperations,'SDK_READY':False}
  raw=canonical(value)+b'\n'
  if len(raw)>LIMIT:raise WorkspaceError('CURATION_SAFE_CAUSE_BOUND')
  return raw
 def emit(self,root,environ,checkout,stderr=None):
  raw=self.record()
  if root is None:
   if stderr is not None:stderr.write(raw)
   return False
  try:
   root=Path(root);temp=Path(environ['RUNNER_TEMP']).resolve();expected='admission04-sdk11-linux-'+environ['GITHUB_RUN_ID']+'-'+environ['GITHUB_RUN_ATTEMPT'];s=root.lstat()
   if root.name!=expected or root.parent.resolve()!=temp or root.is_symlink() or not stat.S_ISDIR(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o700 or s.st_uid!=os.getuid() or s.st_gid!=os.getgid():raise WorkspaceError('CURATION_SAFE_ROOT_REQUIRED')
   target=root/'curation-original-cause.json'
   if target.exists():
    previous=self.saved.get(str(target));st=target.lstat()
    if previous is None:return True # another process's original primary is immutable
    if target.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or (st.st_dev,st.st_ino)!=previous[:2] or st.st_size>LIMIT or digest(target.read_bytes())!=previous[2]:raise WorkspaceError('CURATION_SAFE_ROOT_REQUIRED')
    pending=root/'curation-original-cause.pending'
    with pending.open('xb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
    os.replace(pending,target);st=target.stat();self.saved[str(target)]=(st.st_dev,st.st_ino,digest(raw));return True
   flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
   with os.fdopen(os.open(target,flags,0o600),'wb') as out:out.write(raw)
   st=target.stat();self.saved[str(target)]=(st.st_dev,st.st_ino,digest(raw))
   return True
  except (OSError,KeyError,WorkspaceError):
   if stderr is not None:stderr.write(raw)
   return False
STATE=Trace()
