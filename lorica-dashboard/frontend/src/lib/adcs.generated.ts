// Rendered from Rust by lorica-api/tests/adcs_vocabulary_fixture.rs, which prints
// the whole file as it must read when the committed one differs. Replace the file
// with that output; never edit it by hand.

/** An alert type, as a notification channel subscribes to it. */
export type AlertType = 'cert_expiring' | 'backend_down' | 'waf_alert' | 'config_changed' | 'sla_breached' | 'sla_recovered' | 'ip_banned' | 'cluster_node_left' | 'cluster_config_refused' | 'cluster_drift' | 'log_store_unavailable' | 'log_store_recovered' | 'adcs_authority_failed' | 'cert_issuance_failed';

/** How an alert reads at a glance. */
export type AlertTone = 'problem' | 'recovery' | 'warning' | 'info';

/**
 * One alert type: its label, its tone, and the alert it closes when it is a
 * recovery (a channel subscribed to one is meant to receive the other).
 */
export interface AlertTypeDefinition {
  readonly value: AlertType;
  readonly label: string;
  readonly tone: AlertTone;
  readonly recovers: AlertType | null;
}

/** Every alert type, in `AlertType::ALL` order. */
export const ALERT_TYPES: readonly AlertTypeDefinition[] = [
  { value: 'cert_expiring', label: 'Certificate expiring', tone: 'warning', recovers: null },
  { value: 'backend_down', label: 'Backend down', tone: 'problem', recovers: null },
  { value: 'waf_alert', label: 'WAF alert', tone: 'info', recovers: null },
  { value: 'config_changed', label: 'Configuration changed', tone: 'info', recovers: null },
  { value: 'sla_breached', label: 'SLA breached', tone: 'problem', recovers: null },
  { value: 'sla_recovered', label: 'SLA recovered', tone: 'recovery', recovers: 'sla_breached' },
  { value: 'ip_banned', label: 'IP banned', tone: 'info', recovers: null },
  { value: 'cluster_node_left', label: 'Cluster node left', tone: 'warning', recovers: null },
  { value: 'cluster_config_refused', label: 'Cluster configuration refused', tone: 'problem', recovers: null },
  { value: 'cluster_drift', label: 'Cluster drift', tone: 'warning', recovers: null },
  { value: 'log_store_unavailable', label: 'Log persistence lost', tone: 'problem', recovers: null },
  { value: 'log_store_recovered', label: 'Log persistence restored', tone: 'recovery', recovers: 'log_store_unavailable' },
  { value: 'adcs_authority_failed', label: 'AD CS authority failed', tone: 'problem', recovers: null },
  { value: 'cert_issuance_failed', label: 'Certificate issuance failed', tone: 'problem', recovers: null },
];

/** Where a certificate comes from (`CertificateSource`). */
export type CertificateSource = 'acme' | 'adcs' | 'manual';

export const CERTIFICATE_SOURCE_LABELS: Readonly<Record<CertificateSource, string>> = {
  acme: 'ACME',
  adcs: 'AD CS',
  manual: 'Manual',
};

/** The key an AD CS certificate is generated with (`AdcsKeyType`). */
export type AdcsKeyType = 'rsa2048' | 'rsa3072' | 'ecdsa_p256';

export const ADCS_KEY_TYPE_LABELS: Readonly<Record<AdcsKeyType, string>> = {
  rsa2048: 'RSA 2048',
  rsa3072: 'RSA 3072',
  ecdsa_p256: 'ECDSA P-256',
};

/** A field of the subject an AD CS request carries (`AdcsSubjectDefaults`). */
export type AdcsSubjectField = 'country' | 'state' | 'locality' | 'organization' | 'organizational_unit' | 'email';

export const ADCS_SUBJECT_FIELD_LABELS: Readonly<Record<AdcsSubjectField, string>> = {
  country: 'Country (C)',
  state: 'State or province (ST)',
  locality: 'Locality (L)',
  organization: 'Organization (O)',
  organizational_unit: 'Organizational unit (OU)',
  email: 'Email',
};

/**
 * The step an AD CS operation failed at: the client's (`FailureStep`), then
 * the issuance's (`IssuanceStep`). `error.step`, audit rows and alerts carry it.
 */
export type AdcsFailureStep = 'kdc_discovery' | 'ticket_acquisition' | 'spnego' | 'mutual_authentication' | 'channel_binding' | 'tls' | 'http' | 'krb5_conf' | 'configuration' | 'csr' | 'soap' | 'chain' | 'timeout' | 'gss_task' | 'fault_permission' | 'fault_template' | 'fault_other' | 'denied' | 'pending' | 'certificate_profile' | 'san_coverage' | 'certificate' | 'store' | 'subject' | 'san_refused' | 'template_refused';

export const ADCS_FAILURE_STEP_LABELS: Readonly<Record<AdcsFailureStep, string>> = {
  kdc_discovery: 'KDC discovery',
  ticket_acquisition: 'Ticket acquisition',
  spnego: 'SPNEGO',
  mutual_authentication: 'Mutual authentication',
  channel_binding: 'Channel binding',
  tls: 'TLS connection',
  http: 'HTTP exchange',
  krb5_conf: 'Kerberos configuration',
  configuration: 'Connection parameters',
  csr: 'Certificate request',
  soap: 'SOAP message',
  chain: 'Certificate chain',
  timeout: 'Timeout',
  gss_task: 'Kerberos task',
  fault_permission: 'Authority fault: permission',
  fault_template: 'Authority fault: template',
  fault_other: 'Authority fault',
  denied: 'Denied by the authority',
  pending: 'Pending at the authority',
  certificate_profile: 'Issued certificate profile',
  san_coverage: 'Issued certificate names',
  certificate: 'Issued certificate',
  store: 'Storing the certificate',
  subject: 'Renewal request',
  san_refused: 'Renewal names refused',
  template_refused: 'Renewal template refused',
};

/** The KDC error codes that open the failed state, and what each means. */
export const ADCS_KDC_CODE_MEANINGS: Readonly<Record<number, string>> = {
  18: 'the account is disabled or locked out',
  23: 'the password has expired',
  24: 'the password is wrong',
  31: 'the password is wrong (the account does not require pre-authentication)',
};

/** A code an AD CS endpoint answers with in `error.code`. */
export type AdcsErrorCode = 'adcs_not_configured' | 'adcs_no_issuing_ca' | 'adcs_failed_state' | 'adcs_busy' | 'adcs_san_refused' | 'adcs_template_refused' | 'adcs_denied' | 'adcs_error' | 'adcs_krb5_conf' | 'adcs_not_candidate' | 'adcs_certificate_managed' | 'adcs_key_not_exportable' | 'adcs_renewal_not_on_automation_plane' | 'gateway_timeout';

export interface AdcsErrorCodeDefinition {
  readonly code: AdcsErrorCode;
  readonly status: number;
  readonly meaning: string;
}

/** Every AD CS error code, with the status every endpoint answers it with. */
export const ADCS_ERROR_CODES: readonly AdcsErrorCodeDefinition[] = [
  { code: 'adcs_not_configured', status: 409, meaning: 'No AD CS authority is configured, or it has no service account password' },
  { code: 'adcs_no_issuing_ca', status: 409, meaning: 'The authority does not know its issuing CA certificate, so no certificate can be verified as its own' },
  { code: 'adcs_failed_state', status: 409, meaning: 'The KDC rejected the service account\'s credential; every AD CS operation is suspended until a SuperAdmin saves a new password' },
  { code: 'adcs_busy', status: 409, meaning: 'Another AD CS operation is running' },
  { code: 'adcs_san_refused', status: 422, meaning: 'A requested name is a wildcard, is not under an allowed suffix, or the list is empty or too long' },
  { code: 'adcs_template_refused', status: 422, meaning: 'The requested template is not one the authority allows' },
  { code: 'adcs_denied', status: 422, meaning: 'The authority denied the request under its policy' },
  { code: 'adcs_error', status: 502, meaning: 'The authority answered with a fault, a step of the exchange failed, or the issued certificate was refused; error.step names the step' },
  { code: 'adcs_krb5_conf', status: 500, meaning: 'The generated krb5.conf could not be written; the log names the path and the cause' },
  { code: 'adcs_not_candidate', status: 422, meaning: 'The certificate is not manual, was not signed by the issuing CA, or has a name a renewal could not request' },
  { code: 'adcs_certificate_managed', status: 409, meaning: 'An AD CS certificate\'s PEM, key and domain cannot be replaced; revert it to manual first' },
  { code: 'adcs_key_not_exportable', status: 403, meaning: 'The private key of an AD CS certificate never leaves Lorica' },
  { code: 'adcs_renewal_not_on_automation_plane', status: 403, meaning: 'AD CS certificates are renewed by the background loop and the dashboard only, never by a token' },
  { code: 'gateway_timeout', status: 504, meaning: 'The operation outlived the request and is still finishing; its outcome is audited when it ends' },
];

/** Why an adoption candidate listing is empty without looking. */
export type AdoptionUnavailableReason = 'not_configured' | 'no_issuing_ca' | 'managed_on_control_plane';
