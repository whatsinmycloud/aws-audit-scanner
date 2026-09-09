export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export type Finding = {
  service: string;
  resourceId: string;
  region: string;
  severity: Severity;
  title: string;
  description: string;
  fixSteps: string[];
  estimatedFixMinutes: number;
  estimatedMonthlySavingsUsd?: number;
};

// Temporary credentials from STS AssumeRole. Structurally compatible with the
// AWS SDK's AwsCredentialIdentity, so it can be passed straight to any client.
export type AwsCredentials = {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
};

export type ScanInput = {
  region: string;
  // Omitted = default credential chain (the account the scanner runs in).
  // Provided = scan a customer account via its WhatsInMyCloudAudit role.
  credentials?: AwsCredentials | undefined;
};

export type ScanResult =
  | { ok: true; findings: Finding[] }
  | { ok: false; error: string };
