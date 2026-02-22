import { PermissionTier } from '../../config.js';
import { ToolDefinition } from '../../types/tool.js';
import { s3BucketCheckSchema, s3BucketCheck } from './s3-bucket-check.js';
import { azureBlobCheckSchema, azureBlobCheck } from './azure-blob-check.js';
import { gcpBucketCheckSchema, gcpBucketCheck } from './gcp-bucket-check.js';
import { cloudMetadataSchema, cloudMetadata } from './cloud-metadata.js';
import { subdomainTakeoverSchema, subdomainTakeover } from './subdomain-takeover.js';
import { firebaseCheckSchema, firebaseCheck } from './firebase-check.js';
import { cloudEnumSchema, cloudEnum } from './cloud-enum.js';
import { exposedEnvCheckSchema, exposedEnvCheck } from './exposed-env-check.js';

export const cloudTools: ToolDefinition[] = [
  {
    name: 'vanguard_s3_bucket_check',
    description: 'Check AWS S3 bucket for public access, listing, and exposed objects. SAFE: Passive check.',
    category: 'cloud',
    permission: PermissionTier.SAFE,
    schema: s3BucketCheckSchema,
    handler: s3BucketCheck,
    executionMode: 'native',
    tags: ['aws', 's3', 'bucket', 'cloud', 'storage'],
  },
  {
    name: 'vanguard_azure_blob_check',
    description: 'Check Azure Blob Storage containers for public access and listing. SAFE: Passive check.',
    category: 'cloud',
    permission: PermissionTier.SAFE,
    schema: azureBlobCheckSchema,
    handler: azureBlobCheck,
    executionMode: 'native',
    tags: ['azure', 'blob', 'storage', 'cloud'],
  },
  {
    name: 'vanguard_gcp_bucket_check',
    description: 'Check Google Cloud Storage bucket for public access and listing. SAFE: Passive check.',
    category: 'cloud',
    permission: PermissionTier.SAFE,
    schema: gcpBucketCheckSchema,
    handler: gcpBucketCheck,
    executionMode: 'native',
    tags: ['gcp', 'gcs', 'bucket', 'cloud', 'storage'],
  },
  {
    name: 'vanguard_cloud_metadata',
    description: 'Test for SSRF access to cloud metadata endpoints (AWS, GCP, Azure). DANGEROUS: Active SSRF testing.',
    category: 'cloud',
    permission: PermissionTier.DANGEROUS,
    schema: cloudMetadataSchema,
    handler: cloudMetadata,
    executionMode: 'native',
    requiresScope: true,
    tags: ['ssrf', 'metadata', 'imds', 'cloud', 'aws', 'gcp', 'azure'],
  },
  {
    name: 'vanguard_subdomain_takeover',
    description: 'Check subdomains for takeover via dangling CNAME records (GitHub, Heroku, S3, Azure, etc). DANGEROUS: Active probing.',
    category: 'cloud',
    permission: PermissionTier.DANGEROUS,
    schema: subdomainTakeoverSchema,
    handler: subdomainTakeover,
    executionMode: 'native',
    requiresScope: true,
    tags: ['subdomain', 'takeover', 'cname', 'dns'],
  },
  {
    name: 'vanguard_firebase_check',
    description: 'Check Firebase project for exposed Firestore, Realtime DB, Storage, and Functions. SAFE: Passive check.',
    category: 'cloud',
    permission: PermissionTier.SAFE,
    schema: firebaseCheckSchema,
    handler: firebaseCheck,
    executionMode: 'native',
    tags: ['firebase', 'firestore', 'gcp', 'database', 'cloud'],
  },
  {
    name: 'vanguard_cloud_enum',
    description: 'Enumerate cloud resources (S3, Azure Blob, GCS) by keyword permutations. SAFE: Passive enumeration.',
    category: 'cloud',
    permission: PermissionTier.SAFE,
    schema: cloudEnumSchema,
    handler: cloudEnum,
    executionMode: 'native',
    tags: ['cloud', 'enum', 'discovery', 's3', 'azure', 'gcp'],
  },
  {
    name: 'vanguard_exposed_env_check',
    description: 'Check for exposed .env, config, git, and sensitive files on a web server. DANGEROUS: Active probing.',
    category: 'cloud',
    permission: PermissionTier.DANGEROUS,
    schema: exposedEnvCheckSchema,
    handler: exposedEnvCheck,
    executionMode: 'native',
    requiresScope: true,
    tags: ['env', 'config', 'exposed', 'git', 'sensitive-files'],
  },
];
