import { PermissionTier } from '../../config.js';
import { ToolDefinition } from '../../types/tool.js';
import { hashIdentifySchema, hashIdentify } from './hash-identify.js';
import { hashCrackSchema, hashCrack } from './hash-crack.js';
import { passwordPolicySchema, passwordPolicy } from './password-policy.js';
import { jwtDecodeSchema, jwtDecode } from './jwt-decode.js';
import { jwtAttackSchema, jwtAttack } from './jwt-attack.js';
import { cryptoAuditSchema, cryptoAudit } from './crypto-audit.js';
import { passwordGenSchema, passwordGen } from './password-gen.js';
import { baseDecodeSchema, baseDecode } from './base-decode.js';

export const cryptoTools: ToolDefinition[] = [
  {
    name: 'vanguard_hash_identify',
    description: 'Identify hash type from a hash string (MD5, SHA, bcrypt, NTLM, etc). SAFE: Offline analysis.',
    category: 'crypto',
    permission: PermissionTier.SAFE,
    schema: hashIdentifySchema,
    handler: hashIdentify,
    executionMode: 'native',
    tags: ['hash', 'identify', 'md5', 'sha', 'bcrypt', 'ntlm'],
  },
  {
    name: 'vanguard_hash_crack',
    description: 'Crack password hashes using John the Ripper with wordlists. DANGEROUS: Requires WSL + john.',
    category: 'crypto',
    permission: PermissionTier.DANGEROUS,
    schema: hashCrackSchema,
    handler: hashCrack,
    executionMode: 'wsl',
    wslCommands: ['john'],
    tags: ['hash', 'crack', 'john', 'password', 'wordlist'],
  },
  {
    name: 'vanguard_password_policy',
    description: 'Analyze password strength: entropy, crack time, policy compliance checks. SAFE: Offline analysis.',
    category: 'crypto',
    permission: PermissionTier.SAFE,
    schema: passwordPolicySchema,
    handler: passwordPolicy,
    executionMode: 'native',
    tags: ['password', 'policy', 'strength', 'entropy'],
  },
  {
    name: 'vanguard_jwt_decode',
    description: 'Decode JWT token: header, payload, security issues, expiration. SAFE: Offline analysis.',
    category: 'crypto',
    permission: PermissionTier.SAFE,
    schema: jwtDecodeSchema,
    handler: jwtDecode,
    executionMode: 'native',
    tags: ['jwt', 'decode', 'token', 'auth'],
  },
  {
    name: 'vanguard_jwt_attack',
    description: 'Test JWT for vulnerabilities: none algorithm, weak secrets, algorithm confusion. DANGEROUS: Offensive tool.',
    category: 'crypto',
    permission: PermissionTier.DANGEROUS,
    schema: jwtAttackSchema,
    handler: jwtAttack,
    executionMode: 'native',
    tags: ['jwt', 'attack', 'none-alg', 'brute-force'],
  },
  {
    name: 'vanguard_crypto_audit',
    description: 'Audit HTTPS/TLS security: headers, HSTS, CSP, cookies, info disclosure. SAFE: Passive analysis.',
    category: 'crypto',
    permission: PermissionTier.SAFE,
    schema: cryptoAuditSchema,
    handler: cryptoAudit,
    executionMode: 'native',
    requiresScope: true,
    tags: ['tls', 'ssl', 'headers', 'hsts', 'csp', 'audit'],
  },
  {
    name: 'vanguard_password_gen',
    description: 'Generate secure passwords (random) or targeted wordlists (CeWL spider). DANGEROUS for wordlist mode.',
    category: 'crypto',
    permission: PermissionTier.DANGEROUS,
    schema: passwordGenSchema,
    handler: passwordGen,
    executionMode: 'hybrid',
    wslCommands: ['cewl'],
    tags: ['password', 'generator', 'wordlist', 'cewl'],
  },
  {
    name: 'vanguard_base_decode',
    description: 'Decode/encode strings: Base64, hex, URL, HTML entities, Unicode. Auto-detection mode. SAFE: Offline utility.',
    category: 'crypto',
    permission: PermissionTier.SAFE,
    schema: baseDecodeSchema,
    handler: baseDecode,
    executionMode: 'native',
    tags: ['base64', 'hex', 'decode', 'encode', 'url', 'encoding'],
  },
];
