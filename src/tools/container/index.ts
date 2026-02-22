import { PermissionTier } from '../../config.js';
import { ToolDefinition } from '../../types/tool.js';
import { dockerSocketSchema, dockerSocket } from './docker-socket.js';
import { k8sApiSchema, k8sApi } from './k8s-api.js';
import { containerEscapeSchema, containerEscape } from './container-escape.js';
import { registryEnumSchema, registryEnum } from './registry-enum.js';
import { helmAuditSchema, helmAudit } from './helm-audit.js';

export const containerTools: ToolDefinition[] = [
  {
    name: 'vanguard_docker_socket',
    description: 'Check for exposed Docker daemon socket (TCP 2375/2376). DANGEROUS: Active probing.',
    category: 'container',
    permission: PermissionTier.DANGEROUS,
    schema: dockerSocketSchema,
    handler: dockerSocket,
    executionMode: 'native',
    requiresScope: true,
    tags: ['docker', 'socket', 'daemon', 'container'],
  },
  {
    name: 'vanguard_k8s_api',
    description: 'Check Kubernetes API server or Kubelet for unauthenticated access. DANGEROUS: Active probing.',
    category: 'container',
    permission: PermissionTier.DANGEROUS,
    schema: k8sApiSchema,
    handler: k8sApi,
    executionMode: 'native',
    requiresScope: true,
    tags: ['kubernetes', 'k8s', 'api', 'kubelet'],
  },
  {
    name: 'vanguard_container_escape',
    description: 'Check for container escape vectors (docker socket, privileged, capabilities, mounts). DANGEROUS: Active checks in WSL.',
    category: 'container',
    permission: PermissionTier.DANGEROUS,
    schema: containerEscapeSchema,
    handler: containerEscape,
    executionMode: 'wsl',
    wslCommands: ['bash'],
    tags: ['container', 'escape', 'breakout', 'docker'],
  },
  {
    name: 'vanguard_registry_enum',
    description: 'Enumerate container registry repositories and tags (Docker Registry v2). DANGEROUS: Active enumeration.',
    category: 'container',
    permission: PermissionTier.DANGEROUS,
    schema: registryEnumSchema,
    handler: registryEnum,
    executionMode: 'native',
    requiresScope: true,
    tags: ['registry', 'docker', 'container', 'images'],
  },
  {
    name: 'vanguard_helm_audit',
    description: 'Audit Helm chart/values for security issues (privileged, capabilities, secrets, mounts). SAFE: Static analysis.',
    category: 'container',
    permission: PermissionTier.SAFE,
    schema: helmAuditSchema,
    handler: helmAudit,
    executionMode: 'hybrid',
    wslCommands: ['helm'],
    tags: ['helm', 'kubernetes', 'audit', 'security'],
  },
];
