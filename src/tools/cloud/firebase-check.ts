import { z } from 'zod';

export const firebaseCheckSchema = z.object({
  project: z.string().describe('Firebase project ID to check'),
  timeout: z.number().default(10000).describe('Per-request timeout in milliseconds'),
});

export type FirebaseCheckInput = z.infer<typeof firebaseCheckSchema>;

interface FirebaseResult {
  check: string;
  url: string;
  accessible: boolean;
  details?: string;
}

export async function firebaseCheck(input: FirebaseCheckInput): Promise<{
  success: boolean;
  project: string;
  results: FirebaseResult[];
  vulnerable: boolean;
  error?: string;
}> {
  const { project, timeout } = input;
  const results: FirebaseResult[] = [];

  // Check Firestore REST API (unauthenticated read)
  const firestoreUrl = `https://firestore.googleapis.com/v1/projects/${project}/databases/(default)/documents`;
  results.push(await checkEndpoint(firestoreUrl, 'Firestore REST API', timeout, ['documents', 'fields']));

  // Check Realtime Database
  const rtdbUrl = `https://${project}-default-rtdb.firebaseio.com/.json`;
  results.push(await checkEndpoint(rtdbUrl, 'Realtime Database', timeout, ['{']));

  // Check Firebase Hosting
  const hostingUrl = `https://${project}.web.app/`;
  results.push(await checkEndpoint(hostingUrl, 'Firebase Hosting', timeout, ['<!DOCTYPE', '<html']));

  // Check Firebase Storage
  const storageUrl = `https://firebasestorage.googleapis.com/v0/b/${project}.appspot.com/o`;
  results.push(await checkEndpoint(storageUrl, 'Firebase Storage', timeout, ['items', 'prefixes']));

  // Check Cloud Functions
  const functionsUrl = `https://us-central1-${project}.cloudfunctions.net/`;
  results.push(await checkEndpoint(functionsUrl, 'Cloud Functions (us-central1)', timeout, []));

  return {
    success: true,
    project,
    results,
    vulnerable: results.some(r => r.accessible && (r.check.includes('Firestore') || r.check.includes('Realtime') || r.check.includes('Storage'))),
  };
}

async function checkEndpoint(
  url: string,
  check: string,
  timeout: number,
  indicators: string[],
): Promise<FirebaseResult> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      headers: { 'User-Agent': 'mcp-vanguard/2.0' },
      signal: controller.signal,
    });
    clearTimeout(timer);

    const body = await response.text();
    const accessible = response.status === 200;
    const hasData = indicators.length === 0
      ? accessible
      : indicators.some(ind => body.includes(ind));

    return {
      check,
      url,
      accessible: accessible && hasData,
      details: accessible && hasData
        ? `Accessible (${response.status}). Data preview: ${body.slice(0, 200)}`
        : `Status ${response.status}`,
    };
  } catch {
    return { check, url, accessible: false, details: 'Unreachable' };
  }
}
