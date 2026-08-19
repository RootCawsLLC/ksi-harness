import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

/**
 * Where the evidence locker actually lives, and whether it can be deleted.
 *
 * Everything built so far protects the locker against *alteration*. The chain means an
 * edited bundle invalidates every bundle after it; the manifest pins the chain heads; cosign
 * binds the manifest to a workflow identity; an RFC 3161 token binds it to a time. All four
 * are real, and all four are anchored inside `.evidence/` — which means they protect the
 * artifact against everything except being removed.
 *
 * That gap is not theoretical. Delete two-thirds of a check's history, regenerate the
 * manifest, and `ksi verify` reports "every bundle verifies and every chain is intact",
 * because a chain proves the consistency of what remains and can say nothing about what is
 * gone. The signed manifest would catch it — but the signed manifest is in the same
 * directory as the bundles, so whoever deleted them deletes it too.
 *
 * Two fixes, and this module is the first: make deletion *impossible* by putting the locker
 * in write-once storage. The second is `anchor.mjs`, which makes deletion *detectable* by
 * recording each manifest root somewhere the deleter does not control.
 *
 * The load-bearing decision here is that **a backend claiming immutability has to prove it**.
 * `assertImmutable()` reads the bucket's retention configuration and refuses to publish when
 * it is absent or unlocked. A tool that wrote to an ordinary bucket and called the result an
 * immutable evidence vault would be making exactly the unverified claim this repository
 * exists to refuse — and it is a easy claim to make by accident, because writing to a bucket
 * with Object Lock and writing to one without look identical from the client.
 */

/** What a backend guarantees, stated rather than implied. */
export const DURABILITY = Object.freeze({
  NONE: 'none',
  VERSIONED: 'versioned',
  WORM: 'write-once',
});

/* -------------------------------------------------------------- the refusals */

/**
 * Errors that mean the question was never answered, rather than answered "no".
 *
 * The same distinction the GCP collectors draw out of a 403. A bucket that genuinely has no
 * Object Lock and a bucket nobody had credentials to ask about are different facts, and only
 * the first is a statement about the store. Conflating them sends someone to recreate a
 * bucket that was fine — and lets a correctly configured store be written up as broken.
 */
const UNANSWERED = new Set([
  'CredentialsProviderError',
  'ExpiredToken',
  'ExpiredTokenException',
  'InvalidAccessKeyId',
  'SignatureDoesNotMatch',
  'AccessDenied',
  'AccessDeniedException',
  'UnrecognizedClientException',
  'NetworkingError',
  'TimeoutError',
  'ENOTFOUND',
  'ECONNREFUSED',
]);

/** Whether an SDK error means "could not ask" rather than "asked, and the answer was no". */
export function isUnanswered(errorName) {
  return UNANSWERED.has(errorName);
}

/**
 * Why an S3 bucket is not write-once, given what the API said about it.
 *
 * Separated from the call that fetches it so the decision can be falsified. The refusal *is*
 * the feature here — a tool that published to an ordinary bucket and called the result an
 * evidence vault would be making the unverified claim this repository exists to refuse — and
 * a refusal only reachable through a live AWS call is a refusal nothing can prove still works.
 *
 * @returns an array of problems. Empty means the bucket is genuinely write-once.
 */
export function s3RetentionProblems(lockConfiguration, versioning) {
  const problems = [];
  const rule = lockConfiguration?.ObjectLockConfiguration?.Rule?.DefaultRetention;

  if (lockConfiguration?.ObjectLockConfiguration?.ObjectLockEnabled !== 'Enabled') {
    problems.push('Object Lock is not enabled on the bucket');
  }
  if (!rule) {
    problems.push('no default retention rule, so an object written without an explicit retention is deletable');
  } else if (rule.Mode !== 'COMPLIANCE') {
    // The one that matters. GOVERNANCE looks identical in a package and in every console
    // screenshot, and is lifted by a single permission.
    problems.push(
      `default retention is ${rule.Mode} mode, which a principal holding s3:BypassGovernanceRetention can ` +
        `override — a retention an administrator can lift does not survive an administrator being the problem`
    );
  }
  if (versioning?.Status !== 'Enabled') {
    problems.push('versioning is not enabled, and Object Lock requires it');
  }
  return problems;
}

/** The same decision for a GCS bucket, from its metadata. */
export function gcsRetentionProblems(metadata, retentionDaysRequired) {
  const policy = metadata?.retentionPolicy;
  if (!policy) return ['no retention policy is configured'];

  const problems = [];
  if (!policy.isLocked) {
    // GCS has no separate "mode": an unlocked policy is simply removable by whoever set it,
    // which is the same failure as GOVERNANCE wearing different words.
    problems.push(
      'the retention policy is not locked, so anyone with storage.buckets.update can shorten or remove it — ' +
        'an unlocked policy is a default rather than a guarantee'
    );
  }
  const days = Number(policy.retentionPeriod ?? 0) / 86400;
  if (days < retentionDaysRequired) {
    problems.push(`retention is ${days} day(s), below the ${retentionDaysRequired} required by the profile`);
  }
  return problems;
}

/* ------------------------------------------------------------------ filesystem */

/**
 * The local directory. Makes no durability claim, and says so.
 *
 * Correct for development, for fixture runs, and as the working copy that a durable backend
 * is published from. It is not evidence storage, and `describe()` reports that so a coverage
 * report generated from it cannot imply otherwise.
 */
export function filesystemStore({ dir }) {
  return {
    kind: 'filesystem',
    location: dir,
    durability: DURABILITY.NONE,
    describe: () => ({
      kind: 'filesystem',
      location: dir,
      durability: DURABILITY.NONE,
      immutable: false,
      why: 'A local directory. Anything with write access can alter or delete it, including this process.',
    }),
    async assertImmutable() {
      throw new Error(
        `The evidence store is a local directory (${dir}), which guarantees nothing about retention. ` +
          `Anything that can write there can delete the locker and the manifest that would have proved it ` +
          `existed. Declare evidence.store in the profile with an s3 or gcs backend for a real boundary.`
      );
    },
    async publish() {
      return { published: 0, note: 'filesystem store; nothing to publish' };
    },
    async restore() {
      return { restored: existsSync(dir) };
    },
  };
}

/* -------------------------------------------------------------------------- s3 */

/**
 * S3 with Object Lock in COMPLIANCE mode.
 *
 * COMPLIANCE rather than GOVERNANCE deliberately. GOVERNANCE mode can be overridden by a
 * principal holding `s3:BypassGovernanceRetention`, which means the retention is a policy
 * rather than a property — and a retention an administrator can lift is exactly the thing
 * that fails when an administrator is the problem. `assertImmutable` therefore refuses a
 * bucket configured for GOVERNANCE, which will be an unwelcome surprise to somebody and is
 * the right refusal.
 */
export function s3Store({ bucket, prefix = '', region = 'us-east-1', retainUntil = null }) {
  let cached = null;
  async function client() {
    if (cached) return cached;
    let sdk;
    try {
      sdk = await import('@aws-sdk/client-s3');
    } catch {
      throw new Error('@aws-sdk/client-s3 is not installed. Run: npm install @aws-sdk/client-s3');
    }
    cached = { sdk, s3: new sdk.S3Client({ region }) };
    return cached;
  }

  const key = (relativePath) => `${prefix ? `${prefix.replace(/\/$/, '')}/` : ''}${relativePath.split('\\').join('/')}`;

  return {
    kind: 's3',
    location: `s3://${bucket}/${prefix}`,
    durability: DURABILITY.WORM,

    describe: () => ({
      kind: 's3',
      location: `s3://${bucket}/${prefix}`,
      durability: DURABILITY.WORM,
      immutable: true,
      why: 'S3 Object Lock in COMPLIANCE mode. Objects cannot be deleted or overwritten before their retain-until date, including by the account root.',
    }),

    /**
     * Confirms the bucket is actually write-once before anything relies on it being so.
     *
     * Three separate things have to hold, and a bucket can satisfy two of them while being
     * freely deletable, which is why each is checked and named individually.
     */
    async assertImmutable() {
      const { sdk, s3 } = await client();

      let lock;
      try {
        lock = await s3.send(new sdk.GetObjectLockConfigurationCommand({ Bucket: bucket }));
      } catch (err) {
        // "The bucket has no Object Lock" and "this run could not ask" are different facts,
        // and only the first is a statement about the bucket. Reporting a missing credential
        // as a durability finding sends someone to recreate a bucket that may be correct —
        // and, worse, would let a working store look broken in a report.
        if (UNANSWERED.has(err.name)) {
          throw new Error(
            `s3://${bucket} could not be reached to check its Object Lock configuration (${err.name}). ` +
              `This says nothing about the bucket: it is a credentials or connectivity failure, not a ` +
              `durability finding. Fix the credential and run again.`
          );
        }
        throw new Error(
          `s3://${bucket} has no Object Lock configuration (${err.name}). Object Lock can only be enabled at ` +
            `bucket creation, so this bucket cannot be made write-once — create a new one with ` +
            `ObjectLockEnabledForBucket and republish to it.`
        );
      }

      const versioning = await s3.send(new sdk.GetBucketVersioningCommand({ Bucket: bucket }));
      const rule = lock?.ObjectLockConfiguration?.Rule?.DefaultRetention;
      const problems = s3RetentionProblems(lock, versioning);

      if (problems.length) {
        throw new Error(`s3://${bucket} is not write-once:\n  - ${problems.join('\n  - ')}`);
      }
      return { ok: true, mode: rule.Mode, days: rule.Days ?? null, years: rule.Years ?? null };
    },

    /**
     * Uploads every local object that is not already present. Never overwrites, never deletes.
     *
     * An object that already exists is skipped rather than re-put: under Object Lock a
     * re-put creates a new version rather than failing, which would quietly double the
     * storage and make the version history misleading about how often evidence changed.
     */
    async publish(localDir) {
      const { sdk, s3 } = await client();
      await this.assertImmutable();

      const files = walkFiles(localDir);
      let published = 0;
      const skipped = [];

      for (const file of files) {
        const objectKey = key(relative(localDir, file));
        try {
          await s3.send(new sdk.HeadObjectCommand({ Bucket: bucket, Key: objectKey }));
          skipped.push(objectKey);
          continue;
        } catch (err) {
          if (err.name !== 'NotFound' && err.$metadata?.httpStatusCode !== 404) throw err;
        }
        await s3.send(
          new sdk.PutObjectCommand({
            Bucket: bucket,
            Key: objectKey,
            Body: readFileSync(file),
            ...(retainUntil ? { ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: new Date(retainUntil) } : {}),
          })
        );
        published += 1;
      }
      return { published, skipped: skipped.length, location: `s3://${bucket}/${prefix}` };
    },

    async restore(localDir) {
      const { sdk, s3 } = await client();
      let token;
      let restored = 0;
      do {
        const page = await s3.send(
          new sdk.ListObjectsV2Command({ Bucket: bucket, Prefix: prefix || undefined, ContinuationToken: token })
        );
        for (const object of page.Contents ?? []) {
          const target = join(localDir, object.Key.slice(prefix ? prefix.length + 1 : 0));
          const body = await s3.send(new sdk.GetObjectCommand({ Bucket: bucket, Key: object.Key }));
          mkdirSync(dirname(target), { recursive: true });
          writeFileSync(target, Buffer.from(await body.Body.transformToByteArray()));
          restored += 1;
        }
        token = page.NextContinuationToken;
      } while (token);
      return { restored };
    },
  };
}

/* ------------------------------------------------------------------------- gcs */

/**
 * Cloud Storage with a locked bucket retention policy.
 *
 * The GCS equivalent of COMPLIANCE mode is a retention policy that has been *locked*: an
 * unlocked policy can be shortened or removed by anyone with `storage.buckets.update`, which
 * makes it a default rather than a guarantee. `assertImmutable` requires `isLocked`.
 *
 * Plain REST rather than @google-cloud/storage, matching the GCP collectors — one optional
 * dependency for the token instead of another client library.
 */
export function gcsStore({ bucket, prefix = '', retentionDaysRequired = 1 }) {
  const base = 'https://storage.googleapis.com/storage/v1';
  const upload = 'https://storage.googleapis.com/upload/storage/v1';
  const key = (relativePath) => `${prefix ? `${prefix.replace(/\/$/, '')}/` : ''}${relativePath.split('\\').join('/')}`;

  async function token() {
    const { accessToken } = await import('../collectors/lib/gcp.mjs');
    return accessToken();
  }

  return {
    kind: 'gcs',
    location: `gs://${bucket}/${prefix}`,
    durability: DURABILITY.WORM,

    describe: () => ({
      kind: 'gcs',
      location: `gs://${bucket}/${prefix}`,
      durability: DURABILITY.WORM,
      immutable: true,
      why: 'Cloud Storage with a locked bucket retention policy. Objects cannot be deleted before their retention period elapses, and the policy itself cannot be shortened.',
    }),

    async assertImmutable() {
      const auth = await token();
      const res = await fetch(`${base}/b/${bucket}`, { headers: { authorization: `Bearer ${auth}` } });
      if (!res.ok) throw new Error(`gs://${bucket} could not be read (HTTP ${res.status}).`);
      const meta = await res.json();

      const policy = meta.retentionPolicy;
      const problems = gcsRetentionProblems(meta, retentionDaysRequired);
      if (problems.length) throw new Error(`gs://${bucket} is not write-once:\n  - ${problems.join('\n  - ')}`);
      return { ok: true, locked: true, days: Number(policy.retentionPeriod) / 86400 };
    },

    async publish(localDir) {
      const auth = await token();
      await this.assertImmutable();

      let published = 0;
      let skipped = 0;
      for (const file of walkFiles(localDir)) {
        const objectKey = key(relative(localDir, file));
        const head = await fetch(`${base}/b/${bucket}/o/${encodeURIComponent(objectKey)}`, {
          headers: { authorization: `Bearer ${auth}` },
        });
        if (head.ok) {
          skipped += 1;
          continue;
        }
        const put = await fetch(
          `${upload}/b/${bucket}/o?uploadType=media&name=${encodeURIComponent(objectKey)}`,
          {
            method: 'POST',
            headers: { authorization: `Bearer ${auth}`, 'content-type': 'application/octet-stream' },
            body: readFileSync(file),
          }
        );
        if (!put.ok) throw new Error(`Uploading ${objectKey} failed with HTTP ${put.status}.`);
        published += 1;
      }
      return { published, skipped, location: `gs://${bucket}/${prefix}` };
    },

    async restore(localDir) {
      const auth = await token();
      let pageToken;
      let restored = 0;
      do {
        const url = new URL(`${base}/b/${bucket}/o`);
        if (prefix) url.searchParams.set('prefix', prefix);
        if (pageToken) url.searchParams.set('pageToken', pageToken);
        const res = await fetch(url, { headers: { authorization: `Bearer ${auth}` } });
        if (!res.ok) throw new Error(`Listing gs://${bucket} failed with HTTP ${res.status}.`);
        const body = await res.json();
        for (const object of body.items ?? []) {
          const media = await fetch(`${base}/b/${bucket}/o/${encodeURIComponent(object.name)}?alt=media`, {
            headers: { authorization: `Bearer ${auth}` },
          });
          if (!media.ok) throw new Error(`Downloading ${object.name} failed with HTTP ${media.status}.`);
          const target = join(localDir, object.name.slice(prefix ? prefix.length + 1 : 0));
          mkdirSync(dirname(target), { recursive: true });
          writeFileSync(target, Buffer.from(await media.arrayBuffer()));
          restored += 1;
        }
        pageToken = body.nextPageToken;
      } while (pageToken);
      return { restored };
    },
  };
}

/* ------------------------------------------------------------------- resolution */

export function walkFiles(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...walkFiles(path));
    else out.push(path);
  }
  return out.sort();
}

/**
 * Builds the store the profile declares.
 *
 * Defaults to the filesystem, which is the honest default: a tool cannot know that an
 * undeclared store is durable, and assuming one would be the claim this module exists to
 * prevent. The default reports `durability: none` everywhere it surfaces.
 */
export function resolveStore(profile, { dir = '.evidence' } = {}) {
  const declared = profile?.evidence?.store;
  if (!declared || declared.kind === 'filesystem') return filesystemStore({ dir });

  if (declared.kind === 's3') {
    if (!declared.bucket) throw new Error('evidence.store.kind is s3 but no bucket is declared.');
    return s3Store({
      bucket: declared.bucket,
      prefix: declared.prefix ?? '',
      region: declared.region ?? 'us-east-1',
      retainUntil: declared.retain_until ?? null,
    });
  }
  if (declared.kind === 'gcs') {
    if (!declared.bucket) throw new Error('evidence.store.kind is gcs but no bucket is declared.');
    return gcsStore({
      bucket: declared.bucket,
      prefix: declared.prefix ?? '',
      retentionDaysRequired: declared.retention_days ?? 1,
    });
  }
  throw new Error(`Unknown evidence.store.kind "${declared.kind}". Known: filesystem, s3, gcs.`);
}
