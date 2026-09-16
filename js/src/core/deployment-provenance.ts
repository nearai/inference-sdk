import * as v from 'valibot';
import { parse } from 'yaml';
import {
  DeploymentAppComposeSchema,
  DeploymentDockerComposeSchema,
} from '../schemas';
import type {
  DeploymentAppCompose,
  DeploymentDockerCompose,
  ImageProvenancePolicy,
  VerifyDeploymentImageProvenanceParams,
} from '../types/provenance';
import { ApiError, VerificationError } from '../utils/errors';
import { fetchImageProvenance, verifyImageProvenance } from './provenance';

type RequiredImage = {
  repository: string;
  digest: string;
  policy: ImageProvenancePolicy;
};

/**
 * Check the build provenance of every configured image repository in appCompose.
 * Use in a deployment verifier, after attestation verification has authenticated
 * appCompose. This helper does not verify that measurement binding itself.
 */
export async function verifyDeploymentImageProvenance({
  appCompose,
  imagePolicies,
  githubToken,
}: VerifyDeploymentImageProvenanceParams): Promise<void> {
  const requiredImages = selectRequiredImages(appCompose, imagePolicies);
  for (const { repository, digest, policy } of requiredImages) {
    let bundles: readonly string[];
    try {
      bundles = await fetchImageProvenance({
        repository: policy.repository,
        digest,
        githubToken,
      });
    } catch (cause) {
      if (!(cause instanceof ApiError)) throw cause;
      throw new VerificationError(
        {
          code: 'provenance.image_request_failed',
          details: { imageRepository: repository, digest },
          retryable: cause.retryable,
        },
        { cause },
      );
    }
    await verifyImageProvenance({ bundles, digest, policy });
  }
}

function selectRequiredImages(
  appCompose: string,
  imagePolicies: Readonly<Record<string, ImageProvenancePolicy>>,
): RequiredImage[] {
  const policies = Object.entries(imagePolicies);
  if (policies.length === 0) {
    throw new VerificationError({
      code: 'provenance.deployment_images_invalid',
      details: { reason: 'empty_policy' },
    });
  }

  let configuration: DeploymentAppCompose;
  try {
    configuration = v.parse(DeploymentAppComposeSchema, JSON.parse(appCompose));
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'provenance.deployment_images_invalid',
        details: { reason: 'invalid_app_compose' },
      },
      { cause },
    );
  }

  let compose: DeploymentDockerCompose;
  try {
    const raw: unknown = parse(configuration.docker_compose_file, {
      merge: true,
      logLevel: 'error',
    });
    compose = v.parse(DeploymentDockerComposeSchema, raw);
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'provenance.deployment_images_invalid',
        details: { reason: 'invalid_docker_compose' },
      },
      { cause },
    );
  }

  const images: { service: string; image: string }[] = [];
  for (const [service, { image }] of Object.entries(compose.services)) {
    if (image === undefined) continue;
    // A variable's default is not evidence of its resolved deployment value.
    if (image.includes('$')) {
      throw new VerificationError({
        code: 'provenance.deployment_images_invalid',
        details: { reason: 'unresolved_image', service },
      });
    }
    images.push({ service, image: image.replace(/^docker\.io\//, '') });
  }

  // Finish selection before making any requests, including checking repeated
  // references so a pinned service cannot hide an unpinned one.
  const requiredImages: RequiredImage[] = [];
  for (const [name, policy] of policies) {
    const repository = name.replace(/^docker\.io\//, '');
    const references = images.filter(
      ({ image }) =>
        image === repository ||
        image.startsWith(`${repository}@`) ||
        image.startsWith(`${repository}:`),
    );
    if (references.length === 0) {
      throw new VerificationError({
        code: 'provenance.deployment_images_invalid',
        details: { reason: 'image_missing', imageRepository: repository },
      });
    }
    for (const { service, image } of references) {
      const suffix = image.slice(repository.length);
      const digest = /^(?::\w[\w.-]{0,127})?@(sha256:[0-9a-fA-F]{64})$/.exec(
        suffix,
      )?.[1];
      if (digest === undefined) {
        throw new VerificationError({
          code: 'provenance.deployment_images_invalid',
          details: {
            reason: 'image_not_pinned',
            imageRepository: repository,
            service,
          },
        });
      }
      requiredImages.push({ repository, digest: digest.toLowerCase(), policy });
    }
  }
  return requiredImages;
}
