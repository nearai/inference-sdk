import * as v from 'valibot';
import { parse } from 'yaml';
import type { VerifiedRecordedDeployment } from '../types/compose-manager';
import {
  DeploymentAppComposeSchema,
  DeploymentDockerComposeSchema,
} from '../schemas';
import type {
  DeploymentAppCompose,
  DeploymentDockerCompose,
  ImageProvenancePolicy,
  VerifiedImageProvenance,
  VerifyDeploymentImageProvenanceParams,
} from '../types/provenance';
import { ApiError, VerificationError } from '../utils/errors';
import { fetchImageProvenance, verifyImageProvenance } from './provenance';

type RequiredImage = {
  repository: string;
  digest: string;
  policy: ImageProvenancePolicy;
};

type ComposeImage = { service: string; image: string };

type VerifyComposeImageProvenanceParams = {
  dockerCompose: string;
  imagePolicies: Readonly<Record<string, ImageProvenancePolicy>>;
  githubToken?: string;
  githubApiUrl?: string;
  /** An explicit compose_up selection; omitted or empty selects the whole file. */
  services?: readonly string[];
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
  githubApiUrl,
}: VerifyDeploymentImageProvenanceParams): Promise<void> {
  requireImagePolicies(imagePolicies);
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
  await verifyComposeImageProvenance({
    dockerCompose: configuration.docker_compose_file,
    imagePolicies,
    githubToken,
    githubApiUrl,
  });
}

/** Shared image selection and Sigstore checks for authenticated compose sources. */
export async function verifyComposeImageProvenance({
  dockerCompose,
  imagePolicies,
  githubToken,
  githubApiUrl,
  services,
}: VerifyComposeImageProvenanceParams): Promise<{
  selectedServices: readonly string[];
  verifiedImages: VerifiedRecordedDeployment['verifiedImages'];
}> {
  const { requiredImages, selectedServices } = selectRequiredImages({
    dockerCompose,
    imagePolicies,
    services,
  });
  const verifiedImages = await Promise.all(
    requiredImages.map(async (image) => ({
      service: image.service,
      imageRepository: image.repository,
      digest: image.digest,
      build: await verifyRequiredImageProvenance(image, {
        githubToken,
        githubApiUrl,
      }),
    })),
  );
  return { selectedServices, verifiedImages };
}

export async function verifyRequiredImageProvenance(
  { repository, digest, policy }: RequiredImage,
  access: { githubToken?: string; githubApiUrl?: string },
): Promise<VerifiedImageProvenance> {
  let bundles: readonly string[];
  try {
    bundles = await fetchImageProvenance({
      repository: policy.repository,
      digest,
      ...access,
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
  return verifyImageProvenance({ bundles, digest, policy });
}

function selectRequiredImages({
  dockerCompose,
  imagePolicies,
  services,
}: VerifyComposeImageProvenanceParams): {
  requiredImages: (RequiredImage & { service: string })[];
  selectedServices: string[];
} {
  const policies = Object.entries(imagePolicies);
  requireImagePolicies(imagePolicies);

  let compose: DeploymentDockerCompose;
  try {
    const raw: unknown = parse(dockerCompose, {
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

  const composeServices = new Map(Object.entries(compose.services));
  const selectedServices = [
    ...new Set(services?.length ? services : composeServices.keys()),
  ];
  const images: ComposeImage[] = [];
  for (const service of selectedServices) {
    const config = composeServices.get(service);
    if (config === undefined) {
      throw new VerificationError({
        code: 'provenance.deployment_images_invalid',
        details: { reason: 'service_missing', service },
      });
    }
    const { image } = config;
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
  const requiredImages: (RequiredImage & { service: string })[] = [];
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
      const digest = requirePinnedImageDigest(image, repository, service);
      requiredImages.push({ service, repository, digest, policy });
    }
  }
  return { requiredImages, selectedServices };
}

export function requirePinnedImageDigest(
  image: string,
  repository: string,
  service: string,
): string {
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
  return digest.toLowerCase();
}

function requireImagePolicies(
  imagePolicies: Readonly<Record<string, ImageProvenancePolicy>>,
): void {
  if (Object.keys(imagePolicies).length === 0) {
    throw new VerificationError({
      code: 'provenance.deployment_images_invalid',
      details: { reason: 'empty_policy' },
    });
  }
}
