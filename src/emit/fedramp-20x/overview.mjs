import { assertValid } from '../validate.mjs';

export const kind = 'overview';

/**
 * Emits the FedRAMP Certification Package Overview (FRC-CSO-PKG).
 *
 * This is the document every other artifact points at. `sdr`, `ocr` and `scn` all require a
 * `certificationPackageOverviewUri`, and until now the harness demanded that URI and could
 * not produce the thing it addressed — so the one document the whole package hangs off was
 * the one left to a word processor.
 *
 * It is almost entirely a projection of the profile rather than of the evidence, and that is
 * correct. An overview states who the provider is, what the service does, how it is deployed
 * and who to contact. None of that is observable in a cloud account, and generating it from
 * collected state would be inventing facts about a company. What the emitter contributes is
 * the part that is genuinely easy to get wrong: FedRAMP's schema requires a Security contact
 * *and* a Sales contact, constrains the deployment model and business categories to closed
 * vocabularies, demands a logo URI pointing at a real image type, and formats phone numbers.
 * A package rejected at submission for a missing Sales contact has cost a cycle for no
 * reason, and this catches it at emit time.
 *
 * The one place it does more than transcribe is `thirdPartyInformationResources`. MAS-CSO-TPR
 * asks for the third-party resources inside the minimum assessment scope, split by whether
 * they are themselves FedRAMP certified — and a non-certified dependency inside a package
 * targeting certification is the kind of thing that surfaces late and expensively. Declaring
 * it here puts it in front of a reviewer at the start.
 */

const DEPLOYMENT_MODELS = new Set([
  'Public Cloud',
  'Government-Only Cloud',
  'Hybrid Cloud',
  'Community Cloud',
  'Government Community Cloud',
]);

const SERVICE_MODELS = new Set(['SaaS', 'PaaS', 'IaaS']);

function need(value, field, hint) {
  if (value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0)) {
    throw new Error(`The profile needs ${field}. ${hint}`);
  }
  return value;
}

/**
 * Maps the profile's contact block onto the schema's contact array.
 *
 * The Security-and-Sales requirement is expressed in the schema as two `contains` clauses,
 * which ajv reports as an unhelpfully abstract failure. Checking it here means the error
 * names the missing role instead.
 */
export function contactsFrom(cert, profile) {
  const declared = cert.contacts ?? [];
  const contacts = declared.map((c) => ({
    contactType: need(c.type, 'a type on every certification.contacts entry', 'Security and Sales are both required by FRC-CSO-PKG.'),
    ...(c.name ? { contactName: c.name } : {}),
    ...(c.email ? { contactEmail: c.email } : {}),
    ...(c.phone ? { contactPhone: c.phone } : {}),
  }));

  // The older profile shape carries a single security address. Honour it so a profile written
  // before this emitter existed still produces a valid Security contact.
  if (!contacts.some((c) => c.contactType === 'Security') && profile?.contacts?.security) {
    contacts.push({ contactType: 'Security', contactName: 'Security', contactEmail: profile.contacts.security });
  }

  for (const role of ['Security', 'Sales']) {
    if (!contacts.some((c) => c.contactType === role)) {
      throw new Error(
        `FRC-CSO-PKG requires a ${role} contact and the profile declares none. Add one under ` +
          `certification.contacts with type: ${role}. A package is rejected at submission for this, ` +
          `which is an expensive way to learn it.`
      );
    }
  }
  return contacts;
}

export function emit(state, { profile = null } = {}) {
  if (!profile) {
    throw new Error('ksi emit overview requires --profile: the overview is a projection of the declared boundary.');
  }
  const cert = profile.certification ?? {};

  const serviceIdentification = {
    fedRampPackageId: need(
      cert.package_id,
      'certification.package_id',
      "Use the FedRAMP-assigned id if you have one, or the provider's name and acronym if you do not."
    ),
    ...(cert.uei ? { ueiNumber: cert.uei } : {}),
    providerName: need(profile.provider, 'provider', 'The name of the Cloud Service Provider.'),
    serviceName: need(profile.service_name, 'service_name', 'The full name of the Cloud Service Offering.'),
    serviceAcronym: need(cert.service_acronym, 'certification.service_acronym', 'A short abbreviation for the offering.'),
    serviceDescription: need(cert.description, 'certification.description', 'A detailed description; Markdown is permitted.'),
    certificationType: cert.type ?? '20x',
    website: need(cert.website, 'certification.website', 'The official website for the offering.'),
    logo: need(cert.logo, 'certification.logo', 'A URL pointing at a PNG, JPEG, GIF, SVG, WebP, ICO, BMP or TIFF file.'),
  };

  const serviceModels = need(cert.service_model, 'certification.service_model', 'One or more of SaaS, PaaS, IaaS.');
  for (const model of serviceModels) {
    if (!SERVICE_MODELS.has(model)) {
      throw new Error(`certification.service_model "${model}" is not one of ${[...SERVICE_MODELS].join(', ')}.`);
    }
  }
  const deploymentModel = need(
    cert.deployment_model,
    'certification.deployment_model',
    `One of: ${[...DEPLOYMENT_MODELS].join(', ')}.`
  );
  if (!DEPLOYMENT_MODELS.has(deploymentModel)) {
    throw new Error(`certification.deployment_model "${deploymentModel}" is not one of ${[...DEPLOYMENT_MODELS].join(', ')}.`);
  }

  const serviceProperties = { serviceType: serviceModels, deploymentModel };
  if (cert.business_category?.length) serviceProperties.businessCategory = cert.business_category;
  if (cert.trust_center) {
    serviceProperties.trustCenter = {
      repositoryType: cert.trust_center.types ?? ['Trust Center'],
      url: need(cert.trust_center.url, 'certification.trust_center.url', 'The trust centre URL.'),
      repositoryDescription: need(
        cert.trust_center.description,
        'certification.trust_center.description',
        'What a reader will find there.'
      ),
      authenticationRequired: Boolean(cert.trust_center.authentication_required),
    };
  }

  const document = {
    serviceIdentification,
    serviceProperties,
    contactInformation: contactsFrom(cert, profile),
  };

  if (cert.certified_services?.length) {
    document.certifiedServices = cert.certified_services.map((s) => ({
      serviceName: need(s.name, 'a name on every certification.certified_services entry', ''),
      serviceDescription: need(s.description, `a description on certified service "${s.name}"`, ''),
      dateAvailable: need(s.date_available, `a date_available on certified service "${s.name}"`, 'Format YYYY-MM-DD.'),
    }));
  }

  // MAS-CSO-TPR. Split by certification status, because those are different risks: a
  // certified dependency inherits an authorization, and a non-certified one is a boundary
  // question somebody has to answer before an assessor asks it.
  const third = cert.third_party ?? {};
  if (third.certified?.length || third.non_certified?.length) {
    document.thirdPartyInformationResources = {};
    if (third.certified?.length) {
      document.thirdPartyInformationResources.certified = third.certified.map((r) => ({
        fedRampCertifiedThirdPartyInformationResource: need(r.id, 'an id on every certified third-party resource', ''),
        useCase: need(r.use_case, `a use_case on third-party resource "${r.id}"`, ''),
      }));
    }
    if (third.non_certified?.length) {
      document.thirdPartyInformationResources.nonCertified = third.non_certified.map((r) => ({
        name: need(r.name, 'a name on every non-certified third-party resource', ''),
        provider: need(r.provider, `a provider on third-party resource "${r.name}"`, ''),
        ...(r.website ? { website: r.website } : {}),
        useCase: need(r.use_case, `a use_case on third-party resource "${r.name}"`, ''),
      }));
    }
  }

  if (cert.assessor) {
    document.assessor = cert.assessor;
  }

  return assertValid('overview', document);
}
