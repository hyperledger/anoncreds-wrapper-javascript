import {
  Credential,
  CredentialDefinition,
  CredentialOffer,
  CredentialRequest,
  CredentialRevocationConfig,
  CredentialRevocationState,
  LinkSecret,
  Presentation,
  PresentationRequest,
  RevocationRegistryDefinition,
  RevocationStatusList,
  Schema,
  W3cCredential,
  W3cPresentation,
  anoncreds,
} from '@hyperledger/anoncreds-shared'

import { setup } from './utils'

import { deepStrictEqual, ok, strict, strictEqual, throws } from 'node:assert'
import { before, describe, test } from 'node:test'

describe('API', () => {
  before(setup)

  test('create and verify presentation', () => {
    const nonce = anoncreds.generateNonce()

    const presentationRequest = PresentationRequest.fromJson({
      nonce,
      name: 'pres_req_1',
      version: '0.1',
      requested_attributes: {
        attr1_referent: {
          name: 'name',
          issuer: 'mock:uri',
        },
        attr2_referent: {
          name: 'sex',
        },
        attr3_referent: {
          name: 'phone',
        },
        attr4_referent: {
          names: ['name', 'height'],
        },
      },
      requested_predicates: {
        predicate1_referent: { name: 'age', p_type: '>=', p_value: 18 },
      },
      non_revoked: { from: 13, to: 200 },
    })

    const schema = Schema.create({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } = CredentialDefinition.create({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } = RevocationRegistryDefinition.create({
      credentialDefinitionId: 'mock:uri',
      credentialDefinition,
      issuerId: 'mock:uri',
      tag: 'some_tag',
      revocationRegistryType: 'CL_ACCUM',
      maximumCredentialNumber: 10,
    })

    const tailsPath = revocationRegistryDefinition.getTailsLocation()

    const timeCreateRevStatusList = 12
    const revocationStatusList = RevocationStatusList.create({
      credentialDefinition,
      revocationRegistryDefinitionId: 'mock:uri',
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      issuerId: 'mock:uri',
      issuanceByDefault: true,
      timestamp: timeCreateRevStatusList,
    })

    const credentialOffer = CredentialOffer.create({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = LinkSecret.create()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
      entropy: 'entropy',
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = Credential.create({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
      revocationConfiguration: new CredentialRevocationConfig({
        registryDefinition: revocationRegistryDefinition,
        registryDefinitionPrivate: revocationRegistryDefinitionPrivate,
        statusList: revocationStatusList,
        registryIndex: 9,
      }),
    })

    const credentialReceived = credential.process({
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
      revocationRegistryDefinition,
    })

    const revocationRegistryIndex = credentialReceived.revocationRegistryIndex ?? 0

    const revocationState = CredentialRevocationState.create({
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex,
      tailsPath,
    })

    const presentation = Presentation.create({
      presentationRequest,
      credentials: [
        {
          credential: credentialReceived,
          revocationState,
          timestamp: timeCreateRevStatusList,
        },
      ],
      credentialDefinitions: { 'mock:uri': credentialDefinition },
      credentialsProve: [
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr1_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr2_referent',
          reveal: false,
        },
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr4_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: true,
          referent: 'predicate1_referent',
          reveal: true,
        },
      ],
      linkSecret,
      schemas: { 'mock:uri': schema },
      selfAttest: { attr3_referent: '8-800-300' },
    })

    ok(typeof presentation.handle.handle === 'number')

    // Without revocation timestamp override, it shall fail
    throws(() =>
      presentation.verify({
        presentationRequest,
        schemas: { 'mock:uri': schema },
        credentialDefinitions: { 'mock:uri': credentialDefinition },
        revocationRegistryDefinitions: { 'mock:uri': revocationRegistryDefinition },
        revocationStatusLists: [revocationStatusList],
      })
    )

    const verify = presentation.verify({
      presentationRequest,
      schemas: { 'mock:uri': schema },
      credentialDefinitions: { 'mock:uri': credentialDefinition },
      revocationRegistryDefinitions: { 'mock:uri': revocationRegistryDefinition },
      revocationStatusLists: [revocationStatusList],
      nonRevokedIntervalOverrides: [
        {
          overrideRevocationStatusListTimestamp: 12,
          requestedFromTimestamp: 13,
          revocationRegistryDefinitionId: 'mock:uri',
        },
      ],
    })

    ok(verify)
  })

  test('create and verify presentation (no revocation use case)', () => {
    const schema = Schema.create({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } = CredentialDefinition.create({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema,
      signatureType: 'CL',
      supportRevocation: false,
      tag: 'TAG',
    })

    const credentialOffer = CredentialOffer.create({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = LinkSecret.create()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
      entropy: 'entropy',
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = Credential.create({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
    })

    const credReceived = credential.process({
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
    })

    const credJson = credential.toJson()

    strictEqual(credJson.cred_def_id, 'mock:uri')
    strictEqual(credJson.schema_id, 'mock:uri')

    const credReceivedJson = credential.toJson()
    strictEqual(credReceivedJson.cred_def_id, 'mock:uri')
    strictEqual(credReceivedJson.schema_id, 'mock:uri')

    ok(credReceivedJson.signature)
    strictEqual(credReceivedJson.witness, null)

    const nonce = anoncreds.generateNonce()

    const presentationRequest = PresentationRequest.fromJson({
      nonce,
      name: 'pres_req_1',
      version: '0.1',
      requested_attributes: {
        attr1_referent: {
          name: 'name',
          issuer: 'mock:uri',
        },
        attr2_referent: {
          name: 'sex',
        },
        attr3_referent: {
          name: 'phone',
        },
        attr4_referent: {
          names: ['name', 'height'],
        },
      },
      requested_predicates: {
        predicate1_referent: { name: 'age', p_type: '>=', p_value: 18 },
      },
    })

    const presentation = Presentation.create({
      presentationRequest,
      credentials: [
        {
          credential: credReceived,
        },
      ],
      credentialDefinitions: { 'mock:uri': credentialDefinition },
      credentialsProve: [
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr1_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr2_referent',
          reveal: false,
        },
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr4_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: true,
          referent: 'predicate1_referent',
          reveal: true,
        },
      ],
      linkSecret,
      schemas: { 'mock:uri': schema },
      selfAttest: { attr3_referent: '8-800-300' },
    })

    ok(typeof presentation.handle.handle === 'number')

    const verify = presentation.verify({
      presentationRequest,
      schemas: { 'mock:uri': schema },
      credentialDefinitions: { 'mock:uri': credentialDefinition },
    })

    ok(verify)
  })
})

test('create and verify presentation passing only JSON objects as parameters', () => {
  setup()

  const nonce = anoncreds.generateNonce()

  // a schema can be created from JSON
  const schema = Schema.fromJson({
    name: 'schema-1',
    issuerId: 'mock:uri',
    version: '1',
    attrNames: ['name', 'age', 'sex', 'height'],
  })

  deepStrictEqual(schema.toJson(), {
    name: 'schema-1',
    issuerId: 'mock:uri',
    version: '1',
    attrNames: ['name', 'age', 'sex', 'height'],
  })

  const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } = CredentialDefinition.create({
    schemaId: 'mock:uri',
    issuerId: 'mock:uri',
    schema: {
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attrNames: ['name', 'age', 'sex', 'height'],
    },
    signatureType: 'CL',
    supportRevocation: true,
    tag: 'TAG',
  })

  const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } = RevocationRegistryDefinition.create({
    credentialDefinitionId: 'mock:uri',
    credentialDefinition,
    issuerId: 'mock:uri',
    tag: 'some_tag',
    revocationRegistryType: 'CL_ACCUM',
    maximumCredentialNumber: 10,
  })

  const timeCreateRevStatusList = 12
  const revocationStatusList = RevocationStatusList.create({
    credentialDefinition,
    revocationRegistryDefinitionId: 'mock:uri',
    revocationRegistryDefinition,
    revocationRegistryDefinitionPrivate,
    issuerId: 'mock:uri',
    issuanceByDefault: true,
    timestamp: timeCreateRevStatusList,
  })

  revocationStatusList.update({
    credentialDefinition,
    revocationRegistryDefinition,
    revocationRegistryDefinitionPrivate,
    revoked: [1],
  })
  const credentialOffer = CredentialOffer.fromJson({
    schema_id: 'mock:uri',
    cred_def_id: 'mock:uri',
    key_correctness_proof: keyCorrectnessProof.toJson(),
    nonce,
  })

  const linkSecret = '123'
  const linkSecretId = 'link secret id'

  const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
    entropy: 'entropy',
    credentialDefinition: credentialDefinition.toJson(),
    linkSecret,
    linkSecretId,
    credentialOffer: credentialOffer.toJson(),
  })

  const credential = Credential.create({
    credentialDefinition: credentialDefinition.toJson(),
    credentialDefinitionPrivate: credentialDefinitionPrivate.toJson(),
    credentialOffer: credentialOffer.toJson(),
    credentialRequest: credentialRequest.toJson(),
    attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
    revocationConfiguration: new CredentialRevocationConfig({
      registryDefinition: revocationRegistryDefinition,
      registryDefinitionPrivate: revocationRegistryDefinitionPrivate,
      statusList: revocationStatusList,
      registryIndex: 9,
    }),
  })

  const credReceived = credential.process({
    credentialDefinition: credentialDefinition.toJson(),
    credentialRequestMetadata: credentialRequestMetadata.toJson(),
    linkSecret,
    revocationRegistryDefinition: revocationRegistryDefinition.toJson(),
  })

  const credJson = credential.toJson()

  strictEqual(credJson.cred_def_id, 'mock:uri')
  strictEqual(credJson.schema_id, 'mock:uri')
  strictEqual(credJson.rev_reg_id, 'mock:uri')

  const credReceivedJson = credential.toJson()

  strictEqual(credReceivedJson.cred_def_id, 'mock:uri')
  strictEqual(credReceivedJson.schema_id, 'mock:uri')
  strictEqual(credReceivedJson.rev_reg_id, 'mock:uri')

  ok(credReceivedJson.signature)
  ok(credReceivedJson.witness)

  const presentationRequest = {
    nonce,
    name: 'pres_req_1',
    version: '0.1',
    requested_attributes: {
      attr1_referent: {
        name: 'name',
        issuer: 'mock:uri',
      },
      attr2_referent: {
        name: 'sex',
      },
      attr3_referent: {
        name: 'phone',
      },
      attr4_referent: {
        names: ['name', 'height'],
      },
    },
    requested_predicates: {
      predicate1_referent: { name: 'age', p_type: '>=', p_value: 18 },
    },
  }

  const presentation = Presentation.create({
    presentationRequest,
    credentials: [
      {
        credential: credReceived.toJson(),
      },
    ],
    credentialDefinitions: { 'mock:uri': credentialDefinition.toJson() },
    credentialsProve: [
      {
        entryIndex: 0,
        isPredicate: false,
        referent: 'attr1_referent',
        reveal: true,
      },
      {
        entryIndex: 0,
        isPredicate: false,
        referent: 'attr2_referent',
        reveal: false,
      },
      {
        entryIndex: 0,
        isPredicate: false,
        referent: 'attr4_referent',
        reveal: true,
      },
      {
        entryIndex: 0,
        isPredicate: true,
        referent: 'predicate1_referent',
        reveal: true,
      },
    ],
    linkSecret,
    schemas: { 'mock:uri': schema.toJson() },
    selfAttest: { attr3_referent: '8-800-300' },
  })

  ok(typeof presentation.handle.handle === 'number')

  const verify = Presentation.fromJson(presentation.toJson()).verify({
    presentationRequest,
    schemas: { 'mock:uri': schema.toJson() },
    credentialDefinitions: { 'mock:uri': credentialDefinition.toJson() },
    revocationRegistryDefinitions: { 'mock:uri': revocationRegistryDefinition.toJson() },
    revocationStatusLists: [revocationStatusList.toJson()],
  })

  ok(verify)
})

describe('API W3C', () => {
  before(setup)

  test('create and verify w3c presentation', () => {
    const nonce = anoncreds.generateNonce()

    const presentationRequest = PresentationRequest.fromJson({
      nonce,
      name: 'pres_req_1',
      version: '0.1',
      requested_attributes: {
        attr1_referent: {
          name: 'name',
          issuer: 'mock:uri',
        },
        attr2_referent: {
          names: ['name', 'height'],
        },
      },
      requested_predicates: {
        predicate1_referent: { name: 'age', p_type: '>=', p_value: 18 },
      },
      non_revoked: { from: 13, to: 200 },
    })

    const schema = Schema.create({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } = CredentialDefinition.create({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } = RevocationRegistryDefinition.create({
      credentialDefinitionId: 'mock:uri',
      credentialDefinition,
      issuerId: 'mock:uri',
      tag: 'some_tag',
      revocationRegistryType: 'CL_ACCUM',
      maximumCredentialNumber: 10,
    })

    const tailsPath = revocationRegistryDefinition.getTailsLocation()

    const timeCreateRevStatusList = 12
    const revocationStatusList = RevocationStatusList.create({
      credentialDefinition,
      revocationRegistryDefinitionId: 'mock:uri',
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      issuerId: 'mock:uri',
      issuanceByDefault: true,
      timestamp: timeCreateRevStatusList,
    })

    const credentialOffer = CredentialOffer.create({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = LinkSecret.create()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
      entropy: 'entropy',
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = W3cCredential.create({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
      revocationConfiguration: new CredentialRevocationConfig({
        registryDefinition: revocationRegistryDefinition,
        registryDefinitionPrivate: revocationRegistryDefinitionPrivate,
        statusList: revocationStatusList,
        registryIndex: 9,
      }),
    })

    const legacyCredential = credential.toLegacy()
    strictEqual(legacyCredential.schemaId, 'mock:uri')
    strictEqual(legacyCredential.credentialDefinitionId, 'mock:uri')

    const legacyCredentialFrom = Credential.fromW3c({ credential })
    strictEqual(legacyCredentialFrom.schemaId, 'mock:uri')
    strictEqual(legacyCredentialFrom.credentialDefinitionId, 'mock:uri')

    const w3cCredential = W3cCredential.fromLegacy({ credential: legacyCredential, issuerId: 'mock:uri' })
    strictEqual(w3cCredential.schemaId, 'mock:uri')
    strictEqual(w3cCredential.credentialDefinitionId, 'mock:uri')

    const convertedW3cCredential = legacyCredential.toW3c({ issuerId: 'mock:uri' })
    strictEqual(convertedW3cCredential.schemaId, 'mock:uri')
    strictEqual(convertedW3cCredential.credentialDefinitionId, 'mock:uri')

    const credentialReceived = credential.process({
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
      revocationRegistryDefinition,
    })

    const revocationRegistryIndex = credentialReceived.revocationRegistryIndex ?? 0

    const revocationState = CredentialRevocationState.create({
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex,
      tailsPath,
    })

    const presentation = W3cPresentation.create({
      presentationRequest,
      credentials: [
        {
          credential: credentialReceived,
          revocationState,
          timestamp: timeCreateRevStatusList,
        },
      ],
      credentialDefinitions: { 'mock:uri': credentialDefinition },
      credentialsProve: [
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr1_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr2_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: true,
          referent: 'predicate1_referent',
          reveal: true,
        },
      ],
      linkSecret,
      schemas: { 'mock:uri': schema },
    })

    ok(typeof presentation.handle.handle === 'number')

    // Without revocation timestamp override, it shall fail
    throws(() => {
      presentation.verify({
        presentationRequest,
        schemas: { 'mock:uri': schema },
        credentialDefinitions: { 'mock:uri': credentialDefinition },
        revocationRegistryDefinitions: { 'mock:uri': revocationRegistryDefinition },
        revocationStatusLists: [revocationStatusList],
      })
    })

    const verify = presentation.verify({
      presentationRequest,
      schemas: { 'mock:uri': schema },
      credentialDefinitions: { 'mock:uri': credentialDefinition },
      revocationRegistryDefinitions: { 'mock:uri': revocationRegistryDefinition },
      revocationStatusLists: [revocationStatusList],
      nonRevokedIntervalOverrides: [
        {
          overrideRevocationStatusListTimestamp: 12,
          requestedFromTimestamp: 13,
          revocationRegistryDefinitionId: 'mock:uri',
        },
      ],
    })

    ok(verify)
  })

  test('create and verify w3c presentation (no revocation use case)', () => {
    const schema = Schema.create({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } = CredentialDefinition.create({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema,
      signatureType: 'CL',
      supportRevocation: false,
      tag: 'TAG',
    })

    const credentialOffer = CredentialOffer.create({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = LinkSecret.create()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
      entropy: 'entropy',
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = W3cCredential.create({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
    })

    const credReceived = credential.process({
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
    })

    const nonce = anoncreds.generateNonce()

    const presentationRequest = PresentationRequest.fromJson({
      nonce,
      name: 'pres_req_1',
      version: '0.1',
      requested_attributes: {
        attr1_referent: {
          name: 'name',
          issuer: 'mock:uri',
        },
        attr2_referent: {
          names: ['name', 'height'],
        },
      },
      requested_predicates: {
        predicate1_referent: { name: 'age', p_type: '>=', p_value: 18 },
      },
    })

    const presentation = W3cPresentation.create({
      presentationRequest,
      credentials: [
        {
          credential: credReceived,
        },
      ],
      credentialDefinitions: { 'mock:uri': credentialDefinition },
      credentialsProve: [
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr1_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr2_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: true,
          referent: 'predicate1_referent',
          reveal: true,
        },
      ],
      linkSecret,
      schemas: { 'mock:uri': schema },
    })

    ok(typeof presentation.handle.handle === 'number')

    const verify = presentation.verify({
      presentationRequest,
      schemas: { 'mock:uri': schema },
      credentialDefinitions: { 'mock:uri': credentialDefinition },
    })

    ok(verify)
  })
})
