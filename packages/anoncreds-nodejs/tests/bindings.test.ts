import { deepStrictEqual, ok, strictEqual } from 'node:assert'
import { before, describe, test } from 'node:test'
import { anoncreds } from '@hyperledger/anoncreds-shared'
import { setup } from './utils'

const ENTROPY = 'entropy'

describe('bindings', () => {
  before(setup)

  test('current error', () => {
    const error = anoncreds.getCurrentError()

    deepStrictEqual(JSON.parse(error), {
      code: 0,
      message: null,
    })
  })

  test('generate nonce', () => {
    const nonce = anoncreds.generateNonce()

    ok(!Number.isNaN(Number(nonce)))
  })

  test('create schema', () => {
    const obj = {
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['attr-1'],
    }
    const schemaObj = anoncreds.createSchema(obj)

    const json = anoncreds.getJson({ objectHandle: schemaObj })

    deepStrictEqual(JSON.parse(json), {
      name: 'schema-1',
      version: '1',
      issuerId: 'mock:uri',
      attrNames: ['attr-1'],
    })
  })

  test('create credential definition', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['attr-1'],
    })

    const { keyCorrectnessProof, credentialDefinition, credentialDefinitionPrivate } =
      anoncreds.createCredentialDefinition({
        schemaId: 'mock:uri',
        issuerId: 'mock:uri',
        schema: schemaObj,
        signatureType: 'CL',
        supportRevocation: true,
        tag: 'TAG',
      })

    const credDefJson = anoncreds.getJson({ objectHandle: credentialDefinition })
    strictEqual(JSON.parse(credDefJson).tag, 'TAG')
    strictEqual(JSON.parse(credDefJson).type, 'CL')
    strictEqual(JSON.parse(credDefJson).schemaId, 'mock:uri')
    strictEqual(JSON.parse(credDefJson).issuerId, 'mock:uri')

    const credDefPvtJson = anoncreds.getJson({ objectHandle: credentialDefinitionPrivate })

    ok(JSON.parse(credDefPvtJson).value)

    const keyCorrectnessProofJson = anoncreds.getJson({ objectHandle: keyCorrectnessProof })

    ok(JSON.parse(keyCorrectnessProofJson).c)
    ok(JSON.parse(keyCorrectnessProofJson).xr_cap)
  })

  test('encode credential attributes', () => {
    const encoded = anoncreds.encodeCredentialAttributes({ attributeRawValues: ['value2', 'value1'] })

    deepStrictEqual(encoded, [
      '2360207505573967335061705667247358223962382058438765247085581582985596391831',
      '27404702143883897701950953229849815393032792099783647152371385368148256400014',
    ])
  })

  test('create revocation registry', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const { revocationRegistryDefinition } = anoncreds.createRevocationRegistryDefinition({
      credentialDefinitionId: 'mock:uri',
      credentialDefinition,
      issuerId: 'mock:uri',
      tag: 'default',
      revocationRegistryType: 'CL_ACCUM',
      maximumCredentialNumber: 100,
    })

    const maximumCredentialNumber = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: revocationRegistryDefinition,
      name: 'max_cred_num',
    })

    strictEqual(maximumCredentialNumber, '100')
    const json = anoncreds.getJson({ objectHandle: revocationRegistryDefinition })
    strictEqual(JSON.parse(json).credDefId, 'mock:uri')
    strictEqual(JSON.parse(json).revocDefType, 'CL_ACCUM')
    strictEqual(JSON.parse(json).tag, 'default')
    strictEqual(JSON.parse(json).value.maxCredNum, 100)
  })

  test('create link secret', () => {
    const linkSecret = anoncreds.createLinkSecret()
    ok(typeof linkSecret === 'string')
  })

  test('create credential offer', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['attr-1'],
    })

    const { keyCorrectnessProof } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      schema: schemaObj,
      issuerId: 'mock:uri',
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credOfferObj = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const json = anoncreds.getJson({ objectHandle: credOfferObj })
    strictEqual(JSON.parse(json).cred_def_id, 'mock:uri')
    strictEqual(JSON.parse(json).schema_id, 'mock:uri')

    ok(JSON.parse(json).nonce)
    ok(JSON.parse(json).key_correctness_proof)
  })

  test('create credential request', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, keyCorrectnessProof } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = anoncreds.createLinkSecret()
    const linkSecretId = 'link secret id'

    const { credentialRequest, credentialRequestMetadata } = anoncreds.createCredentialRequest({
      entropy: ENTROPY,
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credReqJson = anoncreds.getJson({ objectHandle: credentialRequest })

    strictEqual(JSON.parse(credReqJson).cred_def_id, 'mock:uri')

    ok(JSON.parse(credReqJson).blinded_ms)
    ok(JSON.parse(credReqJson).nonce)

    const credReqMetadataJson = anoncreds.getJson({ objectHandle: credentialRequestMetadata })
    strictEqual(JSON.parse(credReqMetadataJson).link_secret_name, linkSecretId)

    ok(JSON.parse(credReqMetadataJson).link_secret_blinding_data)
    ok(JSON.parse(credReqMetadataJson).nonce)
  })

  test('create and receive credential', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } =
      anoncreds.createCredentialDefinition({
        schemaId: 'mock:uri',
        issuerId: 'mock:uri',
        schema: schemaObj,
        signatureType: 'CL',
        supportRevocation: true,
        tag: 'TAG',
      })

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
      anoncreds.createRevocationRegistryDefinition({
        credentialDefinitionId: 'mock:uri',
        credentialDefinition,
        issuerId: 'mock:uri',
        tag: 'some_tag',
        revocationRegistryType: 'CL_ACCUM',
        maximumCredentialNumber: 10,
      })

    const tailsPath = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: revocationRegistryDefinition,
      name: 'tails_location',
    })

    ok(tailsPath)

    const timeCreateRevStatusList = 12
    const revocationStatusList = anoncreds.createRevocationStatusList({
      credentialDefinition,
      revocationRegistryDefinitionId: 'mock:uri',
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      issuerId: 'mock:uri',
      issuanceByDefault: true,
      timestamp: timeCreateRevStatusList,
    })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = anoncreds.createLinkSecret()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = anoncreds.createCredentialRequest({
      entropy: ENTROPY,
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = anoncreds.createCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { 'attr-1': 'test' },
      revocationConfiguration: {
        revocationRegistryDefinition,
        revocationRegistryDefinitionPrivate,
        revocationStatusList,
        registryIndex: 9,
      },
    })

    const credReceived = anoncreds.processCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
      revocationRegistryDefinition,
    })

    const credJson = anoncreds.getJson({ objectHandle: credential })

    strictEqual(JSON.parse(credJson).cred_def_id, 'mock:uri')
    strictEqual(JSON.parse(credJson).schema_id, 'mock:uri')
    strictEqual(JSON.parse(credJson).rev_reg_id, 'mock:uri')

    const credReceivedJson = anoncreds.getJson({ objectHandle: credReceived })

    strictEqual(JSON.parse(credReceivedJson).cred_def_id, 'mock:uri')
    strictEqual(JSON.parse(credReceivedJson).schema_id, 'mock:uri')
    strictEqual(JSON.parse(credReceivedJson).rev_reg_id, 'mock:uri')

    ok(JSON.parse(credReceivedJson).signature)
    ok(JSON.parse(credReceivedJson).witness)
  })

  test('create and receive w3c credential', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } =
      anoncreds.createCredentialDefinition({
        schemaId: 'mock:uri',
        issuerId: 'mock:uri',
        schema: schemaObj,
        signatureType: 'CL',
        supportRevocation: true,
        tag: 'TAG',
      })

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
      anoncreds.createRevocationRegistryDefinition({
        credentialDefinitionId: 'mock:uri',
        credentialDefinition,
        issuerId: 'mock:uri',
        tag: 'some_tag',
        revocationRegistryType: 'CL_ACCUM',
        maximumCredentialNumber: 10,
      })

    const tailsPath = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: revocationRegistryDefinition,
      name: 'tails_location',
    })
    ok(tailsPath)

    const timeCreateRevStatusList = 12
    const revocationStatusList = anoncreds.createRevocationStatusList({
      credentialDefinition,
      revocationRegistryDefinitionId: 'mock:uri',
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      issuerId: 'mock:uri',
      issuanceByDefault: true,
      timestamp: timeCreateRevStatusList,
    })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = anoncreds.createLinkSecret()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = anoncreds.createCredentialRequest({
      entropy: ENTROPY,
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = anoncreds.createW3cCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      revocationConfiguration: {
        revocationRegistryDefinition,
        revocationRegistryDefinitionPrivate,
        revocationStatusList,
        registryIndex: 9,
      },
      attributeRawValues: { 'attr-1': 'test' },
      // @ts-expect-error: why is this added?
      encoding: undefined,
    })

    const credReceived = anoncreds.processW3cCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
      revocationRegistryDefinition,
    })

    anoncreds.getJson({ objectHandle: credReceived })
  })

  test('create and verify presentation', () => {
    const nonce = anoncreds.generateNonce()

    const presentationRequest = anoncreds.presentationRequestFromJson({
      json: JSON.stringify({
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
        non_revoked: { from: 10, to: 200 },
      }),
    })

    strictEqual(anoncreds.getTypeName({ objectHandle: presentationRequest }), 'PresentationRequest')

    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } =
      anoncreds.createCredentialDefinition({
        schemaId: 'mock:uri',
        issuerId: 'mock:uri',
        schema: schemaObj,
        signatureType: 'CL',
        supportRevocation: true,
        tag: 'TAG',
      })

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
      anoncreds.createRevocationRegistryDefinition({
        credentialDefinitionId: 'mock:uri',
        credentialDefinition,
        issuerId: 'mock:uri',
        tag: 'some_tag',
        revocationRegistryType: 'CL_ACCUM',
        maximumCredentialNumber: 10,
      })

    const tailsPath = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: revocationRegistryDefinition,
      name: 'tails_location',
    })

    const timeCreateRevStatusList = 12
    const revocationStatusList = anoncreds.createRevocationStatusList({
      credentialDefinition,
      revocationRegistryDefinitionId: 'mock:uri',
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      issuerId: 'mock:uri',
      issuanceByDefault: true,
      timestamp: timeCreateRevStatusList,
    })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = anoncreds.createLinkSecret()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = anoncreds.createCredentialRequest({
      entropy: ENTROPY,
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = anoncreds.createCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
      revocationConfiguration: {
        revocationRegistryDefinition,
        revocationRegistryDefinitionPrivate,
        revocationStatusList,
        registryIndex: 9,
      },
    })

    const credentialReceived = anoncreds.processCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
      revocationRegistryDefinition,
    })

    const revRegIndex = anoncreds.credentialGetAttribute({
      objectHandle: credentialReceived,
      name: 'rev_reg_index',
    })

    const revocationRegistryIndex = revRegIndex === null ? 0 : Number.parseInt(revRegIndex)

    const revocationState = anoncreds.createOrUpdateRevocationState({
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex,
      tailsPath,
    })

    const presentation = anoncreds.createPresentation({
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
      schemas: { 'mock:uri': schemaObj },
      selfAttest: { attr3_referent: '8-800-300' },
    })

    ok(typeof presentation.handle === 'number')

    const verify = anoncreds.verifyPresentation({
      presentation,
      presentationRequest,
      schemas: [schemaObj],
      schemaIds: ['mock:uri'],
      credentialDefinitions: [credentialDefinition],
      credentialDefinitionIds: ['mock:uri'],
      revocationRegistryDefinitions: [revocationRegistryDefinition],
      revocationRegistryDefinitionIds: ['mock:uri'],
      revocationStatusLists: [revocationStatusList],
    })

    ok(verify)
  })

  test('create and verify w3c presentation', () => {
    const nonce = anoncreds.generateNonce()

    const presentationRequest = anoncreds.presentationRequestFromJson({
      json: JSON.stringify({
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
        non_revoked: { from: 10, to: 200 },
      }),
    })

    strictEqual(anoncreds.getTypeName({ objectHandle: presentationRequest }), 'PresentationRequest')

    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } =
      anoncreds.createCredentialDefinition({
        schemaId: 'mock:uri',
        issuerId: 'mock:uri',
        schema: schemaObj,
        signatureType: 'CL',
        supportRevocation: true,
        tag: 'TAG',
      })

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
      anoncreds.createRevocationRegistryDefinition({
        credentialDefinitionId: 'mock:uri',
        credentialDefinition,
        issuerId: 'mock:uri',
        tag: 'some_tag',
        revocationRegistryType: 'CL_ACCUM',
        maximumCredentialNumber: 10,
      })

    const tailsPath = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: revocationRegistryDefinition,
      name: 'tails_location',
    })

    const timeCreateRevStatusList = 12
    const revocationStatusList = anoncreds.createRevocationStatusList({
      credentialDefinition,
      revocationRegistryDefinitionId: 'mock:uri',
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      issuerId: 'mock:uri',
      issuanceByDefault: true,
      timestamp: timeCreateRevStatusList,
    })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = anoncreds.createLinkSecret()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = anoncreds.createCredentialRequest({
      entropy: ENTROPY,
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = anoncreds.createW3cCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      revocationConfiguration: {
        revocationRegistryDefinition,
        revocationRegistryDefinitionPrivate,
        revocationStatusList,
        registryIndex: 9,
      },
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
      // @ts-expect-error: why is this added?
      encoding: undefined,
    })

    const credentialReceived = anoncreds.processW3cCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
      revocationRegistryDefinition,
    })

    const credentialProofDetails = anoncreds.w3cCredentialGetIntegrityProofDetails({
      objectHandle: credentialReceived,
    })

    const revRegIndex = anoncreds.w3cCredentialProofGetAttribute({
      objectHandle: credentialProofDetails,
      name: 'rev_reg_index',
    })

    const revocationRegistryIndex = revRegIndex === null ? 0 : Number.parseInt(revRegIndex)

    const revocationState = anoncreds.createOrUpdateRevocationState({
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex,
      tailsPath,
    })

    const presentation = anoncreds.createW3cPresentation({
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
      schemas: { 'mock:uri': schemaObj },
    })

    ok(typeof presentation.handle === 'number')

    const verify = anoncreds.verifyW3cPresentation({
      presentation,
      presentationRequest,
      schemas: [schemaObj],
      schemaIds: ['mock:uri'],
      credentialDefinitions: [credentialDefinition],
      credentialDefinitionIds: ['mock:uri'],
      revocationRegistryDefinitions: [revocationRegistryDefinition],
      revocationRegistryDefinitionIds: ['mock:uri'],
      revocationStatusLists: [revocationStatusList],
    })

    ok(verify)
  })

  test('create and verify presentation (no revocation use case)', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } =
      anoncreds.createCredentialDefinition({
        schemaId: 'mock:uri',
        issuerId: 'mock:uri',
        schema: schemaObj,
        signatureType: 'CL',
        supportRevocation: false,
        tag: 'TAG',
      })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = anoncreds.createLinkSecret()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = anoncreds.createCredentialRequest({
      entropy: ENTROPY,
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = anoncreds.createCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
    })

    const credReceived = anoncreds.processCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
    })

    const credJson = anoncreds.getJson({ objectHandle: credential })

    strictEqual(JSON.parse(credJson).cred_def_id, 'mock:uri')
    strictEqual(JSON.parse(credJson).schema_id, 'mock:uri')

    const credReceivedJson = anoncreds.getJson({ objectHandle: credReceived })

    strictEqual(JSON.parse(credReceivedJson).cred_def_id, 'mock:uri')
    strictEqual(JSON.parse(credReceivedJson).schema_id, 'mock:uri')

    ok(JSON.parse(credReceivedJson).signature)
    strictEqual(JSON.parse(credReceivedJson).witness, null)

    const nonce = anoncreds.generateNonce()

    const presentationRequest = anoncreds.presentationRequestFromJson({
      json: JSON.stringify({
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
      }),
    })

    const presentation = anoncreds.createPresentation({
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
      schemas: { 'mock:uri': schemaObj },
      selfAttest: { attr3_referent: '8-800-300' },
    })

    ok(typeof presentation.handle === 'number')

    const verify = anoncreds.verifyPresentation({
      presentation,
      presentationRequest,
      schemas: [schemaObj],
      schemaIds: ['mock:uri'],
      credentialDefinitions: [credentialDefinition],
      credentialDefinitionIds: ['mock:uri'],
    })

    ok(verify)
  })

  test('create and verify w3c presentation (no revocation use case)', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } =
      anoncreds.createCredentialDefinition({
        schemaId: 'mock:uri',
        issuerId: 'mock:uri',
        schema: schemaObj,
        signatureType: 'CL',
        supportRevocation: false,
        tag: 'TAG',
      })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const linkSecret = anoncreds.createLinkSecret()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = anoncreds.createCredentialRequest({
      entropy: ENTROPY,
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
    })

    const credential = anoncreds.createW3cCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
    })

    const credReceived = anoncreds.processW3cCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata,
      linkSecret,
    })

    const nonce = anoncreds.generateNonce()

    const presentationRequest = anoncreds.presentationRequestFromJson({
      json: JSON.stringify({
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
      }),
    })

    const presentation = anoncreds.createW3cPresentation({
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
      schemas: { 'mock:uri': schemaObj },
    })

    ok(typeof presentation.handle === 'number')

    const verify = anoncreds.verifyW3cPresentation({
      presentation,
      presentationRequest,
      schemas: [schemaObj],
      schemaIds: ['mock:uri'],
      credentialDefinitions: [credentialDefinition],
      credentialDefinitionIds: ['mock:uri'],
    })

    ok(verify)
  })
})
