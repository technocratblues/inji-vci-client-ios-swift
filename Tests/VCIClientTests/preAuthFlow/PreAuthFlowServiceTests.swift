import XCTest
@testable import VCIClient

final class PreAuthFlowServiceTests: XCTestCase {
    func makeService(
        resolver: AuthorizationServerResolver = MockAuthServerResolver(),
        tokenService: TokenService = MockTokenService(),
        executor: CredentialRequestExecutor = MockCredentialRequestExecutor(),
        nonceService: NonceService = MockNonceService()
    ) -> PreAuthCodeFlowService {
        return PreAuthCodeFlowService(
            authServerResolver: resolver,
            tokenService: tokenService,
            credentialExecutor: executor,
            nonceService: nonceService
        )
    }

    func test_requestCredentials_success() async throws {
        let service = makeService()

        let offer = CredentialOffer.mockWithTxCodeRequired()
        
        let result = try await service.requestCredentialsDraft13(
            issuerMetadata: IssuerMetadata.mock(),
            credentialOffer: offer,
            getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
            getProofJwt: { _ in "jwt-mock" },
            credentialConfigurationId: "mock-id",
            proofBindingContext: ProofBindingContext(),
            getTxCode: { _, _, _ in "tx123" }
        )

        XCTAssertEqual(result.credential.value as? String, "mock-credential")
    }

    func test_requestCredentials_v1_success_usesNonceServiceWhenHolderBindingSupported() async throws {
        let nonceService = MockNonceService()
        nonceService.nonceToReturn = "nonce-v1"

        let service = makeService(nonceService: nonceService)
        let offer = CredentialOffer.mockWithTxCodeRequired()

        var capturedNonce: String?

        let issuerMetadata = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialFormat: .ldp_vc,
            nonceEndpoint: "https://issuer.example.com/nonce"
        )

        let result = try await service.requestCredentials(
            issuerMetadata: issuerMetadata,
            credentialOffer: offer,
            getTokenResponse: { _ in
                TokenResponse(
                    accessToken: "mock",
                    tokenType: "Bearer"
                )
            },
            getProofs: { proofRequest in
                capturedNonce = proofRequest.nonce
                return CredentialRequestProofs(
                    proofs: ["jwt-mock"]
                )
            },
            credentialConfigurationId: "mock-id",
            proofBindingContext: ProofBindingContext(
                cryptographicBindingMethodsSupported: ["jwk"],
                proofTypesSupported: ["jwt"]
            ),
            getTxCode: { _, _, _ in
                "tx123"
            }
        )

        XCTAssertEqual(capturedNonce, "nonce-v1")
        XCTAssertEqual(result.credentials?.count, 1)
    }
    
    func test_requestCredentials_v1_withoutHolderBinding_doesNotGenerateProofs() async throws {
        let nonceService = MockNonceService()
        nonceService.nonceToReturn = "nonce-should-not-be-used"

        let executor = MockCredentialRequestExecutor()
        let service = makeService(
            executor: executor,
            nonceService: nonceService
        )

        let offer = CredentialOffer.mockWithTxCodeRequired()

        var getProofsCalled = false

        let issuerMetadata = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialFormat: .ldp_vc
        )

        let result = try await service.requestCredentials(
            issuerMetadata: issuerMetadata,
            credentialOffer: offer,
            getTokenResponse: { _ in
                TokenResponse(
                    accessToken: "mock",
                    tokenType: "Bearer"
                )
            },
            getProofs: { _ in
                getProofsCalled = true
                return CredentialRequestProofs(
                    proofs: ["jwt-should-not-be-generated"]
                )
            },
            credentialConfigurationId: "mock-id",
            proofBindingContext: ProofBindingContext(),
            getTxCode: { _, _, _ in
                "tx123"
            }
        )

        XCTAssertEqual(result.credentials?.count, 1)
        XCTAssertFalse(getProofsCalled)
        XCTAssertNil(executor.receivedProofs)
    }
    
    func test_requestCredentials_missingTokenEndpoint_shouldThrow() async {
        let resolver = MockAuthServerResolver()
        resolver.mockTokenEndpoint = nil

        let service = makeService(resolver: resolver)

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                credentialOffer: CredentialOffer(credentialIssuer: "mock", credentialConfigurationIds: ["mock-id"], grants: nil),
                getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
                getProofJwt: { _ in "jwt-mock" },
                credentialConfigurationId: "mock-id",
                proofBindingContext: ProofBindingContext(),
                getTxCode: { _, _, _ in "tx123" }
            )
            XCTFail("Expected failure due to missing token endpoint")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Token endpoint is missing"))
        }
    }

    func test_requestCredentials_txCodeRequiredButNotProvided_shouldThrow() async {
        let service = makeService()

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                credentialOffer: CredentialOffer(credentialIssuer: "mock", credentialConfigurationIds: ["mock-id"], grants: CredentialOfferGrants(preAuthorizedGrant: PreAuthCodeGrant(preAuthCode: "mock-pre-auth", txCode: TxCode(inputMode: nil, length: 2, description: nil), authorizationServer: nil, interval: nil), authorizationCodeGrant: nil)),
                getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
                getProofJwt: { _ in "jwt-mock" },
                credentialConfigurationId: "mock-id",
                proofBindingContext: ProofBindingContext()
            )
            XCTFail("Expected failure due to missing tx_code provider")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("tx_code required"))
        }
    }

    func test_requestCredentials_missingGrant_shouldThrow() async {
        let service = makeService()

        _ = CredentialOffer.mockWithoutGrant()

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                credentialOffer: CredentialOffer(credentialIssuer: "mock", credentialConfigurationIds: ["mock-id"], grants: nil),
                getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
                getProofJwt: { _ in "jwt-mock" },
                credentialConfigurationId: "mock-id",
                proofBindingContext: ProofBindingContext(),
                getTxCode: { _, _, _ in "tx123" }
            )
            
            XCTFail("Expected failure due to missing grant")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Missing pre-authorized grant details"))
        }
    }

    func test_requestCredentials_credentialDownloadFails_shouldThrow() async {
        let failingExecutor = MockCredentialRequestExecutor(shouldReturnNil: true)
        let service = makeService(executor: failingExecutor)

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                credentialOffer: CredentialOffer(credentialIssuer: "mock", credentialConfigurationIds: ["mock-id"], grants: CredentialOfferGrants(preAuthorizedGrant: PreAuthCodeGrant(preAuthCode: "mock", txCode: nil, authorizationServer: nil, interval: nil), authorizationCodeGrant: nil)),
                getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
                getProofJwt: { _ in "jwt-mock" },
                credentialConfigurationId: "mock-id",
                proofBindingContext: ProofBindingContext(),
                getTxCode: { _, _, _ in "tx123" }
            )
            XCTFail("Expected failure due to credential download returning nil")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Credential request failed"))
        }
    }
    
    func test_requestCredentialsDraft13_withoutHolderBinding_doesNotGenerateProof() async throws {
        let executor = MockCredentialRequestExecutor()
        let nonceService = MockNonceService()

        let service = makeService(
            executor: executor,
            nonceService: nonceService
        )

        let offer = CredentialOffer.mockWithTxCodeRequired()

        var getProofJwtCalled = false

        let issuerMetadata = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialFormat: .ldp_vc
        )

        let result = try await service.requestCredentialsDraft13(
            issuerMetadata: issuerMetadata,
            credentialOffer: offer,
            getTokenResponse: { _ in
                TokenResponse(
                    accessToken: "mock",
                    tokenType: "Bearer"
                )
            },
            getProofJwt: { _ in
                getProofJwtCalled = true
                return "should-not-be-called"
            },
            credentialConfigurationId: "mock-id",
            proofBindingContext: ProofBindingContext(),
            getTxCode: { _, _, _ in "tx123" }
        )
        XCTAssertNotNil(result)
        XCTAssertFalse(getProofJwtCalled)
        XCTAssertNil(executor.receivedProofDraft13)
    }
}
