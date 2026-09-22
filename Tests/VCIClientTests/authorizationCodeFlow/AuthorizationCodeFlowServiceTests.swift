@testable import VCIClient
import XCTest

final class AuthorizationCodeFlowServiceTests: XCTestCase {
    func makeService(
        resolver: AuthorizationServerResolver = MockAuthServerResolver(),
        tokenService: TokenService = MockTokenService(),
        executor: CredentialRequestExecutor = MockCredentialRequestExecutor(),
        pkceManager: PKCESessionManager = MockPKCESessionManager(),
        interactiveAuthHandler: InteractiveAuthorizationHandler = MockInteractiveAuthorizationHandler(),
        nonceService: NonceService = MockNonceService()
    ) -> AuthorizationCodeFlowService {
        return AuthorizationCodeFlowService(
            authServerResolver: resolver,
            tokenService: tokenService,
            credentialExecutor: executor,
            pkceSessionManager: pkceManager,
            interactiveAuthorizationHandler: interactiveAuthHandler,
            nonceService: nonceService
        )
    }

    func test_requestCredentials_success() async throws {
        let service = makeService()

        let result = try await service.requestCredentialsDraft13(
            issuerMetadata: IssuerMetadata.mock(),
            clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
            authorizationMethods: [
                .redirectToWeb(openWebPage: {
                    _ in ["code": "mock-auth-code"]
                }),
            ],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer") },
            getProofJwt: { _ in "mock-jwt" },
            credentialConfigurationId: "vc1",
            proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
        )

        XCTAssertEqual(result.credential.value as? String, "mock-credential")
    }

    func test_requestCredentials_v1_success_usesNonceServiceWhenHolderBindingSupported() async throws {
        let nonceService = MockNonceService()
        nonceService.nonceToReturn = "nonce-v1"

        let service = makeService(nonceService: nonceService)
        var capturedNonce: String?

        let issuerMetadata = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialFormat: .ldp_vc,
            nonceEndpoint: "https://issuer.example.com/nonce"
        )

        let result = try await service.requestCredentials(
            issuerMetadata: issuerMetadata,
            clientMetadata: ClientMetadata(
                clientId: "client123",
                redirectUri: "app://redirect"
            ),
            authorizationMethods: [
                .redirectToWeb(openWebPage: { _ in
                    ["code": "mock-auth-code"]
                }),
            ],
            getTokenResponse: { _ in
                TokenResponse(
                    accessToken: "mock-token",
                    tokenType: "Bearer"
                )
            },
            getProofs: { proofRequest in
                capturedNonce = proofRequest.nonce

                return CredentialRequestProofs(
                    proofs: ["mock-jwt"]
                )
            },
            credentialConfigurationId: "vc1",
            proofBindingContext: ProofBindingContext(
                proofSigningAlgorithmsSupported: ["rs256"],
                cryptographicBindingMethodsSupported: ["jwk"],
                proofTypesSupported: ["jwt"]
            )
        )

        XCTAssertEqual(capturedNonce, "nonce-v1")
        XCTAssertEqual(result.credentials?.count, 1)
    }
    
    func test_requestCredentials_v1_withoutHolderBinding_doesNotGenerateProofs() async throws {
        let executor = MockCredentialRequestExecutor()
        let service = makeService(executor: executor)

        var getProofsCalled = false

        let issuerMetadata = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialFormat: .ldp_vc
        )

        let result = try await service.requestCredentials(
            issuerMetadata: issuerMetadata,
            clientMetadata: ClientMetadata(
                clientId: "client123",
                redirectUri: "app://redirect"
            ),
            authorizationMethods: [
                .redirectToWeb(openWebPage: { _ in
                    ["code": "mock-auth-code"]
                }),
            ],
            getTokenResponse: { _ in
                TokenResponse(
                    accessToken: "mock-token",
                    tokenType: "Bearer"
                )
            },
            getProofs: { _ in
                getProofsCalled = true

                return CredentialRequestProofs(
                    proofs: ["jwt-should-not-be-generated"]
                )
            },
            credentialConfigurationId: "vc1",
            proofBindingContext: ProofBindingContext(
                proofSigningAlgorithmsSupported: ["rs256"]
            )
        )

        XCTAssertEqual(result.credentials?.count, 1)
        XCTAssertFalse(getProofsCalled)
        XCTAssertNil(executor.receivedProofs)
    }

    func test_missingAuthorizationEndpoint_shouldThrow() async {
        let resolver = MockAuthServerResolver()
        resolver.mcokAuthorizationEndpoint = nil

        let service = makeService(resolver: resolver)

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer") },
                getProofJwt: { _ in "mock-jwt" },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
            )
            XCTFail("Expected to throw due to missing authorization endpoint")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Missing authorization endpoint"))
        }
    }

    func test_missingTokenEndpoint_shouldThrow() async {
        let resolver = MockAuthServerResolver()
        resolver.mockTokenEndpoint = nil

        let service = makeService(resolver: resolver)

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer") },
                getProofJwt: { _ in "mock-jwt" },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
            )
            XCTFail("Expected to throw due to missing token endpoint")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Missing token endpoint"))
        }
    }

    func test_requestCredentials_withInteractiveAuthorizationEndpoint_success() async throws {
        let resolver = MockAuthServerResolver()
        resolver.mockIssuer = "https://auth.example.com"
        resolver.mockGrantTypesSupported = ["authorization_code"]
        resolver.mockTokenEndpoint = "https://auth.example.com/token"
        resolver.mcokAuthorizationEndpoint = nil
        resolver.mockInteractiveAuthorizationEndpoint = "https://auth.example.com/interactive"
        resolver.mockRequireInteractiveAuthorizationRequest = true


        let interactiveHandler = MockInteractiveAuthorizationHandler()
        interactiveHandler.responseToReturn = AuthorizationResponse(
            authorizationCode: "interactive-code",
            status: "success",
            error: nil,
            errorDescription: nil,
            authSession: "session-1"
        )

        let service = makeService(
            resolver: resolver,
            interactiveAuthHandler: interactiveHandler
        )

        let metadata = IssuerMetadata(
            credentialIssuer: "https://example.com",
            credentialEndpoint: "https://example.com/credential",
            credentialFormat: .ldp_vc,
            authorizationServers: ["https://auth.example.com"]
        )

        let offer = CredentialOffer(
            credentialIssuer: "https://example.com",
            credentialConfigurationIds: ["vc1"],
            grants: CredentialOfferGrants(
                preAuthorizedGrant: nil,
                authorizationCodeGrant: AuthorizationCodeGrant(
                    issuerState: nil,
                    authorizationServer: "https://auth.example.com"
                )
            )
        )

        let result = try await service.requestCredentialsDraft13(
            issuerMetadata: metadata,
            clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
            authorizationMethods: [],
            getTokenResponse: { _ in TokenResponse.mock() },
            getProofJwt: { _ in "mock-jwt" },
            credentialConfigurationId: "vc1",
            proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"]),
            credentialOffer: offer
        )

        XCTAssertEqual(result.credential.value as? String, "mock-credential")
    }

    func test_interactiveAuth_threadsDpopJktThumbprintToHandler() async throws {
        let resolver = MockAuthServerResolver()
        resolver.mockIssuer = "https://auth.example.com"
        resolver.mockGrantTypesSupported = ["authorization_code"]
        resolver.mockTokenEndpoint = "https://auth.example.com/token"
        resolver.mcokAuthorizationEndpoint = nil
        resolver.mockInteractiveAuthorizationEndpoint = "https://auth.example.com/interactive"
        resolver.mockRequireInteractiveAuthorizationRequest = true

        let interactiveHandler = MockInteractiveAuthorizationHandler()
        interactiveHandler.responseToReturn = AuthorizationResponse(
            authorizationCode: "interactive-code",
            status: "success",
            error: nil,
            errorDescription: nil,
            authSession: "session-1"
        )

        let service = makeService(resolver: resolver, interactiveAuthHandler: interactiveHandler)
        let dpopManager = DPoPManager()

        _ = try await service.requestCredentialsDraft13(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "https://example.com",
                credentialEndpoint: "https://example.com/credential",
                credentialFormat: .ldp_vc,
                authorizationServers: ["https://auth.example.com"]
            ),
            clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
            authorizationMethods: [],
            getTokenResponse: { _ in TokenResponse.mock() },
            getProofJwt: { _ in "mock-jwt" },
            credentialConfigurationId: "vc1",
            proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"]),
            dpopManager: dpopManager
        )

        let expectedThumbprint = try dpopManager.jwkThumbprint()
        XCTAssertEqual(interactiveHandler.capturedDpopJkt, expectedThumbprint)
    }

    func test_interactiveAuth_missingInteractionType_shouldFallbackToAuthorizationEndpoint() async throws {
        let resolver = MockAuthServerResolver()
        resolver.mockInteractiveAuthorizationEndpoint = "https://auth.example.com/interactive"
        resolver.mockRequireInteractiveAuthorizationRequest = false

        let interactiveHandler = MockInteractiveAuthorizationHandler()
        interactiveHandler.shouldThrowMissingInteractionType = true

        let service = makeService(
            resolver: resolver,
            interactiveAuthHandler: interactiveHandler
        )

        let result = try await service.requestCredentialsDraft13(
            issuerMetadata: IssuerMetadata.mock(),
            clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
            authorizationMethods: [
                .redirectToWeb(openWebPage: { _ in ["code": "fallback-auth-code"] }),
            ],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer") },
            getProofJwt: { _ in "mock-jwt" },
            credentialConfigurationId: "vc1",
            proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
        )

        XCTAssertEqual(result.credential.value as? String, "mock-credential")
    }

    func test_interactiveAuth_missingInteractionType_shouldNotFallbackWhenInteractiveAuthorizationIsRequired() async {

        let resolver = MockAuthServerResolver()
        resolver.mockInteractiveAuthorizationEndpoint = "https://auth.example.com/interactive"
        resolver.mockRequireInteractiveAuthorizationRequest = true

        let interactiveHandler = MockInteractiveAuthorizationHandler()
        interactiveHandler.shouldThrowMissingInteractionType = true

        let service = makeService(
            resolver: resolver,
            interactiveAuthHandler: interactiveHandler
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                authorizationMethods: [
                    .redirectToWeb(openWebPage: { _ in ["code": "fallback-auth-code"] }),
                ],
                getTokenResponse: { _ in
                    TokenResponse(accessToken: "mock-token", tokenType: "Bearer")
                },
                getProofJwt: { _ in "mock-jwt" },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
            )
        } verify: { error in
            let downloadError = error as? DownloadFailedException
            XCTAssertNotNil(downloadError)
            XCTAssertEqual(
                downloadError?.issuerErrorCode,
                Constants.MISSING_INTERACTION_TYPE_ERROR
            )
        }
    }

    func test_requestCredentials_whenInteractiveAuthorizationIsMissingType_wrapsFailure() async {
        let resolver = MockAuthServerResolver()
        resolver.mockIssuer = "https://auth.example.com"
        resolver.mockGrantTypesSupported = ["authorization_code"]
        resolver.mockTokenEndpoint = "https://auth.example.com/token"
        resolver.mcokAuthorizationEndpoint = nil
        resolver.mockInteractiveAuthorizationEndpoint = "https://auth.example.com/interactive"
        resolver.mockRequireInteractiveAuthorizationRequest = true

        let interactiveHandler = MockInteractiveAuthorizationHandler()
        interactiveHandler.errorToThrow = InteractiveAuthorizationException(message: "missing_interaction_type")

        let service = makeService(
            resolver: resolver,
            interactiveAuthHandler: interactiveHandler
        )

        let metadata = IssuerMetadata(
            credentialIssuer: "https://example.com",
            credentialEndpoint: "https://example.com/credential",
            credentialFormat: .ldp_vc,
            authorizationServers: ["https://auth.example.com"]
        )

        let offer = CredentialOffer(
            credentialIssuer: "https://example.com",
            credentialConfigurationIds: ["vc1"],
            grants: CredentialOfferGrants(
                preAuthorizedGrant: nil,
                authorizationCodeGrant: AuthorizationCodeGrant(
                    issuerState: nil,
                    authorizationServer: "https://auth.example.com"
                )
            )
        )

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: metadata,
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                authorizationMethods: [],
                getTokenResponse: { _ in TokenResponse.mock() },
                getProofJwt: { _ in "mock-jwt" },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"]),
                credentialOffer: offer
            )
            XCTFail("Expected interactive authorization failure")
        } catch let error as DownloadFailedException {
            XCTAssertTrue(error.message.contains("Interactive authorization failed"))
            XCTAssertTrue(error.message.contains("missing_interaction_type"))
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func test_requestCredentials_withoutAuthorizationMethod_shouldThrow() async {
        let service = makeService()

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                authorizationMethods: [],
                getTokenResponse: { _ in TokenResponse.mock() },
                getProofJwt: { _ in "mock-jwt" },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
            )
            XCTFail("Expected missing authorization method failure")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("No authorization method available"))
        }
    }

    func test_requestCredentials_whenProofCallbackThrows_wrapsFailure() async {
        let service = makeService()

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata(
                    credentialIssuer: "https://issuer.example.com",
                    credentialEndpoint: "https://issuer.example.com/credential",
                    credentialFormat: .ldp_vc,
                    nonceEndpoint: "https://issuer.example.com/nonce"
                ),
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                authorizationMethods: [
                    .redirectToWeb(openWebPage: { _ in ["code": "mock-auth-code"] }),
                ],
                getTokenResponse: { _ in TokenResponse.mock() },
                getProofJwt: { _ in
                    throw NSError(domain: "proof", code: 1)
                },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(
                    proofSigningAlgorithmsSupported: ["rs256"],
                    cryptographicBindingMethodsSupported: ["jwk"],
                    proofTypesSupported: ["jwt"]
                )
            )
            XCTFail("Expected proof callback failure")
        } catch {
            XCTAssertTrue(
                error.localizedDescription.contains("Failed to obtain proof JWT")
            )
        }
    }

    func test_requestCredentials_whenCredentialExecutorThrows_wrapsFailure() async {
        let executor = MockCredentialRequestExecutor()
        executor.errorToThrow = DownloadFailedException("credential failure")

        let service = makeService(executor: executor)

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                authorizationMethods: [
                    .redirectToWeb(openWebPage: { _ in ["code": "mock-auth-code"] }),
                ],
                getTokenResponse: { _ in TokenResponse.mock() },
                getProofJwt: { _ in "mock-jwt" },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
            )
            XCTFail("Expected credential executor failure")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("credential failure"))
        }
    }

    func test_credentialRequest_failure_shouldThrow() async {
        let executor = MockCredentialRequestExecutor()
        executor.shouldThrow = true

        let service = makeService(executor: executor)

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                authorizationMethods: [
                    .redirectToWeb(openWebPage: { _ in ["code": "mock-auth-code"] }),
                ],
                getTokenResponse: { _ in TokenResponse(accessToken: "mock-token", tokenType: "Bearer") },
                getProofJwt: { _ in "mock-jwt" },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
            )
            XCTFail("Expected credential request failure")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("credential"))
        }
    }

    func test_requestCredentials_whenTokenServiceThrowsWrapsFailure() async {
        let tokenService = MockTokenService()
        tokenService.authCodeErrorToThrow = InvalidDataProvidedException("token service rejected request")
        let service = makeService(tokenService: tokenService)

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                authorizationMethods: [
                    .redirectToWeb(openWebPage: { _ in ["code": "mock-auth-code"] }),
                ],
                getTokenResponse: { _ in TokenResponse.mock() },
                getProofJwt: { _ in "mock-jwt" },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
            )
            XCTFail("Expected token service failure")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Failed to obtain access token via authorization code flow"))
        }
    }

    func test_requestCredentials_whenCredentialResponseIsNil_shouldThrow() async {
        let executor = MockCredentialRequestExecutor(shouldReturnNil: true)
        let service = makeService(executor: executor)

        do {
            _ = try await service.requestCredentialsDraft13(
                issuerMetadata: IssuerMetadata.mock(),
                clientMetadata: ClientMetadata(clientId: "client123", redirectUri: "app://redirect"),
                authorizationMethods: [
                    .redirectToWeb(openWebPage: { _ in ["code": "mock-auth-code"] }),
                ],
                getTokenResponse: { _ in TokenResponse.mock() },
                getProofJwt: { _ in "mock-jwt" },
                credentialConfigurationId: "vc1",
                proofBindingContext: ProofBindingContext(proofSigningAlgorithmsSupported: ["rs256"])
            )
            XCTFail("Expected nil credential failure")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Credential request returned nil"))
        }
    }
}
