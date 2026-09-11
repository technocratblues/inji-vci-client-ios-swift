import XCTest
@testable import VCIClient

final class CredentialOfferFlowHandlerTests: XCTestCase {

    private func makeMinimalIssuerMetadataResult() -> IssuerMetadataResult {
        return IssuerMetadataResult(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "aud",
                credentialEndpoint: "https://example.com",
                credentialFormat: .ldp_vc,
                specVersion: .draft13
            ),
            raw: [:]
        )
    }

    private func makeHolderBindingIssuerMetadataResult() -> IssuerMetadataResult {
        return IssuerMetadataResult(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "aud",
                credentialEndpoint: "https://example.com",
                credentialFormat: .ldp_vc,
                specVersion: .draft13
            ),
            raw: [
                "credential_configurations_supported": [
                    "config": [
                        "format": "ldp_vc",
                        "cryptographic_binding_methods_supported": ["jwk"],
                        "proof_types_supported": [
                            "jwt": [String: Any]()
                        ]
                    ]
                ]
            ]
        )
    }

    private func makeV1IssuerMetadataResult() -> IssuerMetadataResult {
        return IssuerMetadataResult(
            issuerMetadata: IssuerMetadata(
                credentialIssuer: "aud",
                credentialEndpoint: "https://example.com",
                credentialFormat: .ldp_vc,
                nonceEndpoint: "https://example.com/nonce"
            ),
            raw: [:]
        )
    }

    private func makeMinimalCredentialResponse() -> CredentialResponseDraft13 {
        return CredentialResponseDraft13(
            credential: .init("mock-credential"),
            credentialIssuer: "mock",
            credentialConfigurationId: "mcok-id"
        )
    }

    func testPreAuthorizedFlow_withNonceEndpoint_routesToV1() async throws {
        let offerService = MockCredentialOfferService()
        offerService.offerToReturn = CredentialOffer(
            credentialIssuer: "https://issuer.com",
            credentialConfigurationIds: ["config"],
            grants: CredentialOfferGrants(preAuthorizedGrant: PreAuthCodeGrant(preAuthCode: "test", txCode: nil, authorizationServer: nil, interval: nil), authorizationCodeGrant: nil)
        )

        let issuerService = MockIssuerMetadataService()
        issuerService.resultToReturn = makeV1IssuerMetadataResult()

        let preAuthFlowService = MockPreAuthFlowService()

        let handler = CredentialOfferFlowHandler(
            credentialOfferService: offerService,
            issuerMetadataService: issuerService,
            preAuthFlowService: preAuthFlowService,
            authorizationCodeFlowService: MockAuthorizationCodeFlowService()
        )

        let result = try await handler.downloadCredentials(
            credentialOffer: "offer",
            clientMetadata: ClientMetadata(clientId: "id", redirectUri: "uri"),
            getTxCode: { _, _, _ in "tx-code" },
            authorizationMethods: [],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
            getProofs: { _ in CredentialRequestProofs(proofs: ["mock-jwt"]) }
        )

        XCTAssertTrue(preAuthFlowService.didCallRequest)
        XCTAssertNotNil(result.credentials)
    }

    func testPreAuthorizedFlow_withoutNonceEndpoint_routesToDraft13() async throws {
        let offerService = MockCredentialOfferService()
        offerService.offerToReturn = CredentialOffer(
            credentialIssuer: "https://issuer.com",
            credentialConfigurationIds: ["config"],
            grants: CredentialOfferGrants(preAuthorizedGrant: PreAuthCodeGrant(preAuthCode: "test", txCode: nil, authorizationServer: nil, interval: nil), authorizationCodeGrant: nil)
        )

        let issuerService = MockIssuerMetadataService()
        issuerService.resultToReturn = makeMinimalIssuerMetadataResult()

        let preAuthFlowService = MockPreAuthFlowService()
        preAuthFlowService.responseToReturn = CredentialResponseDraft13(
            credential: .init("draft13-credential"),
            credentialIssuer: "mock-issuer",
            credentialConfigurationId: "mock"
        )

        let handler = CredentialOfferFlowHandler(
            credentialOfferService: offerService,
            issuerMetadataService: issuerService,
            preAuthFlowService: preAuthFlowService,
            authorizationCodeFlowService: MockAuthorizationCodeFlowService()
        )

        let result = try await handler.downloadCredentials(
            credentialOffer: "offer",
            clientMetadata: ClientMetadata(clientId: "id", redirectUri: "uri"),
            getTxCode: { _, _, _ in "tx-code" },
            authorizationMethods: [],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
            getProofs: { _ in CredentialRequestProofs(proofs: ["mock-jwt"]) }
        )

        XCTAssertTrue(preAuthFlowService.didCallRequest)
        XCTAssertEqual(result.credentials?.count, 1)
        XCTAssertEqual(result.credentials?.first?.credential?.value as? String, "draft13-credential")
        XCTAssertEqual(result.credentialIssuer, "mock-issuer")
        XCTAssertEqual(result.credentialConfigurationId, "mock")
    }

    func testAuthorizationCodeFlow_withNonceEndpoint_routesToV1() async throws {
        let offerService = MockCredentialOfferService()
        offerService.offerToReturn = CredentialOffer(
            credentialIssuer: "https://issuer.com",
            credentialConfigurationIds: ["config"],
            grants: CredentialOfferGrants(
                preAuthorizedGrant: nil,
                authorizationCodeGrant: AuthorizationCodeGrant(issuerState: nil, authorizationServer: nil)
            )
        )

        let issuerService = MockIssuerMetadataService()
        issuerService.resultToReturn = makeV1IssuerMetadataResult()

        let authCodeFlowService = MockAuthorizationCodeFlowService()

        let handler = CredentialOfferFlowHandler(
            credentialOfferService: offerService,
            issuerMetadataService: issuerService,
            preAuthFlowService: MockPreAuthFlowService(),
            authorizationCodeFlowService: authCodeFlowService
        )

        let result = try await handler.downloadCredentials(
            credentialOffer: "offer",
            clientMetadata: ClientMetadata(clientId: "id", redirectUri: "uri"),
            getTxCode: { _, _, _ in "tx-code" },
            authorizationMethods: [.redirectToWeb(openWebPage: { _ in ["code": "auth_code"] })],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
            getProofs: { _ in CredentialRequestProofs(proofs: ["mock-jwt"]) }
        )

        XCTAssertTrue(authCodeFlowService.didCallRequestCredentials)
        XCTAssertEqual(result.credentials?.count, 1)
    }

    func testDraft13Flow_withoutHolderBinding_allowsMissingJwtProof() async throws {
        let offerService = MockCredentialOfferService()

        offerService.offerToReturn = CredentialOffer(
            credentialIssuer: "https://issuer.com",
            credentialConfigurationIds: ["config"],
            grants: CredentialOfferGrants(
                preAuthorizedGrant: PreAuthCodeGrant(
                    preAuthCode: "test",
                    txCode: nil,
                    authorizationServer: nil,
                    interval: nil
                ),
                authorizationCodeGrant: nil
            )
        )

        let issuerService = MockIssuerMetadataService()
        issuerService.resultToReturn = makeMinimalIssuerMetadataResult()

        let handler = CredentialOfferFlowHandler(
            credentialOfferService: offerService,
            issuerMetadataService: issuerService,
            preAuthFlowService: PreAuthCodeFlowService(
                authServerResolver: MockAuthServerResolver(),
                tokenService: MockTokenService(),
                credentialExecutor: MockCredentialRequestExecutor(),
                nonceService: MockNonceService()
            ),
            authorizationCodeFlowService: MockAuthorizationCodeFlowService()
        )

        let result = try await handler.downloadCredentials(
            credentialOffer: "offer",
            clientMetadata: ClientMetadata(
                clientId: "id",
                redirectUri: "uri"
            ),
            getTxCode: { _, _, _ in "tx-code" },
            authorizationMethods: [],
            getTokenResponse: { _ in
                TokenResponse(
                    accessToken: "mock",
                    tokenType: "Bearer"
                )
            },
            getProofs: { _ in
                CredentialRequestProofs(proofs: [])
            }
        )

        XCTAssertNotNil(result)
    }

    func testDraft13Flow_withHolderBinding_missingJwtProof_throwsError() async {
        let offerService = MockCredentialOfferService()

        offerService.offerToReturn = CredentialOffer(
            credentialIssuer: "https://issuer.com",
            credentialConfigurationIds: ["config"],
            grants: CredentialOfferGrants(
                preAuthorizedGrant: PreAuthCodeGrant(
                    preAuthCode: "test",
                    txCode: nil,
                    authorizationServer: nil,
                    interval: nil
                ),
                authorizationCodeGrant: nil
            )
        )

        let issuerService = MockIssuerMetadataService()
        issuerService.resultToReturn = makeHolderBindingIssuerMetadataResult()

        let handler = CredentialOfferFlowHandler(
            credentialOfferService: offerService,
            issuerMetadataService: issuerService,
            preAuthFlowService: PreAuthCodeFlowService(
                authServerResolver: MockAuthServerResolver(),
                tokenService: MockTokenService(),
                credentialExecutor: MockCredentialRequestExecutor(),
                nonceService: MockNonceService()
            ),
            authorizationCodeFlowService: MockAuthorizationCodeFlowService()
        )

        await assertThrowsVCIErrorContainingMessage(
            expectedType: DownloadFailedException.self,
            messageContains: "proof"
        ) {
            try await handler.downloadCredentials(
                credentialOffer: "offer",
                clientMetadata: ClientMetadata(
                    clientId: "id",
                    redirectUri: "uri"
                ),
                getTxCode: { _, _, _ in "tx-code" },
                authorizationMethods: [],
                getTokenResponse: { _ in
                    TokenResponse(
                        accessToken: "mock",
                        tokenType: "Bearer"
                    )
                },
                getProofs: { _ in
                    CredentialRequestProofs(proofs: [])
                }
            ) as Any
        }
    }
    
    func testAuthorizationCodeFlow_callsAuthCodeFlowService() async throws {
        let offerService = MockCredentialOfferService()
        offerService.offerToReturn = CredentialOffer(
            credentialIssuer: "https://issuer.com",
            credentialConfigurationIds: ["config"],
            grants: CredentialOfferGrants(preAuthorizedGrant: nil, authorizationCodeGrant: AuthorizationCodeGrant(issuerState: nil, authorizationServer: nil))
        )

        let issuerService = MockIssuerMetadataService()
        issuerService.resultToReturn = makeMinimalIssuerMetadataResult()

        let authCodeFlowService = MockAuthorizationCodeFlowService()
        authCodeFlowService.responseToReturn = makeMinimalCredentialResponse()

        let handler = CredentialOfferFlowHandler(
            credentialOfferService: offerService,
            issuerMetadataService: issuerService,
            preAuthFlowService: MockPreAuthFlowService(),
            authorizationCodeFlowService: authCodeFlowService
        )

        _ = try await handler.downloadCredentials(
            credentialOffer: "offer",
            clientMetadata: ClientMetadata(clientId: "id", redirectUri: "uri"),
            getTxCode: { _, _, _ in "tx-code" },
            authorizationMethods: [AuthorizationMethod.redirectToWeb(openWebPage: { _ in ["code": "auth_code"] })],
            getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
            getProofs: { _ in CredentialRequestProofs(proofs: ["jwt"]) }
        )
        XCTAssertTrue(authCodeFlowService.didCallRequestCredentials)
    }

    func testTrustCheckBlocksWhenRejected() async {
        let offerService = MockCredentialOfferService()
        offerService.offerToReturn = CredentialOffer(
            credentialIssuer: "https://issuer.com",
            credentialConfigurationIds: ["config"],
            grants: CredentialOfferGrants(preAuthorizedGrant: PreAuthCodeGrant(preAuthCode: "test", txCode: nil, authorizationServer: nil, interval: nil), authorizationCodeGrant: nil)
        )

        let issuerService = MockIssuerMetadataService()
        issuerService.resultToReturn = makeMinimalIssuerMetadataResult()

        let preAuthFlowService = MockPreAuthFlowService()
        preAuthFlowService.responseToReturn = makeMinimalCredentialResponse()

        let handler = CredentialOfferFlowHandler(
            credentialOfferService: offerService,
            issuerMetadataService: issuerService,
            preAuthFlowService: preAuthFlowService,
            authorizationCodeFlowService: MockAuthorizationCodeFlowService()
        )

        do {
            _ = try await handler.downloadCredentials(
                credentialOffer: "offer",
                clientMetadata: ClientMetadata(clientId: "id", redirectUri: "uri"),
                getTxCode: { _, _, _ in "tx-code" },
                authorizationMethods: [AuthorizationMethod.redirectToWeb(openWebPage: { _ in ["code": "auth_code"] })],
                getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
                getProofs: { _ in CredentialRequestProofs(proofs: ["jwt"]) },
                onCheckIssuerTrust: { _, _ in false }
            )
            XCTFail("Expected OfferFetchFailedException")
        } catch let error as CredentialOfferFetchFailedException {
            XCTAssertTrue(error.message.contains("Issuer not trusted by user"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testThrowsWhenNoValidGrant() async {
        let offerService = MockCredentialOfferService()
        offerService.offerToReturn = CredentialOffer(
            credentialIssuer: "https://issuer.com",
            credentialConfigurationIds: ["config"],
            grants: CredentialOfferGrants(preAuthorizedGrant: nil, authorizationCodeGrant: nil)
        )

        let issuerService = MockIssuerMetadataService()
        issuerService.resultToReturn = makeMinimalIssuerMetadataResult()

        let handler = CredentialOfferFlowHandler(
            credentialOfferService: offerService,
            issuerMetadataService: issuerService,
            preAuthFlowService: MockPreAuthFlowService(),
            authorizationCodeFlowService: MockAuthorizationCodeFlowService()
        )

        do {
            _ = try await handler.downloadCredentials(
                credentialOffer: "offer",
                clientMetadata: ClientMetadata(clientId: "id", redirectUri: "uri"),
                getTxCode: { _, _, _ in "tx-code" },
                authorizationMethods: [AuthorizationMethod.redirectToWeb(openWebPage: { _ in ["code": "auth_code"] })],
                getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
                getProofs: { _ in CredentialRequestProofs(proofs: ["jwt"]) }
            )
            XCTFail("Expected OfferFetchFailedException")
        } catch let error as CredentialOfferFetchFailedException {
            XCTAssertTrue(error.message.contains("supported grant type"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testBatchCredentialOffer_throwsError() async {
        let offerService = MockCredentialOfferService()
        offerService.offerToReturn = CredentialOffer(
            credentialIssuer: "https://issuer.com",
            credentialConfigurationIds: ["config1", "config2"],
            grants: CredentialOfferGrants(
                preAuthorizedGrant: PreAuthCodeGrant(
                    preAuthCode: "test",
                    txCode: nil,
                    authorizationServer: nil,
                    interval: nil
                ),
                authorizationCodeGrant: nil
            )
        )

        let issuerService = MockIssuerMetadataService()
        issuerService.resultToReturn = makeMinimalIssuerMetadataResult()

        let preAuthFlowService = MockPreAuthFlowService()
        preAuthFlowService.responseToReturn = makeMinimalCredentialResponse()

        let handler = CredentialOfferFlowHandler(
            credentialOfferService: offerService,
            issuerMetadataService: issuerService,
            preAuthFlowService: preAuthFlowService,
            authorizationCodeFlowService: MockAuthorizationCodeFlowService()
        )

        do {
            _ = try await handler.downloadCredentials(
                credentialOffer: "offer",
                clientMetadata: ClientMetadata(clientId: "id", redirectUri: "uri"),
                getTxCode: { _, _, _ in "tx-code" },
                authorizationMethods: [AuthorizationMethod.redirectToWeb(openWebPage: { _ in ["code": "auth_code"] })],
                getTokenResponse: { _ in TokenResponse(accessToken: "mock", tokenType: "Bearer") },
                getProofs: { _ in CredentialRequestProofs(proofs: ["jwt"]) }
            )
            XCTFail("Expected CredentialOfferFetchFailedException for batch credential offer")
        } catch let error as DownloadFailedException {
            XCTAssertTrue(error.message.contains("Batch credential request is not supported"))
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

}
