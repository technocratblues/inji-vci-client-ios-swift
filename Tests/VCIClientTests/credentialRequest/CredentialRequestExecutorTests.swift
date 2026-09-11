import XCTest
@testable import VCIClient

final class CredentialRequestExecutorTests: XCTestCase {

    // MARK: - Mock Network Manager

    final class MockNetworkManager: NetworkManager {
        var responseBody: String = ""
        var responseHeaders: [AnyHashable: Any]? = nil
        var shouldThrowNetworkError: Bool = false
        var shouldThrowTimeout: Bool = false
        var simulateDelay: TimeInterval = 0

        var capturedUrlRequest: URLRequest?

        override func sendRequest(request: URLRequest) async throws -> NetworkResponse {
            if simulateDelay > 0 {
                try await Task.sleep(nanoseconds: UInt64(simulateDelay * 1_000_000_000))
            }

            if shouldThrowTimeout {
                throw NetworkRequestTimeoutException("Simulated timeout")
            }
            if shouldThrowNetworkError {
                throw DownloadFailedException("Simulated network failure")
            }

            capturedUrlRequest = request

            return NetworkResponse(
                body: responseBody,
                headers: responseHeaders
            )
        }
    }
    
    class MockCredentialRequestFactory: CredentialRequestFactoryProtocol {
        var mockRequestToReturn: URLRequest = URLRequest(url: URL(string: "https://example.com")!)
        var shouldThrow: Bool = false

        func createCredentialRequest(
            credentialFormat: CredentialFormat,
            accessToken: String,
            issuer: IssuerMetadata,
            proofJwt: Proof?
        ) throws -> URLRequest {
            if shouldThrow {
                throw DownloadFailedException("Simulated factory failure")
            }
            return mockRequestToReturn
        }
    }

    final class MockCredentialRequestFactoryV1: CredentialRequestFactory {
        var mockRequestToReturn: URLRequest = URLRequest(url: URL(string: "https://example.com")!)
        var shouldThrow: Bool = false

        override func createCredentialRequest(
            accessToken: String,
            issuer: IssuerMetadata,
            credentialConfigurationId: String,
            proofs: CredentialRequestProofs?
        ) throws -> URLRequest {
            if shouldThrow {
                throw DownloadFailedException("Simulated factory failure")
            }
            return mockRequestToReturn
        }
    }


    // MARK: - Tests

    func testRequestCredential_success_returnsParsedResponse() async throws {
        let factory = MockCredentialRequestFactory()
        factory.mockRequestToReturn = URLRequest(url: URL(string: "https://mocked.com")!)

        let networkManager = MockNetworkManager()
        networkManager.responseBody = "{\"credential\":\"test\"}"

        let executor = CredentialRequestExecutor(credentialRequestFactoryDraft13: factory)
        let result = try await executor.requestCredentialDraft13(
            issuerMetadata: mockIssuerMetadata(),
            credentialConfigurationId: "mock",
            proof: mockProof(),
            accessToken: "token",
            timeoutInMillis: 10000,
            session: networkManager
        )

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.credential.value as? String, "test")
    }

    func testRequestCredential_v1_success_returnsParsedResponseAndBackfillsMetadata() async throws {
        let factory = MockCredentialRequestFactoryV1()
        factory.mockRequestToReturn = URLRequest(url: URL(string: "https://mocked.com")!)

        let networkManager = MockNetworkManager()
        networkManager.responseBody = "{\"credentials\":[{\"credential\":\"test\"}]}"

        let executor = CredentialRequestExecutor(credentialRequestFactory: factory)
        let result = try await executor.requestCredential(
            issuerMetadata: mockIssuerMetadata(),
            credentialConfigurationId: "mock-config",
            proofs: CredentialRequestProofs(proofs: ["jwt-1"]),
            accessToken: "token",
            timeoutInMillis: 10000,
            session: networkManager
        )

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.credentials?.count, 1)
        XCTAssertEqual(result?.credentials?.first?.credential?.value as? String, "test")
        XCTAssertEqual(result?.credentialConfigurationId, "mock-config")
        XCTAssertEqual(result?.credentialIssuer, mockIssuerMetadata().credentialIssuer)
    }

    func testRequestCredential_v1_emptyBody_returnsNil() async throws {
        let factory = MockCredentialRequestFactoryV1()
        let networkManager = MockNetworkManager()
        networkManager.responseBody = ""

        let executor = CredentialRequestExecutor(credentialRequestFactory: factory)
        let result = try await executor.requestCredential(
            issuerMetadata: mockIssuerMetadata(),
            credentialConfigurationId: "mock",
            proofs: CredentialRequestProofs(proofs: ["jwt-1"]),
            accessToken: "token",
            session: networkManager
        )

        XCTAssertNil(result)
    }

    func testRequestCredential_v1_invalidJSON_shouldThrowDownloadFailedException() async {
        let factory = MockCredentialRequestFactoryV1()
        let networkManager = MockNetworkManager()
        networkManager.responseBody = "{invalid json}"

        let executor = CredentialRequestExecutor(credentialRequestFactory: factory)

        do {
            _ = try await executor.requestCredential(
                issuerMetadata: mockIssuerMetadata(),
                credentialConfigurationId: "mock",
                proofs: CredentialRequestProofs(proofs: ["jwt-1"]),
                accessToken: "token",
                session: networkManager
            )
            XCTFail("Expected DownloadFailedException but got success")
        } catch is DownloadFailedException {
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }



    func testFactoryThrowsError_shouldThrowDownloadFailedException() async {
            let factory = MockCredentialRequestFactory()
            factory.shouldThrow = true
            let executor = CredentialRequestExecutor(credentialRequestFactoryDraft13: factory)
            
            do {
                _ = try await executor.requestCredentialDraft13(
                    issuerMetadata: mockIssuerMetadata(),
                    credentialConfigurationId: "mock",
                    proof: mockProof(),
                    accessToken: "token"
                )
                XCTFail("Expected DownloadFailedException but got success")
            } catch is DownloadFailedException {
                // Success
            } catch {
                XCTFail("Unexpected error type: \(error)")
            }
        }
        
        func testNetworkManagerThrowsTimeout_shouldThrowDownloadFailedException() async {
            let factory = MockCredentialRequestFactory()
            let networkManager = MockNetworkManager()
            networkManager.shouldThrowTimeout = true
            let executor = CredentialRequestExecutor(credentialRequestFactoryDraft13: factory)
            
            do {
                _ = try await executor.requestCredentialDraft13(
                    issuerMetadata: mockIssuerMetadata(),
                    credentialConfigurationId: "mock",
                    proof: mockProof(),
                    accessToken: "token",
                    session: networkManager
                )
                XCTFail("Expected NetworkRequestTimeoutException but got success")
            } catch is DownloadFailedException {
                // Success
            } catch {
                XCTFail("Unexpected error type: \(error)")
            }
        }
        
        func testNetworkManagerThrowsDownloadFailed_shouldRethrowDownloadFailedException() async {
            let factory = MockCredentialRequestFactory()
            let networkManager = MockNetworkManager()
            networkManager.shouldThrowNetworkError = true
            let executor = CredentialRequestExecutor(credentialRequestFactoryDraft13: factory)
            
            do {
                _ = try await executor.requestCredentialDraft13(
                    issuerMetadata: mockIssuerMetadata(),
                    credentialConfigurationId: "mock",
                    proof: mockProof(),
                    accessToken: "token",
                    session: networkManager
                )
                XCTFail("Expected DownloadFailedException but got success")
            } catch is DownloadFailedException {
                // Success
            } catch {
                XCTFail("Unexpected error type: \(error)")
            }
        }
        
        func testNetworkManagerReturnsInvalidJSON_shouldThrowDownloadFailedException() async {
            let factory = MockCredentialRequestFactory()
            let networkManager = MockNetworkManager()
            networkManager.responseBody = "{invalid json}"
            let executor = CredentialRequestExecutor(credentialRequestFactoryDraft13: factory)
            
            do {
                _ = try await executor.requestCredentialDraft13(
                    issuerMetadata: mockIssuerMetadata(),
                    credentialConfigurationId: "mock",
                    proof: mockProof(),
                    accessToken: "token",
                    session: networkManager
                )
                XCTFail("Expected DownloadFailedException but got success")
            } catch is DownloadFailedException {
                // Success
            } catch {
                XCTFail("Unexpected error type: \(error)")
            }
        }
        
        func testUnexpectedErrorIsCaughtAndWrapped() async {
            class FailingNetworkManager: NetworkManager {
                override func sendRequest(request: URLRequest) async throws -> NetworkResponse {
                    throw NSError(domain: "Test", code: -999, userInfo: nil)
                }
            }
            
            let factory = MockCredentialRequestFactory()
            let networkManager = FailingNetworkManager()
            let executor = CredentialRequestExecutor(credentialRequestFactoryDraft13: factory)
            
            do {
                _ = try await executor.requestCredentialDraft13(
                    issuerMetadata: mockIssuerMetadata(),
                    credentialConfigurationId: "mock",
                    proof: mockProof(),
                    accessToken: "token",
                    session: networkManager
                )
                XCTFail("Expected DownloadFailedException but got success")
            } catch is DownloadFailedException {
                // Success
            } catch {
                XCTFail("Unexpected error type: \(error)")
            }
        }

    // MARK: - DPoP

    final class SequencedNetworkManager: NetworkManager {
        var outcomes: [() throws -> NetworkResponse] = []
        var sent: [URLRequest] = []
        private var index = 0

        override func sendRequest(request: URLRequest) async throws -> NetworkResponse {
            sent.append(request)
            defer { index += 1 }
            return try outcomes[index]()
        }
    }

    private func dpopManager() throws -> DPoPManager {
        let manager = DPoPManager()
        try manager.initialize(tokenEndpoint: "https://as.example.com/token", authorizationServerSupportedAlgorithms: ["ES256"])
        return manager
    }

    private func nonceClaim(in request: URLRequest) throws -> String? {
        let proof = try XCTUnwrap(request.value(forHTTPHeaderField: "DPoP"))
        let payload = try XCTUnwrap(try Data(base64URLEncodedString: proof.components(separatedBy: ".")[1]))
        let claims = try XCTUnwrap(try JSONSerialization.jsonObject(with: payload) as? [String: Any])
        return claims["nonce"] as? String
    }

    func testRequestCredential_dpop_appliesDpopAuthorizationAndProof() async throws {
        let factory = MockCredentialRequestFactory()
        let networkManager = MockNetworkManager()
        networkManager.responseBody = "{\"credential\":\"vc\"}"

        let executor = CredentialRequestExecutor(credentialRequestFactoryDraft13: factory)
        _ = try await executor.requestCredentialDraft13(
            issuerMetadata: mockIssuerMetadata(),
            credentialConfigurationId: "mock",
            proof: mockProof(),
            accessToken: "token",
            session: networkManager,
            tokenType: "DPoP",
            dpopManager: try dpopManager()
        )

        let request = try XCTUnwrap(networkManager.capturedUrlRequest)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "DPoP token")
        XCTAssertNotNil(request.value(forHTTPHeaderField: "DPoP"))
    }

    func testRequestCredential_dpop_retriesWithServerNonce() async throws {
        let factory = MockCredentialRequestFactory()
        let networkManager = SequencedNetworkManager()
        networkManager.outcomes = [
            {
                throw NetworkRequestFailedException(
                    message: "HTTP 401",
                    httpStatusCode: 401,
                    headers: [
                        "WWW-Authenticate": "DPoP error=\"use_dpop_nonce\"",
                        "DPoP-Nonce": "server-nonce",
                    ]
                )
            },
            { NetworkResponse(body: "{\"credential\":\"vc\"}", headers: nil) },
        ]

        let executor = CredentialRequestExecutor(credentialRequestFactoryDraft13: factory)
        let result = try await executor.requestCredentialDraft13(
            issuerMetadata: mockIssuerMetadata(),
            credentialConfigurationId: "mock",
            proof: mockProof(),
            accessToken: "token",
            session: networkManager,
            tokenType: "DPoP",
            dpopManager: try dpopManager()
        )

        XCTAssertNotNil(result)
        XCTAssertEqual(networkManager.sent.count, 2)
        XCTAssertEqual(try nonceClaim(in: networkManager.sent[1]), "server-nonce")
    }

    func testRequestCredential_dpop_carriesSeededIssuerNonceOnFirstRequest() async throws {
        let factory = MockCredentialRequestFactory()
        let networkManager = SequencedNetworkManager()
        networkManager.outcomes = [
            { NetworkResponse(body: "{\"credential\":\"vc\"}", headers: nil) },
        ]
        let manager = try dpopManager()
        manager.updateNonce("nonce-endpoint-nonce")

        _ = try await CredentialRequestExecutor(credentialRequestFactoryDraft13: factory).requestCredentialDraft13(
            issuerMetadata: mockIssuerMetadata(),
            credentialConfigurationId: "mock",
            proof: mockProof(),
            accessToken: "token",
            session: networkManager,
            tokenType: "DPoP",
            dpopManager: manager
        )

        XCTAssertEqual(networkManager.sent.count, 1)
        XCTAssertEqual(try nonceClaim(in: networkManager.sent[0]), "nonce-endpoint-nonce")
    }

    func testRequestCredential_dpop_storesRotatedNonceFromSuccessResponse() async throws {
        let factory = MockCredentialRequestFactory()
        let networkManager = MockNetworkManager()
        networkManager.responseBody = "{\"credential\":\"vc\"}"
        networkManager.responseHeaders = ["DPoP-Nonce": "rotated-nonce"]
        let manager = try dpopManager()

        _ = try await CredentialRequestExecutor(credentialRequestFactoryDraft13: factory).requestCredentialDraft13(
            issuerMetadata: mockIssuerMetadata(),
            credentialConfigurationId: "mock",
            proof: mockProof(),
            accessToken: "token",
            session: networkManager,
            tokenType: "DPoP",
            dpopManager: manager
        )

        let nextProof = try manager.generateCredentialProof(
            credentialEndpoint: mockIssuerMetadata().credentialEndpoint,
            accessToken: "token"
        )
        let payload = try XCTUnwrap(try Data(base64URLEncodedString: nextProof.components(separatedBy: ".")[1]))
        let claims = try XCTUnwrap(try JSONSerialization.jsonObject(with: payload) as? [String: Any])
        XCTAssertEqual(claims["nonce"] as? String, "rotated-nonce")
    }

    func testRequestCredential_dpop_bearerFallbackOnBearerOnlyChallenge() async throws {
        let factory = MockCredentialRequestFactory()
        let networkManager = SequencedNetworkManager()
        networkManager.outcomes = [
            {
                throw NetworkRequestFailedException(
                    message: "HTTP 401",
                    httpStatusCode: 401,
                    headers: ["WWW-Authenticate": "Bearer error=\"invalid_token\""]
                )
            },
            { NetworkResponse(body: "{\"credential\":\"vc\"}", headers: nil) },
        ]

        let executor = CredentialRequestExecutor(credentialRequestFactoryDraft13: factory)
        _ = try await executor.requestCredentialDraft13(
            issuerMetadata: mockIssuerMetadata(),
            credentialConfigurationId: "mock",
            proof: mockProof(),
            accessToken: "token",
            session: networkManager,
            tokenType: "DPoP",
            dpopManager: try dpopManager()
        )

        XCTAssertEqual(networkManager.sent.count, 2)
        XCTAssertEqual(networkManager.sent[1].value(forHTTPHeaderField: "Authorization"), "Bearer token")
        XCTAssertNil(networkManager.sent[1].value(forHTTPHeaderField: "DPoP"))
    }
}
