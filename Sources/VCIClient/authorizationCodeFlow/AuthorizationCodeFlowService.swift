import Foundation

class AuthorizationCodeFlowService {
    private let authServerResolver: AuthorizationServerResolver
    private let tokenService: TokenService
    private let credentialRequestExecutor: CredentialRequestExecutor
    private let pkceSessionManager: PKCESessionManager
    private let interactiveAuthorizationHandler: InteractiveAuthorizationHandler
    private let nonceService: NonceService
    
    init(
        authServerResolver: AuthorizationServerResolver = AuthorizationServerResolver(),
        tokenService: TokenService = TokenService(),
        credentialExecutor: CredentialRequestExecutor = CredentialRequestExecutor(),
        pkceSessionManager: PKCESessionManager = PKCESessionManager(),
        interactiveAuthorizationHandler: InteractiveAuthorizationHandler = InteractiveAuthorizationHandler(),
        nonceService: NonceService = NonceService()
    ) {
        self.authServerResolver = authServerResolver
        self.tokenService = tokenService
        credentialRequestExecutor = credentialExecutor
        self.pkceSessionManager = pkceSessionManager
        self.interactiveAuthorizationHandler = interactiveAuthorizationHandler
        self.nonceService = nonceService
    }
    
    func requestCredentials(
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        authorizationMethods: [AuthorizationMethod] = [],
        getTokenResponse: @escaping TokenResponseCallback,
        getProofs: @escaping ProofsCallback,
        credentialConfigurationId: String,
        proofSigningAlgorithmsSupported: [String],
        credentialOffer: CredentialOffer? = nil,
        downloadTimeOutInMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        session: NetworkManager = NetworkManager.shared
    ) async throws -> CredentialResponse {
        try await executeRequestCredentials(
            issuerMetadata: issuerMetadata,
            clientMetadata: clientMetadata,
            authorizationMethods: authorizationMethods,
            getTokenResponse: getTokenResponse,
            credentialConfigurationId: credentialConfigurationId,
            proofSigningAlgorithmsSupported: proofSigningAlgorithmsSupported,
            credentialOffer: credentialOffer,
            downloadTimeOutInMillis: downloadTimeOutInMillis,
            session: session
        ) { token in
            let proofs: CredentialRequestProofs
            let nonce = try await nonceService.fetchNonce(issuerMetadata: issuerMetadata, timeoutInMillis: downloadTimeOutInMillis)
            
            do {
                proofs = try await getProofs(
                    issuerMetadata.credentialIssuer,
                    nonce,
                    proofSigningAlgorithmsSupported
                )
            } catch {
                throw DownloadFailedException("Failed to obtain proofs from callback: \(error.localizedDescription)")
            }
            
            return try await self.credentialRequestExecutor.requestCredential(
                issuerMetadata: issuerMetadata,
                credentialConfigurationId: credentialConfigurationId,
                proofs: proofs,
                accessToken: token.accessToken,
                timeoutInMillis: downloadTimeOutInMillis,
                session: session
            )
        }
    }
    
    func requestCredentialsDraft13(
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        authorizationMethods: [AuthorizationMethod] = [],
        getTokenResponse: @escaping TokenResponseCallback,
        getProofJwt: @escaping ProofJwtCallback,
        credentialConfigurationId: String,
        proofSigningAlgorithmsSupported: [String],
        credentialOffer: CredentialOffer? = nil,
        downloadTimeOutInMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        session: NetworkManager = NetworkManager.shared
    ) async throws -> CredentialResponseDraft13 {
        try await executeRequestCredentials(
            issuerMetadata: issuerMetadata,
            clientMetadata: clientMetadata,
            authorizationMethods: authorizationMethods,
            getTokenResponse: getTokenResponse,
            credentialConfigurationId: credentialConfigurationId,
            proofSigningAlgorithmsSupported: proofSigningAlgorithmsSupported,
            credentialOffer: credentialOffer,
            downloadTimeOutInMillis: downloadTimeOutInMillis,
            session: session
        ) { token in
            
            let nonce = try NonceService.extractNonceFromTokenResponse(token)
            let jwt: String
            do {
                jwt = try await getProofJwt(
                    issuerMetadata.credentialIssuer,
                    nonce,
                    proofSigningAlgorithmsSupported
                )
            } catch {
                throw DownloadFailedException("Failed to obtain proof JWT from callback: \(error.localizedDescription)")
            }
            
            return try await self.credentialRequestExecutor.requestCredentialDraft13(
                issuerMetadata: issuerMetadata,
                credentialConfigurationId: credentialConfigurationId,
                proof: JWTProof(jwt: jwt),
                accessToken: token.accessToken,
                timeoutInMillis: downloadTimeOutInMillis,
                session: session
            )
        }
    }
    
    private func executeRequestCredentials<Response>(
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        authorizationMethods: [AuthorizationMethod],
        getTokenResponse: @escaping TokenResponseCallback,
        credentialConfigurationId: String,
        proofSigningAlgorithmsSupported: [String],
        credentialOffer: CredentialOffer?,
        downloadTimeOutInMillis: Int64,
        session: NetworkManager,
        requestCredential: (TokenResponse) async throws -> Response?
    ) async throws -> Response {
        do {
            let pkceSession = pkceSessionManager.createSession()
            
            let authServerMetadata: AuthorizationServerMetadata
            do {
                authServerMetadata = try await authServerResolver.resolveForAuthCode(
                    issuerMetadata: issuerMetadata,
                    credentialOffer: credentialOffer
                )
            } catch let e as DownloadFailedException {
                throw e
            } catch let e as VCIClientException {
                throw DownloadFailedException(
                    message: "Failed to resolve authorization server metadata for issuer \(e.localizedDescription)",
                    serverErrorCode: e.serverErrorCode,
                    serverErrorDescription: e.serverErrorDescription
                )
            }
            
            let token: TokenResponse
            do {
                token = try await performAuthorizationAndGetToken(
                    authServerMetadata: authServerMetadata,
                    issuerMetadata: issuerMetadata,
                    clientMetadata: clientMetadata,
                    authorizationMethods: authorizationMethods,
                    pkceSession: pkceSession,
                    getTokenResponse: getTokenResponse,
                    credentialConfigurationId: credentialConfigurationId
                )
            } catch let e as DownloadFailedException {
                throw e
            } catch let e as VCIClientException {
                throw DownloadFailedException(
                    message: "Failed to obtain access token via authorization code flow: \(e.localizedDescription)",
                    serverErrorCode: e.serverErrorCode,
                    serverErrorDescription: e.serverErrorDescription,
                    cause: e
                )
            } catch {
                throw DownloadFailedException(message: "Failed to obtain access token via authorization code flow: \(error.localizedDescription)", cause: error)
            }
            
            guard let response = try await requestCredential(token) else {
                throw DownloadFailedException("Credential request returned nil.")
            }
            
            return response
        } catch let e as DownloadFailedException {
            throw e
        } catch let e as VCIClientException {
            throw DownloadFailedException(
                message: e.message,
                serverErrorCode: e.serverErrorCode,
                serverErrorDescription: e.serverErrorDescription,
                cause: e
            )
        } catch {
            throw DownloadFailedException(
                message: "Download failed via authorization code flow: \(error.localizedDescription)",
                cause: error
            )
        }
    }
    
    private func performAuthorizationAndGetToken(
        authServerMetadata: AuthorizationServerMetadata,
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        authorizationMethods: [AuthorizationMethod],
        pkceSession: PKCESessionManager.PKCESession,
        getTokenResponse: @escaping TokenResponseCallback,
        credentialConfigurationId: String
    ) async throws -> TokenResponse {
        guard let tokenEndpoint = issuerMetadata.tokenEndpoint ?? authServerMetadata.tokenEndpoint else {
            throw DownloadFailedException("Missing token endpoint for issuer \(issuerMetadata.credentialIssuer)")
        }
        
        let authCode = try await obtainAuthorizationCode(authorizationServerMetadata: authServerMetadata, issuerMetadata: issuerMetadata, clientMetadata: clientMetadata, pkceSession: pkceSession, credentialConfigurationId: credentialConfigurationId, authorizationMethods: authorizationMethods)
        
        return try await tokenService.getAccessToken(
            getTokenResponse: getTokenResponse,
            tokenEndpoint: tokenEndpoint,
            authCode: authCode,
            clientId: clientMetadata.clientId,
            redirectUri: clientMetadata.redirectUri,
            codeVerifier: pkceSession.codeVerifier
        )
    }
    
    private func obtainAuthorizationCode(
        authorizationServerMetadata: AuthorizationServerMetadata,
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        pkceSession: PKCESessionManager.PKCESession,
        credentialConfigurationId: String,
        authorizationMethods: [AuthorizationMethod]
    ) async throws -> String {
        if authorizationServerMetadata.requireInteractiveAuthorizationRequest == true ||
            authorizationServerMetadata.interactiveAuthorizationEndpoint != nil {
            
            guard let interactiveEndpoint = authorizationServerMetadata.interactiveAuthorizationEndpoint else {
                throw DownloadFailedException(message: "Missing interactive authorization endpoint")
            }
            
            do {
                return try await obtainAuthorizationCodeViaInteractiveAuthorizationEndpoint(
                    endpoint: interactiveEndpoint,
                    issuerMetadata: issuerMetadata,
                    clientMetadata: clientMetadata,
                    pkceSession: pkceSession,
                    credentialConfigurationId: credentialConfigurationId,
                    authorizationMethods: authorizationMethods
                )
            } catch let error as VCIClientException {
                if error.serverErrorCode == Constants.MISSING_INTERACTION_TYPE_ERROR {
                    return try await obtainAuthorizationCodeViaAuthorizationEndpoint(
                        authorizationServerMetadata: authorizationServerMetadata,
                        issuerMetadata: issuerMetadata,
                        clientMetadata: clientMetadata,
                        pkceSession: pkceSession,
                        authorizationMethods: authorizationMethods
                    )
                } else {
                    throw error
                }
            }
        } else {
            return try await obtainAuthorizationCodeViaAuthorizationEndpoint(
                authorizationServerMetadata: authorizationServerMetadata,
                issuerMetadata: issuerMetadata,
                clientMetadata: clientMetadata,
                pkceSession: pkceSession,
                authorizationMethods: authorizationMethods
            )
        }
    }
    
    private func obtainAuthorizationCodeViaInteractiveAuthorizationEndpoint(
        endpoint: String,
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        pkceSession: PKCESessionManager.PKCESession,
        credentialConfigurationId: String,
        authorizationMethods: [AuthorizationMethod]
    ) async throws -> String {
        let response: AuthorizationResponse
        do {
            response = try await interactiveAuthorizationHandler.handle(
                endpoint: endpoint,
                clientMetadata: clientMetadata,
                credentialConfigurationId: credentialConfigurationId,
                authorizationMethods: authorizationMethods,
                pkceSession: pkceSession
            )
        } catch let error as VCIClientException {
            throw DownloadFailedException(
                message: "Interactive authorization failed at endpoint \(endpoint): \(error.localizedDescription)",
                serverErrorCode: error.serverErrorCode,
                serverErrorDescription: error.serverErrorDescription,
                cause: error
            )
        } catch {
            throw DownloadFailedException(
                "Interactive authorization failed at endpoint \(endpoint): \(error.localizedDescription)"
            )
        }
        
        guard let authorizationCode = response.authorizationCode else {
            throw DownloadFailedException(
                "Authorization failed: code not received from interactive authorization endpoint \(endpoint). Error: \(response.error ?? "unknown"), Description: \(response.errorDescription ?? "unknown")"
            )
        }
        
        return authorizationCode
    }
    
    private func obtainAuthorizationCodeViaAuthorizationEndpoint(
        authorizationServerMetadata: AuthorizationServerMetadata,
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        pkceSession: PKCESessionManager.PKCESession,
        authorizationMethods: [AuthorizationMethod]? = nil
    ) async throws -> String {
        guard let authorizationEndpoint =
                authorizationServerMetadata.authorizationEndpoint else {
            throw DownloadFailedException(
                "Missing authorization endpoint for issuer \(issuerMetadata.credentialIssuer)"
            )
        }
        
        let redirectToWebAuthorizationMethod =
        authorizationMethods?
            .first {
                if case .redirectToWeb = $0 { return true }
                return false
            }
        
        if let redirectMethod = redirectToWebAuthorizationMethod,
           case let .redirectToWeb(openWebPage) = redirectMethod {
            let requestData = ImplicitAuthorizationRequestData(
                authorizeUrl: authorizationEndpoint,
                clientMetadata: clientMetadata,
                pkceSession: pkceSession,
                scope: issuerMetadata.scope ?? "default"
            )
            
            let response: AuthorizationResponse
            do {
                response = try await RedirectToWebAuthorizationMethodService(
                    openWebPage: openWebPage
                ).authorizeUser(requestData: requestData)
            } catch {
                throw DownloadFailedException(
                    "Authorization failed at authorization endpoint \(authorizationEndpoint): \(error.localizedDescription)"
                )
            }
            
            guard let authorizationCode = response.authorizationCode else {
                throw DownloadFailedException(
                    "Authorization code not received from authorization endpoint \(authorizationEndpoint)"
                )
            }
            
            return authorizationCode
            
        } else {
            throw DownloadFailedException(
                "No authorization method available to obtain authorization code from \(authorizationEndpoint)"
            )
        }
    }
}
