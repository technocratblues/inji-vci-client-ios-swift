import Foundation

class PreAuthCodeFlowService {
    private let authServerResolver: AuthorizationServerResolver
    private let tokenService: TokenService
    private let credentialExecutor: CredentialRequestExecutor
    private let nonceService: NonceService

    init(
        authServerResolver: AuthorizationServerResolver = AuthorizationServerResolver(),
        tokenService: TokenService = TokenService(),
        credentialExecutor: CredentialRequestExecutor = CredentialRequestExecutor(),
        nonceService: NonceService = NonceService()
    ) {
        self.authServerResolver = authServerResolver
        self.tokenService = tokenService
        self.credentialExecutor = credentialExecutor
        self.nonceService = nonceService
    }

    func requestCredentials(
        issuerMetadata: IssuerMetadata,
        credentialOffer: CredentialOffer,
        getTokenResponse: @escaping TokenResponseCallback,
        getProofs: @escaping ProofsCallback,
        credentialConfigurationId: String,
        proofBindingContext: ProofBindingContext,
        getTxCode: TxCodeCallback = nil,
        downloadTimeoutInMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        dpopManager: DPoPManager = DPoPManager()
    ) async throws -> CredentialResponse {
        try await executeRequestCredentials(
            issuerMetadata: issuerMetadata,
            credentialOffer: credentialOffer,
            getTokenResponse: getTokenResponse,
            credentialConfigurationId: credentialConfigurationId,
            proofBindingContext: proofBindingContext,
            getTxCode: getTxCode,
            downloadTimeoutInMillis: downloadTimeoutInMillis,
            dpopManager: dpopManager
        ) { token in

            var proofs: CredentialRequestProofs? = nil

            if !proofBindingContext.proofTypesSupported.isEmpty {
                let nonce = try await nonceService.fetchNonce(
                    issuerMetadata: issuerMetadata,
                    timeoutInMillis: downloadTimeoutInMillis,
                    dpopManager: dpopManager
                )

                do {
                    proofs = try await getProofs(
                        proofBindingContext.toCredentialRequestProofMetadata(
                            credentialIssuer: issuerMetadata.credentialIssuer,
                            nonce: nonce
                        )
                    )
                } catch {
                    throw DownloadFailedException(
                        "Failed to obtain proofs from callback: \(error.localizedDescription)"
                    )
                }
            }

            return try await self.credentialExecutor.requestCredential(
                issuerMetadata: issuerMetadata,
                credentialConfigurationId: credentialConfigurationId,
                proofs: proofs,
                accessToken: token.accessToken,
                timeoutInMillis: downloadTimeoutInMillis,
                tokenType: token.tokenType,
                dpopManager: dpopManager
            )
        }
    }

    func requestCredentialsDraft13(
        issuerMetadata: IssuerMetadata,
        credentialOffer: CredentialOffer,
        getTokenResponse: @escaping TokenResponseCallback,
        getProofJwt: @escaping ProofJwtCallback,
        credentialConfigurationId: String,
        proofBindingContext: ProofBindingContext,
        getTxCode: TxCodeCallback = nil,
        downloadTimeoutInMillis: Int64 = Constants.defaultNetworkTimeoutInMillis,
        dpopManager: DPoPManager = DPoPManager()
    ) async throws -> CredentialResponseDraft13 {

        let response = try await executeRequestCredentials(
            issuerMetadata: issuerMetadata,
            credentialOffer: credentialOffer,
            getTokenResponse: getTokenResponse,
            credentialConfigurationId: credentialConfigurationId,
            proofBindingContext: proofBindingContext,
            getTxCode: getTxCode,
            downloadTimeoutInMillis: downloadTimeoutInMillis,
            dpopManager: dpopManager
        ) { token in

            var proof: JWTProof? = nil

            if !proofBindingContext.proofTypesSupported.isEmpty {

                let nonce = try NonceService.extractNonceFromTokenResponse(token)

                let jwt: String

                do {
                    jwt = try await getProofJwt(
                        proofBindingContext.toCredentialRequestProofMetadata(
                            credentialIssuer: issuerMetadata.credentialIssuer,
                            nonce: nonce
                        )
                    )
                } catch {
                    throw DownloadFailedException(
                        "Failed to obtain proof JWT from callback: \(error.localizedDescription)"
                    )
                }

                proof = JWTProof(jwt: jwt)
            }

            return try await self.credentialExecutor.requestCredentialDraft13(
                issuerMetadata: issuerMetadata,
                credentialConfigurationId: credentialConfigurationId,
                proof: proof,
                accessToken: token.accessToken,
                timeoutInMillis: downloadTimeoutInMillis,
                tokenType: token.tokenType,
                dpopManager: dpopManager
            )
        }

        return response
    }
    private func executeRequestCredentials<Response>(
        issuerMetadata: IssuerMetadata,
        credentialOffer: CredentialOffer,
        getTokenResponse: @escaping TokenResponseCallback,
        credentialConfigurationId: String,
        proofBindingContext: ProofBindingContext,
        getTxCode: TxCodeCallback,
        downloadTimeoutInMillis: Int64,
        dpopManager: DPoPManager = DPoPManager(),
        requestCredential: (TokenResponse) async throws -> Response?
    ) async throws -> Response {
        do {
            let authServerMetadata = try await authServerResolver
                .resolveForPreAuth(
                    issuerMetadata: issuerMetadata,
                    credentialOffer: credentialOffer
                )

            guard let tokenEndpoint = authServerMetadata.tokenEndpoint else {
                throw DownloadFailedException(
                    "Token endpoint is missing in Authorization Server metadata."
                )
            }

            try dpopManager.initialize(
                tokenEndpoint: tokenEndpoint,
                authorizationServerSupportedAlgorithms:
                    authServerMetadata.dpopSigningAlgValuesSupported
            )

            guard let grant = credentialOffer.grants?.preAuthorizedGrant else {
                throw InvalidDataProvidedException(
                    "Missing pre-authorized grant details."
                )
            }

            let txCode: String? = try await {
                if let txCodeObject = grant.txCode {
                    return try await getTxCode?(
                        txCodeObject.inputMode,
                        txCodeObject.description,
                        txCodeObject.length
                    )
                } else {
                    return nil
                }
            }()

            if grant.txCode != nil && txCode == nil {
                throw DownloadFailedException(
                    "tx_code required but no provider was given."
                )
            }

            let token = try await tokenService.getAccessToken(
                getTokenResponse: getTokenResponse,
                tokenEndpoint: tokenEndpoint,
                preAuthCode: grant.preAuthCode,
                txCode: txCode,
                dpopManager: dpopManager
            )

            guard let credential = try await requestCredential(token) else {
                throw DownloadFailedException("Credential request failed.")
            }

            return credential

        } catch let e as DownloadFailedException {
            throw e

        } catch let e as VCIClientException {
            throw DownloadFailedException(
                message: "Pre-Authorized Code Flow failed: \(e.message)",
                issuerErrorCode: e.issuerErrorCode,
                issuerErrorDescription: e.issuerErrorDescription,
                cause: e
            )

        } catch {
            throw DownloadFailedException(
                message: "Unexpected error during Pre-Authorized Code Flow: \(error.localizedDescription)",
                cause: error
            )
        }
    }
}
