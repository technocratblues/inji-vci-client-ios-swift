import Foundation

class CredentialRequestExecutor {
    private let credentialRequestFactory: CredentialRequestFactory
    private let credentialRequestFactoryDraft13: CredentialRequestFactoryProtocol

    init(
        credentialRequestFactoryDraft13: CredentialRequestFactoryProtocol = CredentialRequestFactoryDraft13(),
        credentialRequestFactory: CredentialRequestFactory = CredentialRequestFactory()
    ) {
        self.credentialRequestFactoryDraft13 = credentialRequestFactoryDraft13
        self.credentialRequestFactory = credentialRequestFactory
    }

    func requestCredential(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        proofs: CredentialRequestProofs?,
        accessToken: String,
        timeoutInMillis: Int64 = 10000,
        session: NetworkManager = NetworkManager.shared,
        tokenType: String? = nil,
        dpopManager: DPoPManager = DPoPManager()
    ) async throws -> CredentialResponse? {
        let timeoutSeconds = timeoutInMillis / 1000

        do {
            var request = try credentialRequestFactory.createCredentialRequest(
                accessToken: accessToken,
                issuer: issuerMetadata,
                credentialConfigurationId: credentialConfigurationId,
                proofs: proofs
            )

            request.timeoutInterval = TimeInterval(timeoutInMillis) / 1000

            let networkResponse = try await sendCredentialRequest(session: session,
                baseRequest: request,
                accessToken: accessToken,
                credentialEndpoint: issuerMetadata.credentialEndpoint,
                tokenType: tokenType,
                dpopManager: dpopManager
            )
            let responseBody = networkResponse.body



            if !responseBody.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {

                guard var result = try JsonUtils.deserialize(
                    responseBody,
                    as: CredentialResponse.self
                ) else {
                    throw DownloadFailedException(
                        "Failed to parse credential response."
                    )
                }

                if let items = result.credentials {
                    for (index, item) in items.enumerated() {
                        guard let credential = item.credential,
                              !(credential.value is NSNull) else {
                            throw DownloadFailedException(
                                "Invalid credential response: credentials[\(index)] is missing the 'credential' key or has a null value."
                            )
                        }
                    }
                }

                result.credentialConfigurationId = credentialConfigurationId
                result.credentialIssuer = issuerMetadata.credentialIssuer

                return result
            }

            Util.logWarning(
                message: "Credential endpoint returned empty body",
                className: String(describing: type(of: self))
            )

            return nil

        } catch let e as NetworkRequestTimeoutException {

            Util.logWarning(
                message: "Credential download timed out after \(timeoutSeconds)s",
                className: String(describing: type(of: self))
            )

            throw DownloadFailedException(
                message: "Credential download timed out after \(timeoutSeconds)s",
                cause: e
            )

        } catch let e as NetworkRequestFailedException {

            Util.logWarning(
                message: "Credential download failed: \(e.message)",
                className: String(describing: type(of: self))
            )

            throw DownloadFailedException(
                message: e.message,
                issuerErrorCode: e.issuerErrorCode,
                issuerErrorDescription: e.issuerErrorDescription,
                cause: e
            )

        } catch let e as InvalidPublicKeyException {

            throw DownloadFailedException(
                message: e.message,
                cause: e
            )

        } catch let e as DownloadFailedException {

            throw e

        } catch {

            Util.logWarning(
                message: "Unexpected error during credential download: \(error.localizedDescription)",
                className: String(describing: type(of: self))
            )

            throw DownloadFailedException(
                message: error.localizedDescription,
                cause: error
            )
        }
    }

    func requestCredentialDraft13(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        proof: Proof?,
        accessToken: String,
        timeoutInMillis: Int64 = 10000,
        session: NetworkManager = NetworkManager.shared,
        tokenType: String? = nil,
        dpopManager: DPoPManager = DPoPManager()
    ) async throws -> CredentialResponseDraft13? {

        let timeoutSeconds = timeoutInMillis / 1000

        do {
            var request = try credentialRequestFactoryDraft13.createCredentialRequest(
                credentialFormat: issuerMetadata.credentialFormat,
                accessToken: accessToken,
                issuer: issuerMetadata,
                proofJwt: proof
            )

            request.timeoutInterval = TimeInterval(timeoutInMillis) / 1000

            let networkResponse = try await sendCredentialRequest(session: session,
                baseRequest: request,
                accessToken: accessToken,
                credentialEndpoint: issuerMetadata.credentialEndpoint,
                tokenType: tokenType,
                dpopManager: dpopManager
            )
            let responseBody = networkResponse.body



            if !responseBody.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {

                guard var result = try JsonUtils.deserialize(
                    responseBody,
                    as: CredentialResponseDraft13.self
                ) else {
                    throw DownloadFailedException(
                        "Failed to parse credential response."
                    )
                }

                result.credentialConfigurationId = credentialConfigurationId
                result.credentialIssuer = issuerMetadata.credentialIssuer

                return result
            }

            Util.logWarning(
                message: "Credential endpoint returned empty body",
                className: String(describing: type(of: self))
            )

            return nil

        } catch let e as NetworkRequestTimeoutException {

            Util.logWarning(
                message: "Credential download timed out after \(timeoutSeconds)s",
                className: String(describing: type(of: self))
            )

            throw DownloadFailedException(
                message: "Credential download timed out after \(timeoutSeconds)s",
                cause: e
            )

        } catch let e as NetworkRequestFailedException {

            Util.logWarning(
                message: "Credential download failed: \(e.message)",
                className: String(describing: type(of: self))
            )

            throw DownloadFailedException(
                message: e.message,
                issuerErrorCode: e.issuerErrorCode,
                issuerErrorDescription: e.issuerErrorDescription,
                cause: e
            )

        } catch let e as InvalidPublicKeyException {

            throw DownloadFailedException(
                message: e.message,
                cause: e
            )

        } catch let e as DownloadFailedException {

            throw e

        } catch {

            Util.logWarning(
                message: "Unexpected error during credential download: \(error.localizedDescription)",
                className: String(describing: type(of: self))
            )

            throw DownloadFailedException(
                message: error.localizedDescription,
                cause: error
            )
        }
    }

    private func sendCredentialRequest(
        session: NetworkManager,
        baseRequest: URLRequest,
        accessToken: String,
        credentialEndpoint: String,
        tokenType: String?,
        dpopManager: DPoPManager
    ) async throws -> NetworkResponse {
        let isDpopToken = tokenType?.caseInsensitiveCompare(Constants.dpopTokenType) == .orderedSame

        if isDpopToken && !dpopManager.isInitialized {
            throw DownloadFailedException("DPoP token_type requires an initialized DPoP session")
        }

        guard isDpopToken else {
            return try await session.sendRequest(request: baseRequest)
        }

        let proof = try dpopManager.generateCredentialProof(
            credentialEndpoint: credentialEndpoint,
            accessToken: accessToken
        )

        do {
            let response = try await session.sendRequest(
                request: withDpop(baseRequest, accessToken: accessToken, proof: proof)
            )
            return persistIssuerNonce(response, dpopManager: dpopManager)
        } catch let failure as NetworkRequestFailedException {
            guard failure.httpStatusCode == 401 else { throw failure }

            let challenge = WwwAuthenticateChallenge.parse(
                header(Constants.wwwAuthenticateHeader, in: failure.headers)
            )
            let nonce = header(Constants.dpopNonceHeader, in: failure.headers)

            if challenge.error == Constants.useDpopNonceError, let nonce = nonce {
                let retryProof = try dpopManager.generateCredentialProof(
                    credentialEndpoint: credentialEndpoint,
                    accessToken: accessToken,
                    nonce: nonce
                )
                let response = try await session.sendRequest(
                    request: withDpop(baseRequest, accessToken: accessToken, proof: retryProof)
                )
                return persistIssuerNonce(response, dpopManager: dpopManager)
            }

            if !challenge.isDpop && challenge.isBearer {
                Util.logWarning(
                    message: "DPoP token downgraded to Bearer: AS does not require DPoP " +
                             "(WWW-Authenticate: \(header(Constants.wwwAuthenticateHeader, in: failure.headers) ?? ""))",
                    className: String(describing: type(of: self))
                )
                return try await session.sendRequest(
                    request: withBearer(baseRequest, accessToken: accessToken)
                )
            }

            throw failure
        }
    }

    private func withDpop(_ request: URLRequest, accessToken: String, proof: String) -> URLRequest {
        var updated = request
        updated.setValue("\(Constants.dpopTokenType) \(accessToken)", forHTTPHeaderField: Constants.authorizationHeader)
        updated.setValue(proof, forHTTPHeaderField: Constants.dpopHeader)
        return updated
    }

    private func withBearer(_ request: URLRequest, accessToken: String) -> URLRequest {
        var updated = request
        updated.setValue("\(Constants.bearerTokenType) \(accessToken)", forHTTPHeaderField: Constants.authorizationHeader)
        updated.setValue(nil, forHTTPHeaderField: Constants.dpopHeader)
        return updated
    }

    private func persistIssuerNonce(_ response: NetworkResponse, dpopManager: DPoPManager) -> NetworkResponse {
        dpopManager.updateNonce(header(Constants.dpopNonceHeader, in: response.headers))
        return response
    }

    private func header(_ name: String, in headers: [AnyHashable: Any]?) -> String? {
        guard let headers = headers else { return nil }
        for (key, value) in headers {
            if let keyString = key as? String, keyString.caseInsensitiveCompare(name) == .orderedSame {
                return value as? String
            }
        }
        return nil
    }

}
