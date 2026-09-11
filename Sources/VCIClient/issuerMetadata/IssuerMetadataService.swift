import Foundation

class IssuerMetadataService {
    private let session: NetworkManager
    private let timeoutMillis: Int64
    private var cachedRawMetadata: [String: [String: Any]] = [:]

    init(session: NetworkManager = NetworkManager.shared, timeoutMillis: Int64 = 10000) {
        self.session = session
        self.timeoutMillis = timeoutMillis
    }

    func fetchIssuerMetadataResult(
        credentialIssuer: String,
        credentialConfigurationId: String
    ) async throws -> IssuerMetadataResult {
        do {
            let rawIssuerMetadata: [String: Any] =
                try await getOrFetchRawIssuerMetadata(for: credentialIssuer)

            try validateCredentialIssuerMatch(expected: credentialIssuer, rawMetadata: rawIssuerMetadata)

            let resolvedIssuerMetadata = try resolveMetadata(
                credentialConfigurationId: credentialConfigurationId,
                rawIssuerMetadata: rawIssuerMetadata
            )

            return IssuerMetadataResult(
                issuerMetadata: resolvedIssuerMetadata,
                raw: rawIssuerMetadata,
                credentialIssuer: credentialIssuer
            )

        } catch let e as IssuerMetadataFetchException {
            throw e
        } catch let e as VCIClientException {
            throw IssuerMetadataFetchException(
                e.message,
                issuerErrorCode: e.issuerErrorCode,
                issuerErrorDescription: e.issuerErrorDescription,
                cause: e
            )
        } catch {
            throw IssuerMetadataFetchException(
                "Unexpected error while resolving issuer metadata: \(error.localizedDescription)",
                cause: error
            )
        }
    }

    func fetchAndParseIssuerMetadata(from credentialIssuer: String) async throws -> [String: Any] {
        let wellKnownUrl: String
        let draft13WellKnownUrl: String
        do {
            wellKnownUrl = try Self.buildWellKnownUrl(from: credentialIssuer)
            draft13WellKnownUrl = Self.buildDraft13WellKnownUrl(from: credentialIssuer)
        } catch {
            throw IssuerMetadataFetchException(
                "Invalid credential issuer URL: \(credentialIssuer)",
                cause: error
            )
        }

        do {
            return try await fetchAndParse(wellKnownUrl: wellKnownUrl)
        } catch let error as IssuerMetadataFetchException {
            if draft13WellKnownUrl == wellKnownUrl { throw error }
            return try await fetchAndParse(wellKnownUrl: draft13WellKnownUrl)
        }
    }

    /// Builds the well-known URL as per RFC 8414 (required since OID4VCI draft 16):
    /// the well-known suffix is inserted between the authority and the path.
    /// e.g. https://host/tenant -> https://host/.well-known/openid-credential-issuer/tenant
    static func buildWellKnownUrl(from credentialIssuer: String) throws -> String {
        guard let url = WellKnownUrl.insertSuffix(
            baseUrl: credentialIssuer,
            suffix: Constants.credentialIssuerWellknownUriSuffix
        ) else {
            throw IssuerMetadataFetchException("Invalid credential issuer URL: \(credentialIssuer)")
        }
        return url
    }

    /// Builds the pre-draft-16 (draft 13 / OpenID Connect style) well-known URL:
    /// the well-known suffix is appended to the issuer URL. Kept as a fallback.
    static func buildDraft13WellKnownUrl(from credentialIssuer: String) -> String {
        var normalized = credentialIssuer
        while normalized.hasSuffix("/") { normalized.removeLast() }
        return normalized + Constants.credentialIssuerWellknownUriSuffix
    }

    private func fetchAndParse(wellKnownUrl: String) async throws -> [String: Any] {
        do {
            let response = try await session.sendRequest(
                url: wellKnownUrl,
                method: .get,
                headers: ["Accept": "application/json"],
                timeoutMillis: timeoutMillis
            )

            guard !response.body.isEmpty else {
                throw IssuerMetadataFetchException("Issuer metadata response is empty.")
            }

            guard let data = response.body.data(using: .utf8),
                  let jsonObject = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw IssuerMetadataFetchException("Issuer metadata is not valid JSON.")
            }

            return jsonObject

        } catch let e as IssuerMetadataFetchException {
            throw e
        } catch let e as VCIClientException {
            throw IssuerMetadataFetchException(
                e.message,
                issuerErrorCode: e.issuerErrorCode,
                issuerErrorDescription: e.issuerErrorDescription,
                cause: e
            )
        } catch {
            throw IssuerMetadataFetchException(
                "Unexpected error while fetching issuer metadata: \(error.localizedDescription)",
                cause: error
            )
        }
    }

    private func validateCredentialIssuerMatch(expected: String, rawMetadata: [String: Any]) throws {
        guard let actual = rawMetadata["credential_issuer"] as? String else {
            throw IssuerMetadataFetchException("Missing credential_issuer in issuer metadata")
        }
        if expected != actual {
            throw IssuerMetadataFetchException("credential_issuer mismatch: expected '\(expected)', got '\(actual)'")
        }
    }

    func fetchCredentialConfigurationsSupported(from credentialIssuer: String) async throws -> [String: Any] {
        let rawIssuerMetadata: [String: Any] = try await fetchAndParseIssuerMetadata(from: credentialIssuer)

        try validateCredentialIssuerMatch(expected: credentialIssuer, rawMetadata: rawIssuerMetadata)

        guard let configurations = rawIssuerMetadata["credential_configurations_supported"] as? [String: Any] else {
            throw IssuerMetadataFetchException("Missing or invalid 'credential_configurations_supported' in issuer metadata.")
        }

        if configurations.isEmpty {
            throw IssuerMetadataFetchException("'credential_configurations_supported' is empty.")
        }

        for (configId, config) in configurations {
            guard let configDict = config as? [String: Any] else {
                throw IssuerMetadataFetchException("Invalid configuration format for '\(configId)'")
            }
            if configDict["format"] == nil {
                throw IssuerMetadataFetchException("Missing 'format' in configuration '\(configId)'")
            }
        }

        return configurations
    }

    private func getOrFetchRawIssuerMetadata(for credentialIssuer: String) async throws -> [String: Any] {
        if let cachedIssuerMetadata = cachedRawMetadata[credentialIssuer] {
            return cachedIssuerMetadata
        }
        let fetchedIssuerMetadata = try await fetchAndParseIssuerMetadata(from: credentialIssuer)
        cachedRawMetadata[credentialIssuer] = fetchedIssuerMetadata
        return fetchedIssuerMetadata
    }

    private func resolveMetadata(credentialConfigurationId: String, rawIssuerMetadata: [String: Any]) throws -> IssuerMetadata {
        guard let configurations = rawIssuerMetadata["credential_configurations_supported"] as? [String: Any],
              let credentialType = configurations[credentialConfigurationId] as? [String: Any] else {
            throw IssuerMetadataFetchException("Missing or invalid credential configuration")
        }

        guard let credentialEndpoint = rawIssuerMetadata["credential_endpoint"] as? String else {
            throw IssuerMetadataFetchException("Missing credential_endpoint")
        }

        guard let credentialIssuer = rawIssuerMetadata["credential_issuer"] as? String else {
            throw IssuerMetadataFetchException("Missing credential_issuer")
        }

        let formatString = credentialType["format"] as? String
        guard let format = CredentialFormat(rawValue: formatString ?? "") else {
            throw IssuerMetadataFetchException("Unsupported or missing credential format")
        }

        let scope = credentialType["scope"] as? String ?? "openid"
        let nonceEndpoint = rawIssuerMetadata["nonce_endpoint"] as? String
        let specVersion = detectSpecVersion(
            rawIssuerMetadata: rawIssuerMetadata,
            credentialConfiguration: credentialType
        )

        switch format {
        case .mso_mdoc:
            guard let doctype = credentialType["doctype"] as? String else {
                throw IssuerMetadataFetchException("Missing doctype")
            }

            let claims = credentialType["claims"] as? [String: Any]
            return IssuerMetadata(
                credentialIssuer: credentialIssuer,
                credentialEndpoint: credentialEndpoint,
                credentialFormat: .mso_mdoc,
                doctype: doctype,
                claims: claims?.mapValues { AnyCodable($0) },
                authorizationServers: rawIssuerMetadata["authorization_servers"] as? [String],
                nonceEndpoint: nonceEndpoint,
                scope: scope,
                specVersion: specVersion,
            )

        case .ldp_vc:
            let definition = credentialType["credential_definition"] as? [String: Any] ?? [:]
            let types = definition["type"] as? [String]
            let context = definition["@context"] as? [String]
            return IssuerMetadata(
                credentialIssuer: credentialIssuer,
                credentialEndpoint: credentialEndpoint,
                credentialType: types,
                context: context,
                credentialFormat: .ldp_vc,
                authorizationServers: rawIssuerMetadata["authorization_servers"] as? [String],
                nonceEndpoint: nonceEndpoint,
                scope: scope,
                specVersion: specVersion,
            )

        case .vc_sd_jwt, .dc_sd_jwt:
            guard let vct = credentialType["vct"] as? String else {
                throw IssuerMetadataFetchException("Missing vct in sd_jwt_vc configuration")
            }

            return IssuerMetadata(
                credentialIssuer: credentialIssuer,
                credentialEndpoint: credentialEndpoint,
                credentialFormat: format,
                authorizationServers: rawIssuerMetadata["authorization_servers"] as? [String],
                nonceEndpoint: nonceEndpoint,
                vct: vct,
                scope: scope,
                specVersion: specVersion,
            )
        }
    }

    private func detectSpecVersion(
        rawIssuerMetadata: [String: Any],
        credentialConfiguration: [String: Any]
    ) -> OID4VCIVersion {
        if let nonceEndpoint = rawIssuerMetadata["nonce_endpoint"] as? String,
           !nonceEndpoint.isEmpty {
            return .v1
        }
        
        if credentialConfiguration["credential_metadata"] != nil {
                return .v1
            }
        
        if credentialConfiguration["display"] != nil {
            return .draft13
        }

        return .v1
    }
}
