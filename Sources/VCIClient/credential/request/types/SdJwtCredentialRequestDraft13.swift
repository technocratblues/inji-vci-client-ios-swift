import Foundation

class SdJwtCredentialRequestDraft13: CredentialRequestProtocol {
    let accessToken: String
    let issuerMetaData: IssuerMetadata
    let proof: JWTProof?

    required init(
        accessToken: String,
        issuerMetaData: IssuerMetadata,
        proof: JWTProof?
    ) {
        self.accessToken = accessToken
        self.issuerMetaData = issuerMetaData
        self.proof = proof
    }

    func validateIssuerMetadata() -> ValidatorResult {
        let validatorResult = ValidatorResult()

        if issuerMetaData.vct?.isEmpty != false {
            validatorResult.addInvalidField("vct")
        }

        return validatorResult
    }

    func constructRequest() throws -> URLRequest {
        guard let url = URL(string: issuerMetaData.credentialEndpoint) else {
            throw DownloadFailedException("Invalid credential endpoint URL")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        request.addValue(
            "Bearer \(accessToken)",
            forHTTPHeaderField: "Authorization"
        )

        let body = try generateRequestBody(
            proofJWT: proof,
            issuer: issuerMetaData
        )

        request.httpBody = body

        return request
    }

    private func generateRequestBody(
        proofJWT: JWTProof?,
        issuer: IssuerMetadata
    ) throws -> Data {

        guard let vct = issuer.vct else {
            throw DownloadFailedException(
                "Missing 'vct' in issuer metadata"
            )
        }

        let requestBody = SdJwtVcCredentialRequestBodyDraft13(
            format: issuer.credentialFormat,
            vct: vct,
            proof: proofJWT
        )

        do {
            return try JSONEncoder().encode(requestBody)
        } catch {
            throw DownloadFailedException(
                "Failed to encode request body: \(error.localizedDescription)"
            )
        }
    }
}


struct SdJwtVcCredentialRequestBodyDraft13: Encodable {
    let format: CredentialFormat
    let vct: String
    let proof: JWTProof?

    enum CodingKeys: String, CodingKey {
        case format
        case vct
        case proof
    }

    init(
        format: CredentialFormat,
        vct: String,
        proof: JWTProof?
    ) {
        self.format = format
        self.vct = vct
        self.proof = proof
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(
            keyedBy: CodingKeys.self
        )

        try container.encode(
            format,
            forKey: .format
        )

        try container.encode(
            vct,
            forKey: .vct
        )

        if let proof {
            try container.encode(
                proof,
                forKey: .proof
            )
        }
    }
}
