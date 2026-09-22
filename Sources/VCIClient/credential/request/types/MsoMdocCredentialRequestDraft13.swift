import Foundation

class MsoMdocCredentialRequestDraft13: CredentialRequestProtocol {
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

        if issuerMetaData.doctype.isBlank() {
            validatorResult.addInvalidField("docType")
        }

        return validatorResult
    }

    func constructRequest() throws -> URLRequest {
        guard let url = URL(string: issuerMetaData.credentialEndpoint) else {
            throw DownloadFailedException(
                "Invalid credential endpoint URL: \(issuerMetaData.credentialEndpoint)"
            )
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        request.setValue(
            "Bearer \(accessToken)",
            forHTTPHeaderField: "Authorization"
        )

        guard let requestBody = try generateRequestBody() else {
            throw DownloadFailedException(
                "Failed to generate mso_mdoc credential request body"
            )
        }

        request.httpBody = requestBody

        return request
    }

    private func generateRequestBody() throws -> Data? {
        guard let doctype = issuerMetaData.doctype else {
            throw DownloadFailedException(
                "Missing doctype in issuer metadata"
            )
        }

        let credentialRequestBody = MsoMdocCredentialRequestBodyDraft13(
            format: issuerMetaData.credentialFormat,
            doctype: doctype,
            proof: proof
        )

        do {
            return try JSONEncoder().encode(credentialRequestBody)
        } catch {
            Util.logError(
                message: "Error occurred while constructing request body: \(error.localizedDescription)",
                className: String(describing: type(of: self))
            )

            throw DownloadFailedException(
                "Failed to encode credential request body"
            )
        }
    }
}


struct MsoMdocCredentialRequestBodyDraft13: Encodable {
    let format: CredentialFormat
    let proof: JWTProof?
    let doctype: String

    enum CodingKeys: String, CodingKey {
        case format
        case proof
        case doctype
    }

    init(
        format: CredentialFormat,
        doctype: String,
        proof: JWTProof?
    ) {
        self.format = format
        self.doctype = doctype
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
            doctype,
            forKey: .doctype
        )

        if let proof {
            try container.encode(
                proof,
                forKey: .proof
            )
        }
    }
}
