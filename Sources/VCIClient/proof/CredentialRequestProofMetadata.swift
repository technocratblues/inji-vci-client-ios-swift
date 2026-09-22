import Foundation

public struct CredentialRequestProofMetadata {
    public let credentialIssuer: String
    public let nonce: String?
    public let proofSigningAlgorithmsSupported: [String]
    public let cryptographicBindingMethodsSupported: [String]
    public let proofTypesSupported: [String]

    public init(
        credentialIssuer: String,
        nonce: String?,
        proofSigningAlgorithmsSupported: [String] = [],
        cryptographicBindingMethodsSupported: [String] = [],
        proofTypesSupported: [String] = []
    ) {
        self.credentialIssuer = credentialIssuer
        self.nonce = nonce
        self.proofSigningAlgorithmsSupported = proofSigningAlgorithmsSupported
        self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
        self.proofTypesSupported = proofTypesSupported
    }
}

struct ProofBindingContext {
    let proofSigningAlgorithmsSupported: [String]
    let cryptographicBindingMethodsSupported: [String]
    let proofTypesSupported: [String]

    init(
        proofSigningAlgorithmsSupported: [String] = [],
        cryptographicBindingMethodsSupported: [String] = [],
        proofTypesSupported: [String] = []
    ) {
        self.proofSigningAlgorithmsSupported = proofSigningAlgorithmsSupported
        self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
        self.proofTypesSupported = proofTypesSupported
    }

    func requiresProof() -> Bool {
        !cryptographicBindingMethodsSupported.isEmpty &&
        !proofTypesSupported.isEmpty
    }
    func toCredentialRequestProofMetadata(credentialIssuer: String, nonce: String?) -> CredentialRequestProofMetadata {
        CredentialRequestProofMetadata(
            credentialIssuer: credentialIssuer,
            nonce: nonce,
            proofSigningAlgorithmsSupported: proofSigningAlgorithmsSupported,
            cryptographicBindingMethodsSupported: cryptographicBindingMethodsSupported,
            proofTypesSupported: proofTypesSupported
        )
    }
}

extension IssuerMetadataResult {
    func toProofBindingContext(credentialConfigurationId: String) -> ProofBindingContext {
        ProofBindingContext(
            proofSigningAlgorithmsSupported: extractJwtProofSigningAlgorithms(
                credentialConfigurationId: credentialConfigurationId
            ),
            cryptographicBindingMethodsSupported: extractCryptographicBindingMethods(
                credentialConfigurationId: credentialConfigurationId
            ),
            proofTypesSupported: extractSupportedProofTypes(
                credentialConfigurationId: credentialConfigurationId
            )
        )
    }
}
