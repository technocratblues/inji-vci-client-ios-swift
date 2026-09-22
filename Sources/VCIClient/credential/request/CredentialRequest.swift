import Foundation

protocol CredentialRequestProtocol {
    init(accessToken: String,
         issuerMetaData: IssuerMetadata,
         proof: JWTProof?
    )

    func constructRequest() throws -> URLRequest

    func validateIssuerMetadata() -> ValidatorResult
}
