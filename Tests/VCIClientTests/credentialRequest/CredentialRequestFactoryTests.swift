@testable import VCIClient
import XCTest

final class CredentialRequestFactoryTests: XCTestCase {
    func testCreateCredentialRequest_includesProofsJwtArray() throws {
        let factory = CredentialRequestFactory()
        let issuer = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialType: ["VerifiableCredential"],
            credentialFormat: .ldp_vc
        )

        let request = try factory.createCredentialRequest(
            accessToken: "token",
            issuer: issuer,
            credentialConfigurationId: "UniversityDegreeCredential",
            proofs: CredentialRequestProofs(proofs: ["proof-1"])
        )

        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.allHTTPHeaderFields?["Authorization"], "Bearer token")

        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any]
        )
        let proofs = try XCTUnwrap(json["proofs"] as? [String: Any])

        XCTAssertEqual(json["credential_configuration_id"] as? String, "UniversityDegreeCredential")
        XCTAssertEqual(proofs["jwt"] as? [String], ["proof-1"])
        XCTAssertNil(json["proof"])
        XCTAssertNil(json["format"])
        XCTAssertNil(json["credential_definition"])
        XCTAssertNil(json["doctype"])
        XCTAssertNil(json["vct"])
    }

    func testCreateCredentialRequest_forMsoMdocStillUsesCredentialConfigurationIdShape() throws {
        let factory = CredentialRequestFactory()
        let body = try factory.constructRequestBody(
            credentialConfigurationId: "org.iso.18013.5.1.mDL",
            proofs: CredentialRequestProofs(proofs: ["proof-1"])
        )

        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: body) as? [String: Any]
        )

        XCTAssertEqual(json["credential_configuration_id"] as? String, "org.iso.18013.5.1.mDL")
        XCTAssertNotNil(json["proofs"])
        XCTAssertNil(json["format"])
        XCTAssertNil(json["doctype"])
        XCTAssertNil(json["vct"])
    }
    
    func testCreateCredentialRequest_withoutProofs_omitsProofs() throws {
        let factory = CredentialRequestFactory()

        let issuer = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialType: ["VerifiableCredential"],
            credentialFormat: .ldp_vc
        )

        let request = try factory.createCredentialRequest(
            accessToken: "token",
            issuer: issuer,
            credentialConfigurationId: "UniversityDegreeCredential",
            proofs: nil
        )

        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(
                with: XCTUnwrap(request.httpBody)
            ) as? [String: Any]
        )

        XCTAssertEqual(
            json["credential_configuration_id"] as? String,
            "UniversityDegreeCredential"
        )

        XCTAssertNil(json["proofs"])
    }
}
