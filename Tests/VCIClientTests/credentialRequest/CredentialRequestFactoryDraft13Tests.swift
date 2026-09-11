@testable import VCIClient
import XCTest

final class CredentialRequestFactoryDraft13Tests: XCTestCase {
    private let validProof = JWTProof(jwt: "valid.jwt.string")
    private let issuer = IssuerMetadata(
        credentialIssuer: "https://issuer.example.com",
        credentialEndpoint: "https://issuer.example.com/credential",
        credentialType: ["VerifiableCredential"],
        credentialFormat: .ldp_vc,
        doctype: "org.iso.18013.5.1.mDL",
        vct: "vc.type"
    )

    func testCreateCredentialRequest_ldpvc_returnsValidRequest() throws {
        let factory = CredentialRequestFactoryDraft13()

        let request = try factory.createCredentialRequest(
            credentialFormat: .ldp_vc,
            accessToken: "token",
            issuer: issuer,
            proofJwt: validProof
        )

        XCTAssertEqual(request.url?.absoluteString, "https://issuer.example.com/credential")
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any]
        )
        XCTAssertNotNil(json["proof"])
        XCTAssertNil(json["proofs"])
    }

    func testCreateCredentialRequest_msomdoc_returnsValidRequest() throws {
        let factory = CredentialRequestFactoryDraft13()

        let request = try factory.createCredentialRequest(
            credentialFormat: .mso_mdoc,
            accessToken: "token",
            issuer: issuer,
            proofJwt: validProof
        )

        XCTAssertEqual(request.url?.absoluteString, "https://issuer.example.com/credential")
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any]
        )
        XCTAssertEqual(json["doctype"] as? String, "org.iso.18013.5.1.mDL")
    }

    func testCreateCredentialRequest_withoutProof_allowsNilProof() throws {
        let factory = CredentialRequestFactoryDraft13()

        let issuer = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialType: ["VerifiableCredential"],
            credentialFormat: .ldp_vc,
            doctype: "org.iso.18013.5.1.mDL",
            vct: "vc.type"
        )

        let request = try factory.createCredentialRequest(
            credentialFormat: .ldp_vc,
            accessToken: "token",
            issuer: issuer,
            proofJwt: nil
        )

        XCTAssertNotNil(request)
    }
    
    func testCreateCredentialRequest_withInvalidProof_throwsException() throws {

        let factory = CredentialRequestFactoryDraft13()

        let issuer = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialType: ["VerifiableCredential"],
            credentialFormat: .ldp_vc,
            doctype: "org.iso.18013.5.1.mDL",
            vct: "vc.type"
        )

        XCTAssertThrowsError(
            try factory.createCredentialRequest(
                credentialFormat: .ldp_vc,
                accessToken: "token",
                issuer: issuer,
                proofJwt: JWTProof(jwt: "")
            )
        )
    }

    func testCreateCredentialRequest_missingCredentialType_throwsException() {
        let factory = CredentialRequestFactoryDraft13()
        let invalidIssuer = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialEndpoint: "https://issuer.example.com/credential",
            credentialType: nil,
            credentialFormat: .ldp_vc
        )

        XCTAssertThrowsError(
            try factory.createCredentialRequest(
                credentialFormat: .ldp_vc,
                accessToken: "token",
                issuer: invalidIssuer,
                proofJwt: validProof
            )
        ) { error in
            XCTAssertTrue(error is InvalidDataProvidedException)
        }
    }
}
