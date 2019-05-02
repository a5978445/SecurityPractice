//
//  SecTrustTests.swift
//  SecurityPracticeTests
//
//  Created by 李腾芳 on 2019/4/30.
//  Copyright © 2019年 HSBC Holdings plc. All rights reserved.
//

import XCTest
import Security


protocol CertificateConvertible {
    func asCertificate() -> SecCertificate
    var path: String { get }
}

extension CertificateConvertible {
    func asCertificate() -> SecCertificate {
        var url = getSourceUrl()
        url.appendPathComponent(path)
        let data = try! Data.init(contentsOf: url)
        return SecCertificateCreateWithData(nil, data as CFData)!
    }
}

func getSourceUrl() -> URL {
    return Bundle(for: SecTrustTests.self).resourceURL!
}

enum RootCertificate: CertificateConvertible {

    case root
    
    var path: String { return "alamofire-root-ca.cer" }

}

enum IntermediateCert: CertificateConvertible {

    
    case ca1
    case ca2
    
    var path: String {
        switch self {
        case .ca1:
            return "alamofire-signing-ca1.cer"
        case .ca2:
            return "alamofire-signing-ca2.cer"
        }
        
        
    }
}

enum LeafCertCA1: CertificateConvertible {
   
    
    case mutipleDNSNames
    case signed
    case test
    case wildcard
    
    
    
     var path: String {
        switch self {
        case .mutipleDNSNames:
            return "multiple-dns-names.cer"
        case .signed:
            return "signed-by-ca1.cer"
        case .test:
            return "test.alamofire.org.cer"
        case .wildcard:
            return "wildcard.alamofire.org.cer"
     
        }
        
        
    }
}

enum LeafCertCA2: CertificateConvertible {
    
    case expired
    case missingDNSAndUrl
    case signed
    case validDNSName
    case validUri
    
    
    var path: String {
        switch self {
        case .expired:
            return "expired.cer"
        case .missingDNSAndUrl:
            return "missing-dns-name-and-uri.cer"
        case .signed:
            return "signed-by-ca2.cer"
        case .validDNSName:
            return "valid-dns-name.cer"
        case .validUri:
            return "valid-uri.cer"
  
        }
        
    }
    
    
    
    
}

class SecTrustTests: XCTestCase {
    
    
    
    
    lazy var validatCertificates = { () -> [SecCertificate] in
        
        // 顺序不能乱 leafCert, IntermediateCert, RootCert
        return [LeafCertCA1.signed.asCertificate(),
                
                IntermediateCert.ca1.asCertificate(),
                RootCertificate.root.asCertificate(),
                ]
    }()
    
    func createDefaultTrust() -> SecTrust {
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let serverCertificates = self.validatCertificates
        // AnyObject
        let trustCreationStatus = SecTrustCreateWithCertificates(serverCertificates as CFArray, policy, &trust)
        
        XCTAssert(trustCreationStatus == errSecSuccess)
        XCTAssert(SecTrustGetCertificateCount(trust!) == 3)
        return trust!
    }
    
    func createExpiredTrust() -> SecTrust {
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        
        // unvalidate service trust
        let serverCertificates = [LeafCertCA2.expired.asCertificate(),
                                  IntermediateCert.ca2.asCertificate(),
                                  RootCertificate.root.asCertificate(),
                                  ]
        
        // unvalidate service trust, miss leaf cert
//        let serverCertificates = [
//                                  IntermediateCert.ca2.asCertificate(),
//                                  RootCertificate.root.asCertificate(),
//                                  ]
        
        // validate service trust
//        let serverCertificates = [LeafCertCA2.signed.asCertificate(),
//                                  IntermediateCert.ca2.asCertificate(),
//                                  RootCertificate.root.asCertificate(),
//                                  ]
        
   ///      unvalidate service trust
        /// 这个最终回导致 SecTrustGetCertificateCount(serverTrust) = 1， 因为mediate cert 不对
//                let serverCertificates = [LeafCertCA2.signed.asCertificate(),
//                                          IntermediateCert.ca1.asCertificate(),
//                                          RootCertificate.root.asCertificate(),
//                                          ]
        
        
        // AnyObject
        let trustCreationStatus = SecTrustCreateWithCertificates(serverCertificates as CFArray, policy, &trust)
        
        XCTAssert(trustCreationStatus == errSecSuccess)
        XCTAssert(SecTrustGetCertificateCount(trust!) == 3)
        return trust!
    }


    
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func setRootCertificateAsLoneAnchorCertificateForTrust(_ trust: SecTrust) {
        SecTrustSetAnchorCertificates(trust, [RootCertificate.root.asCertificate()] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
    }

    func testValidateTrust() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        
        // 这是一个合法的ServerTrust, 拥有leafCert, intermediateCert, rootCert
        // 注意：serverTrust的certificates数组一定是这个顺序
        let serverTrust = createDefaultTrust()
        XCTAssert(certificates(for: serverTrust).count == 3)
        
        
        // 设置认证策略
        // 进行域名认证可以有效防止： A站使用B站证书，但B站的证书是合法的， 从而最终导致和A站认证通过情况出现
        let policy = SecPolicyCreateSSL(true,  "test.alamofire.org" as CFString)
        SecTrustSetPolicies(serverTrust, policy)
        
        
        // 设置SecTrustSetAnchorCertificates后SecTrustGetCertificateCount的值可能改变
        // * 取决于证书AnchorCertificates 具体是leaf or Intermediate or root , 那么对应的数量就是1，2，3
        // * 如果AnchorCertificates 证书非法，则数量不变
        
        
        // root cert是一张自签名证书，所以需要SecTrustSetAnchorCertificates 信任根证书，才能完成认证
        // 如果root cert 是第三方机构颁发的则不用，设置该属性，也可以通过
        // 认证通过
        SecTrustSetAnchorCertificates(serverTrust, [RootCertificate.root.asCertificate()] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        XCTAssert(trustIsValid(serverTrust))
        
        
        // 信任 intermediateCert Cert 认证通过
        SecTrustSetAnchorCertificates(serverTrust, [IntermediateCert.ca1.asCertificate()] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        XCTAssert(trustIsValid(serverTrust))
        
 
        
        // 信任Leaf Cert 认证通过
        SecTrustSetAnchorCertificates(serverTrust, [LeafCertCA1.signed.asCertificate()] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        XCTAssert(trustIsValid(serverTrust))
        
        // 信任一张不在SeverTrust证书列表中的证书, 认证不通过
        SecTrustSetAnchorCertificates(serverTrust, [LeafCertCA2.expired.asCertificate()] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        XCTAssert(trustIsValid(serverTrust) == false)
        
        
        // 信任两张证书： 一张在SeverTrust证书列表中， 一张不在， 认证通过
        SecTrustSetAnchorCertificates(serverTrust, [LeafCertCA2.expired.asCertificate(), LeafCertCA1.signed.asCertificate()] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        XCTAssert(trustIsValid(serverTrust) == true)
        
        
    }
    
    func testValidateExpiredCert() {
  
        /// leaf cert 已经过期的ServerTrust
        let serverTrust = createExpiredTrust()
        XCTAssert(certificates(for: serverTrust).count == 3)
        
        
        // 不认证域名
        let policy = SecPolicyCreateSSL(true,  nil)
        SecTrustSetPolicies(serverTrust, policy)
        
        // 无论信任对应的RootCert, IntermediateCert or leafCert 都无法通过评估
        SecTrustSetAnchorCertificates(serverTrust, [RootCertificate.root.asCertificate()] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        
        XCTAssert(trustIsValid(serverTrust) == false)
        
        
        
        SecTrustSetAnchorCertificates(serverTrust, [IntermediateCert.ca2.asCertificate()] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        
        XCTAssert(trustIsValid(serverTrust) == false)
        
        SecTrustSetAnchorCertificates(serverTrust, [LeafCertCA2.expired.asCertificate()] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        
        XCTAssert(trustIsValid(serverTrust) == false)
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}


// MARK: - Private - Trust Validation

private func trustIsValid(_ trust: SecTrust) -> Bool {
    var isValid = false

    var result = SecTrustResultType.invalid
    let status = SecTrustEvaluate(trust, &result)

    if status == errSecSuccess {
        let unspecified = SecTrustResultType.unspecified
        let proceed = SecTrustResultType.proceed


        isValid = result == unspecified || result == proceed
    }

    return isValid
}

// MARK: - Private - Certificate Data

private func certificates(for trust: SecTrust) -> [SecCertificate] {
    var certificates: [SecCertificate] = []
    
    for index in 0..<SecTrustGetCertificateCount(trust) {
        if let certificate = SecTrustGetCertificateAtIndex(trust, index) {
            certificates.append(certificate)
        }
    }
    
    return certificates
}

private func certificateData(for trust: SecTrust) -> [Data] {
   
    return certificateData(for: certificates(for: trust))
}

private func certificateData(for certificates: [SecCertificate]) -> [Data] {
    return certificates.map { SecCertificateCopyData($0) as Data }
}

// MARK: - Private - Public Key Extraction

private  func publicKeys(for trust: SecTrust) -> [SecKey] {
    var publicKeys: [SecKey] = []
    
    for index in 0..<SecTrustGetCertificateCount(trust) {
        if
            let certificate = SecTrustGetCertificateAtIndex(trust, index),
            let publicKey = publicKey(for: certificate)
        {
            publicKeys.append(publicKey)
        }
    }
    
    return publicKeys
}


private  func publicKey(for certificate: SecCertificate) -> SecKey? {
    var publicKey: SecKey?
    
    let policy = SecPolicyCreateBasicX509()
    var trust: SecTrust?
    let trustCreationStatus = SecTrustCreateWithCertificates(certificate, policy, &trust)
    
    if let trust = trust, trustCreationStatus == errSecSuccess {
        publicKey = SecTrustCopyPublicKey(trust)
    }
    
    return publicKey
}
