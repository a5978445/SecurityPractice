//
//  CertificatesStorageKeyChainTests.swift
//  SecurityPracticeTests
//
//  Created by 李腾芳 on 2019/4/29.
//  Copyright © 2019年 HSBC Holdings plc. All rights reserved.
//

import XCTest

class CertificatesStorageKeyChainTests: XCTestCase {
    lazy var certificate: SecCertificate = { () -> SecCertificate in
        var url = Bundle(for: CertificatesStorageKeyChainTests.self).resourceURL!
        url.appendPathComponent("www.apple.com.cer")
        let data = try! Data(contentsOf: url)

        return SecCertificateCreateWithData(nil, data as CFData)!
    }()

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.

        print("************")

        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: "My Certificate",
        ]

        SecItemDelete(deleteQuery as CFDictionary)

//
//
//        let getquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
//                                       kSecAttrLabel as String: "My Certificate",
//                                       kSecReturnRef as String: kCFBooleanTrue]
//
//
//
//        var item: CFTypeRef?
//        let status = SecItemCopyMatching(query as CFDictionary, &item)
//        guard status == errSecSuccess else { throw <# an error #> }
//        let certificate = item as! SecCertificate
    }

    func testAdd() {
        let addquery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: self.certificate,
            kSecAttrLabel as String: "My Certificate",
        ]

        var status = SecItemAdd(addquery as CFDictionary, nil)
        guard status == errSecSuccess else {
            XCTFail()
            return
        }

        let getquery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: "My Certificate",
            kSecReturnRef as String: kCFBooleanTrue,
        ]

        var item: CFTypeRef?
        status = SecItemCopyMatching(getquery as CFDictionary, &item)
        guard status == errSecSuccess else {
            XCTFail()
            return
        }
        //  XCTAssert(item is SecCertificate)
        let certificate = item as! SecCertificate
    }

    func testDelete() {
        let getquery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: "My Certificate",
            kSecReturnRef as String: kCFBooleanTrue,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(getquery as CFDictionary, &item)
        XCTAssert(status == errSecItemNotFound)
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
    }
}
