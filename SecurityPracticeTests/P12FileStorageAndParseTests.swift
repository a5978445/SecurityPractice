//
//  P12FileStorageAndParseTests.swift
//  SecurityPracticeTests
//
//  Created by 李腾芳 on 2019/4/29.
//  Copyright © 2019年 HSBC Holdings plc. All rights reserved.
//

import XCTest

class P12FileStorageAndParseTests: XCTestCase {
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        
        deleteItemIfExist()
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testParseP12File() {
        let p12Attrs = loadP12File()

        // parse p12 file
        let identity = p12Attrs[kSecImportItemIdentity as String] as! SecIdentity

        let trust = p12Attrs[kSecImportItemTrust as String] as! SecTrust
    }

    func testParseIdentity() {
        let p12Attrs = loadP12File()

        // parse p12 file
        let identity = p12Attrs[kSecImportItemIdentity as String] as! SecIdentity
        let (secKey, sertificate) = try! parseIdentity(identity: identity)
    }

    func testStorageIntoKeyChain() {
 
       let persistentRef = addToKeyChain() as! NSData
        
        UserDefaults.standard.set(persistentRef, forKey: "kSecReturnPersistentRef")
        print(persistentRef)
        
        let identity = queryItem(persistentRef: persistentRef)!
        
        // get  private key
        var privateKey: SecKey?
        var status = SecIdentityCopyPrivateKey(identity, &privateKey)
        
        XCTAssert(status == noErr)
        XCTAssert(privateKey != nil)
        
        // get public key
        var certificate: SecCertificate?
        status = SecIdentityCopyCertificate(identity, &certificate)
        
        XCTAssert(status == noErr)
        XCTAssert(certificate != nil)
        let publicKey = SecCertificateCopyKey(certificate!)
        XCTAssert(publicKey != nil)
        
        
        
       
        
        XCTAssert(queryItem(persistentRef: persistentRef) != nil)
        
        deleteItemIfExist()
        XCTAssert(queryItem(persistentRef: persistentRef) == nil)
    }
    




    func parseIdentity(identity: SecIdentity) throws -> (SecKey, SecCertificate) {
        var privateKey: SecKey?
        var status = SecIdentityCopyPrivateKey(identity, &privateKey)
        guard status == errSecSuccess else { throw NSError(domain: "SecIdentityCopyPrivateKey failure", code: Int(status), userInfo: nil) }

        var certificate: SecCertificate?
        status = SecIdentityCopyCertificate(identity, &certificate)
        guard status == errSecSuccess else { throw NSError(domain: "SecIdentityCopyPrivateKey failure", code: Int(status), userInfo: nil) }

        return (privateKey!, certificate!)
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
    }


}


//MARK: private method
extension P12FileStorageAndParseTests {
    func loadP12File() -> Dictionary<String, Any> {
        var url = Bundle(for: P12FileStorageAndParseTests.self).resourceURL!
        url.appendPathComponent("fitchAppleAccount.p12")
        
        let data = try! Data(contentsOf: url)
        
        let password = "a5978445"
        let options = [kSecImportExportPassphrase as String: password]
        
        var rawItems: CFArray?
        // suport DER 和 PEM Encode
        let status = SecPKCS12Import(data as CFData,
                                     options as CFDictionary,
                                     &rawItems)
        
        guard status == errSecSuccess else {
            fatalError("parse p12 file failure")
        }
        // p12 文件可以包含多个证书和私钥
        let items = rawItems! as! Array<Dictionary<String, Any>>
        let p12Attrs = items[0]
        return p12Attrs
    }
    
    func addToKeyChain() -> CFTypeRef? {
        let p12Attrs = loadP12File()
        
        // parse p12 file
        let identity = p12Attrs[kSecImportItemIdentity as String] as! SecIdentity
        
        var addResult: CFTypeRef?
        let addquery: [String: Any] = [
            kSecValueRef as String: identity,
            kSecReturnPersistentRef as String: true,
            ]

        let status = SecItemAdd(addquery as CFDictionary, &addResult)
        guard status == errSecSuccess else {
            print("addToKeyChain failure: \(status)")
            return nil
        }
        
        return addResult
    }
    
    func queryItem(persistentRef: NSData) -> SecIdentity? {
        let getquery: [String: Any] = [
            kSecReturnRef as String: kCFBooleanTrue,
            kSecValuePersistentRef as String: persistentRef,
            ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(getquery as CFDictionary, &item)
        guard status == errSecSuccess else {
           
            print("queryItem failure \(status)")
            return nil
        }
        return item as! SecIdentity
    }
    
    func deleteItemIfExist() {
        if let persistentRef = UserDefaults.standard.value(forKey: "kSecReturnPersistentRef") as? NSData {
            let deleteQuery: [String: Any] = [
                kSecValuePersistentRef as String: persistentRef,
                ]
            
            SecItemDelete(deleteQuery as CFDictionary)
        }
    }
}
