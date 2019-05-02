//
//  ViewController.swift
//  SecurityPractice
//
//  Created by 李腾芳 on 2019/4/26.
//  Copyright © 2019年 HSBC Holdings plc. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.

        /*
         let firstItem = loadP12File()

         // parse p12 file
         let identity = firstItem[kSecImportItemIdentity as String] as! SecIdentity

         let addquery: [String: Any] = [kSecClass as String: kSecClassIdentity,
         kSecValueRef as String: identity,
         kSecAttrLabel as String: "MyP12FileIdentity"]

         var status = SecItemAdd(addquery as CFDictionary, nil)
         guard status == errSecSuccess else {
         fatalError()
         //    XCTFail()
         return

         }

         let getquery: [String: Any] = [kSecClass as String: kSecClassIdentity,
         kSecAttrLabel as String: "MyP12FileIdentity",
         kSecReturnRef as String: kCFBooleanTrue
         ]
         //  kSecValuePersistentRef

         /*

          let addquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
          kSecValueRef as String: self.certificate,
          kSecAttrLabel as String: "My Certificate"]

          var status = SecItemAdd(addquery as CFDictionary, nil)
          guard status == errSecSuccess else {
          XCTFail()
          return

          }

          let getquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
          kSecAttrLabel as String: "My Certificate",
          kSecReturnRef as String: kCFBooleanTrue]
          */

         var item: CFTypeRef?
         status = SecItemCopyMatching(getquery as CFDictionary, &item)
         guard status == errSecSuccess else {
         //   XCTFail()
         fatalError()
         return

         }
         //  XCTAssert(item is SecCertificate)
         let certificate = item as! SecIdentity
         */
    }

    func loadP12File() -> Dictionary<String, Any> {
        var url = Bundle(for: ViewController.self).resourceURL!
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
            // throw <# an error #>
            fatalError("parse p12 file failure")
            // return
        }
        let items = rawItems! as! Array<Dictionary<String, Any>>
        let firstItem = items[0]
        return firstItem
    }

    func storageIdentity() {
        //  SecItemDelete(CFDictionaryRef query)
        /*

         Use SecIdentity objects instead of SecCertificate objects.

         Use kSecClassIdentity instead of kSecClassCertificate for the kSecClass attribute.

         */
    }
}
