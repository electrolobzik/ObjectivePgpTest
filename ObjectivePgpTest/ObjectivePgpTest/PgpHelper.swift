//
//  PgpHelper.swift
//  ObjectivePgpTest
//
//  Created by Roman Chernyak on 23/03/15.
//  Copyright (c) 2015 Elisher Arts. All rights reserved.
//

import Foundation
import Security

class PGPHelper {
    
    let password = "qwerty"
    
    
    let publicFilename = NSBundle.mainBundle().pathForResource("pubring", ofType:"gpg")
    let privateFilename = NSBundle.mainBundle().pathForResource("secring", ofType:"gpg")
    let keyLength = 3072
    
    var currentKey: PGPKey? = nil
    
    lazy var opgp = ObjectivePGP()
    
    func importKey(#stringData: String) {
        let keys = opgp.importKeysFromData(PGPHelper.stringToNsData(stringData), allowDuplicates: false)
        var error: NSError?
        opgp.exportKeysOfType(PGPKeyType.Public, toFile: publicFilename, error: &error)
    }
    
    func setCurrentKey(#id: String, keyPrivate: Bool) {
        currentKey = opgp.getKeyForIdentifier(id, type: keyPrivate ? PGPKeyType.Secret : PGPKeyType.Public)
    }
    
    func encrypt(data: String) -> String {
        
        var error: NSError?
        let data = opgp.encryptData(PGPHelper.stringToNsData(data), usingPublicKey: currentKey, armored: false, error: &error)
        var result = ""
        
        if error != nil {
            result = error!.description
        } else {
            let armored = PGPArmor.armoredData(data, `as`: PGPArmorType.TypeMessage)
            result = NSString(data: armored, encoding: NSUTF8StringEncoding)!
        }
        
        return result
    }
    
    func decryptNet(data: String) -> String {
        
        var error: NSError?
        
        let pgp = UNNetPGP()
        pgp.secretKeyRingPath = privateFilename
        pgp.password = password
        pgp.armored = true
        
        let decr_data = pgp.decryptData(PGPHelper.stringToNsData(data))
        
        return PGPHelper.nsDataToString(decr_data)
    }
    
    
    func encryptFile(filename: String) -> String {
        
        var error: NSError?
        
        let fileContent = NSData(contentsOfFile: filename)
        
        var encryptedData = opgp.encryptData(fileContent, usingPublicKey:currentKey, armored:false, error:&error)
        if encryptedData != nil {
            NSLog("file encryption success")
            encryptedData.writeToFile(filename + ".gpg", atomically: true)
        }
        
        if error == nil {
            return "encryptFile OK"
        } else {
            return "encryptFile error: \(error)"
        }
    }
    
    
    func decryptFile(filename: String) -> String {
        
        var error: NSError?
        
        let fileContent = NSData(contentsOfFile: filename)
        
        var decryptedData = opgp.decryptData(fileContent, passphrase: password, error: &error)
        
        if decryptedData != nil {
            NSLog("file decryption success")
            decryptedData.writeToFile(filename + ".dec", atomically:true)
        }
        
        if error == nil {
            return "decryptFile OK"
        } else {
            return "decryptFile error: \(error)"
        }
    }
    
    func decrypt(data: String) -> String {
        
        var error: NSError?
        
        currentKey!.decrypt(password, error: &error)
        
        if (error != nil) {
            return error!.description
        }
        
        //        let decr = currentKey!.decryptionKeyPacket(&error)
        
        //        if (error != nil) {
        //            return error!.description
        //        }
        
        //        let pack = decr.decryptedKeyPacket("qwerty", error: &error)
        
        //        if (error != nil) {
        //            return error!.description
        //        }
        
        let unarmoredData = PGPArmor.readArmoredData(data, error: &error)
        
        if (error != nil) {
            return error!.description
        }
        
        //        let decr_data = pack.decryptData(unarmoredData, withPublicKeyAlgorithm: PGPPublicKeyAlgorithm.RSA)
        
        let decr_data = opgp.decryptData(unarmoredData, passphrase: password, error: &error)
        
        var result = ""
        
        if error != nil {
            result = error!.description
        } else {
            result = PGPHelper.nsDataToString(decr_data)
        }
        
        return result
    }
    
    func loadKey(#filename: String) {
        opgp.importKeysFromFile(filename, allowDuplicates: false)
    }
    
    func loadKeys() {
        loadKey(filename: publicFilename!)
        loadKey(filename: privateFilename!)
    }
    
    func listKeys(#type: PGPKeyType) -> String {
        
        var keysDesc = ""
        let keys = opgp.getKeysOfType(type)
        
        for key in keys {
            let keyId = key.keyID.description
            let encrypted = key.isEncrypted
            let keyType = key.type == PGPKeyType.Public ? "public" : "private"
            var subcount = "none"
            
            if let subKeys = key.subKeys {
                if subKeys.count > 0 {
                    subcount = String(subKeys.count)
                }
            }
            
            keysDesc += "\n" + "key id = '\(keyId)', encrypted = '\(encrypted)', type = '\(keyType)', subkeys = '\(subcount)'"
        }
        
        return keysDesc
    }
    
    func listKeys() -> String {
        return listKeys(type: PGPKeyType.Public) + "\n" + listKeys(type: PGPKeyType.Secret)
    }
  
    
    func exportCurrentKey() -> String? {
        
        let data = opgp.exportKey(currentKey, armored: true)
        return NSString(data: data, encoding: NSUTF8StringEncoding)
    }
    
    class func nsDataToString(data: NSData) -> String {
        
        return NSString(data: data, encoding: NSUTF8StringEncoding)!
    }
    
    class func stringToNsData(data: String) -> NSData! {
        
        return (data as NSString).dataUsingEncoding(NSUTF8StringEncoding)
    }
}
