//
//  ViewController.swift
//  ObjectivePgpTest
//
//  Created by Roman Chernyak on 23/03/15.
//  Copyright (c) 2015 Elisher Arts. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var textView: UITextView!
    
    @IBAction func encodeFile(sender: AnyObject) {
        
        let imageFile = NSBundle.mainBundle().pathForResource("test_image", ofType:"jpg")
        let helper = PGPHelper()
        
        helper.loadKeys()
        helper.setCurrentKey(id: "FE402D38A3945EEF", keyPrivate: true)
        
        
        
        textView.text = helper.encryptFile(imageFile!)
    }
}

