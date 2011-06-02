//
//  SecurityOfficer.h
//  iMenu360
//
//  Created by Siddharth Mahendraker on 11-02-23.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

    //A singleton class to provide security support 

@interface SecurityOfficer : NSObject {
    
    NSString *sharedSymmetricKey;   
}

@property (retain) NSString *sharedSymmetricKey;

    //Public encryption adn decryption methods
- (NSData*) encryptData:(NSData*)data;
- (NSData*) decryptData:(NSData*)data;

    //Returns an instance of the class
+ (SecurityOfficer *) sharedOfficer;

    //Key methods
- (const char *) getKeyAsChar;
- (NSData*) getKeyAsData;

    //Does all the encryption
    //Return encrypted or decrypted data
- (NSData *)doCipher:(NSData *)plainText key:(NSData *)symmetricKey 
             context:(CCOperation)encryptOrDecrypt padding:(CCOptions *)pkcs7; 

    
@end
