//
//  SecurityOfficer.m
//  iMenu360
//
//  Created by Siddharth Mahendraker on 11-02-23.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#import "SecurityOfficer.h"

#define kChosenCipherBlockSize	kCCBlockSizeAES128
#define kChosenCipherKeySize	kCCKeySizeAES128


@implementation SecurityOfficer 

static SecurityOfficer *sharedOfficer = nil;


@synthesize sharedSymmetricKey;

#pragma mark -
#pragma mark Key Access

- (const char *) getKeyAsChar
{
    @synchronized(self) {
        
        if (self.sharedSymmetricKey != nil)
        {
            const char *key = [self.sharedSymmetricKey UTF8String];

            return key;
        }
    }
    
    return nil;
}

- (NSData*) getKeyAsData 
{
    
    @synchronized(self) {
        
        if (self.sharedSymmetricKey != nil)
        {
            const char *charKey = [self getKeyAsChar];
            NSData *key = [NSData dataWithBytes:charKey length:sizeof(charKey)];
            
            return key;
        }
    }
    
    return nil;
}

#pragma mark -
#pragma mark Encryption and Decryption (Public)

- (NSData*) encryptData:(NSData*)data
{
    CCOptions pad = kCCOptionPKCS7Padding;
    
    NSData *encryptedData = [self doCipher:data key:[self getKeyAsData] context:kCCEncrypt padding:&pad]; 

    return encryptedData;
}

- (NSData*) decryptData:(NSData*)data
{
    CCOptions pad = kCCOptionPKCS7Padding;
    
    NSData *decryptedData = [self doCipher:data key:[self getKeyAsData] context:kCCDecrypt padding:&pad]; 
    
    return decryptedData;
}

#pragma mark -
#pragma mark Standard Methods

+ (SecurityOfficer *) sharedOfficer
{
    @synchronized(self) {
        
        if (sharedOfficer == nil)
        {
            [[[self alloc]init]release];
        }
        
    }

    return sharedOfficer;
}

+ (id)allocWithZone:(NSZone *)zone 
{
    @synchronized(self) {
        
        if (sharedOfficer == nil) {
            
            sharedOfficer = [super allocWithZone:zone];
            return sharedOfficer;
        }
    }
    
    return nil;
}

- (id)copyWithZone:(NSZone *)zone {
    return self;
}

- (void)release {
        // do nothing I'm a singleton
}

- (id)retain {
    return self;
}

- (id)autorelease {
    return self;
}

- (NSUInteger)retainCount {
    return UINT_MAX;
}

- (void) dealloc {
    
    [super dealloc];
    [sharedSymmetricKey release];
}

#pragma mark -
#pragma mark Encryption and Decryption (Private)

- (NSData *)doCipher:(NSData *)plainText key:(NSData *)symmetricKey context:(CCOperation)encryptOrDecrypt padding:(CCOptions *)pkcs7 
{
	CCCryptorStatus ccStatus = kCCSuccess;
        // Symmetric crypto reference.
	CCCryptorRef thisEncipher = NULL;
        // Cipher Text container.
	NSData * cipherOrPlainText = nil;
        // Pointer to output buffer.
	uint8_t * bufferPtr = NULL;
        // Total size of the buffer.
	size_t bufferPtrSize = 0;
        // Remaining bytes to be performed on.
	size_t remainingBytes = 0;
        // Number of bytes moved to buffer.
	size_t movedBytes = 0;
        // Length of plainText buffer.
	size_t plainTextBufferSize = 0;
        // Placeholder for total written.
	size_t totalBytesWritten = 0;
        // A friendly helper pointer.
	uint8_t * ptr;
	
        // Initialization vector; dummy in this case 0's.
    uint8_t iv[kChosenCipherBlockSize];
    memset((void *) iv, 0x0, (size_t) sizeof(iv));
	
	plainTextBufferSize = [plainText length];
		
        // We don't want to toss padding on if we don't need to
	if (encryptOrDecrypt == kCCEncrypt) {
		if (*pkcs7 != kCCOptionECBMode) {
			if ((plainTextBufferSize % kChosenCipherBlockSize) == 0) {
				*pkcs7 = 0x0000;
			} else {
				*pkcs7 = kCCOptionPKCS7Padding;
			}
		}
	} else if (encryptOrDecrypt != kCCDecrypt) {
        
        NSLog(@"Invalid parameter!");
        } 
	
        // Create and Initialize the crypto reference.
	ccStatus = CCCryptorCreate(	encryptOrDecrypt, 
                               kCCAlgorithmAES128, 
                               *pkcs7, 
                               (const void *)[symmetricKey bytes], 
                               kChosenCipherKeySize, 
                               (const void *)iv, 
                               &thisEncipher
                               );
	

	if(ccStatus != kCCSuccess)
    {
        NSLog(@"Problem creating context Errno:%d", ccStatus);
    }
        // Calculate byte block alignment for all calls through to and including final.
	bufferPtrSize = CCCryptorGetOutputLength(thisEncipher, plainTextBufferSize, true);
	
        // Allocate buffer.
	bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t) );
	
        // Zero out buffer.
	memset((void *)bufferPtr, 0x0, bufferPtrSize);
	
        // Initialize some necessary book keeping.
	
	ptr = bufferPtr;
	
        // Set up initial size.
	remainingBytes = bufferPtrSize;
	
        // Actually perform the encryption or decryption.
	ccStatus = CCCryptorUpdate( thisEncipher,
                               (const void *) [plainText bytes],
                               plainTextBufferSize,
                               ptr,
                               remainingBytes,
                               &movedBytes
                               );
	
    if(ccStatus != kCCSuccess)
    {
        NSLog(@"Problem with CCCryptor update context Errno:%d", ccStatus);
    }	
        // Handle book keeping.
	ptr += movedBytes;
	remainingBytes -= movedBytes;
	totalBytesWritten += movedBytes;
	
        // Finalize everything to the output buffer.
	ccStatus = CCCryptorFinal(	thisEncipher,
                              ptr,
                              remainingBytes,
                              &movedBytes
                              );
	
	totalBytesWritten += movedBytes;
	
	if (thisEncipher) {
		(void) CCCryptorRelease(thisEncipher);
		thisEncipher = NULL;
	}
	
    if(ccStatus != kCCSuccess)
    {
        NSLog(@"Problem with encyphirment Errno:%d", ccStatus);
    }	
	cipherOrPlainText = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)totalBytesWritten];
    
	if (bufferPtr) free(bufferPtr);
	
	return cipherOrPlainText;
	
	/*
	 Or the corresponding one-shot call:
	 
	 ccStatus = CCCrypt(	encryptOrDecrypt,
     kCCAlgorithmAES128,
     typeOfSymmetricOpts,
     (const void *)[self getSymmetricKeyBytes],
     kChosenCipherKeySize,
     iv,
     (const void *) [plainText bytes],
     plainTextBufferSize,
     (void *)bufferPtr,
     bufferPtrSize,
     &movedBytes
     );
	 */
}

@end
