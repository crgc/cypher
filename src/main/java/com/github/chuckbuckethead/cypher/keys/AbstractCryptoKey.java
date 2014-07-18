/*
 * Copyright (C) 2014 Carlos González.
 * All rights reserved.
 *
 * The software in this package is published under the terms of the MIT
 * license a copy of which has been included with this distribution in
 * the LICENSE.txt file.
 * 
 * Created on Jul 17, 2014 by Carlos González
 */
package com.github.chuckbuckethead.cypher.keys;

import java.io.UnsupportedEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import com.thoughtworks.xstream.core.util.Base64Encoder;

/**
 * Abstract implementation of the CryptoKey interface. This class defines
 * the generic behavior of a cryptography key.
 *
 * @author Carlos González
 */
public abstract class AbstractCryptoKey implements CryptoKey
{

	private Base64Encoder encoder;
	
	/**
	 * 
	 */
	protected AbstractCryptoKey() { }
	
	
	/* (non-Javadoc)
	 * @see com.github.chuckbuckethead.cypher.keys.CryptoKey#encrypt(java.lang.String)
	 */
	public String encrypt(String str) {
		String encryptedStr = null;
		
		try {
			byte[] utf8 = str.getBytes("UTF-8");
			encryptedStr = encryptBytes(utf8);
			
		} catch(UnsupportedEncodingException e) { /* ignore */ }
		
		return encryptedStr;
	}
	
	
	/* (non-Javadoc)
	 * @see com.github.chuckbuckethead.cypher.keys.CryptoKey#encryptBytes(byte[])
	 */
	public synchronized String encryptBytes(byte[] bytes) {
		String encryptedStr = null;
		
		try {
			//Encrypt
			byte[] enc = getEncryptCipher().doFinal(bytes);
			
			//Encode bytes to base64 to get a string
			encryptedStr = getEncoder().encode(enc);
		}
		catch(BadPaddingException e) { /* ignore */ }
		catch(IllegalBlockSizeException e) { /* ignore */ }  	
		
		return encryptedStr;
	}
	
	
	/* (non-Javadoc)
	 * @see com.github.chuckbuckethead.cypher.keys.CryptoKey#decrypt(java.lang.String)
	 */
	public String decrypt(String base64Str) {
		String decryptedStr = null;
		
		try {
			byte[] dec = decryptBytes(base64Str);
			if(dec != null) {
				//Decode using UTF-8
				decryptedStr = new String(dec, "UTF-8");
			}
			
		} catch(UnsupportedEncodingException e) {}
		
		return decryptedStr;
	}
	
	
	/* (non-Javadoc)
	 * @see com.github.chuckbuckethead.cypher.keys.CryptoKey#decryptBytes(java.lang.String)
	 */
	public synchronized byte[] decryptBytes(String base64Str) {
		byte[] bytes = null;
		
		try {
			byte[] dec = getEncoder().decode(base64Str);
			
			//Decrypt
			bytes = getDecryptCipher().doFinal(dec);
		}
		catch (IllegalBlockSizeException e) {}
		catch (BadPaddingException e) { }
		
		return bytes;
	}
	
	
	protected Base64Encoder getEncoder() {
		if(encoder == null) {
			encoder = new Base64Encoder();
		}
		
		return encoder;
	}
	
	
	/**
	 * Return the <code>Cipher</code> to use to encrypt data.
	 */
	protected abstract Cipher getEncryptCipher();
	
	
	/**
	 * Return the <code>Cipher</code> to use to decrypt data.
	 */
	protected abstract Cipher getDecryptCipher();
}