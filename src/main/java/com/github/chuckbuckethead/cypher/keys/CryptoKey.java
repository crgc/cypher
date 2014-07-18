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

/**
 * Implement this interface for each encryption algorithm you want to support (i.e., Blowfish, RSA, DES, AES, etc.)
 * 
 * @author Carlos González
 */
public interface CryptoKey
{

	/**
	 * Blowfish algorithm name.
	 */
	public static final String	BLOWFISH_ALGORITHM	= "Blowfish";

	/**
	 * RSA algorithm name.
	 */
	public static final String	RSA_ALGORITHM		= "RSA";


	/**
	 * Return the name of the algorithm.
	 */
	String getAlgorithmName();


	/**
	 * Encrypt the specified string.
	 * 
	 * @param str The string to encrypt.
	 * @return The encrypted string (base64 encoded).
	 */
	String encrypt(String str);


	/**
	 * Encrypt the specified byte array.
	 * 
	 * @param bytes The byte array to encrypt.
	 * @return The encrypted string (base64 encoded).
	 */
	String encryptBytes(byte[] bytes);


	/**
	 * Decrypt the specified string.
	 * 
	 * @param str The string to decrypt.
	 * @return The decrypted string.
	 */
	String decrypt(String str);


	/**
	 * Decrypt the specified byte array.
	 * 
	 * @param bytes The string (base64 encoded) to decrypt
	 * @return The decrypted byte array.
	 */
	byte[] decryptBytes(String str);
}