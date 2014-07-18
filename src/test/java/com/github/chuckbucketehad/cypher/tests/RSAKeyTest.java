/*
 * Copyright (C) 2014 Carlos González.
 * All rights reserved.
 *
 * The software in this package is published under the terms of the MIT
 * license a copy of which has been included with this distribution in
 * the LICENSE.txt file.
 * 
 * Created on Jul 18, 2014 by Carlos González
 */
package com.github.chuckbucketehad.cypher.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;

import java.security.InvalidParameterException;

import org.junit.Test;

import com.github.chuckbuckethead.cypher.Cypher;
import com.github.chuckbuckethead.cypher.keys.CryptoKey;
import com.github.chuckbuckethead.cypher.keys.RSAKey;

/**
 * 
 * @author Carlos González
 */
public class RSAKeyTest
{
	/**
	 * 
	 */
	public RSAKeyTest()
	{
	}
	
	
	@Test(expected = InvalidParameterException.class)
	public void testKeySizeLessThanMinimum()
	{
		Cypher.generateRSAKey(128);
	}


	@Test
	public void testGenerateRSAKey()
	{
		RSAKey key = Cypher.generateRSAKey();
		
		assertNotNull(key);
		assertEquals(CryptoKey.RSA_ALGORITHM, key.getAlgorithmName());
		assertNotNull(key.getPrivateKey());
		assertNotNull(key.getPublicKey());
	}
	
	
	@Test
	public void testEncryptDecrypt()
	{
		String phrase = "Cypher";
		RSAKey key = Cypher.generateRSAKey();
		
		String encryptedPhrase = key.encrypt(phrase);
		
		assertNotSame(phrase, encryptedPhrase);
		assertEquals(phrase, key.decrypt(encryptedPhrase));
	}
}