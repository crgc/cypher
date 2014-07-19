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
package com.github.chuckbuckethead.cypher;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.github.chuckbuckethead.cypher.keys.BlowfishKey;
import com.github.chuckbuckethead.cypher.keys.CryptoKey;
import com.thoughtworks.xstream.core.util.Base64Encoder;

/**
 * Blowfish key generator.
 * 
 * @author Carlos González
 */
public class BlowfishKeyGen
{

	/**
	 * 
	 */
	public BlowfishKeyGen()
	{
	}
	
	
	/**
	 * Generate a Blowfish key
	 * 
	 * @param bits number of bits
	 * @return the Blowfish key
	 */
	public BlowfishKey generateKey(int bits) throws NoSuchAlgorithmException
	{
		KeyGenerator keyGen = KeyGenerator.getInstance(CryptoKey.BLOWFISH_ALGORITHM);
		keyGen.init(bits);

		SecretKey key = keyGen.generateKey();
		String encodedKey = new Base64Encoder().encode(key.getEncoded());
		return new BlowfishKey(encodedKey);
	}
}
