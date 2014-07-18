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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import com.github.chuckbuckethead.cypher.keys.CryptoKey;
import com.github.chuckbuckethead.cypher.keys.RSAKey;
import com.thoughtworks.xstream.core.util.Base64Encoder;

/**
 * 
 * RSA key generator.
 * 
 * @author Carlos González
 */
class RSAKeyGen
{
	/**
	 * 
	 */
	protected RSAKeyGen()
	{
	}
	
	
	/**
	 * Generate an RSA key
	 * 
	 * @param bits number of bits
	 * @return the RSA key
	 */
	protected RSAKey generateKey(int bits) throws NoSuchAlgorithmException
	{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoKey.RSA_ALGORITHM);
		keyGen.initialize(bits);

		KeyPair keyPair = keyGen.generateKeyPair();

		Base64Encoder encoder = new Base64Encoder();
		String publicKey = encoder.encode(keyPair.getPublic().getEncoded());
		String privateKey = encoder.encode(keyPair.getPrivate().getEncoded());

		RSAKey key = new RSAKey();
		key.setPublicKey(publicKey);
		key.setPrivateKey(privateKey);
		
		return key;
	}
}
