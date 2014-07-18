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

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;

import com.github.chuckbuckethead.cypher.keys.BlowfishKey;
import com.github.chuckbuckethead.cypher.keys.RSAKey;


/**
 * This class servers as point of entry for the Cypher API.
 *
 * @author Carlos Gonzalez
 */
public class Cypher
{
	/**
	 * 
	 */
	private Cypher() {	}
	
	
	/**
	 * Creates a new <code>RSAKey</code> instance.
	 * 
	 * @param keySize
	 * @return the RSA key
	 * 
	 * @throws InvalidParameterException if key size is less than 512
	 */
	public static RSAKey generateRSAKey(int keySize)
	{
		try
		{
			return new RSAKeyGen().generateKey(keySize);
		}
		catch (NoSuchAlgorithmException e)
		{
			/* This will probably never happen */
			throw new RuntimeException(e);
		}
	}
	
	
	/**
	 * Creates a new <code>RSAKey</code> instance with a key size 512 bits.
	 * 
	 * @return the RSA key
	 */
	public static RSAKey generateRSAKey()
	{
		return generateRSAKey(RSAKey.MINIMUM_KEY_SIZE);
	}
	
	
	/**
	 * Creates a new <code>BlowfishKey</code> instance.
	 * 
	 * @param keySize
	 * @return the Blowfish key
	 * 
	 * @throws InvalidParameterException if key size is not multiple of 8, or if it's not within a range from 32 to 448 (inclusive)
	 */
	public static BlowfishKey generateBlowfishKey(int keySize)
	{
		try
		{
			return new BlowfishKeyGen().generateKey(keySize);
		}
		catch (NoSuchAlgorithmException e)
		{
			/* This will probably never happen */
			throw new RuntimeException(e);
		}
	}
}