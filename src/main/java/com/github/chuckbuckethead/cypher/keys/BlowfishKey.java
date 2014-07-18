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

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Symmetric key cryptography implementation of the <code>CryptoKey</code> interface
 * using the Blowfish encryption algorithm.
 * 
 * @author Carlos González
 */
public class BlowfishKey extends AbstractCryptoKey implements CryptoKey
{

	// Base64 key
	private String				key;

	// Ciphers
	private transient Cipher	encodeCipher;
	private transient Cipher	decodeCipher;


	/**
	 * 
	 */
	public BlowfishKey(String key)
	{
		this.key = key;
		if (key != null)
		{
			initCiphers();
		}
	}


	/**
	 * @return the base64Key
	 */
	public String getKey()
	{
		return key;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see com.github.chuckbuckethead.cypher.keys.CryptoKey#getAlgorithmName()
	 */
	public String getAlgorithmName()
	{
		return CryptoKey.BLOWFISH_ALGORITHM;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see com.github.chuckbuckethead.cypher.keys.AbstractCryptoKey#getEncryptCipher()
	 */
	@Override
	protected Cipher getEncryptCipher()
	{
		if (encodeCipher == null)
		{
			initCiphers();
		}

		return encodeCipher;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see com.github.chuckbuckethead.cypher.keys.AbstractCryptoKey#getDecryptCipher()
	 */
	@Override
	protected Cipher getDecryptCipher()
	{
		if (decodeCipher == null)
		{
			initCiphers();
		}

		return decodeCipher;
	}


	/**
	 * 
	 */
	private void initCiphers()
	{
		try
		{
			byte[] bytes = getEncoder().decode(key);
			SecretKeySpec keySpec = new SecretKeySpec(bytes, BLOWFISH_ALGORITHM);

			// Instantiate the ciphers
			encodeCipher = Cipher.getInstance(BLOWFISH_ALGORITHM);
			encodeCipher.init(Cipher.ENCRYPT_MODE, keySpec);

			decodeCipher = Cipher.getInstance(BLOWFISH_ALGORITHM);
			decodeCipher.init(Cipher.DECRYPT_MODE, keySpec);

		}
		catch (Exception e)
		{
			throw new IllegalArgumentException("Error constructing Cipher: ", e);
		}
	}
}