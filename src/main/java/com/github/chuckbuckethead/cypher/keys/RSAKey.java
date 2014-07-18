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

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * Asymmetric cryptography implementation of the <code>CryptoKey</code>
 * interface using the RSA encryption algorithm.
 * 
 * @author Carlos González
 */
public class RSAKey extends AbstractCryptoKey implements CryptoKey
{
	
	private String							publicKey;
	private String							privateKey;
	
	// Ciphers
	private transient AsymmetricBlockCipher	encodeCipher;
	private transient AsymmetricBlockCipher	decodeCipher;
	
	public static final int					MINIMUM_KEY_SIZE	= 512;
	
	/**
	 * Default
	 */
	public RSAKey()
	{
	}


	/**
	 * @param publicKey
	 * @param privateKey
	 */
	public RSAKey(String publicKey, String privateKey)
	{
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}


	/**
	 * @return the privateKey
	 */
	public String getPrivateKey()
	{
		return privateKey;
	}


	/**
	 * @param privateKey
	 *            the privateKey to set
	 */
	public void setPrivateKey(String privateKey)
	{
		this.privateKey = privateKey;
	}


	/**
	 * @return the publicKey
	 */
	public String getPublicKey()
	{
		return publicKey;
	}


	/**
	 * @param publicKey
	 *            the publicKey to set
	 */
	public void setPublicKey(String publicKey)
	{
		this.publicKey = publicKey;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see com.github.chuckbuckethead.cypher.keys.CryptoKey#getAlgorithmName()
	 */
	public String getAlgorithmName()
	{
		return CryptoKey.RSA_ALGORITHM;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see com.github.chuckbuckethead.cypher.keys.AbstractCryptoKey#getEncryptCipher()
	 */
	@Override
	protected Cipher getEncryptCipher()
	{
		throw new UnsupportedOperationException("This method should never be called.");
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see com.github.chuckbuckethead.cypher.keys.AbstractCryptoKey#getDecryptCipher()
	 */
	@Override
	protected Cipher getDecryptCipher()
	{
		throw new UnsupportedOperationException("This method should never be called.");
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.github.chuckbuckethead.cypher.keys.AbstractCryptoKey#decryptBytes(java.lang
	 * .String)
	 */
	@Override
	public synchronized byte[] decryptBytes(String base64Str)
	{
		byte[] bytes = null;

		try
		{
			byte[] dec = getEncoder().decode(base64Str);

			// Decrypt
			bytes = getRSADecryptCipher().processBlock(dec, 0, dec.length);
		}
		catch (InvalidCipherTextException e)
		{
			e.printStackTrace();
		}

		return bytes;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.github.chuckbuckethead.cypher.keys.AbstractCryptoKey#encryptBytes(byte[])
	 */
	@Override
	public synchronized String encryptBytes(byte[] bytes)
	{
		String encryptedStr = null;

		try
		{
			// Encrypt
			byte[] enc = getRSAEncryptCipher().processBlock(bytes, 0,
					bytes.length);

			// Encode bytes to base64 to get a string
			encryptedStr = getEncoder().encode(enc);
		}
		catch (InvalidCipherTextException e)
		{
			e.printStackTrace();
		}

		return encryptedStr;
	}


	/**
	 * @return an RSA decryption cipher
	 */
	protected synchronized AsymmetricBlockCipher getRSADecryptCipher()
	{
		if (decodeCipher == null)
		{
			try
			{
				byte[] bytes = getEncoder().decode(privateKey);
				EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytes);

				KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
				PrivateKey key = keyFactory.generatePrivate(privateKeySpec);

				this.decodeCipher = new PKCS1Encoding(new RSABlindedEngine());
				decodeCipher.init(false, generatePrivateKeyParameter((RSAPrivateKey) key));
			}
			catch (Exception e)
			{
				throw new RuntimeException("Error constructing Cipher: ", e);
			}
		}

		return decodeCipher;
	}


	/**
	 * @param key
	 * @return
	 */
	private static RSAKeyParameters generatePrivateKeyParameter(
			RSAPrivateKey key)
	{
		RSAKeyParameters parameters = null;

		if (key instanceof RSAPrivateCrtKey)
		{
			RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) key;
			parameters = new RSAPrivateCrtKeyParameters(crtKey.getModulus(),
					crtKey.getPublicExponent(), crtKey.getPrivateExponent(),
					crtKey.getPrimeP(), crtKey.getPrimeQ(),
					crtKey.getPrimeExponentP(), crtKey.getPrimeExponentQ(),
					crtKey.getCrtCoefficient());
		}
		else
		{
			parameters = new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());
		}

		return parameters;
	}


	/**
	 * @return
	 */
	protected synchronized AsymmetricBlockCipher getRSAEncryptCipher()
	{
		if (encodeCipher == null)
		{
			try
			{
				byte[] bytes = getEncoder().decode(publicKey);
				EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytes);

				KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
				PublicKey key = keyFactory.generatePublic(publicKeySpec);

				this.encodeCipher = new PKCS1Encoding(new RSABlindedEngine());
				encodeCipher.init(true, generatePublicKeyParameter((RSAPublicKey) key));
			}
			catch (Exception e)
			{
				throw new RuntimeException("Error constructing Cipher: ", e);
			}
		}

		return encodeCipher;
	}


	/**
	 * @param key
	 * @return
	 */
	private static RSAKeyParameters generatePublicKeyParameter(RSAPublicKey key)
	{
		return new RSAKeyParameters(false, key.getModulus(), key.getPublicExponent());
	}
}