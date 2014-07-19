# Cypher

A general-purpose, easy-to-use wrapper of the Bouncy Castle cryptography API.

# Install

Use the following dependency in your project:

```xml
<dependency>
	<groupId>com.github.chuckbuckethead</groupId>
	<artifactId>cypher</artifactId>
	<version>0.1.0</version>
</dependency>
```

# Usage

Cypher exports both asymmectric and symmetric encryption/decryption capabilities via a simple API. The `Cypher` class serves as point of entry.

## Asymmetric encryption

```java
package com.github.chuckbuckethead.cypher.usage;

import com.github.chuckbuckethead.cypher.Cypher;

public class Usage {
  
  public static void main(String... args)
  {
    String phrase = "github";
    RSAKey key = Cypher.generateRSAKey(1024);
    
    System.out.println("public_key:" + key.getPublicKey());
    System.out.println("private_key:" + key.getPrivateKey());
    
    // Encrypt the phrase
    String encryptedPhrase = key.encrypt(phrase);
    System.out.println("encrypted_phrase:" + encryptedPhrase);
    
    // Print the decrypted phrase
    System.out.println("original_phrase:" + key.decrypt(encryptedPhrase));
  }
}
```

## Symmetric encryption

```java
package com.github.chuckbuckethead.cypher.usage;

import com.github.chuckbuckethead.cypher.Cypher;

public class Usage {
  
  public static void main(String... args)
  {
    String phrase = "github";
    BlowfishKey key = Cypher.generateBlowfishKey(128);
    
    System.out.println("key:" + key.getKey());
    
    // Encrypt the phrase
    String encryptedPhrase = key.encrypt(phrase);
    System.out.println("encrypted_phrase:" + encryptedPhrase);
    
    // Print the decrypted phrase
    System.out.println("original_phrase:" + key.decrypt(encryptedPhrase));
  }
}
```

# License

The MIT License (MIT)

Copyright (c) 2014 Carlos González

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
