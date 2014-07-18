/*
 * Copyright (C) 2004 Joe Walnes.
 * Copyright (C) 2006, 2007 XStream Committers.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 * 
 * 3. Neither the name of XStream nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * 
 * Created on 06. August 2004 by Joe Walnes
 */
package com.thoughtworks.xstream.core.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

/**
 * Encodes binary data to plain text as Base64.
 *
 * <p>Despite there being a gazillion other Base64 implementations out there, this has been written as part of XStream as
 * it forms a core part but is too trivial to warrant an extra dependency.</p>
 *
 * <p>This meets the standard as described in RFC 1521, section 5.2 <http://www.freesoft.org/CIE/RFC/1521/7.htm>, allowing
 * other Base64 tools to manipulate the data.</p>
 *
 * @author Joe Walnes
 */
public class Base64Encoder {

    // Here's how encoding works:
    //
    // 1) Incoming bytes are broken up into groups of 3 (each byte having 8 bits).
    //
    // 2) The combined 24 bits (3 * 8) are split into 4 groups of 6 bits.
    //
    // input  |------||------||------| (3 values each with 8 bits)
    //        101010101010101010101010
    // output |----||----||----||----| (4 values each with 6 bits)
    //
    // 3) Each of these 4 groups of 6 bits are converted back to a number, which will fall in the range of 0 - 63.
    //
    // 4) Each of these 4 numbers are converted to an alphanumeric char in a specified mapping table, to create
    //    a 4 character string.
    //
    // 5) This is repeated for all groups of three bytes.
    //
    // 6) Special padding is done at the end of the stream using the '=' char.

    private static final char[] SIXTY_FOUR_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
    private static final int[] REVERSE_MAPPING = new int[123];

    static {
        for (int i = 0; i < SIXTY_FOUR_CHARS.length; i++) REVERSE_MAPPING[SIXTY_FOUR_CHARS[i]] = i + 1;
    }

    public String encode(byte[] input) {
        StringBuffer result = new StringBuffer();
        int outputCharCount = 0;
        for (int i = 0; i < input.length; i += 3) {
            int remaining = Math.min(3, input.length - i);
            int oneBigNumber = (input[i] & 0xff) << 16 | (remaining <= 1 ? 0 : input[i + 1] & 0xff) << 8 | (remaining <= 2 ? 0 : input[i + 2] & 0xff);
            for (int j = 0; j < 4; j++) result.append(remaining + 1 > j ? SIXTY_FOUR_CHARS[0x3f & oneBigNumber >> 6 * (3 - j)] : '=');
            if ((outputCharCount += 4) % 76 == 0) result.append('\n');
        }
        return result.toString();
    }

    public byte[] decode(String input) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            StringReader in = new StringReader(input);
            for (int i = 0; i < input.length(); i += 4) {
                int a[] = {mapCharToInt(in), mapCharToInt(in), mapCharToInt(in), mapCharToInt(in)};
                int oneBigNumber = (a[0] & 0x3f) << 18 | (a[1] & 0x3f) << 12 | (a[2] & 0x3f) << 6 | (a[3] & 0x3f);
                for (int j = 0; j < 3; j++) if (a[j + 1] >= 0) out.write(0xff & oneBigNumber >> 8 * (2 - j));
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new Error(e + ": " + e.getMessage());
        }
    }

    private int mapCharToInt(Reader input) throws IOException {
        int c;
        while ((c = input.read()) != -1) {
            int result = REVERSE_MAPPING[c];
            if (result != 0) return result -1;
            if (c == '=') return -1;
        }
        return -1;
    }
}
