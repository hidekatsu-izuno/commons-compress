/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.commons.compress.archivers.zip;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.apache.commons.compress.archivers.zip.UnsupportedZipFeatureException.Feature;

public abstract class Encrypter {
    private static final Random RANDOM;

    static {
        try {
            RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Encrypter createEncrypter(ZipEncryptionAlgorithm encryptionAlgorithm, String password)
            throws UnsupportedZipFeatureException {
        switch (encryptionAlgorithm) {
            case STANDARD:
                return new ZipCryptEncrypter(password);
            default:
                throw new UnsupportedZipFeatureException(Feature.ENCRYPTION);
        }
    }

    public byte[] header(ZipArchiveEntry entry) {
        return null;
    }

    public abstract int encrypt(final byte[] data, final int offset, final int length);

    public byte[] footer() {
        return null;
    }

    public abstract void reset();

    protected static class ZipCryptEncrypter extends Encrypter {
        private static final int[] CRC32_TABLE = new int[256];

        static {
            for (int div = 0; div < CRC32_TABLE.length; div++) {
                int remainder = div;
                for (int i = 0; i < 8; i++) {
                    if ((remainder & 1) == 1) {
                        remainder = (remainder >>> 1) ^ 0xEDB88320;
                    } else {
                        remainder = (remainder >>> 1);
                    }
                }
                CRC32_TABLE[div] = remainder;
            }
        }
        
        public static int crc32(final int oldCrc, final byte ch) {
            return (oldCrc >>> 8) ^ CRC32_TABLE[(oldCrc ^ ch) & 0xff];
        }

        private final int[] initKeys;

        private int[] keys = { 305419896, 591751049, 878082192 };

        public ZipCryptEncrypter(String password) {
            for (int i = 0; i < password.length(); i++) {
                updateKeys((byte) (password.charAt(i) & 0xff));
            }

            initKeys = Arrays.copyOf(keys, keys.length);
        }

        @Override
        public byte[] header(ZipArchiveEntry entry) {
            byte[] header = new byte[12];
            RANDOM.nextBytes(header);
            encrypt(header, 0, header.length);

            long crc = entry.getCrc();
            if (crc == -1) {
                byte[] dosTime = ZipUtil.toDosTime(entry.getTime());
                header[10] = dosTime[2];
                header[11] = dosTime[1];
            } else {
                header[10] = (byte) (crc >> 16 & 0xFF);
                header[11] = (byte) (crc >> 24 & 0xFF);
            }

            reset();
            encrypt(header, 0, header.length);
            return header;
        }

        @Override
        public int encrypt(byte[] data, int offset, int length) {
            for (int i = offset; i < offset + length; i++) {
                byte b = (byte) (data[i] ^ decryptByte() & 0xff);
                updateKeys(data[i]);
                data[i] = b;
            }
            return -1;
        }

        private void updateKeys(byte b) {
            keys[0] = crc32(keys[0], b);
            keys[1] += keys[0] & 0xff;
            keys[1] = keys[1] * 134775813 + 1;
            keys[2] = crc32(keys[2], (byte) (keys[1] >> 24));
        }

        private byte decryptByte() {
            int temp = keys[2] | 2;
            return (byte) ((temp * (temp ^ 1)) >>> 8);
        }

        @Override
        public void reset() {
            System.arraycopy(initKeys, 0, keys, 0, initKeys.length);
        }
    }
}