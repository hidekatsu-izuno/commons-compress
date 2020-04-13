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

public enum ZipEncryptionAlgorithm {
    STANDARD(0),
    DES(0x6601),
    TDES_168(0x6603),
    TDES_112(0x6609),
    AES_128(0x660E),
    AES_196(0x660F),
    AES_256(0x6610),
    RC2(0x6702),
    BLOWFISH(0x6720),
    TWOFISH(0x6721),
    RC4(0x6801);

    private final int algId;

    ZipEncryptionAlgorithm(int algId) {
        this.algId = algId;
    }

    public int getAlgId() {
        return this.algId;
    }
}