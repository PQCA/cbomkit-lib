/*
 * CBOMkit-lib
 * Copyright (C) 2025 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pqca.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.pqca.errors.ClientDisconnected;
import org.pqca.indexing.ProjectModule;
import org.pqca.indexing.java.JavaIndexService;
import org.pqca.scanning.java.JavaScannerService;
import org.pqca.utils.AssertableCBOM;

class JavaScannerServiceTest {

    @Test
    void test() throws ClientDisconnected {
        final File projectDirectory = new File("src/test/testdata/java/keycloak");
        final JavaIndexService javaIndexService = new JavaIndexService(projectDirectory);
        // indexing
        final List<ProjectModule> projectModules = javaIndexService.index(null);
        assertThat(projectModules).hasSize(2);
        for (final ProjectModule projectModule : projectModules) {
            if (projectModule.identifier().equals("crypto/default")) {
                assertThat(projectModule.inputFileList()).hasSize(13);
            } else if (projectModule.identifier().equals("services")) {
                assertThat(projectModule.inputFileList()).hasSize(18);
            }
        }
        // scanning
        final JavaScannerService javaScannerService = new JavaScannerService(projectDirectory);
        javaScannerService.addJavaDependencyJar("src/test/resources/java/scan");
        javaScannerService.setRequireBuild(false);
        ScanResultDTO scanResult = javaScannerService.scan(projectModules);

        // check
        AssertableCBOM assertableCBOM = new AssertableCBOM(scanResult.cbom());
        assertableCBOM.hasNumberOfDetections(14);

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "AES",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCEcdhEsAlgorithmProvider.java",
                                86))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "AES",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCEcdhEsAlgorithmProvider.java",
                                119))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "key",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCEcdhEsAlgorithmProvider.java",
                                132))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "EC",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCEcdhEsAlgorithmProvider.java",
                                132))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "ConcatenationKDF",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCEcdhEsAlgorithmProvider.java",
                                157))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "public-key",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCEcdhEsAlgorithmProvider.java",
                                199))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "EC",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCEcdhEsAlgorithmProvider.java",
                                199))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "ECDH",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCEcdhEsAlgorithmProvider.java",
                                208))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "public-key",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCECDSACryptoProvider.java",
                                80))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "EC",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/BCECDSACryptoProvider.java",
                                80))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "AES",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/AesKeyWrapAlgorithmProvider.java",
                                38))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "AES",
                                "src/test/testdata/java/keycloak/crypto/default/src/main/java/org/keycloak/crypto/def/AesKeyWrapAlgorithmProvider.java",
                                45))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "TLS",
                                "src/test/testdata/java/keycloak/services/src/main/java/org/keycloak/connections/httpclient/HttpClientBuilder.java",
                                234))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "TLS",
                                "src/test/testdata/java/keycloak/services/src/main/java/org/keycloak/connections/httpclient/HttpClientBuilder.java",
                                245))
                .isTrue();
    }

    @Test
    void testRequireBuildException() throws ClientDisconnected {
        final File projectDirectory = new File("src/test/testdata/java/plain");
        final JavaIndexService javaIndexService = new JavaIndexService(projectDirectory);

        final List<ProjectModule> projectModules = javaIndexService.index(null);
        final JavaScannerService javaScannerService = new JavaScannerService(projectDirectory);
        javaScannerService.setRequireBuild(true);

        assertThatIllegalStateException()
                .isThrownBy(() -> javaScannerService.scan(projectModules))
                .withMessage(
                        "No Java build artifacts found. Project must be built prior to scanning");
    }

    @Test
    void testRequireBuildTrue() throws ClientDisconnected {
        final File projectDirectory = new File("src/test/testdata/java/plain");
        final JavaIndexService javaIndexService = new JavaIndexService(projectDirectory);

        final List<ProjectModule> projectModules = javaIndexService.index(null);
        final JavaScannerService javaScannerService = new JavaScannerService(projectDirectory);
        javaScannerService.setRequireBuild(true);
        javaScannerService.addJavaDependencyJar(projectDirectory.getAbsolutePath());
        javaScannerService.scan(projectModules);

        ScanResultDTO scanResult = javaScannerService.scan(projectModules);
        AssertableCBOM assertableCBOM = new AssertableCBOM(scanResult.cbom());
        assertableCBOM.hasNumberOfDetections(1);
    }

    @Test
    void testRequireBuildFalse() throws ClientDisconnected {
        final File projectDirectory = new File("src/test/testdata/java/plain");
        final JavaIndexService javaIndexService = new JavaIndexService(projectDirectory);

        final List<ProjectModule> projectModules = javaIndexService.index(null);
        final JavaScannerService javaScannerService = new JavaScannerService(projectDirectory);
        javaScannerService.setRequireBuild(false);
        javaScannerService.scan(projectModules);

        ScanResultDTO scanResult = javaScannerService.scan(projectModules);
        AssertableCBOM assertableCBOM = new AssertableCBOM(scanResult.cbom());
        assertableCBOM.hasNumberOfDetections(1);
    }

    @Test
    void testNoJavaProjects() throws ClientDisconnected {
        final File projectDirectory = new File("src/test/testdata/java/plain");
        final List<ProjectModule> projectModules = new ArrayList<ProjectModule>();
        final JavaScannerService javaScannerService = new JavaScannerService(projectDirectory);
        javaScannerService.setRequireBuild(true);

        ScanResultDTO scanResult = javaScannerService.scan(projectModules);
        AssertableCBOM assertableCBOM = new AssertableCBOM(scanResult.cbom());
        assertableCBOM.hasNumberOfDetections(0);
    }
}
