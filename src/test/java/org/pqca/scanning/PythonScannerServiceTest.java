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

import java.io.File;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.pqca.errors.ClientDisconnected;
import org.pqca.indexing.ProjectModule;
import org.pqca.indexing.python.PythonIndexService;
import org.pqca.scanning.python.PythonScannerService;
import org.pqca.utils.AssertableCBOM;

class PythonScannerServiceTest {

    @Test
    void test() throws ClientDisconnected {
        // indexing
        final File projectDirectory = new File("src/test/testdata/python/pyca");
        final PythonIndexService pythonIndexService = new PythonIndexService(projectDirectory);
        final List<ProjectModule> projectModules = pythonIndexService.index(null);
        assertThat(projectModules).hasSize(1);
        final ProjectModule projectModule = projectModules.getFirst();
        assertThat(projectModule.inputFileList()).hasSize(1);
        // scanning
        final PythonScannerService pythonScannerService =
                new PythonScannerService(projectDirectory);
        ScanResultDTO scanResult = pythonScannerService.scan(projectModules);

        // check
        AssertableCBOM assertableCBOM = new AssertableCBOM(scanResult.cbom());
        assertableCBOM.hasNumberOfDetections(5);

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "SHA256", "src/test/testdata/python/pyca/generate_key.py", 4))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "AES128-CBC-PKCS7",
                                "src/test/testdata/python/pyca/generate_key.py",
                                4))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "HMAC-SHA256", "src/test/testdata/python/pyca/generate_key.py", 4))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "Fernet", "src/test/testdata/python/pyca/generate_key.py", 4))
                .isTrue();

        assertThat(
                        assertableCBOM.hasDetectionWithNameAt(
                                "secret-key", "src/test/testdata/python/pyca/generate_key.py", 4))
                .isTrue();
    }
}
