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
package org.pqca;

import java.io.File;
import java.util.List;
import org.pqca.indexing.ProjectModule;
import org.pqca.indexing.java.JavaIndexService;
import org.pqca.scanning.ScanResultDTO;
import org.pqca.scanning.java.JavaScannerService;

public class Main {
    public static void main(String[] args) throws Exception {
        final File projectDirectory = new File("src/test/testdata/java/keycloak");
        final JavaIndexService javaIndexService = new JavaIndexService(projectDirectory);
        javaIndexService.setFileExcluder(f -> false);
        // indexing
        final List<ProjectModule> projectModules = javaIndexService.index(null);
        // scanning
        final JavaScannerService javaScannerService = new JavaScannerService(projectDirectory);
        javaScannerService.setJavaDependencyJars(
                "/Users/san/oss/cbomkit-lib/src/test/resources/java/scan");
        javaScannerService.setRequireBuild(false);
        ScanResultDTO scanResult = javaScannerService.scan(projectModules);
        System.out.println(
                scanResult.cbom().cycloneDXbom().getComponents().stream()
                        .mapToInt(component -> component.getEvidence().getOccurrences().size())
                        .sum());
    }
}
