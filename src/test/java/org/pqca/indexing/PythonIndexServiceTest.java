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
package org.pqca.indexing;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.pqca.errors.ClientDisconnected;
import org.pqca.indexing.python.PythonIndexService;

class PythonIndexServiceTest {
    @Test
    void testDefaultExclusion() throws ClientDisconnected {
        final PythonIndexService pythonIndexService = new PythonIndexService(new File("."));
        final List<ProjectModule> projectModules = pythonIndexService.index(null);
        assertThat(projectModules).hasSize(0);
    }

    @Test
    void testNoExclusion() throws ClientDisconnected {
        final PythonIndexService pythonIndexService = new PythonIndexService(new File("."));
        pythonIndexService.setExcludePatterns(List.of());
        final List<ProjectModule> projectModules = pythonIndexService.index(null);
        assertThat(projectModules).hasSize(1);
        final ProjectModule projectModule = projectModules.getFirst();
        assertThat(projectModule.inputFileList()).hasSize(1);
    }
}
