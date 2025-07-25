/*
 * CBOMkit-lib
 * Copyright (C) 2024 PQCA
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
package org.pqca.indexing.java;

import jakarta.annotation.Nonnull;
import java.io.File;
import java.util.List;
import javax.annotation.Nullable;
import org.pqca.indexing.IBuildType;
import org.pqca.indexing.IndexingService;
import org.pqca.progress.IProgressDispatcher;

public final class JavaIndexService extends IndexingService {

    public JavaIndexService(@Nonnull File baseDirectory) {
        this(null, baseDirectory);
    }

    public JavaIndexService(
            @Nullable IProgressDispatcher progressDispatcher, @Nonnull File baseDirectory) {
        super(progressDispatcher, baseDirectory, "java", ".java");
        this.setExcludePatterns(null);
    }

    public void setExcludePatterns(@Nullable List<String> patterns) {
        if (patterns == null) {
            super.setExcludePatterns(
                    List.of("src/test/", "/package-info.java$", "/module-info.java$"));
        } else {
            super.setExcludePatterns(patterns);
        }
    }

    @Override
    public boolean isModule(@Nonnull File directory) {
        if (!directory.isDirectory()) {
            return false;
        }
        final File srcFolder = new File(directory, "src");
        for (String buildFileName : List.of("pom.xml", "build.gradle", "build.gradle.kts")) {
            final File file = new File(directory, buildFileName);
            if (file.exists() && file.isFile() && srcFolder.exists()) {
                return true;
            }
        }
        return false;
    }

    @Override
    @Nullable public IBuildType getMainBuildTypeFromModuleDirectory(@Nonnull File directory) {
        if (!directory.isDirectory()) {
            return null;
        }
        // maven
        final File pomFile = new File(directory, "pom.xml");
        if (pomFile.exists() && pomFile.isFile()) {
            return JavaBuildType.MAVEN;
        }
        // gradle
        for (String gradleFileName : List.of("build.gradle", "build.gradle.kts")) {
            final File gradleFile = new File(directory, gradleFileName);
            if (gradleFile.exists() && gradleFile.isFile()) {
                return JavaBuildType.GRADLE;
            }
        }
        return null;
    }
}
