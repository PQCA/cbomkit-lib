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
package org.pqca.scanning.java;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.pqca.errors.ClientDisconnected;
import org.pqca.indexing.ProjectModule;
import org.pqca.progress.IProgressDispatcher;
import org.pqca.progress.ProgressMessage;
import org.pqca.progress.ProgressMessageType;
import org.pqca.scanning.CBOM;
import org.pqca.scanning.ScanResultDTO;
import org.pqca.scanning.ScannerService;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.DefaultFileSystem;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.api.config.internal.MapSettings;
import org.sonar.api.measures.FileLinesContext;
import org.sonar.api.measures.FileLinesContextFactory;
import org.sonar.java.DefaultJavaResourceLocator;
import org.sonar.java.JavaFrontend;
import org.sonar.java.SonarComponents;
import org.sonar.java.classpath.ClasspathForMain;
import org.sonar.java.classpath.ClasspathForTest;
import org.sonar.java.model.JavaVersionImpl;
import org.sonar.plugins.java.api.JavaResourceLocator;
import org.sonar.plugins.java.api.JavaVersion;

public final class JavaScannerService extends ScannerService {

    private static final JavaVersion JAVA_VERSION =
            new JavaVersionImpl(JavaVersionImpl.MAX_SUPPORTED);

    private String javaDependencyJars = null;
    private String targetClassDirectories = null;
    private boolean requireBuild = true;

    public JavaScannerService(@Nonnull File projectDirectory) {
        this(null, projectDirectory);
    }

    public JavaScannerService(
            @Nullable IProgressDispatcher progressDispatcher, @Nonnull File projectDirectory) {
        super(progressDispatcher, projectDirectory);

        // this.javaDependencyJars = findJars();
        // this.targetClassDirectories = findClassDirs();
    }

    public String getJavaDependencyJars() {
        return this.javaDependencyJars;
    }

    // Sonar needs absolute paths. This adapts the path part in a list of glob patterns.
    public void setJavaDependencyJars(String javaDependencyJars) {
        this.javaDependencyJars =
                javaDependencyJars == null
                        ? null
                        : Arrays.stream(javaDependencyJars.split("\\s*,\\s*"))
                                .map(
                                        pattern -> {
                                            int globIdx = indexOfFirstGlobChar(pattern);
                                            String pathPart =
                                                    globIdx >= 0
                                                            ? pattern.substring(0, globIdx)
                                                            : pattern;
                                            String globPart =
                                                    globIdx >= 0 ? pattern.substring(globIdx) : "";
                                            Path absPath =
                                                    Paths.get(pathPart)
                                                            .toAbsolutePath()
                                                            .normalize();
                                            return absPath.toString() + globPart;
                                        })
                                .collect(Collectors.joining(","));
    }

    private static int indexOfFirstGlobChar(String pattern) {
        int minIdx = -1;
        for (char c : new char[] {'*', '?', '[', '{'}) {
            int idx = pattern.indexOf(c);
            if (idx != -1 && (minIdx == -1 || idx < minIdx)) {
                minIdx = idx;
            }
        }
        return minIdx;
    }

    public String getJavaClassDirs() {
        return this.targetClassDirectories;
    }

    // Sonar needs absolute paths. This adapts a list of directories.
    public void setJavaClassDirs(String targetClassDirectories) {
        this.targetClassDirectories =
                targetClassDirectories == null
                        ? null
                        : Arrays.stream(targetClassDirectories.split("\\s*,\\s*"))
                                .map(dir -> Paths.get(dir).toAbsolutePath().normalize().toString())
                                .collect(Collectors.joining(","));
    }

    public boolean getRequireBuild() {
        return this.requireBuild;
    }

    public void setRequireBuild(boolean requireBuild) {
        this.requireBuild = requireBuild;
    }

    @Override
    @Nonnull
    public synchronized ScanResultDTO scan(@Nonnull List<ProjectModule> index)
            throws ClientDisconnected {
        // if (javaDependencyJars == null && targetClassDirectories == null) {
        //     if (requireBuild) {
        //         throw new IllegalStateException(
        //                 "No Java build artifacts found. Propject must be build prior to
        // scanning");
        //     } else {
        //         LOG.warn(
        //                 "No Java build artifacts found. Scanning Java code without prior build
        // may produce less accurate CBOMs.");
        //     }
        // }

        final SensorContextTester sensorContext = SensorContextTester.create(projectDirectory);
        sensorContext.setSettings(
                new MapSettings()
                        .setProperty(SonarComponents.SONAR_BATCH_MODE_KEY, true)
                        // .setProperty("sonar.java.jdkHome", System.getProperty("java.home"))
                        .setProperty("sonar.java.libraries", javaDependencyJars)
                        .setProperty("sonar.java.binaries", targetClassDirectories)
                        .setProperty(SonarComponents.SONAR_AUTOSCAN, false)
                        .setProperty(SonarComponents.SONAR_BATCH_SIZE_KEY, 8 * 1024 * 1024));
        final DefaultFileSystem fileSystem = sensorContext.fileSystem();
        final ClasspathForMain classpathForMain =
                new ClasspathForMain(sensorContext.config(), fileSystem);
        final ClasspathForTest classpathForTest =
                new ClasspathForTest(sensorContext.config(), fileSystem);
        final SonarComponents sonarComponents =
                getSonarComponents(fileSystem, classpathForMain, classpathForTest);
        sonarComponents.setSensorContext(sensorContext);
        LOGGER.info("Start scanning {} java projects", index.size());

        final JavaResourceLocator javaResourceLocator =
                new DefaultJavaResourceLocator(classpathForMain, classpathForTest);
        final JavaFrontend javaFrontend =
                new JavaFrontend(
                        JAVA_VERSION,
                        sonarComponents,
                        null,
                        javaResourceLocator,
                        null,
                        new JavaDetectionCollectionRule(this));

        long scanTimeStart = System.currentTimeMillis();
        int counter = 1;
        int numberOfScannedLines = 0;
        int numberOfScannedFiles = 0;
        for (ProjectModule project : index) {
            numberOfScannedFiles += project.inputFileList().size();
            numberOfScannedLines +=
                    project.inputFileList().stream().map(InputFile::lines).reduce(0, Integer::sum);

            final String projectStr =
                    project.identifier() + " (" + counter + "/" + index.size() + ")";
            if (this.progressDispatcher != null) {
                this.progressDispatcher.send(
                        new ProgressMessage(
                                ProgressMessageType.LABEL, "Scanning java project " + projectStr));
            }
            LOGGER.info("Scanning java project {}", projectStr);
            javaFrontend.scan(project.inputFileList(), List.of(), List.of());
            counter++;
        }
        LOGGER.info("Scanned {} java projects", index.size());

        return new ScanResultDTO(
                scanTimeStart,
                System.currentTimeMillis(),
                numberOfScannedLines,
                numberOfScannedFiles,
                this.getBOM().map(CBOM::new).orElse(null));
    }

    @Nonnull
    private static SonarComponents getSonarComponents(
            DefaultFileSystem fileSystem,
            ClasspathForMain classpathForMain,
            ClasspathForTest classpathForTest) {
        final FileLinesContextFactory fileLinesContextFactory =
                inputFile ->
                        new FileLinesContext() {
                            @Override
                            public void setIntValue(@Nonnull String s, int i, int i1) {
                                // nothing
                            }

                            @Override
                            public void setStringValue(
                                    @Nonnull String s, int i, @Nonnull String s1) {
                                // nothing
                            }

                            @Override
                            public void save() {
                                // nothing
                            }
                        };
        return new SonarComponents(
                fileLinesContextFactory,
                fileSystem,
                classpathForMain,
                classpathForTest,
                null,
                null);
    }

    // private String findClassDirs() {
    //     try (Stream<Path> stream = Files.walk(this.projectDirectory.toPath())) {
    //         return String.join(
    //                 ",",
    //                 stream.filter(Files::isDirectory)
    //                         .filter(path -> path.endsWith("classes"))
    //                         .map(path -> path.toAbsolutePath().toString())
    //                         .collect(Collectors.joining(",")));
    //     } catch (Exception e) {
    //         return null;
    //     }
    // }

    // private String findJars() {
    //     try (Stream<Path> stream = Files.walk(this.projectDirectory.toPath())) {
    //         return String.join(
    //                 ",",
    //                 stream.filter(Files::isRegularFile)
    //                         .filter(path -> path.toString().toLowerCase().endsWith(".jar"))
    //                         .map(path -> path.toAbsolutePath().toString())
    //                         .collect(Collectors.joining(",")));
    //     } catch (Exception e) {
    //         return null;
    //     }
    // }
}
