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
package org.pqca.scanning;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.mapper.model.INode;
import com.ibm.output.IOutputFileFactory;
import com.ibm.output.cyclondx.CBOMOutputFile;
import com.ibm.output.cyclondx.CBOMOutputFileFactory;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.pqca.errors.ClientDisconnected;
import org.pqca.progress.IProgressDispatcher;
import org.pqca.progress.ProgressMessage;
import org.pqca.progress.ProgressMessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class ScannerService implements IScannerService {
    protected static final Logger LOGGER = LoggerFactory.getLogger(ScannerService.class);

    @Nullable protected final IProgressDispatcher progressDispatcher;
    @Nonnull protected final File projectDirectory;
    @Nonnull protected final CBOMOutputFile cbomOutputFile;

    protected ScannerService(
            @Nullable IProgressDispatcher progressDispatcher, @Nonnull File projectDirectory) {
        this.progressDispatcher = progressDispatcher;
        this.projectDirectory = projectDirectory;
        this.cbomOutputFile = new CBOMOutputFile();
    }

    @Override
    public void accept(@Nonnull final List<INode> nodes) {
        synchronized (this) {
            this.cbomOutputFile.add(nodes);
            if (this.progressDispatcher != null) {
                final CBOMOutputFileFactory fileFactory = new CBOMOutputFileFactory();
                final CBOMOutputFile componentAsCBOM = fileFactory.createOutputFormat(nodes);
                componentAsCBOM
                        .getBom()
                        .getComponents()
                        .forEach(
                                component -> {
                                    ScannerService.sanitizeOccurrence(
                                            this.projectDirectory, component);
                                    try {
                                        this.progressDispatcher.send(
                                                new ProgressMessage(
                                                        ProgressMessageType.DETECTION,
                                                        new ObjectMapper()
                                                                .writeValueAsString(component)));
                                    } catch (JsonProcessingException | ClientDisconnected e) {
                                        LOGGER.error(e.getMessage());
                                    }
                                });
            }
        }
    }

    @Nonnull
    protected synchronized Optional<Bom> getBOM() {
        final Bom bom = this.cbomOutputFile.getBom();
        // sanitizeOccurrence
        bom.getComponents().forEach(component -> sanitizeOccurrence(projectDirectory, component));
        // reset scanner
        final com.ibm.plugin.ScannerManager scannerMgr =
                new com.ibm.plugin.ScannerManager(IOutputFileFactory.DEFAULT);
        scannerMgr.reset();

        return Optional.of(bom);
    }

    public static void sanitizeOccurrence(
            @Nonnull final File baseDirectory, @Nonnull Component component) {
        List<Occurrence> occurrenceList =
                Optional.ofNullable(component.getEvidence())
                        .map(Evidence::getOccurrences)
                        .orElse(Collections.emptyList());

        if (occurrenceList.isEmpty()) {
            return;
        }
        try {
            final String baseDirPath = baseDirectory.getCanonicalPath();
            occurrenceList.forEach(
                    occurrence -> {
                        if (occurrence.getLocation().startsWith(baseDirPath)) {
                            occurrence.setLocation(
                                    occurrence.getLocation().substring(baseDirPath.length() + 1));
                        }
                    });
        } catch (IOException ioe) {
            // noting
        }
    }
}
