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
import com.google.common.base.Objects;
import com.ibm.mapper.model.INode;
import com.ibm.output.IOutputFileFactory;
import com.ibm.output.cyclondx.CBOMOutputFile;
import com.ibm.output.cyclondx.CBOMOutputFileFactory;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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
    @Nonnull Set<Integer> findings;

    protected ScannerService(
            @Nullable IProgressDispatcher progressDispatcher, @Nonnull File projectDirectory) {
        this.progressDispatcher = progressDispatcher;
        this.projectDirectory = projectDirectory;
        this.findings = new HashSet<Integer>();
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
                                    List<Occurrence> deduplicated = deduplicateFindings(component);
                                    if (!deduplicated.isEmpty()) {
                                        final Component newComponent =
                                                ScannerService.copyCryptoAsset(component);
                                        final Evidence newEvidence = new Evidence();
                                        newEvidence.setOccurrences(deduplicated);
                                        newComponent.setEvidence(newEvidence);

                                        ScannerService.sanitizeOccurrence(
                                                this.projectDirectory, newComponent);
                                        try {
                                            this.progressDispatcher.send(
                                                    new ProgressMessage(
                                                            ProgressMessageType.DETECTION,
                                                            new ObjectMapper()
                                                                    .writeValueAsString(
                                                                            newComponent)));
                                        } catch (JsonProcessingException | ClientDisconnected e) {
                                            LOGGER.error(e.getMessage());
                                        }
                                    }
                                });
            }
        }
    }

    // Fix for #268: A finding is a cryptoProperties object at a particular
    // location.
    // A single component may therefore represent multiple findings.
    // Subsequent calls to accept may produce duplicate findings in different
    // components.
    @Nonnull
    private List<Occurrence> deduplicateFindings(@Nonnull Component component) {
        List<Occurrence> deduplicated = new ArrayList<Occurrence>();
        component
                .getEvidence()
                .getOccurrences()
                .forEach(
                        occurrence -> {
                            int findingId =
                                    Objects.hashCode(
                                            component.getName(),
                                            occurrence.getLocation(),
                                            occurrence.getLine(),
                                            occurrence.getOffset());
                            if (!this.findings.contains(findingId)) {
                                deduplicated.add(occurrence);
                                this.findings.add(findingId);
                            }
                        });
        return deduplicated;
    }

    @Nonnull
    private static Component copyCryptoAsset(@Nonnull Component component) {
        final Component newComponent = new Component();
        newComponent.setBomRef(component.getBomRef());
        ;
        newComponent.setName(component.getName());
        newComponent.setType(component.getType());
        newComponent.setCryptoProperties(component.getCryptoProperties());
        return newComponent;
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
