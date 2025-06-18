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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.Nonnull;
import java.nio.file.Path;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.Service;
import org.cyclonedx.model.metadata.ToolInformation;
import org.pqca.errors.CBOMSerializationFailed;

public record CBOM(@Nonnull Bom cycloneDXbom) {
    private static final String ACTION_NAME = "CBOMkit";
    private static final String ACTION_ORG = "PQCA";

    public void merge(@Nonnull CBOM cbom) {
        // components
        Optional.ofNullable(this.cycloneDXbom.getComponents())
                .ifPresent(
                        components -> {
                            if (cbom.cycloneDXbom().getComponents() != null) {
                                components.addAll(cbom.cycloneDXbom.getComponents());
                            }
                        });
        // dependencies
        Optional.ofNullable(this.cycloneDXbom.getDependencies())
                .ifPresent(
                        dependencies -> {
                            if (cbom.cycloneDXbom().getDependencies() != null) {
                                dependencies.addAll(cbom.cycloneDXbom.getDependencies());
                            }
                        });
    }

    public static @Nonnull CBOM formJSON(@Nonnull JsonNode jsonNode)
            throws CBOMSerializationFailed {
        try {
            final ObjectMapper mapper = new ObjectMapper();
            return new CBOM(mapper.treeToValue(jsonNode, Bom.class));
        } catch (JsonProcessingException e) {
            throw new CBOMSerializationFailed();
        }
    }

    public @Nonnull JsonNode toJSON() throws CBOMSerializationFailed {
        try {
            final ObjectMapper mapper = new ObjectMapper();
            final BomJsonGenerator bomGenerator =
                    BomGeneratorFactory.createJson(Version.VERSION_16, cycloneDXbom);
            return mapper.readTree(bomGenerator.toJsonString());
        } catch (JsonProcessingException | GeneratorException e) {
            throw new CBOMSerializationFailed();
        }
    }

    public void addMetadata(
            @Nonnull String gitUrl,
            @Nonnull String revision,
            @Nonnull String commit,
            Optional<Path> subFolder) {
        final Metadata metadata = new Metadata();
        metadata.setTimestamp(new Date());

        final ToolInformation scannerInfo = new ToolInformation();
        final Service scannerService = new Service();
        scannerService.setName(ACTION_NAME);

        final OrganizationalEntity organization = new OrganizationalEntity();
        organization.setName(ACTION_ORG);
        scannerService.setProvider(organization);
        scannerInfo.setServices(List.of(scannerService));
        metadata.setToolChoice(scannerInfo);

        final Property gitUrlProperty = new Property();
        gitUrlProperty.setName("gitUrl");
        gitUrlProperty.setValue(gitUrl);
        metadata.addProperty(gitUrlProperty);

        final Property revisionProperty = new Property();
        revisionProperty.setName("revision");
        revisionProperty.setValue(revision);
        metadata.addProperty(revisionProperty);

        final Property commitProperty = new Property();
        commitProperty.setName("commit");
        commitProperty.setValue(commit);
        metadata.addProperty(commitProperty);

        subFolder.ifPresent(
                path -> {
                    final Property subFolderProperty = new Property();
                    subFolderProperty.setName("subfolder");
                    subFolderProperty.setValue(path.toString());
                    metadata.addProperty(subFolderProperty);
                });

        cycloneDXbom.setMetadata(metadata);
    }
}
