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
package org.pqca.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.Service;
import org.junit.jupiter.api.Test;
import org.pqca.scanning.CBOM;

public class CBOMTest {
    @Test
    void testMergeAddMetadata() {
        Bom bom = new Bom();
        CBOM cbom = new CBOM(bom);
        cbom.addMetadata(
                "https://github.com/keycloak/keycloak",
                "main",
                "9c2825eb0e64aa7ea40b8dc3605d37046f6a24cb",
                Optional.of(Paths.get("core")));
        Metadata metadata = cbom.cycloneDXbom().getMetadata();
        assertThat(metadata).isNotNull();
        assertThat(metadata.getTimestamp()).isNotNull();
        assertThat(metadata.getToolChoice()).isNotNull();
        assertThat(metadata.getToolChoice().getServices()).isNotNull();
        assertThat(metadata.getToolChoice().getServices()).hasSize(1);

        Service service = metadata.getToolChoice().getServices().getFirst();
        assertThat(service.getName()).isEqualTo("CBOMkit");
        assertThat(service.getProvider()).isNotNull();
        assertThat(service.getProvider().getName()).isEqualTo("PQCA");

        List<Property> properties = metadata.getProperties();
        assertThat(properties).hasSize(4);
        assertThat(properties)
                .extracting("name", "value")
                .contains(tuple("gitUrl", "https://github.com/keycloak/keycloak"));
        assertThat(properties).extracting("name", "value").contains(tuple("revision", "main"));
        assertThat(properties)
                .extracting("name", "value")
                .contains(tuple("commit", "9c2825eb0e64aa7ea40b8dc3605d37046f6a24cb"));
        assertThat(properties).extracting("name", "value").contains(tuple("subfolder", "core"));
    }

    @Test
    void testMerge() {
        Bom bom1 = new Bom();
        Component c11 = new Component();
        c11.setName("c11");
        c11.setBomRef("ref_c11");
        bom1.addComponent(c11);
        Component c12 = new Component();
        c12.setName("c12");
        c12.setBomRef("ref_c12");
        bom1.addComponent(c11);
        Dependency d1 = new Dependency("ref_c11");
        d1.addDependency(new Dependency("ref_c12"));
        bom1.addDependency(d1);
        CBOM cbom1 = new CBOM(bom1);

        Bom bom2 = new Bom();
        Component c21 = new Component();
        c21.setName("c21");
        c21.setBomRef("ref_c21");
        bom1.addComponent(c11);
        Component c22 = new Component();
        c22.setName("c22");
        c22.setBomRef("ref_c22");
        bom1.addComponent(c11);
        Dependency d2 = new Dependency("ref_c21");
        d2.addDependency(new Dependency("ref_c22"));
        bom1.addDependency(d2);
        CBOM cbom2 = new CBOM(bom2);

        cbom1.merge(cbom2);
        assertThat(cbom1.cycloneDXbom()).isNotNull();
        assertThat(cbom1.cycloneDXbom().getComponents()).hasSize(4);
        assertThat(cbom1.cycloneDXbom().getDependencies()).hasSize(2);
    }
}
