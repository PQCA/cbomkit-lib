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
import java.util.Optional;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;
import org.pqca.scanning.java.JavaScannerService;

public class ScannerServiceTest {
    @Test
    void testDeduplication() {
        // Create a component with two identical findings
        Component c = new Component();
        c.setName("test");
        c.setBomRef("test-ref");
        c.setType(Type.CRYPTOGRAPHIC_ASSET);

        CryptoProperties cp = new CryptoProperties();
        cp.setAssetType(AssetType.ALGORITHM);
        AlgorithmProperties ap = new AlgorithmProperties();
        ap.setPrimitive(Primitive.UNKNOWN);
        cp.setAlgorithmProperties(ap);
        c.setCryptoProperties(cp);

        Evidence e = new Evidence();
        Occurrence o1 = new Occurrence();
        o1.setLocation("/tmp/x");
        o1.setLine(1);
        o1.setOffset(0);
        e.setOccurrences(List.of(o1, o1));
        c.setEvidence(e);

        ScannerService scannerService = new JavaScannerService(new File("."));
        Optional<Component> deduplicated = scannerService.deduplicateFindings(c);
        // Deduplicating this component should produce a component with only one
        // finding.
        assertThat(deduplicated)
                .hasValueSatisfying(
                        dc -> {
                            assertThat(dc.getName()).isEqualTo(c.getName());
                            assertThat(dc.getBomRef()).isEqualTo(c.getBomRef());
                            assertThat(dc.getType()).isEqualTo(c.getType());
                            assertThat(dc.getCryptoProperties()).isEqualTo(cp); // same instance
                            assertThat(dc.getEvidence().getOccurrences()).hasSize(1);
                        });

        // The ScannerService keeps state. Deduplicating tne same component again
        // would create an invilid component with no findings. The method should
        // return Optional.empty().
        deduplicated = scannerService.deduplicateFindings(c);
        assertThat(deduplicated).isEmpty();
    }
}
