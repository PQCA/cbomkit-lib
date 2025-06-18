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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.util.List;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.pqca.scanning.CBOM;

public class AssertableCBOM {
    private final CBOM cbom;

    public AssertableCBOM(CBOM cbom) {
        this.cbom = cbom;
    }

    public boolean hasDetectionAt(@Nullable String location, @Nullable Integer line) {
        if (location == null && line == null) {
            return false;
        }
        for (Component component : this.cbom.cycloneDXbom().getComponents()) {
            final List<Occurrence> occurrences = component.getEvidence().getOccurrences();
            assertThat(occurrences).isNotEmpty();
            boolean locationResult = false;
            boolean lineResult = false;
            if (location != null) {
                locationResult =
                        occurrences.stream()
                                .map(Occurrence::getLocation)
                                .anyMatch(location::equals);
            }
            if (line != null) {
                lineResult = occurrences.stream().map(Occurrence::getLine).anyMatch(line::equals);
            }
            if (locationResult && lineResult) {
                return true;
            }
        }
        return false;
    }

    public boolean hasDetectionWithNameAt(
            @Nonnull String name, @Nonnull String location, @Nonnull Integer line) {
        for (Component component : this.cbom.cycloneDXbom().getComponents()) {
            boolean nameResult =
                    component.getName().equals(name) || component.getName().contains(name);

            final List<Occurrence> occurrences = component.getEvidence().getOccurrences();
            assertThat(occurrences).isNotEmpty();

            boolean locationResult =
                    occurrences.stream().map(Occurrence::getLocation).anyMatch(location::equals);
            boolean lineResult =
                    occurrences.stream().map(Occurrence::getLine).anyMatch(line::equals);

            if (nameResult && locationResult && lineResult) {
                return true;
            }
        }
        return false;
    }

    public void hasNumberOfDetections(int number) {
        assertThat(
                        this.cbom.cycloneDXbom().getComponents().stream()
                                .mapToInt(
                                        component ->
                                                component.getEvidence().getOccurrences().size())
                                .sum())
                .isEqualTo(number);
    }
}
