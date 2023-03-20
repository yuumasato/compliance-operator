FROM registry.ci.openshift.org/openshift/release:rhel-8-release-golang-1.19-openshift-4.12 AS builder

COPY bundle/manifests /manifests/
# replace quay.io/compliance-operator/compliance-operator:latest with ghcr.io/complianceascode/compliance-operator:latest
RUN sed -i 's/quay.io\/compliance-operator\/compliance-operator:latest/ghcr.io\/complianceascode\/compliance-operator:latest/g' /manifests/*.yaml
# replace quay.io/compliance-operator/openscap-ocp:latest with ghcr.io/complianceascode/openscap-ocp:latest
RUN sed -i 's/quay.io\/compliance-operator\/openscap-ocp:latest/ghcr.io\/complianceascode\/openscap-ocp:latest/g' /manifests/*.yaml


FROM scratch
# Core bundle labels.
LABEL operators.operatorframework.io.bundle.mediatype.v1=registry+v1
LABEL operators.operatorframework.io.bundle.manifests.v1=manifests/
LABEL operators.operatorframework.io.bundle.metadata.v1=metadata/
LABEL operators.operatorframework.io.bundle.package.v1=compliance-operator
LABEL operators.operatorframework.io.bundle.channels.v1=alpha
LABEL operators.operatorframework.io.bundle.channel.default.v1=alpha
LABEL operators.operatorframework.io.metrics.builder=operator-sdk-v1.19.0+git
LABEL operators.operatorframework.io.metrics.mediatype.v1=metrics+v1
LABEL operators.operatorframework.io.metrics.project_layout=go.kubebuilder.io/v3

# Labels for testing.
LABEL operators.operatorframework.io.test.mediatype.v1=scorecard+v1
LABEL operators.operatorframework.io.test.config.v1=tests/scorecard/

COPY --from=0 /manifests /manifests
# Copy files to locations specified by labels.
COPY bundle/metadata /metadata/
COPY bundle/tests/scorecard /tests/scorecard/

