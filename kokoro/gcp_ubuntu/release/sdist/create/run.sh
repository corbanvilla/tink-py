#!/bin/bash
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# Creates a source distribution.
#
# The behavior of this script can be modified using the following optional env
# variables:
#
# - CONTAINER_IMAGE (unset by default): By default when run locally this script
#   executes tests directly on the host. The CONTAINER_IMAGE variable can be set
#   to execute tests in a custom container image for local testing. E.g.:
#
#   CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-py-base:latest" \
#     sh ./kokoro/gcp_ubuntu/release/sdist/create/run.sh
#
IS_KOKORO="false"
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

RUN_COMMAND_ARGS=()
if [[ "${IS_KOKORO}" == "true" ]]; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_py"
  source ./kokoro/testutils/py_test_container_images.sh
  CONTAINER_IMAGE="${TINK_PY_BASE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi
readonly RUN_COMMAND_ARGS

CREATE_DIST_OPTIONS=()
if [[ "${KOKORO_JOB_NAME:-}" =~ tink/github/py/.*/release ]]; then
  CREATE_DIST_OPTIONS+=( -t release )
fi
readonly CREATE_DIST_OPTIONS

# Generate a source distribution.
./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
  ./tools/distribution/create_sdist.sh "${CREATE_DIST_OPTIONS[@]}"
