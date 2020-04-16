#! /bin/bash

# Preconditions:
# - A mock responder is NOT running.
# - mongod is running with the correct configuration. (use integration-tests.sh or spawn one manually).
#
# Environment variables:
#
# CDRIVER_ROOT
#   Optional. The path to mongo-c-driver source (may be same as CDRIVER_BUILD).
#   Defaults to $(pwd)
#

# Fail on any command returning a non-zero exit status.
set -o errexit
set -o xtrace

CDRIVER_ROOT=${CDRIVER_ROOT:-$(pwd)}
MONGODB_URI="mongodb://localhost:27017/?tls=true&tlsCAFile=${CDRIVER_ROOT}/.evergreen/ocsp/rsa/ca.pem"
MONGOC_PING=${CDRIVER_ROOT}/cmake-build-debug/src/libmongoc/mongoc-ping


expect_success () {
    echo "Should succeed:"
    if ! ${MONGOC_PING} ${MONGODB_URI}; then
        echo "Unexpected failure"
    fi
}

expect_failure () {
    echo "Should fail:"
    if ${MONGOC_PING} ${MONGODB_URI} >output.txt 2>&1; then
        echo "Unexpected - succeeded but it should not have"
    else
        echo "failed as expected"
    fi

    # libmongoc really should give a better error message for a revocation failure...
    # It is not at all obvious what went wrong.
    if ! grep "No suitable servers found" output.txt >/dev/null; then
        echo "Unexpected error, expecting TLS handshake failure"
        cat output.txt
    fi
}

# start mock OCSP responder that revokes all certs; this is to avoid confusion between valid responses and soft-fails
TEST_COLUMN=TEST_4 CERT_TYPE=rsa SKIP_PIP_INSTALL=true sh ${CDRIVER_ROOT}/.evergreen/run-ocsp-responder.sh &
sleep 5
expect_failure

# shutdown revoked and start valid OCSP responder
pkill -f "ocsp_mock"
TEST_COLUMN=TEST_3 CERT_TYPE=rsa SKIP_PIP_INSTALL=true sh ${CDRIVER_ROOT}/.evergreen/run-ocsp-responder.sh &
sleep 5
expect_failure

# clear cache
# cert should be good

# shutdown valid and start revoked OCSP responder
# cert should be good

# increase clock time to outside of cert's range (>= 20 years)
# cert should be revoked
