/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openssl/pem.h>
#include <mongoc/mongoc.h>
#include "mongoc/mongoc-ocsp-cache-private.h"

#include "TestSuite.h"

static X509 *
load_pem_file (const char *file_path)
{
   FILE *fp = NULL;
   X509 *cert = NULL;

   fp = fopen (file_path, "r");
   if (!fp) {
      MONGOC_ERROR ("unable to open: %s\n", file_path);
      goto done;
   }

   cert = PEM_read_X509 (fp, NULL, NULL, NULL);
   if (!cert) {
      MONGOC_ERROR ("unable to parse certificate in: %s\n", file_path);
   }

done:
   if (fp)
      fclose (fp);
   return cert;
}

static void
test_mongoc_cache (void) {
   OCSP_CERTID *id;
   OCSP_RESPONSE *expected;
   OCSP_RESPONSE *actual;
   X509 *peer;
   X509 *issuer;
   OCSP_BASICRESP *bs;

   peer = load_pem_file(CERT_SERVER);
   issuer = load_pem_file(CERT_CA);

   id = OCSP_cert_to_id (NULL /* SHA1 */, peer, issuer);

   bs = OCSP_BASICRESP_new();
   expected = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

   _mongoc_ocsp_cache_set_resp (id, expected);
   actual = _mongoc_ocsp_cache_get_resp (id);

   ASSERT(actual);
   ASSERT (OCSP_response_status(actual) == OCSP_response_status(expected));
}

void
test_ocsp_cache_install (TestSuite *suite)
{
   TestSuite_Add (suite,
                  "/ocsp_cache/test_mongoc_cache",
                  test_mongoc_cache);
}
