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

static OCSP_CERTID *
create_cert_id (long serial)
{
   OCSP_CERTID *id;
   X509_NAME *issuer_name;
   ASN1_BIT_STRING *issuer_key;
   ASN1_INTEGER *serial_number;

   issuer_name = X509_NAME_new ();
   issuer_key = ASN1_BIT_STRING_new ();
   serial_number = ASN1_INTEGER_new ();
   ASN1_INTEGER_set (serial_number, serial);

   id = OCSP_cert_id_new (EVP_sha1 (), issuer_name, issuer_key, serial_number);
   return id;
}

static void
test_mongoc_cache_upsert (void)
{
   OCSP_CERTID *id;
   cache_entry_list_t *expected;
   cache_entry_list_t *actual;
   OCSP_RESPONSE *resp;
   OCSP_BASICRESP *bs;
   int status;

   BSON_ASSERT (_mongoc_ocsp_cache_length () == 0);
   id = create_cert_id (1234567890L);

   bs = OCSP_BASICRESP_new ();
   resp = OCSP_response_create (OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

   _mongoc_ocsp_cache_set_resp (id, resp);
   BSON_ASSERT (_mongoc_ocsp_cache_length () == 1);

   actual = _mongoc_ocsp_get_cache_entry (id);
   BSON_ASSERT (actual);

   // TODO: cmp set and get
}

void
test_ocsp_cache_install (TestSuite *suite)
{
   TestSuite_Add (suite, "/ocsp_cache/upsert", test_mongoc_cache_upsert);
}
