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
cache_insert (OCSP_CERTID *id, int status, ASN1_GENERALIZEDTIME *next_update)
{
   OCSP_RESPONSE *resp;
   OCSP_BASICRESP *bs;

   bs = OCSP_BASICRESP_new ();
   OCSP_basic_add1_status (bs, id, 0, 0, NULL, NULL, next_update);
   resp = OCSP_response_create (status, bs);

   _mongoc_ocsp_cache_set_resp (id, resp);
}

static void
test_mongoc_cache_insert (void)
{
   int i, size = 5;

   BSON_ASSERT (_mongoc_ocsp_cache_length () == 0);

   for (i = 0; i < size; i++) {
      OCSP_CERTID *id = create_cert_id (i);
      cache_insert(id, OCSP_RESPONSE_STATUS_SUCCESSFUL, NULL);
   }

   BSON_ASSERT (_mongoc_ocsp_cache_length () == size);

   for (i = 0; i < size; i++) {
      cache_entry_list_t *entry;
      OCSP_CERTID *actual = create_cert_id (i);
      OCSP_CERTID *expected = create_cert_id (i);
      int status;

      entry = _mongoc_ocsp_get_cache_entry (expected);
      BSON_ASSERT (entry);

      _mongoc_ocsp_cache_get_status (
         entry, &actual, &status, NULL, NULL, NULL, NULL);
      BSON_ASSERT (OCSP_id_cmp (actual, expected) == 0);
      BSON_ASSERT (status == OCSP_RESPONSE_STATUS_SUCCESSFUL);
   }
}

static void
test_mongoc_cache_update (void)
{
//    time_t now;
//    time_t later;
//    ASN1_GENERALIZEDTIME *next_update;
//
//    now = time (NULL);
//    next_update = ASN1_GENERALIZEDTIME_set (NULL, now);
//
//    BSON_ASSERT (ASN1_TIME_compare (actual_next_update, expected_next_update) ==
//                 0);
//
//    /* should update for same cert ID with later next_update field */
//    expected_next_update = ASN1_GENERALIZEDTIME_set (NULL, time (NULL));
//    bs = OCSP_BASICRESP_new ();
//    OCSP_basic_add1_status (
//       bs, expected_id, 0, 0, NULL, NULL, expected_next_update);
//    resp = OCSP_response_create (OCSP_RESPONSE_STATUS_UNAUTHORIZED, bs);
//
//    _mongoc_ocsp_cache_set_resp (expected_id, resp);
//    BSON_ASSERT (_mongoc_ocsp_cache_length () == 1);
}
void
test_ocsp_cache_install (TestSuite *suite)
{
   TestSuite_Add (suite, "/ocsp_cache/insert", test_mongoc_cache_insert);
   TestSuite_Add (suite, "/ocsp_cache/update", test_mongoc_cache_update);
}
