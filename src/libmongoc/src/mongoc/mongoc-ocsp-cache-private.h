/*
 * Copyright 2013 MongoDB, Inc.
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

#ifndef MONGOC_OCSP_CACHE_PRIVATE_H
#define MONGOC_OCSP_CACHE_PRIVATE_H

#include <openssl/ocsp.h>

typedef struct _cache_entry_list_t cache_entry_list_t;

cache_entry_list_t *
_mongoc_ocsp_get_cache_entry (OCSP_CERTID *id);

void
_mongoc_ocsp_cache_set_resp (OCSP_CERTID *id, OCSP_RESPONSE *resp);

int
_mongoc_ocsp_cache_length ();

void
_mongoc_ocsp_cache_find_status (cache_entry_list_t *entry,
                                OCSP_CERTID **id,
                                int *cert_status,
                                int *reason,
                                ASN1_GENERALIZEDTIME **produced_at,
                                ASN1_GENERALIZEDTIME **this_update,
                                ASN1_GENERALIZEDTIME **next_update);

#endif /* MONGO_C_DRIVER_MONGOC_OCSP_CACHE_PRIVATE_H */
