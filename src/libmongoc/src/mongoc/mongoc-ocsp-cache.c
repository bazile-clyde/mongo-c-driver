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

#include "mongoc-ocsp-cache-private.h"
#include "utlist.h"
#include <bson/bson.h>

typedef struct _cache_entry_list_t cache_entry_list_t;

struct _cache_entry_list_t {
   cache_entry_list_t *next;
   OCSP_CERTID *id;
   OCSP_RESPONSE *resp;
};

static cache_entry_list_t *cache = NULL;

#define INIT(entry) (entry) = bson_malloc0 (sizeof (cache_entry_list_t))

static int
cache_cmp (cache_entry_list_t *out, OCSP_CERTID *id)
{
   if (!out || !id)
      return 1;
   return OCSP_id_cmp (out->id, id);
}

OCSP_RESPONSE *
_mongoc_ocsp_cache_get_resp (OCSP_CERTID *id)
{
   cache_entry_list_t *iter = NULL;

   if (cache) {
      CDL_SEARCH (cache, iter, id, cache_cmp);
   } else {
      INIT (cache);
   }

   return !iter ? NULL : iter->resp;
}

void
_mongoc_ocsp_cache_set_resp (OCSP_CERTID *id, OCSP_RESPONSE *resp)
{
   cache_entry_list_t *entry;
   INIT (entry);

   entry->id = OCSP_CERTID_dup (id);
   // TODO: memcpy
   entry->resp = resp;
   LL_APPEND(cache, entry);
}
