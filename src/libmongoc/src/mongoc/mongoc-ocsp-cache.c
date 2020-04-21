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


struct _cache_entry_list_t {
   cache_entry_list_t *next;
   OCSP_CERTID *id;
   int cert_status, reason;
   ASN1_GENERALIZEDTIME *produced_at, *this_update, *next_update;
};

static cache_entry_list_t *cache = NULL;

static int
cache_cmp (cache_entry_list_t *out, OCSP_CERTID *id)
{
   if (!out || !out->id || !id)
      return 1;
   return OCSP_id_cmp (out->id, id);
}

cache_entry_list_t *
_mongoc_ocsp_get_cache_entry (OCSP_CERTID *id)
{
   cache_entry_list_t *iter = NULL;

   LL_SEARCH (cache, iter, id, cache_cmp);
   return iter;
}

static void
update_entry (cache_entry_list_t *entry, OCSP_RESPONSE *resp)
{
   OCSP_BASICRESP *basic;
   int cert_status, reason;
   ASN1_GENERALIZEDTIME *produced_at, *this_update, *next_update;

   basic = OCSP_response_get1_basic (resp);
   OCSP_resp_find_status (basic,
                          entry->id,
                          &cert_status,
                          &reason,
                          &produced_at,
                          &this_update,
                          &next_update);

   if (ASN1_TIME_compare (next_update, entry->next_update) == 1) {
      // TODO: copy times
      entry->next_update = next_update;
      entry->this_update = this_update;
      entry->produced_at = produced_at;
      entry->cert_status = cert_status;
      entry->reason = reason;
   }
}

void
_mongoc_ocsp_cache_set_resp (OCSP_CERTID *id, OCSP_RESPONSE *resp)
{
   cache_entry_list_t *entry = NULL;

   if (!(entry = _mongoc_ocsp_get_cache_entry (id))) {
      entry = bson_malloc0 (sizeof (cache_entry_list_t));
      entry->id = OCSP_CERTID_dup (id);
      LL_APPEND (cache, entry);
   }

   update_entry (entry, resp);
}

int
_mongoc_ocsp_cache_length ()
{
   cache_entry_list_t *iter;
   int counter;

   // LL_COUNT (cache, iter, counter);
   {
      counter = 0;
      for (iter = cache; iter; iter = (iter)->next) {
         ++counter;
      }
   }
   return counter;
}

void
_mongoc_ocsp_cache_get_status (cache_entry_list_t *entry,
                               OCSP_CERTID **id,
                               int *cert_status,
                               int *reason,
                               ASN1_GENERALIZEDTIME **produced_at,
                               ASN1_GENERALIZEDTIME **this_update,
                               ASN1_GENERALIZEDTIME **next_update)
{
   BSON_ASSERT (entry);

   if (id)
      *id = entry->id;
   if (cert_status)
      *cert_status = entry->cert_status;
   if (reason)
      *reason = entry->reason;
   if (produced_at)
      *produced_at = entry->produced_at;
   if (this_update)
      *this_update = entry->this_update;
   if (next_update)
      *next_update = entry->next_update;
}

void
_mongoc_ocsp_cache_clear ()
{
   cache = NULL;
}
