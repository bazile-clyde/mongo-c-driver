/*
 * Copyright 2020 MongoDB, Inc.
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

#include "mongoc-timeout-private.h"
#include "mongoc-timeout.h"
#include "mongoc.h"

int64_t
mongoc_timeout_get_timeout_ms (const mongoc_timeout_t *timeout)
{
   BSON_ASSERT (timeout);

   return timeout->timeout_ms;
}

void
mongoc_timeout_set_timeout_ms (mongoc_timeout_t *timeout, int64_t timeout_ms)
{
   BSON_ASSERT (timeout);
   if (timeout_ms < 0) {
      MONGOC_WARNING ("invalid negative timeout");
      return;
   }

   timeout->timeout_ms = timeout_ms;
   timeout->is_set = true;
}

mongoc_timeout_t *
mongoc_timeout_new ()
{
   mongoc_timeout_t *timeout;

   timeout = (mongoc_timeout_t *) bson_malloc0 (sizeof *timeout);
   timeout->timeout_ms = 0;
   timeout->is_set = false;

   return timeout;
}

mongoc_timeout_t *
mongoc_timeout_new_int64 (int64_t timeout_ms)
{
   mongoc_timeout_t *timeout = mongoc_timeout_new ();
   mongoc_timeout_set_timeout_ms (timeout, timeout_ms);
   return timeout;
}

mongoc_timeout_t *
mongoc_timeout_copy (mongoc_timeout_t *timeout)
{
   BSON_ASSERT (timeout);

   return mongoc_timeout_new (timeout->timeout_ms);
}

void
mongoc_timeout_destroy (mongoc_timeout_t *timeout)
{
   bson_free (timeout);
}

bool
mongoc_timeout_is_set (mongoc_timeout_t *timeout)
{
   return timeout && timeout->is_set;
}
