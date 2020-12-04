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

int64_t
mongoc_timeout_get_timeout_ms ( const mongoc_timeout_t *timeout) {
   return timeout->timeout_ms;
}

void
mongoc_timeout_set_timeout_ms (mongoc_timeout_t *timeout, int64_t value) {
   timeout->timeout_ms = value;
   timeout->is_set = true;
}


mongoc_timeout_t *
mongoc_timeout_new (int64_t value) {
   mongoc_timeout_t *timeout;

   timeout = (mongoc_timeout_t *) bson_malloc0 (sizeof *timeout);

   mongoc_timeout_set_timeout_ms(timeout, value);
   return timeout;
}

mongoc_timeout_t *
mongoc_timeout_copy (mongoc_timeout_t *timeout) {
   return mongoc_timeout_new(timeout->timeout_ms);
}

void
mongoc_timeout_destroy (mongoc_timeout_t *timeout) {
     bson_free(timeout);
}

bool
mongoc_timeout_is_set(mongoc_timeout_t *timeout) {
   return timeout->is_set;
}

