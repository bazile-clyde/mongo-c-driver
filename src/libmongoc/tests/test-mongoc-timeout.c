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

#include "TestSuite.h"

#include <mongoc-timeout.h>

void
test_mongoc_timeout_new (void)
{
   mongoc_timeout_t *timeout = NULL;
   int64_t expected;

   BSON_ASSERT (!mongoc_timeout_is_set (timeout));

   timeout = mongoc_timeout_new ();
   BSON_ASSERT (!mongoc_timeout_is_set (timeout));
   mongoc_timeout_destroy (timeout);

   expected = 123;
   timeout = mongoc_timeout_new_int64 (expected);
   BSON_ASSERT (mongoc_timeout_is_set (timeout));
   BSON_ASSERT (expected == mongoc_timeout_get_timeout_ms (timeout));
   mongoc_timeout_destroy (timeout);
}

void
test_timeout_install (TestSuite *suite)
{
   TestSuite_Add (suite, "/Timeout/new", test_mongoc_timeout_new);
}
