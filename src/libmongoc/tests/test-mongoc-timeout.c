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
#include "test-libmongoc.h"
#include "test-conveniences.h"

#include <mongoc-timeout-private.h>
#include <mongoc/mongoc-client-private.h>
#include <mongoc/mongoc-database-private.h>

const int DEFAULT_TIMEOUT = 0;

void
_test_mongoc_timeout_new_success (int64_t expected)
{
   mongoc_timeout_t *timeout;

   timeout = mongoc_timeout_new_timeout_int64 (expected);
   BSON_ASSERT (mongoc_timeout_is_set (timeout));
   BSON_ASSERT (expected == mongoc_timeout_get_timeout_ms (timeout));
   mongoc_timeout_destroy (timeout);
}

void
_test_mongoc_timeout_new_failure (int64_t try, const char *err_msg)
{
   capture_logs (true);
   BSON_ASSERT (!mongoc_timeout_new_timeout_int64 (try));
   ASSERT_CAPTURED_LOG ("mongoc", MONGOC_LOG_LEVEL_ERROR, err_msg);
   clear_captured_logs ();
}

void
test_mongoc_timeout_new (void)
{
   mongoc_timeout_t *timeout = NULL;

   BSON_ASSERT (!mongoc_timeout_is_set (timeout));

   BSON_ASSERT (timeout = mongoc_timeout_new ());
   BSON_ASSERT (!mongoc_timeout_is_set (timeout));
   mongoc_timeout_destroy (timeout);

   _test_mongoc_timeout_new_failure (-1, "invalid negative timeout");
   _test_mongoc_timeout_new_failure (INT64_MIN, "invalid negative timeout");

   _test_mongoc_timeout_new_success (0);
   _test_mongoc_timeout_new_success (1);
   _test_mongoc_timeout_new_success (INT64_MAX);
}

void
_test_mongoc_timeout_set_failure (mongoc_timeout_t *timeout,
                                  int64_t try,
                                  const char *err_msg)
{
   capture_logs (true);
   mongoc_timeout_set_timeout_ms (timeout, try);
   ASSERT_CAPTURED_LOG ("mongoc", MONGOC_LOG_LEVEL_ERROR, err_msg);
   clear_captured_logs ();

   BSON_ASSERT (!mongoc_timeout_is_set (timeout));
   BSON_ASSERT (DEFAULT_TIMEOUT == mongoc_timeout_get_timeout_ms (timeout));
}

void
_test_mongoc_timeout_set_success (mongoc_timeout_t *timeout, int64_t expected)
{
   mongoc_timeout_set_timeout_ms (timeout, expected);
   BSON_ASSERT (mongoc_timeout_is_set (timeout));
   BSON_ASSERT (expected == mongoc_timeout_get_timeout_ms (timeout));
}

void
test_mongoc_timeout_set (void)
{
   mongoc_timeout_t *timeout = NULL;

   timeout = mongoc_timeout_new ();
   BSON_ASSERT (!mongoc_timeout_is_set (timeout));

   _test_mongoc_timeout_set_failure (timeout, -1, "invalid negative timeout");
   _test_mongoc_timeout_set_failure (
      timeout, INT64_MIN, "invalid negative timeout");

   _test_mongoc_timeout_set_success (timeout, 0);
   _test_mongoc_timeout_set_success (timeout, 1);
   _test_mongoc_timeout_set_success (timeout, INT64_MAX);

   mongoc_timeout_destroy (timeout);
}

void
test_mongoc_timeout_get (void)
{
   mongoc_timeout_t *timeout = NULL;
   int64_t expected;

   BSON_ASSERT (timeout = mongoc_timeout_new ());
   BSON_ASSERT (!mongoc_timeout_is_set (timeout));
   BSON_ASSERT (DEFAULT_TIMEOUT == mongoc_timeout_get_timeout_ms (timeout));

   expected = 1;
   mongoc_timeout_set_timeout_ms (timeout, expected);
   BSON_ASSERT (mongoc_timeout_is_set (timeout));
   BSON_ASSERT (expected == mongoc_timeout_get_timeout_ms (timeout));

   mongoc_timeout_destroy (timeout);
}

void
_test_mongoc_timeout_copy (mongoc_timeout_t *expected)
{
   mongoc_timeout_t *actual = mongoc_timeout_copy (expected);

   /* different memory addresses */
   BSON_ASSERT (expected != actual);

   BSON_ASSERT (mongoc_timeout_get_timeout_ms (actual) ==
                mongoc_timeout_get_timeout_ms (expected));
   BSON_ASSERT (mongoc_timeout_is_set (actual) ==
                mongoc_timeout_is_set (expected));

   mongoc_timeout_destroy (actual);
}
void
test_mongoc_timeout_copy (void)
{
   mongoc_timeout_t *expected = NULL;

   expected = mongoc_timeout_new ();
   _test_mongoc_timeout_copy (expected);
   mongoc_timeout_destroy (expected);

   expected = mongoc_timeout_new_timeout_int64 (1);
   _test_mongoc_timeout_copy (expected);
   mongoc_timeout_destroy (expected);
}

void
test_mongoc_timeout_set_on_client (void)
{
   mongoc_client_t *client = NULL;
   bson_error_t error;
   int64_t expected;

   client = mongoc_client_new (NULL);

   BSON_ASSERT (!mongoc_timeout_is_set (client->timeout));
   BSON_ASSERT (DEFAULT_TIMEOUT == mongoc_client_get_timeout (client));

   expected = 1;
   BSON_ASSERT (mongoc_client_set_timeout (client, expected, &error));
   BSON_ASSERT (mongoc_timeout_is_set (client->timeout));
   BSON_ASSERT (expected == mongoc_client_get_timeout (client));

   mongoc_client_destroy (client);
}

void
test_mongoc_timeout_set_on_database (void)
{
   mongoc_client_t *client = NULL;
   mongoc_database_t *database = NULL;
   int64_t expected;

   client = mongoc_client_new (NULL);
   database = _mongoc_database_new (client, "test", NULL, NULL, NULL);

   BSON_ASSERT (!mongoc_timeout_is_set (database->timeout));
   BSON_ASSERT (DEFAULT_TIMEOUT == mongoc_database_get_timeout (database));

   expected = 1;
   mongoc_database_set_timeout (database, expected);
   BSON_ASSERT (mongoc_timeout_is_set (database->timeout));
   BSON_ASSERT (expected == mongoc_database_get_timeout (database));

   mongoc_database_destroy (database);
   mongoc_client_destroy (client);
}

void
test_mongoc_timeout_set_on_collection (void)
{
   mongoc_client_t *client = NULL;
   mongoc_collection_t *collection = NULL;
   int64_t expected;

   client = mongoc_client_new (NULL);
   collection =
      _mongoc_collection_new (client, "test", "test", NULL, NULL, NULL, NULL);

   BSON_ASSERT (!mongoc_timeout_is_set (collection->timeout));
   BSON_ASSERT (DEFAULT_TIMEOUT == mongoc_collection_get_timeout (collection));

   expected = 1;
   mongoc_collection_set_timeout (collection, expected);
   BSON_ASSERT (mongoc_timeout_is_set (collection->timeout));
   BSON_ASSERT (expected == mongoc_collection_get_timeout (collection));

   mongoc_collection_destroy (collection);
   mongoc_client_destroy (client);
}

void
test_mongoc_timeout_database_inherit_from_client (void)
{
   mongoc_client_t *client = NULL;
   mongoc_database_t *database = NULL;
   bson_error_t error;
   int64_t expected = 1;

   client = mongoc_client_new (NULL);
   BSON_ASSERT (mongoc_client_set_timeout (client, expected, &error));
   BSON_ASSERT (expected == mongoc_client_get_timeout (client));

   database = _mongoc_database_new (client, "test", NULL, NULL, NULL);
   BSON_ASSERT (expected == mongoc_database_get_timeout (database));

   mongoc_database_destroy (database);
   mongoc_client_destroy (client);
}

void
test_mongoc_timeout_collection_inherit_from_database (void)
{
   mongoc_client_t *client = NULL;
   mongoc_database_t *database = NULL;
   mongoc_collection_t *collection = NULL;
   int64_t expected;

   client = mongoc_client_new (NULL);
   BSON_ASSERT (!mongoc_timeout_is_set (client->timeout));

   expected = 1;
   database = mongoc_client_get_database (client, "test");
   mongoc_database_set_timeout (database, expected);
   BSON_ASSERT (mongoc_timeout_is_set (database->timeout));
   BSON_ASSERT (expected == mongoc_database_get_timeout (database));

   collection = mongoc_database_get_collection (database, "test");
   BSON_ASSERT (mongoc_timeout_is_set (collection->timeout));
   BSON_ASSERT (expected == mongoc_collection_get_timeout (collection));

   mongoc_collection_destroy (collection);
   mongoc_database_destroy (database);
   mongoc_client_destroy (client);
}

void
test_mongoc_timeout_deprecation_socket_timeout_ms (void)
{
   mongoc_uri_t *uri = NULL;
   mongoc_client_t *client = NULL;
   bson_error_t error;

   capture_logs (true);
   ASSERT (
      !mongoc_uri_new ("mongodb://user@localhost/?" MONGOC_URI_SOCKETTIMEOUTMS
                       "=1&" MONGOC_URI_TIMEOUTMS "=1"));
   clear_captured_logs ();

   ASSERT (uri = mongoc_uri_new (
              "mongodb://user@localhost/?" MONGOC_URI_SOCKETTIMEOUTMS "=1"));
   client = mongoc_client_new_from_uri (uri);
   BSON_ASSERT (!mongoc_client_set_timeout (client, 1, &error));
   ASSERT_ERROR_CONTAINS (error,
                          MONGOC_ERROR_CLIENT,
                          MONGOC_ERROR_TIMEOUT_DEPRECATED_ARG,
                          "Cannot 'timeout' with deprecated timeout options");


   mongoc_uri_destroy (uri);
   mongoc_client_destroy (client);
}

void
test_mongoc_timeout_with_server_selection_timeout (void)
{
   const char *non_existent_host = "mongodb://localhost:12345/";
   mongoc_uri_t *uri = NULL;
   mongoc_client_t *client = NULL;
   mongoc_collection_t *coll = NULL;
   bson_t reply = BSON_INITIALIZER;
   bson_error_t error;

   uri = mongoc_uri_new (non_existent_host);
   mongoc_uri_set_option_as_int32 (
      uri, MONGOC_URI_SERVERSELECTIONTIMEOUTMS, 100);
   mongoc_uri_set_option_as_bool (
      uri, MONGOC_URI_SERVERSELECTIONTRYONCE, false);
   mongoc_uri_set_option_as_int64 (uri, MONGOC_URI_TIMEOUTMS, 50);

   client = mongoc_client_new_from_uri (uri);
   coll = mongoc_client_get_collection (client, "db", "coll");

   BSON_ASSERT (!mongoc_collection_command_simple (
      coll, tmp_bson ("{'ping': 1}"), NULL, &reply, &error));
   ASSERT_ERROR_CONTAINS (error,
                          MONGOC_ERROR_SERVER_SELECTION,
                          MONGOC_ERROR_SERVER_SELECTION_FAILURE,
                          "serverselectiontimeoutms");

   mongoc_uri_destroy (uri);
   mongoc_collection_drop (coll, &error);
   mongoc_collection_destroy (coll);
   mongoc_client_destroy (client);
}

void
test_timeout_install (TestSuite *suite)
{
   TestSuite_Add (suite, "/Timeout/new", test_mongoc_timeout_new);
   TestSuite_Add (suite, "/Timeout/set", test_mongoc_timeout_set);
   TestSuite_Add (suite, "/Timeout/get", test_mongoc_timeout_get);
   TestSuite_Add (suite, "/Timeout/copy", test_mongoc_timeout_copy);

   TestSuite_Add (
      suite, "/Timeout/configure/client", test_mongoc_timeout_set_on_client);
   TestSuite_Add (suite,
                  "/Timeout/configure/database",
                  test_mongoc_timeout_set_on_database);
   TestSuite_Add (suite,
                  "/Timeout/configure/collection",
                  test_mongoc_timeout_set_on_collection);

   TestSuite_Add (suite,
                  "/Timeout/inheritance/database",
                  test_mongoc_timeout_database_inherit_from_client);
   TestSuite_Add (suite,
                  "/Timeout/inheritance/collection",
                  test_mongoc_timeout_collection_inherit_from_database);

   TestSuite_Add (suite,
                  "/Timeout/deprecation/socket_timeout_ms",
                  test_mongoc_timeout_deprecation_socket_timeout_ms);

   TestSuite_Add (suite,
                  "/Timeout/with/server_selection_timeout",
                  test_mongoc_timeout_with_server_selection_timeout);
}
