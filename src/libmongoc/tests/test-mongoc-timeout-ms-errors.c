#include "TestSuite.h"
#include "test-conveniences.h"

static void
test_server_selection_timeout (void)
{
   mongoc_uri_t *uri;
   mongoc_client_t *client;
   mongoc_collection_t *collection;
   bson_error_t error;
   bson_t *command;
   bson_t reply;
   bool result;

   uri = mongoc_uri_new ("mongodb://localhost:11111");
   ASSERT (uri);

   mongoc_uri_set_option_as_int32 (uri, MONGOC_URI_SERVERSELECTIONTIMEOUTMS, 1);
   mongoc_uri_set_option_as_bool (uri, MONGOC_URI_SERVERSELECTIONTRYONCE, false);

   client = mongoc_client_new_from_uri(uri);
   collection = mongoc_client_get_collection (client, "test", "test");
   command = tmp_bson ("{'ping': 1}");
   result = mongoc_collection_command_simple (
      collection, command, NULL, &reply, &error);
   ASSERT (!result);

   bson_destroy (&reply);
   mongoc_collection_destroy (collection);
   mongoc_client_destroy (client);
   mongoc_uri_destroy (uri);
}

void
test_timeout_ms_errors_install (TestSuite *suite)
{
   TestSuite_Add (suite,
                  "/timeoutMS/errors/test_server_selection_timeout",
                  test_server_selection_timeout);

}
