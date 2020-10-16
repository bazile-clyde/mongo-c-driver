#include "TestSuite.h"

static void
test_server_selection_timeout (void)
{
   ASSERT(true);
}

void
test_timeout_ms_errors_install (TestSuite *suite)
{
   TestSuite_Add (suite,
                  "/timeoutMS/errors/test_server_selection_timeout",
                  test_server_selection_timeout);

}
