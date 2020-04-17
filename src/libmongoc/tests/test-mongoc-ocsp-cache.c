#include "mongoc/mongoc-ocsp-cache-private.h"

#include "TestSuite.h"

void
test_ocsp_cache_install (TestSuite *suite)
{
   TestSuite_Add (suite,
                  "/ocsp_cache",
                  NULL);
}
