#ifndef WW_TEST_CASE_H
#define WW_TEST_CASE_H

#ifdef __cplusplus
extern "C"
{
#endif

    /* One context per executable, shared by all translation units. The name must
     * have static storage. Set it before starting a case; do not change it until
     * every thread and callback from that case has joined or quiesced. */
    void        testCaseSet(const char *name);
    const char *testCaseName(void);

#ifdef __cplusplus
}
#endif

/* Ordered execution stays in main. Parameterized cases can call testCaseSet
 * explicitly so their arguments, setup and teardown remain visible. */
#define TEST_RUN_CASE(function)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        testCaseSet(#function);                                                                                        \
        function();                                                                                                    \
    } while (0)

#endif
