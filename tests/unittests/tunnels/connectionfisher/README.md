# Selection and Est reentry

Fisher and continuing-path Est fixtures cover synchronous transport notification,
selection/header barriers and exact-line teardown. See
[connectionfisherclient_reentrant_selection_test.c](connectionfisherclient_reentrant_selection_test.c),
[connectionfisherserver_est_reentry_test.c](connectionfisherserver_est_reentry_test.c)
and the [shared Est fixture](../../../support/c/fixtures/protocols/protocol_est_ordering_fixture.h)
for setup and ownership. Sources give their exact CTest selections.
