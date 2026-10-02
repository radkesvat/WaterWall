/* Private cross-TU declarations for the support regression driver. The driver
 * owns case publication and deliberate subprocess failure modes. */
#ifndef WW_SUPPORT_REGRESSION_AUX_H
#define WW_SUPPORT_REGRESSION_AUX_H

#include "test_assert.h"

void supportCheckCaseFromOtherTU(void);
void supportFailFromOtherTU(test_failure_policy_t policy);

#endif
