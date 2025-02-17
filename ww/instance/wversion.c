#include "wversion.h"
#include "wtime.h"

/**
 * @brief Returns the compile version string.
 *
 * @return const char* A static string containing the version in the format "WW_VERSION_MAJOR.YY.MM.DD".
 */
const char* wwGetCompileVersion(void) {
    static char s_version[16] = {0};
    datetime_t dt = wwCompileDateTime();
    snprintf(s_version, sizeof(s_version), "%d.%d.%d.%d",
        WW_VERSION_MAJOR, dt.year%100, dt.month, dt.day);
    return s_version;
}

/**
 * @brief Converts a version string (e.g., "v1.2.3.4" or "1.2.3.4") to an integer.
 *
 * Parses the version string and converts it into a 32-bit integer, where each part of the version
 * represents a byte.  For example, "1.2.3.4" becomes 0x01020304.
 *
 * @param str const char* The version string to convert.
 * @return int The integer representation of the version.
 */
int versionATOI(const char* str) {
    int hex = 0;

    // trim v1.2.3.4
    const char* pv = strchr(str, 'v');
    const char* pdot = pv ? pv+1 : str;

    while (1) {
        hex = (hex << 8) | atoi(pdot);
        pdot = strchr(pdot, '.');
        if (pdot == NULL) {
            break;
        }
        ++pdot;
    }

    return hex;
}

/**
 * @brief Converts an integer representation of a version to a string (e.g., "1.2.3.4").
 *
 * Converts a 32-bit integer, where each byte represents a part of the version, into a string
 * in the format "X.Y.Z.W".  For example, 0x01020304 becomes "1.2.3.4". Leading zeros are trimmed.
 *
 * @param num int The integer representation of the version.
 * @param str char* The buffer to store the resulting version string.  Must be large enough to hold the string.
 */
void versionITOA(int num, char* str) {
    unsigned char* ch = (unsigned char*)&num; // Use unsigned char to avoid sign extension issues
    sprintf(str, "%d.%d.%d.%d", ch[0], ch[1], ch[2], ch[3]);

    // trim 0.1.2.3
    const char* p = str;
    while (p[0] == '0' && p[1] == '.') {
        p += 2;
    }

    if (p != str) {
        strcpy(str, p);
    }
}
