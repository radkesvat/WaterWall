/* Exercise the production WebTransport header compatibility overlay: distinct
 * mutable field bindings, const serialization, defaults and invalid values.
 * Run waterwall.quic_web_transport_headers_unit in native Debug and Release. */
#include "test_assert.h"

#include "quiche/web_transport/web_transport_headers.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

int main()
{
    testCaseSet("web_transport_header_field_bindings");
    const auto parsed = webtransport::ParseInitHeader("br=33, ignored=7, u=11, bl=22");
    require(parsed.ok(), "valid init header rejected");
    require(parsed->initial_unidi_limit == 11, "unidirectional field bound incorrectly");
    require(parsed->initial_incoming_bidi_limit == 22, "incoming field bound incorrectly");
    require(parsed->initial_outgoing_bidi_limit == 33, "outgoing field bound incorrectly");
    const auto serialized = webtransport::SerializeInitHeader(*parsed);
    require(serialized.ok() && *serialized == "u=11, bl=22, br=33",
            "const serialization changed field mapping or order");

    testCaseSet("web_transport_header_defaults");
    const auto defaults = webtransport::ParseInitHeader("bl=5");
    require(defaults.ok(), "partial init header rejected");
    require(defaults->initial_unidi_limit == 0 && defaults->initial_incoming_bidi_limit == 5 &&
                defaults->initial_outgoing_bidi_limit == 0,
            "absent fields lost their defaults");

    testCaseSet("web_transport_header_invalid_values");
    require(! webtransport::ParseInitHeader("u=-1").ok(), "negative unidirectional limit accepted");
    require(! webtransport::ParseInitHeader("bl=-1").ok(), "negative incoming limit accepted");
    require(! webtransport::ParseInitHeader("br=-1").ok(), "negative outgoing limit accepted");
    require(! webtransport::ParseInitHeader("u=\"text\"").ok(), "non-integer limit accepted");
    return 0;
}
