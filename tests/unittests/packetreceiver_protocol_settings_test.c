#include "PacketReceiver/interface.h"
#include "PacketReceiver/structure.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void checkValid(const char *selection, const uint8_t *protocols, uint16_t count)
{
    char      settings[512];
    const int written = snprintf(
        settings, sizeof(settings), "{\"source-ipv4-range\":\"198.51.100.10/32\",\"protocol-number\":%s}", selection);
    require(written > 0 && (size_t) written < sizeof(settings), "settings fixture overflow");

    node_t node             = nodePacketReceiverGet();
    node.node_settings_json = cJSON_Parse(settings);
    require(node.node_settings_json != NULL, "settings fixture did not parse");

    tunnel_t *tunnel = packetreceiverTunnelCreate(&node);
    require(tunnel != NULL, "valid protocol selection was rejected");
    packetreceiver_tstate_t *state = tunnelGetState(tunnel);
    require(state->protocol_count == count, "wrong number of selected protocols");
    bool selected[256] = {0};

    for (uint16_t i = 0; i < count; ++i)
    {
        require(state->protocol_numbers[i] == protocols[i], "selected protocol order changed");
        require(state->protocol_slots[protocols[i]] == i + 1U, "selected protocol slot is wrong");
        selected[protocols[i]] = true;
    }
    for (uint16_t protocol = 0; protocol < 256; ++protocol)
    {
        if (! selected[protocol])
        {
            require(state->protocol_slots[protocol] == 0, "unselected protocol has a slot");
        }
    }

    packetreceiverTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
}

static void checkInvalid(const char *selection)
{
    char      settings[512];
    const int written = snprintf(settings,
                                 sizeof(settings),
                                 "{\"source-ipv4-range\":\"198.51.100.10/32\"%s%s}",
                                 selection == NULL ? "" : ",\"protocol-number\":",
                                 selection == NULL ? "" : selection);
    require(written > 0 && (size_t) written < sizeof(settings), "settings fixture overflow");

    node_t node             = nodePacketReceiverGet();
    node.node_settings_json = cJSON_Parse(settings);
    require(node.node_settings_json != NULL, "settings fixture did not parse");
    require(packetreceiverTunnelCreate(&node) == NULL, "invalid protocol selection was accepted");
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
}

static void checkReport(void)
{
    const char *path        = "packetreceiver_protocol_settings_test_report.txt";
    node_t      node        = nodePacketReceiverGet();
    node.node_settings_json = cJSON_Parse("{\"source-ipv4-range\":\"198.51.100.10/32\","
                                          "\"protocol-number\":[\"TCP\",\"UDP\",253],"
                                          "\"expected-packets-per-ip\":10,"
                                          "\"output-file\":\"packetreceiver_protocol_settings_test_report.txt\"}");
    require(node.node_settings_json != NULL, "report fixture did not parse");
    discard remove(path);

    tunnel_t *tunnel = packetreceiverTunnelCreate(&node);
    require(tunnel != NULL, "report fixture creation failed");
    packetreceiver_tstate_t *state = tunnelGetState(tunnel);
    state->received_counts         = memoryAllocateZero(3U * sizeof(uint64_t));
    require(state->received_counts != NULL, "report counters allocation failed");
    state->received_counts[2]     = 22;
    state->total_expected_packets = 30;
    state->unexpected_packets     = 4;
    packetreceiverFinalizeReport(tunnel, false);

    FILE *file = fopen(path, "rb");
    require(file != NULL, "report file was not written");
    char         report[4096];
    const size_t length = fread(report, 1, sizeof(report) - 1U, file);
    require(! ferror(file) && feof(file), "report could not be read completely");
    report[length] = '\0';
    require(fclose(file) == 0, "report file close failed");

    require(strstr(report, "expected-total-packets: 30\n") != NULL, "report expected total is wrong");
    require(strstr(report, "received-total-packets: 22\n") != NULL, "report received total is wrong");
    require(strstr(report, "lost-total-packets: 20\n") != NULL, "report lost total is wrong");
    require(strstr(report, "unexpected-packets: 4\n") != NULL, "report unexpected total is wrong");
    const char *total = strstr(report, "198.51.100.10 | total | 30 | 22 | 20 | 66.67%");
    const char *tcp = strstr(report, "198.51.100.10 | 6 | 10 | 0 | 10 | 100.00% | [--------------------------------]");
    const char *udp = strstr(report, "198.51.100.10 | 17 | 10 | 0 | 10 | 100.00% | [--------------------------------]");
    const char *custom =
        strstr(report, "198.51.100.10 | 253 | 10 | 22 | 0 | 0.00% | [################################]");
    require(total != NULL && tcp != NULL && udp != NULL && custom != NULL, "report rows are wrong");
    require(total < tcp && tcp < udp && udp < custom, "report protocol rows are out of order");

    packetreceiverTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
    require(remove(path) == 0, "report file removal failed");
}

int main(void)
{
    const uint8_t single_tcp[] = {6};
    const uint8_t pair[]       = {6, 17};
    const uint8_t mixed[]      = {253, 1, 17, 6};
    const uint8_t custom_max[] = {255};
    uint8_t       all_protocols[255];
    for (uint16_t i = 0; i < 255; ++i)
    {
        all_protocols[i] = (uint8_t) i;
    }

    checkValid("\"TCP\"", single_tcp, 1);
    checkValid("6", single_tcp, 1);
    checkValid("[6,17]", pair, 2);
    checkValid("[\"TCP\",\"UDP\"]", pair, 2);
    checkValid("[253,\"ICMP\",\"UDP\",\"TCP\"]", mixed, 4);
    checkValid("255", custom_max, 1);
    checkValid("\"ALL\"", all_protocols, 255);

    checkInvalid(NULL);
    checkInvalid("[]");
    checkInvalid("[6,\"TCP\"]");
    checkInvalid("[17,17]");
    checkInvalid("[\"ALL\"]");
    checkInvalid("[\"ALL\",17]");
    checkInvalid("256");
    checkInvalid("-1");
    checkInvalid("6.5");
    checkInvalid("\"253\"");
    checkInvalid("\"SCTP\"");
    checkInvalid("true");
    checkReport();

    return 0;
}
