/*
 * Windows implementation for the libuuid public API.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <bcrypt.h>
#include <rpc.h>
#include <string.h>

/* rpcdce.h maps uuid_t to UUID, but libuuid owns uuid_t here. */
#ifdef uuid_t
#undef uuid_t
#endif

#include "uuidP.h"

static void rpc_uuid_pack(const GUID *rpc_uuid, uuid_t out)
{
	struct uuid uu;

	uu.time_low = rpc_uuid->Data1;
	uu.time_mid = rpc_uuid->Data2;
	uu.time_hi_and_version = rpc_uuid->Data3;
	uu.clock_seq = ((uint16_t) rpc_uuid->Data4[0] << 8) | rpc_uuid->Data4[1];
	memcpy(uu.node, &rpc_uuid->Data4[2], sizeof(uu.node));

	uuid_pack(&uu, out);
}

void uuid_generate_random(uuid_t out)
{
	PUCHAR out_bytes = (PUCHAR) out;

	if (BCryptGenRandom(NULL, out_bytes, (ULONG) sizeof(uuid_t),
			    BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
		GUID rpc_uuid;

		(void) UuidCreate(&rpc_uuid);
		rpc_uuid_pack(&rpc_uuid, out);
		return;
	}

	out_bytes[6] = (out_bytes[6] & 0x0F) | 0x40;
	out_bytes[8] = (out_bytes[8] & 0x3F) | 0x80;
}

int uuid_generate_time_safe(uuid_t out)
{
	GUID rpc_uuid;
	RPC_STATUS status = UuidCreateSequential(&rpc_uuid);

	if (status != RPC_S_OK && status != RPC_S_UUID_LOCAL_ONLY)
		return -1;

	rpc_uuid_pack(&rpc_uuid, out);
	return status == RPC_S_OK ? 0 : -1;
}

void uuid_generate_time(uuid_t out)
{
	(void) uuid_generate_time_safe(out);
}

void uuid_generate(uuid_t out)
{
	uuid_generate_random(out);
}

time_t uuid_time(const uuid_t uu, struct timeval *ret_tv)
{
	struct timeval tv;
	struct uuid uuid;
	uint32_t high;
	uint64_t clock_reg;

	uuid_unpack(uu, &uuid);

	high = uuid.time_mid | ((uuid.time_hi_and_version & 0xFFF) << 16);
	clock_reg = uuid.time_low | ((uint64_t) high << 32);

	clock_reg -= (((uint64_t) 0x01B21DD2) << 32) + 0x13814000;
	tv.tv_sec = (long) (clock_reg / 10000000);
	tv.tv_usec = (long) ((clock_reg % 10000000) / 10);

	if (ret_tv)
		*ret_tv = tv;

	return tv.tv_sec;
}

int uuid_type(const uuid_t uu)
{
	struct uuid uuid;

	uuid_unpack(uu, &uuid);
	return (uuid.time_hi_and_version >> 12) & 0xF;
}

int uuid_variant(const uuid_t uu)
{
	struct uuid uuid;
	int var;

	uuid_unpack(uu, &uuid);
	var = uuid.clock_seq;

	if ((var & 0x8000) == 0)
		return UUID_VARIANT_NCS;
	if ((var & 0x4000) == 0)
		return UUID_VARIANT_DCE;
	if ((var & 0x2000) == 0)
		return UUID_VARIANT_MICROSOFT;
	return UUID_VARIANT_OTHER;
}
