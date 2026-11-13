//========== Copyright (c) Valve Corporation. All Rights Reserved. ============
//
// "External transport" for GameNetworkingSockets: WaterWall's replacement for
// steamnetworkingsockets_socketthread.cpp at upstream commit
// d534c19aa760df3fb75fd20db13ba1932b8a5463.  Most of this file is upstream's
// text and stays under upstream's license
// (ww/cmake/dependencies/licenses/gamenetworkingsockets-LICENSE).
//
// This file is compiled INSTEAD of steamnetworkingsockets_socketthread.cpp.
// It provides every low level entry point that the rest of the library
// expects from that file, but it never creates or uses an OS socket:
//
// - Outgoing datagrams are handed to a C callback (see gns_external_transport.h).
// - Incoming datagrams enter through gns_external_receive().
// - The service thread sleeps on a mutex + condition variable until the next
//   thinker deadline or until WakeServiceThread() is called.
//
// Every block is tagged with where it came from:
//   [COPIED a-b]   taken from steamnetworkingsockets_socketthread.cpp lines a-b
//                  without functional change
//   [ADAPTED a-b]  taken from those lines, with the socket specific parts
//                  removed or replaced
//   [NEW]          does not exist upstream
//
// Dropped on purpose: real sockets (CRawUDPSocketImpl), epoll/poll, the wake
// socket pair, fake lag / loss / reorder / duplication / jitter / rate limit
// simulation, packet tracing, ECN, dual Wifi, the mock network, DNS, local
// interface enumeration, and the queue that can hold an out of order packet
// back (672-1115: HandleOutOfOrderPacket, which nothing in the library calls).
// Every datagram is processed inside gns_external_receive(), on the caller's
// thread.
//
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <chrono>

#include "steamnetworkingsockets_lowlevel.h"
#include "../steamnetworkingsockets_internal.h"
#include "../steamnetworkingsockets_thinker.h"
#include "steamnetworkingsockets_connections.h"
#include <vstdlib/random.h>
#include "crypto.h"
#include <tier0/valve_tracelogging.h>

#include "gns_external_transport.h"

#if IsPosix()
	#include <pthread.h>
	#include <sched.h>
#endif
#ifdef _WIN32
	#include <windows.h>
	#include <mmsystem.h> // timeBeginPeriod
#endif

#include <tier0/memdbgon.h>

// [COPIED 59-66]
TRACELOGGING_DECLARE_PROVIDER( HTraceLogging_SteamNetworkingSockets );

TRACELOGGING_DEFINE_PROVIDER(
	HTraceLogging_SteamNetworkingSockets,
	"Valve.SteamNetworkingSockets",
	/* OLD GUID:               ( 0xb77d8a36, 0xef0c, 0x4976, 0x8d, 0x22, 0x08, 0xf9, 0x86, 0xf5, 0x6c, 0xfb ) */
	/* NEW hash-based guid: */ ( 0xd4e956eb, 0xde52, 0x57ac, 0xdc, 0xaa, 0x1f, 0x9b, 0xa1, 0x04, 0x17, 0xc8 )
);

namespace SteamNetworkingSocketsLib {

// [COPIED 93-102]  (g_nSendECNAuto dropped: no ECN without a socket)
constexpr int k_msMaxPollWait = 1000;

// There is no socket buffer any more.  The only remaining reader is
// SNP_ThinkSendState(), which sends at most (this >> 11) packets per pass.
constexpr int k_cbDefaultUDPSocketBufferSize = 256*1024;
int g_cbUDPSocketBufferSize = k_cbDefaultUDPSocketBufferSize;

std::atomic<int> s_nLowLevelSupportRefCount(0);
static volatile bool s_bManualPollMode;

// [ADAPTED 104-165]  Mock network branches removed.
int ClassifyIP( const CIPAddress &ip )
{
	switch ( ip.GetType() )
	{
		case k_EIPTypeV4:
		{
			uint32 ipv4 = ip.GetIPv4();  // host order: first octet in bits 31-24
			uint8 a = (uint8)( ipv4 >> 24 );
			uint8 b = (uint8)( ipv4 >> 16 );
			if ( a == 127 )
				return k_nIPClassify_IPv4 | k_nIPClassify_Localhost;
			if ( a == 10
				|| ( a == 172 && b >= 16 && b <= 31 )
				|| ( a == 192 && b == 168 )
				|| ( a == 169 && b == 254 ) )
				return k_nIPClassify_IPv4 | k_nIPClassify_LAN;
			return k_nIPClassify_IPv4 | k_nIPClassify_Public;
		}

		case k_EIPTypeV6:
		{
			const uint8 *b = ip.GetIPV6Bytes();
			// ::1 (loopback) should never appear in non-mock mode
			if ( memcmp( b, k_ipv6Bytes_Loopback, 16 ) == 0 )
				return k_nIPClassify_IPv6 | k_nIPClassify_Localhost;
			if ( (b[0] & 0xfe) == 0xfc )  // fc00::/7 -- ULA private space
				return k_nIPClassify_IPv6 | k_nIPClassify_LAN;
			if ( b[0] == 0xfe && (b[1] & 0xc0) == 0x80 )  // fe80::/10 -- link-local
				return k_nIPClassify_IPv6 | k_nIPClassify_LAN;
			return k_nIPClassify_IPv6 | k_nIPClassify_Public;
		}

		default:
			break;
	}

	AssertMsg( false, "Invalid IP type %d", ip.GetType() );
	return 0;
}

// [COPIED 167-174]
int ClassifyIP( const SteamNetworkingIPAddr &ip )
{
	// FIXME We really should just get rid of all of our internal uses of the
	// SteamNetworkingIPAddr type, and only use it for the API
	netadr_t adr;
	SteamNetworkingIPAddrToNetAdr( adr, ip );
	return ClassifyIP( adr );
}

// [ADAPTED 181-305]  The Windows routing table query is removed.  What is
// left only looks at the (synthetic) address bits.
bool IsRouteToAddressProbablyLocal( netadr_t addr )
{
	int nClassify = ClassifyIP( addr );
	if ( nClassify & k_nIPClassify_Public )
		return false;  // public internet (real or mock-simulated) is never local
	if ( nClassify & ( k_nIPClassify_LAN | k_nIPClassify_Localhost ) )
		return true;

	// Assume that if we are able to send to any "reserved" route, that is is local.
	// Note that this will be true for VPNs, too!
	if ( addr.IsReservedAdr() )
		return true;

	// Nope
	return false;
}

/////////////////////////////////////////////////////////////////////////////
//
// External endpoints
//
/////////////////////////////////////////////////////////////////////////////

// [COPIED 350-351]
inline IRawUDPSocket::IRawUDPSocket() {}
inline IRawUDPSocket::~IRawUDPSocket() {}

// [NEW] The object behind gns_external_endpoint_t.  It takes the place of
// upstream's CRawUDPSocketImpl.  All members are protected by the global lock.
class CExternalEndpoint final : public IRawUDPSocket
{
public:
	STEAMNETWORKINGSOCKETS_DECLARE_CLASS_OPERATOR_NEW

	enum ERole
	{
		k_ERole_Listen, // found by OpenRawUDPSocket, key is the local address
		k_ERole_Connect, // found by OpenUDPSocketBoundToHost, key is the remote address
	};

	CExternalEndpoint( ERole eRole, const netadr_t &adrKey, gns_external_send_fn fnSend, gns_external_event_fn fnEvent, void *pUser )
	: m_eRole( eRole ), m_adrKey( adrKey ), m_fnSend( fnSend ), m_fnEvent( fnEvent ), m_pUser( pUser )
	{
		m_boundAddr.Clear();
	}

	const ERole m_eRole;

	/// Synthetic address this endpoint is registered under
	const netadr_t m_adrKey;

	/// Where outgoing datagrams and events go.  Cleared when the owner releases the endpoint.
	gns_external_send_fn m_fnSend;
	gns_external_event_fn m_fnEvent;
	void *m_pUser;

	/// Tell the owner, if it is still there, what the library did with us
	void NotifyOwner( gns_external_event_t eEvent ) const
	{
		SteamNetworkingGlobalLock::AssertHeldByCurrentThread();
		if ( m_fnEvent )
			(*m_fnEvent)( m_pUser, eEvent );
	}

	/// Who to notify when we receive a packet on this endpoint.
	/// This is null while no listen socket or connection is bound to us.
	CRecvPacketCallback m_callback;

	/// True between OpenRawUDPSocket / OpenUDPSocketBoundToHost and Close()
	bool m_bOpen = false;

	/// True once gns_external_endpoint_release was called.  The registration
	/// is gone, and we are deleted as soon as the library closes us.
	bool m_bOwnerReleased = false;

	// Implements IRawUDPSocket
	virtual bool BSendRawPacketGather( int nChunks, const iovec *pChunks, const netadr_t &adrTo, int ecn = -1 ) const override;
	virtual void Close() override;
	virtual void SetCallbackRecvPacket( CRecvPacketCallback callback ) override
	{
		SteamNetworkingGlobalLock::AssertHeldByCurrentThread();
		m_callback = callback;
	}
};

// [NEW] Registered endpoints.  Protected by the global lock.
typedef CUtlHashMap<netadr_t, CExternalEndpoint *, std::equal_to<netadr_t>, netadr_t::Hash > ExternalEndpointMap;
static ExternalEndpointMap s_mapListenEndpoints; // key: synthetic local address
static ExternalEndpointMap s_mapConnectEndpoints; // key: synthetic remote address

// [NEW] Address conversion.  Goes through SteamNetworkingIPAddr so that an
// IPv4-mapped address gets the same normal form the rest of the library uses.
static inline void ExternalAddrToNetAdr( netadr_t &adr, const gns_external_addr_t &ext )
{
	SteamNetworkingIPAddr temp;
	temp.SetIPv6( ext.ip, ext.port );
	SteamNetworkingIPAddrToNetAdr( adr, temp );
}

static inline void NetAdrToExternalAddr( gns_external_addr_t &ext, const netadr_t &adr )
{
	adr.GetIPV6( ext.ip );
	ext.port = adr.GetPort();
}

/////////////////////////////////////////////////////////////////////////////
//
// Waking the service thread
//
/////////////////////////////////////////////////////////////////////////////

// [NEW] Replaces the wake socket pair / event and the epoll handle.
// s_mutexWake is a leaf lock: nothing else is ever locked while it is held.
static std::mutex s_mutexWake;
static std::condition_variable s_condWake;
static bool s_bWakeRequested; // protected by s_mutexWake

// [COPIED 1157-1163]
static std::thread *s_pServiceThread = nullptr;
static void (*s_fnServiceThreadInitCallback)() = nullptr;

bool IsServiceThreadRunning()
{
	return ( s_pServiceThread != nullptr );
}

// [NEW] (upstream 1165-1181 writes a byte to a socket pair or sets an event)
void WakeServiceThread()
{
	{
		std::lock_guard<std::mutex> lockWake( s_mutexWake );
		s_bWakeRequested = true;
	}
	s_condWake.notify_all();
}

/////////////////////////////////////////////////////////////////////////////
//
// External endpoint methods and lookup
//
/////////////////////////////////////////////////////////////////////////////

// [NEW] (the checks at the top mirror CRawUDPSocketImpl::BSendRawPacketGather, upstream 1206-1212)
bool CExternalEndpoint::BSendRawPacketGather( int nChunks, const iovec *pChunks, const netadr_t &adrTo, int ecn ) const
{
	// Add a tag.  If we end up holding the lock for a long time, this tag
	// will tell us how many packets were sent
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread( "SendUDPacket" );
	Assert( nChunks > 0 );

	// Silently ignore a request to send a packet anytime we're in the process of shutting down the system
	if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) <= 0 )
		return true;

	// The owner is gone.  The wire no longer exists, so this is the same as a lost packet.
	if ( !m_fnSend )
		return true;

	gns_external_addr_t to;
	NetAdrToExternalAddr( to, adrTo );

	// Single chunk: pass it straight through
	if ( nChunks == 1 )
	{
		(*m_fnSend)( m_pUser, (const uint8_t *)pChunks->iov_base, (size_t)pChunks->iov_len, &to );
		return true;
	}

	// The callback takes one contiguous datagram, so gather the chunks.
	// (Same idea as upstream's sendto_gather, 356-377.)
	uint8 pkt[ k_cbSteamNetworkingSocketsMaxUDPMsgLen ];
	uint8 *d = pkt;
	uint8 *max = pkt + sizeof(pkt);
	for ( int i = 0 ; i < nChunks ; ++i )
	{
		const iovec &chunk = pChunks[i];
		if ( d + chunk.iov_len > max )
		{
			AssertMsg( false, "Gather send too big!" );
			return false;
		}
		memcpy( d, chunk.iov_base, chunk.iov_len );
		d += chunk.iov_len;
	}
	(*m_fnSend)( m_pUser, pkt, (size_t)( d - pkt ), &to );
	return true;
}

// [NEW] (upstream 1316-1359 puts the socket on a cleanup queue, because the
// service thread might be polling the descriptor without the lock.  Nothing
// touches an external endpoint without the global lock, so there is no queue.)
void CExternalEndpoint::Close()
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread( "IRawUDPSocket::Close" );

	/// Clear the callback, to ensure that no further callbacks will be executed.
	Assert( m_bOpen );
	Assert( m_callback.m_fnCallback );
	m_callback.m_fnCallback = nullptr;
	m_callback.m_pContext = nullptr;
	m_bOpen = false;

	// If the owner has already let go of us, then nobody else has a pointer to us.
	// Otherwise we stay registered and can be opened again, and the owner hears
	// that the library is done with us.
	if ( m_bOwnerReleased )
		delete this;
	else
		NotifyOwner( GNS_EXTERNAL_EVENT_CLOSED );
}

// [NEW] Replaces upstream 2181-2288 (and OpenRawUDPSocketInternal, 1504-1782).
// Used by listen sockets, through CSharedSocket::BInit.
IRawUDPSocket *OpenRawUDPSocket( CRecvPacketCallback callback, SteamNetworkingErrMsg &errMsg, SteamNetworkingIPAddr *pAddrLocal, int *pnAddressFamilies )
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	// Make sure have been initialized
	if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) <= 0 )
	{
		V_strcpy_safe( errMsg, "Internal order of operations bug.  Can't create socket, because low level systems not initialized" );
		AssertMsgFormatted( false, errMsg );
		return nullptr;
	}

	if ( !pAddrLocal )
	{
		V_strcpy_safe( errMsg, "External transport: a local address is required" );
		return nullptr;
	}

	netadr_t adrLocal;
	SteamNetworkingIPAddrToNetAdr( adrLocal, *pAddrLocal );
	int idx = s_mapListenEndpoints.Find( adrLocal );
	if ( idx == s_mapListenEndpoints.InvalidIndex() )
	{
		V_sprintf_safe( errMsg, "External transport: no endpoint registered for local address %s", SteamNetworkingIPAddrRender( *pAddrLocal ).c_str() );
		return nullptr;
	}
	CExternalEndpoint *pSock = s_mapListenEndpoints[ idx ];
	if ( pSock->m_bOpen )
	{
		V_sprintf_safe( errMsg, "External transport: endpoint for local address %s is already in use", SteamNetworkingIPAddrRender( *pAddrLocal ).c_str() );
		return nullptr;
	}

	pSock->m_boundAddr = *pAddrLocal;
	pSock->m_callback = callback;
	pSock->m_bOpen = true;

	// Give back info on address families
	if ( pnAddressFamilies )
		*pnAddressFamilies = pAddrLocal->IsIPv4() ? k_nAddressFamily_IPv4 : k_nAddressFamily_IPv6;

	return pSock;
}

/////////////////////////////////////////////////////////////////////////////
//
// Service thread
//
/////////////////////////////////////////////////////////////////////////////

// [ADAPTED 2599-2819]  PollRawUDPSockets without the sockets.  What is left
// is: release the lock, run idle work, sleep until woken or until the timeout,
// take the lock again.
/// This will return true if we own the lock, or false if we detected
/// a shutdown request and bailed without re-squiring the lock.
static bool ServiceThreadWait( int nMaxTimeoutMS, bool bManualPoll )
{
	// This should only ever be called from our one thread proc,
	// and we assume that it will have locked the lock exactly once.
	AssertGlobalLockHeldExactlyOnce();

	// Release lock while we're asleep
	SteamNetworkingGlobalLock::Unlock();

	// Run idle tasks since we don't have the lock.
	// !FIXME! Should we move this to another thread?
	g_taskListRunInBackground.RunTasks();

	// If we have spewed, flush to disk.
	// We probably could use the background task system for this.
	FlushSystemSpew();

	// Shutdown request?
	if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) <= 0 || s_bManualPollMode != bManualPoll )
		return false; // ABORT THREAD

	// [NEW] Wait for us to be asked to wake up.  A wake request that arrived
	// while we were awake is still pending here, like a byte in upstream's
	// socket pair, and makes us go around once more without sleeping.
	{
		std::unique_lock<std::mutex> lockWake( s_mutexWake );
		if ( !s_bWakeRequested && nMaxTimeoutMS > 0 )
			s_condWake.wait_for( lockWake, std::chrono::milliseconds( nMaxTimeoutMS ), []{ return s_bWakeRequested; } );
		s_bWakeRequested = false;
	}

	// We're back awake.  Grab the lock again.
	// (Upstream asserts here that this did not take long.  With an external
	// transport other threads hold the lock while they process the datagrams
	// they deliver, so waiting for it is ordinary.  The lock itself still
	// warns about long waits.)
	for (;;)
	{

		// Shutdown request?  We've potentially been waiting a long time.
		// Don't attempt to grab the lock again if we know we want to shutdown,
		// that is just a waste of time.
		if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) <= 0 || s_bManualPollMode != bManualPoll )
			return false;

		// Try to acquire the lock.  But don't wait forever, in case the other thread has
		// the lock and then makes a shutdown request while we're waiting on the lock here.
		if ( SteamNetworkingGlobalLock::TryLock( "ServiceThread", 20 ) )
			break;
	}

	// We retained the lock
	return true;
}

// [ADAPTED 2821-2843]  External endpoints are never queued for destruction
// (see CExternalEndpoint::Close), so there is nothing to do.  The function
// stays because steamnetworkingsockets_lowlevel.h declares it.
void ProcessPendingDestroyClosedRawUDPSockets()
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();
}

// [COPIED 2845-2859]
static void ProcessDeferredOperations()
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	// Tasks that were queued to be run while we hold the lock
	g_taskListRunWithGlobalLock.RunTasks();

	// Process any connections queued for delete
	CSteamNetworkConnectionBase::ProcessDeletionList();

	// Close any sockets pending delete, if we discarded a server
	// We can close the sockets safely now, because we know we're
	// not polling on them and we know we hold the lock
	ProcessPendingDestroyClosedRawUDPSockets();
}

// [COPIED 3266-3342]  One change: the call to PollRawUDPSockets became
// ServiceThreadWait.
//
// Polling function.
// On entry: lock is held *exactly once*
// Returns: true - we want to keep running, lock is held
// Returns: false - stop request detected, lock no longer held
//
static bool SteamNetworkingSockets_InternalPoll( int msWait, bool bManualPoll )
{
	AssertGlobalLockHeldExactlyOnce();

	// Figure out how long to sleep
	SteamNetworkingMicroseconds usecNextWakeTime = IThinker::Thinker_GetNextScheduledThinkTime();
	if ( usecNextWakeTime < k_nThinkTime_Never )
	{

		// Calc wait time to wake up as late as possible,
		// rounded up to the nearest millisecond.
		SteamNetworkingMicroseconds usecNow = SteamNetworkingSockets_GetLocalTimestamp();
		int64 usecUntilNextThinkTime = usecNextWakeTime - usecNow;

		if ( usecNow >= usecNextWakeTime )
		{
			// Earliest thinker in the queue is ready to go now.
			// There is no point in going to sleep
			msWait = 0;
		}
		else
		{

			// Set wake time to wake up at the target time.  We assume the scheduler
			// only has 1ms precision, so we round to the nearest ms, so that we don't
			// always wake up exactly 1ms early, go to sleep and wait for 1ms.
			//
			// NOTE: On linux, we have a precise timer and we could probably do better
			// than this.  On windows, we could use an alertable timer, and presumably when
			// we set the we could use a high precision relative time, and Windows could do
			// smart stuff.
			int msTaskWait = ( usecUntilNextThinkTime + 500 ) / 1000;

			// We must wait at least 1 ms
			msTaskWait = std::max( 1, msTaskWait );

			// Limit to what the caller has requested
			msWait = std::min( msWait, msTaskWait );
		}
	}

	// Don't ever sleep for too long, just in case.  This timeout
	// is long enough so that if we have a bug where we really need to
	// be explicitly waking the thread for good perf, we will notice
	// the delay.  But not so long that a bug in some rare
	// shutdown race condition (or the like) will be catastrophic
	msWait = std::min( msWait, k_msMaxPollWait );

	// Sleep.  (Upstream: PollRawUDPSockets( msWait, bManualPoll ))
	if ( !ServiceThreadWait( msWait, bManualPoll ) )
	{
		// Shutdown request, and they did NOT re-acquire the lock
		return false;
	}

	AssertGlobalLockHeldExactlyOnce();

	// Shutdown request?
	if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) <= 0 || s_bManualPollMode != bManualPoll )
	{
		SteamNetworkingGlobalLock::Unlock();
		return false; // Shutdown request, we have released the lock
	}

	// Check for periodic processing
	IThinker::Thinker_ProcessThinkers();

	// Check for various deferred operations
	ProcessDeferredOperations();
	return true;
}

// [COPIED 3344-3450]  The Windows / Playstation thread naming and priority
// blocks are left out; only the POSIX priority bump is kept.
static void SteamNetworkingThreadProc()
{

	// This is an "interrupt" thread.  When an incoming packet raises the event,
	// we need to take priority above normal threads and wake up immediately
	// to process the packet.  We should be asleep most of the time waiting
	// for packets to arrive.
	#if IsPosix()
		// This probably won't work on Linux, because you cannot raise thread priority
		// without being root.  But on some systems it works.  So we try, and if it
		// works, great.
		struct sched_param sched;
		int policy;
		pthread_t thread = pthread_self();
		if ( pthread_getschedparam(thread, &policy, &sched) == 0 )
		{
			// Make sure we're not already at max.  No matter what, we don't
			// want to lower our priority!  On linux, it appears that what happens
			// is that the current and max priority values here are 0.
			int max_priority = sched_get_priority_max(policy);
			//printf( "pthread_getschedparam worked, policy=%d, pri=%d, max_pri=%d\n", policy, sched.sched_priority, max_priority );
			if ( max_priority > sched.sched_priority )
			{

				// Determine new priority.
				int min_priority = sched_get_priority_min(policy);
				sched.sched_priority = std::max( sched.sched_priority+1, (min_priority + max_priority*3) / 4 );

				// Try to set it
				pthread_setschedparam( thread, policy, &sched );
			}
		}
	#endif

	// Invoke user callback, if any
	if ( s_fnServiceThreadInitCallback )
		(*s_fnServiceThreadInitCallback)();

	// In the loop, we will always hold global lock while we're awake.
	// So go ahead and acquire it now.  But watch out for a race condition
	// where we want to shut down immediately after starting the thread
	do
	{
		if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) <= 0 || s_bManualPollMode )
			return;
	} while ( !SteamNetworkingGlobalLock::TryLock( "ServiceThread", 10 ) );

	// Random number generator may be per thread!  Make sure and see it for
	// this thread, if so
	SeedWeakRandomGenerator();

	SpewVerbose( "Service thread running.\n" );

	// Keep looping until we're asked to terminate
	while ( SteamNetworkingSockets_InternalPoll( 5000, false ) )
	{
		// If they activate manual poll mode, then bail!
		if ( s_bManualPollMode )
		{
			SteamNetworkingGlobalLock::Unlock();
			break;
		}
	}

	SpewVerbose( "Service thread exiting.\n" );
}

// [COPIED 3452-3466]
static void StopServiceThread()
{
	// They should have set some sort of flag that will cause us the thread to stop
	Assert( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) == 0 || s_bManualPollMode );

	// Send wake up signal
	WakeServiceThread();

	// Wait for thread to finish
	s_pServiceThread->join();

	// Clean up
	delete s_pServiceThread;
	s_pServiceThread = nullptr;
}

/////////////////////////////////////////////////////////////////////////////
//
// Bound sockets / socket sharing
//
/////////////////////////////////////////////////////////////////////////////

// [COPIED 3474-3513]
class CDedicatedBoundSocket : public IBoundUDPSocket
{
private:
	inline virtual ~CDedicatedBoundSocket() {}
public:
	CDedicatedBoundSocket( IRawUDPSocket *pRawSock, const netadr_t &adr )
	: IBoundUDPSocket( pRawSock, adr ) {}

	CRecvPacketCallback m_callback;

	virtual void Close() OVERRIDE
	{
		m_pRawSock->Close();
		m_pRawSock = nullptr;
		delete this;
	}
};

static void DedicatedBoundSocketCallback( const RecvPktInfo_t &info, CDedicatedBoundSocket *pSock )
{

	// Make sure that it's from the guy we are supposed to be talking to.
	if ( info.m_adrFrom != pSock->GetRemoteHostAddr() )
	{
		// Packets from random internet hosts happen all the time,
		// especially on a LAN where all sorts of people have broadcast
		// discovery protocols.  So this probably isn't a bug or a problem.
		SpewVerbose( "Ignoring stray packet from %s received on port %d.  Should only be talking to %s on that port.\n",
			CUtlNetAdrRender( info.m_adrFrom ).String(), pSock->GetRawSock()->m_boundAddr.m_port,
			CUtlNetAdrRender( pSock->GetRemoteHostAddr() ).String() );
		return;
	}

	// Now execute their callback.
	// Passing the address in this context is sort of superfluous.
	// Should we use a different signature here so that the user
	// of our API doesn't write their own useless code to check
	// the from address?
	pSock->m_callback( info );
}

// [ADAPTED 3515-3536]  Instead of opening an OS socket on an ephemeral port,
// look up the endpoint that was registered for this remote address.
// Used by client connections, through CConnectionTransportUDP::BConnect.
IBoundUDPSocket *OpenUDPSocketBoundToHost( const netadr_t &adrRemote, CRecvPacketCallback callback, SteamNetworkingErrMsg &errMsg )
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	// Make sure have been initialized
	if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) <= 0 )
	{
		V_strcpy_safe( errMsg, "Internal order of operations bug.  Can't create socket, because low level systems not initialized" );
		AssertMsgFormatted( false, errMsg );
		return nullptr;
	}

	int idx = s_mapConnectEndpoints.Find( adrRemote );
	if ( idx == s_mapConnectEndpoints.InvalidIndex() )
	{
		V_sprintf_safe( errMsg, "External transport: no endpoint registered for remote address %s", CUtlNetAdrRender( adrRemote ).String() );
		return nullptr;
	}
	CExternalEndpoint *pRawSock = s_mapConnectEndpoints[ idx ];
	if ( pRawSock->m_bOpen )
	{
		V_sprintf_safe( errMsg, "External transport: endpoint for remote address %s is already in use", CUtlNetAdrRender( adrRemote ).String() );
		return nullptr;
	}

	// There is no local address.  Leave it as [::]:0
	pRawSock->m_boundAddr.Clear();

	// Return wrapper interface that can only talk to this remote host
	CDedicatedBoundSocket *pBoundSock = new CDedicatedBoundSocket( pRawSock, adrRemote );
	pRawSock->m_callback = CRecvPacketCallback( DedicatedBoundSocketCallback, pBoundSock );
	pRawSock->m_bOpen = true;
	pBoundSock->m_callback = callback;

	return pBoundSock;
}

// [NEW] Upstream (3538-3570) opens two OS sockets on 127.0.0.1.  That is only
// used by CreateSocketPair( bUseNetworkLoopback = true ), which makes no sense
// without an OS network stack.  The pipe based socket pair still works.
bool CreateBoundSocketPair( CRecvPacketCallback callback1, CRecvPacketCallback callback2, IBoundUDPSocket **ppOutSockets, SteamNetworkingErrMsg &errMsg )
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();
	V_strcpy_safe( errMsg, "External transport: socket pairs over network loopback are not supported" );
	return false;
}

// [COPIED 3572-3670]  One addition, marked [NEW], in CloseRemoteHostByIndex.
CSharedSocket::CSharedSocket()
{
	m_pRawSock = nullptr;
}

CSharedSocket::~CSharedSocket()
{
	Kill();
}

void CSharedSocket::DefaultCallbackRecvPacket( const RecvPktInfo_t &info, CSharedSocket *pSock )
{
	// Locate the client
	int idx = pSock->m_mapRemoteHosts.Find( info.m_adrFrom );

	// Select the callback to invoke, ether client-specific, or the default
	const CRecvPacketCallback &callback = ( idx == pSock->m_mapRemoteHosts.InvalidIndex() ) ? pSock->m_callbackUnknownAddress : pSock->m_mapRemoteHosts[ idx ]->m_callback;

	// Execute the callback
	callback( info );
}

bool CSharedSocket::BInit( const SteamNetworkingIPAddr &localAddr, CRecvPacketCallback callbackUnknownAddress, SteamNetworkingErrMsg &errMsg )
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	Kill();

	SteamNetworkingIPAddr bindAddr = localAddr;
	m_pRawSock = OpenRawUDPSocket( CRecvPacketCallback( DefaultCallbackRecvPacket, this ), errMsg, &bindAddr, nullptr );
	if ( m_pRawSock == nullptr )
		return false;

	m_callbackUnknownAddress = callbackUnknownAddress;
	return true;
}

void CSharedSocket::SetCallbackRecvPacket( CRecvPacketCallback callback )
{
	m_pRawSock->SetCallbackRecvPacket( callback );
}

void CSharedSocket::Kill()
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	m_callbackUnknownAddress.m_fnCallback = nullptr;
	if ( m_pRawSock )
	{
		m_pRawSock->Close();
		m_pRawSock = nullptr;
	}
	FOR_EACH_HASHMAP( m_mapRemoteHosts, idx )
	{
		CloseRemoteHostByIndex( idx );
	}
}

void CSharedSocket::CloseRemoteHostByIndex( int idx )
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	delete m_mapRemoteHosts[ idx ];
	m_mapRemoteHosts[idx] = nullptr; // just for grins
	m_mapRemoteHosts.RemoveAt( idx );

	// [NEW] Tell the owner of the endpoint when the last remote host is gone.
	// m_pRawSock is null while the shared socket itself is being closed (Kill);
	// the owner hears about that from CExternalEndpoint::Close.
	if ( m_pRawSock && m_mapRemoteHosts.Count() == 0 )
		assert_cast<CExternalEndpoint *>( m_pRawSock )->NotifyOwner( GNS_EXTERNAL_EVENT_IDLE );
}

IBoundUDPSocket *CSharedSocket::AddRemoteHost( const netadr_t &adrRemote, CRecvPacketCallback callback )
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	if ( m_mapRemoteHosts.HasElement( adrRemote ) )
	{
		AssertMsg1( false, "Already talking to %s on this shared socket, cannot add another remote host!", CUtlNetAdrRender( adrRemote ).String() );
		return nullptr;
	}
	RemoteHost *pRemoteHost = new RemoteHost( m_pRawSock, adrRemote );
	pRemoteHost->m_pOwner = this;
	pRemoteHost->m_callback = callback;
	m_mapRemoteHosts.Insert( adrRemote, pRemoteHost );

	return pRemoteHost;
}

void CSharedSocket::RemoteHost::Close()
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	int idx = m_pOwner->m_mapRemoteHosts.Find( m_adr );
	if ( idx == m_pOwner->m_mapRemoteHosts.InvalidIndex() || m_pOwner->m_mapRemoteHosts[idx] != this )
	{
		AssertMsg( false, "CSharedSocket client table corruption!" );
		delete this;
	}
	else
	{
		m_pOwner->CloseRemoteHostByIndex( idx );
	}
}

/////////////////////////////////////////////////////////////////////////////
//
// Init / shutdown
//
/////////////////////////////////////////////////////////////////////////////

// [ADAPTED 3672-3849]  Removed: WSAStartup, COM, the wake socket pair / event,
// the epoll handle, the poll list and the fake rate limit.
bool BSteamNetworkingSocketsLowLevelAddRef( SteamNetworkingErrMsg &errMsg )
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	// Make sure and call time function at least once
	// just before we start up our thread, so we don't lurch
	// on our first reading after the thread is running and
	// take action to correct this.
	SteamNetworkingSockets_GetLocalTimestamp();

	// First time init?
	if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) == 0 )
	{
		InitSpew();

		CCrypto::Init();

		// Initialize event tracing
		TraceLoggingRegister( HTraceLogging_SteamNetworkingSockets );

		// Give us a extra time here.  This is a one-time init function and the OS might
		// need to load up libraries and stuff.
		SteamNetworkingGlobalLock::SetLongLockWarningThresholdMS( "BSteamNetworkingSocketsLowLevelAddRef", 500 );

		// The service thread sleeps in whole milliseconds, which needs the
		// timer resolution that upstream asks Windows for at this point.
		#if defined( _WIN32 ) && !IsXbox()
			if ( ::timeBeginPeriod( 1 ) != 0 )
			{
				V_strcpy_safe( errMsg, "timeBeginPeriod failed" );
				return false;
			}
		#endif

		// Make sure random number generator is seeded
		SeedWeakRandomGenerator();

		// [NEW] Forget any wake request left over from an earlier life
		{
			std::lock_guard<std::mutex> lockWake( s_mutexWake );
			s_bWakeRequested = false;
		}

		SpewMsg( "Initialized low level external transport/threading support.\n" );
	}

	s_nLowLevelSupportRefCount.fetch_add(1, std::memory_order_acq_rel);

	// Make sure the thread is running, if it should be
	if ( !s_bManualPollMode && !s_pServiceThread )
		s_pServiceThread = new std::thread( SteamNetworkingThreadProc );

	// Install an axexit handler, so that if static destruction is triggered without
	// cleaning up the library properly, we won't crash.
	static bool s_bInstalledAtExitHandler = false;
	if ( !s_bInstalledAtExitHandler )
	{
		s_bInstalledAtExitHandler = true;
		atexit( []{
			SteamNetworkingGlobalLock scopeLock( "atexit" );

			// Static destruction is about to happen.  If we have a thread,
			// we need to nuke it
			KillSpew();
			while ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) > 0 )
				SteamNetworkingSocketsLowLevelDecRef();
		} );
	}

	return true;
}

// [ADAPTED 3851-3959]  Removed: closing the wake objects, the epoll handle,
// the poll list, WSACleanup, COM, dual Wifi.
void SteamNetworkingSocketsLowLevelDecRef()
{
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread();

	// Last user is now done?
	int nLastRefCount = s_nLowLevelSupportRefCount.fetch_sub(1, std::memory_order_acq_rel);
	Assert( nLastRefCount > 0 );
	if ( nLastRefCount > 1 )
		return;

	SpewMsg( "Shutting down low level external transport/threading support.\n" );

	// Give us a extra time here.  This is a one-time shutdown function.
	// There is a potential race condition / deadlock with the service thread,
	// that might cause us to have to wait for it to timeout.
	SteamNetworkingGlobalLock::SetLongLockWarningThresholdMS( "SteamNetworkingSocketsLowLevelDecRef", 500 );

	// Stop the service thread, if we have one
	if ( s_pServiceThread )
		StopServiceThread();

	// Check for any leftover tasks that were queued to be run while we hold the lock
	ProcessDeferredOperations();

	// [NEW] At this point, no listen socket or connection should still be
	// bound to an endpoint.  Endpoints that are merely registered are fine,
	// they belong to their owner and survive a shutdown of the library.
	FOR_EACH_HASHMAP( s_mapListenEndpoints, idx )
	{
		AssertMsg( !s_mapListenEndpoints[ idx ]->m_bOpen, "Trying to close low level socket support, but we still have sockets open!" );
	}
	FOR_EACH_HASHMAP( s_mapConnectEndpoints, idx )
	{
		AssertMsg( !s_mapConnectEndpoints[ idx ]->m_bOpen, "Trying to close low level socket support, but we still have sockets open!" );
	}

	// Shutdown event tracing
	TraceLoggingUnregister( HTraceLogging_SteamNetworkingSockets );

	#if defined( _WIN32 ) && !IsXbox()
		::timeEndPeriod( 1 );
	#endif

	// If we have any tasks that were queued to run in the background,
	// we'll have to just abandon them.  We don't have enough context
	// here to run them safely because we hold the lock, and some jobs are
	// queued to run in the background precisely because there are
	// potential deadlock issues if they are run while holding the lock.
	g_taskListRunInBackground.DeleteTasks();

	KillSpew();
}

// [ADAPTED 3971-4051]  Only the branch without DNS is kept: a literal IP
// address parses, anything else fails.  Only the ICE client calls this.
bool ResolveHostname( const char* pszHostname, CUtlVector< SteamNetworkingIPAddr > *pAddrs )
{
	SteamNetworkingIPAddr addr;
	if ( !addr.ParseString( pszHostname ) )
		return false;
	pAddrs->AddToTail( addr );
	return true;
}

// [NEW] Upstream (4121-4284) enumerates OS network interfaces.  There are
// none here.  Only the ICE client calls this.
bool GetLocalAddresses( CUtlVector<LocalAddress_t> *pAddrs )
{
	return false;
}

} // namespace SteamNetworkingSocketsLib

using namespace SteamNetworkingSocketsLib;

// [COPIED 4291-4343]
STEAMNETWORKINGSOCKETS_INTERFACE void SteamNetworkingSockets_SetManualPollMode( bool bFlag )
{
	if ( s_bManualPollMode == bFlag )
		return;
	SteamNetworkingGlobalLock scopeLock( "SteamNetworkingSockets_SetManualPollMode" );
	s_bManualPollMode = bFlag;

	// Check for starting/stopping the thread
	if ( s_pServiceThread )
	{
		// Thread is active.  Should it be?
		if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) <= 0 || s_bManualPollMode )
		{
			SpewMsg( "Service thread is running, and manual poll mode actiavted.  Stopping service thread.\n" );
			StopServiceThread();
		}
	}
	else
	{
		if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) > 0 && !s_bManualPollMode )
		{
			// Start up the thread
			SpewMsg( "Service thread is not running, and manual poll mode was turned off, starting service thread.\n" );
			s_pServiceThread = new std::thread( SteamNetworkingThreadProc );
		}
	}
}

STEAMNETWORKINGSOCKETS_INTERFACE void SteamNetworkingSockets_Poll( int msMaxWaitTime )
{
	if ( !s_bManualPollMode )
	{
		AssertMsg( false, "Not in manual poll mode!" );
		return;
	}
	Assert( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) > 0 );

	while ( !SteamNetworkingGlobalLock::TryLock( "SteamNetworkingSockets_Poll", 1 ) )
	{
		if ( --msMaxWaitTime <= 0 )
			return;
	}

	bool bStillLocked = SteamNetworkingSockets_InternalPoll( msMaxWaitTime, true );
	if ( bStillLocked )
		SteamNetworkingGlobalLock::Unlock();
}

STEAMNETWORKINGSOCKETS_INTERFACE void SteamNetworkingSockets_SetServiceThreadInitCallback( void (*callback)() )
{
	AssertMsg( !IsServiceThreadRunning(), "Too late!" );
	s_fnServiceThreadInitCallback = callback;
}

/////////////////////////////////////////////////////////////////////////////
//
// [NEW] External endpoint API, see gns_external_transport.h
//
/////////////////////////////////////////////////////////////////////////////

#if defined( __GNUC__ ) || defined( __clang__ )
	#define GNS_EXTERNAL_API extern "C" __attribute__(( visibility("default") ))
#else
	#define GNS_EXTERNAL_API extern "C"
#endif

static gns_external_endpoint_t *ExternalEndpointCreate( CExternalEndpoint::ERole eRole, const gns_external_addr_t *pAddr, gns_external_send_fn fnSend, gns_external_event_fn fnEvent, void *pUser )
{
	if ( !pAddr || !fnSend )
		return nullptr;

	netadr_t adrKey;
	ExternalAddrToNetAdr( adrKey, *pAddr );

	SteamNetworkingGlobalLock scopeLock( "gns_external_endpoint_create" );
	ExternalEndpointMap &map = ( eRole == CExternalEndpoint::k_ERole_Listen ) ? s_mapListenEndpoints : s_mapConnectEndpoints;
	if ( map.HasElement( adrKey ) )
		return nullptr;

	CExternalEndpoint *pSock = new CExternalEndpoint( eRole, adrKey, fnSend, fnEvent, pUser );
	map.Insert( adrKey, pSock );
	return reinterpret_cast<gns_external_endpoint_t *>( pSock );
}

GNS_EXTERNAL_API gns_external_endpoint_t *gns_external_endpoint_create_listen( const gns_external_addr_t *local, gns_external_send_fn send, gns_external_event_fn event, void *user )
{
	// A listen socket refuses port 0 (CSteamNetworkListenSocketDirectUDP::BInit)
	if ( !local || local->port == 0 )
		return nullptr;
	return ExternalEndpointCreate( CExternalEndpoint::k_ERole_Listen, local, send, event, user );
}

GNS_EXTERNAL_API gns_external_endpoint_t *gns_external_endpoint_create_connect( const gns_external_addr_t *remote, gns_external_send_fn send, gns_external_event_fn event, void *user )
{
	return ExternalEndpointCreate( CExternalEndpoint::k_ERole_Connect, remote, send, event, user );
}

GNS_EXTERNAL_API bool gns_external_receive( gns_external_endpoint_t *endpoint, const gns_external_addr_t *from, const uint8_t *data, size_t length )
{
	CExternalEndpoint *pSock = reinterpret_cast<CExternalEndpoint *>( endpoint );
	if ( !pSock || !data )
		return false;

	// Nothing the library sends is longer than this, and the queue used for
	// out-of-order correction copies packets into a buffer of this size.
	if ( length > (size_t)k_cbSteamNetworkingSocketsMaxUDPMsgLen )
		return false;

	// The native receive path runs in the service thread, which holds the
	// global lock the whole time it is awake.  Take the same lock here.
	SteamNetworkingGlobalLock scopeLock( "gns_external_receive" );

	if ( s_nLowLevelSupportRefCount.load(std::memory_order_acquire) <= 0 )
		return false;

	// If the callback is cleared, no listen socket or connection is bound to us.
	if ( !pSock->m_callback.m_fnCallback )
		return false;

	RecvPktInfo_t info;
	if ( from )
		ExternalAddrToNetAdr( info.m_adrFrom, *from );
	else if ( pSock->m_eRole == CExternalEndpoint::k_ERole_Connect )
		info.m_adrFrom = pSock->m_adrKey;
	else
		return false;

	// Add a tag.  If we end up holding the lock for a long time, this tag
	// will tell us how many packets were processed
	SteamNetworkingGlobalLock::AssertHeldByCurrentThread( "RecvUDPPacket" );

	// Process the packet now.  (Same fields as upstream's DrainSocket, 2570-2576.)
	info.m_pPkt = data;
	info.m_cbPkt = (int)length;
	info.m_usecNow = SteamNetworkingSockets_GetLocalTimestamp();
	info.m_pSock = pSock;
	info.m_bQueuedForOutOfOrder = false;
	info.m_tos = 0xff; // unknown
	pSock->m_callback( info );

	// NOTE: do not touch pSock after this point.
	return true;
}

GNS_EXTERNAL_API void gns_external_endpoint_release( gns_external_endpoint_t *endpoint )
{
	CExternalEndpoint *pSock = reinterpret_cast<CExternalEndpoint *>( endpoint );
	if ( !pSock )
		return;

	SteamNetworkingGlobalLock scopeLock( "gns_external_endpoint_release" );
	if ( pSock->m_bOwnerReleased )
	{
		AssertMsg( false, "External endpoint released twice" );
		return;
	}

	// Remove the registration
	ExternalEndpointMap &map = ( pSock->m_eRole == CExternalEndpoint::k_ERole_Listen ) ? s_mapListenEndpoints : s_mapConnectEndpoints;
	int idx = map.Find( pSock->m_adrKey );
	if ( idx != map.InvalidIndex() && map[ idx ] == pSock )
		map.RemoveAt( idx );
	else
		AssertMsg( false, "External endpoint table corruption!" );

	// From here on, outgoing datagrams are discarded and no event is reported
	pSock->m_bOwnerReleased = true;
	pSock->m_fnSend = nullptr;
	pSock->m_fnEvent = nullptr;
	pSock->m_pUser = nullptr;

	// If the library still has a listen socket or connection on it, it will
	// delete the object when it closes it.  Otherwise we are the last user.
	if ( !pSock->m_bOpen )
		delete pSock;
}
