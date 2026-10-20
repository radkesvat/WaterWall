#pragma once

/* Shared producer/client wire geometry and operation numbers. Request 9 returns
 * one bounded credential-bearing page; both peers use the same traversal. */
enum
{
    kAuthenticationMessageHeaderSize          = 4,
    kAuthenticationSessionTokenSize           = 64,
    kAuthenticationRevisionHeaderSize         = 16,
    kAuthenticationRequestEnvelopeHeaderSize  = kAuthenticationMessageHeaderSize + kAuthenticationSessionTokenSize,
    kAuthenticationResponseEnvelopeHeaderSize = kAuthenticationMessageHeaderSize + kAuthenticationRevisionHeaderSize,
    kAuthenticationCorrelationIdSize          = 4,
    kAuthenticationRequestHeaderSize          = 1 + kAuthenticationCorrelationIdSize + 4,
    kAuthenticationResponseHeaderSize         = 1 + kAuthenticationCorrelationIdSize + 4,
    kAuthenticationMaxMessagePayload          = 16U * 1024U * 1024U,
    kAuthenticationMaxRequestData             = 16U * 1024U * 1024U,
    kAuthenticationMaxResponsePayload         = 16U * 1024U * 1024U,
    kAuthenticationMaxBatchEntries            = 4096,

    kAuthenticationRequestTypePing                  = 1,
    kAuthenticationRequestTypeGetUserBySHA256Hex    = 2,
    kAuthenticationRequestTypeGetUserBySHA256Base64 = 3,
    kAuthenticationRequestTypeGetUserBySHA256       = 4,
    kAuthenticationRequestTypeGetUserByPassword     = 5,
    kAuthenticationRequestTypeAddNewUser            = 6,
    kAuthenticationRequestTypeUpdateUser            = 7,
    kAuthenticationRequestTypeGetUsersPage          = 9,
    kAuthenticationRequestTypeGetAllUsers           = kAuthenticationRequestTypeGetUsersPage,
    kAuthenticationRequestTypeAuthenticate          = 10,
    kAuthenticationRequestTypePushUserStats         = 11,
    kAuthenticationRequestTypeGetUserBySHA224Hex    = 12,
    kAuthenticationRequestTypeGetUserBySHA224Base64 = 13,
    kAuthenticationRequestTypeGetUserBySHA224       = 14,

    kAuthenticationResponseTypeOk      = 0,
    kAuthenticationResponseTypeError   = 0xFF,
    kAuthenticationResponseTypePong    = 1,
    kAuthenticationResponseTypeUser    = 2,
    kAuthenticationResponseTypeUsers   = 3,
    kAuthenticationResponseTypeSession = 4,

    kAuthenticationUsersPageTargetBytes = 256U * 1024U,
    kAuthenticationUsersPageMaxUsers    = 128U,
    kAuthenticationDefaultSyncMaxUsers  = 100000U,
    kAuthenticationDefaultSyncMaxBytes  = 268435456U
};
