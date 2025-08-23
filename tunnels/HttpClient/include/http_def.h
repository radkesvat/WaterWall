#pragma once
/**
 * IMPORTANT
 *  if you format this file, the content type macros will not work and the http parsers will break!
*/

#define DEFAULT_HTTP_PORT       80
#define DEFAULT_HTTPS_PORT      443

enum http_version { kHttpV1 = 1, kHttpV2 = 2 };
enum http_session_type { kHttpClient, kHttpServer };
enum http_parser_type { kHttpRequest, kHttpResponse, kHttpBoth };
enum http_parser_state {
    kHpStartReqOrRes,
    kHpMessageBegin,
    kHpUrl,
    kHpStatus,
    kHpHeaderField,
    kHpHeaderValue,
    kHpHeadersComplete,
    kHpChunkHeader,
    kHpBody,
    kHpChunkComplete,
    kHpMessageComplete,
    kHpError
};

// http_status
// XX(num, name, string)
#define HTTP_STATUS_MAP(XX)                                                     \
  XX(100, Continue,                       Continue)                             \
  XX(101, SwitchingProtocols,             Switching Protocols)                  \
  XX(102, PROCESSING,                     Processing)                           \
  XX(200, OK,                             OK)                                   \
  XX(201, CREATED,                        Created)                              \
  XX(202, ACCEPTED,                       Accepted)                             \
  XX(203, NonAuthoritativeInformation,    Non-Authoritative Information)        \
  XX(204, NoContent,                      No Content)                           \
  XX(205, ResetContent,                   Reset Content)                        \
  XX(206, PartialContent,                 Partial Content)                      \
  XX(207, MultiStatus,                    Multi-Status)                         \
  XX(208, AlreadyReported,                Already Reported)                     \
  XX(226, ImUsed,                         IM Used)                              \
  XX(300, MultipleChoices,                Multiple Choices)                     \
  XX(301, MovedPermanently,               Moved Permanently)                    \
  XX(302, FOUND,                          Found)                                \
  XX(303, SeeOther,                       See Other)                            \
  XX(304, NotModified,                    Not Modified)                         \
  XX(305, UseProxy,                       Use Proxy)                            \
  XX(307, TemporaryRedirect,              Temporary Redirect)                   \
  XX(308, PermanentRedirect,              Permanent Redirect)                   \
  XX(400, BadRequest,                     Bad Request)                          \
  XX(401, UNAUTHORIZED,                   Unauthorized)                         \
  XX(402, PaymentRequired,                Payment Required)                     \
  XX(403, FORBIDDEN,                      Forbidden)                            \
  XX(404, NotFound,                       Not Found)                            \
  XX(405, MethodNotAllowed,               Method Not Allowed)                   \
  XX(406, NotAcceptable,                  Not Acceptable)                       \
  XX(407, ProxyAuthenticationRequired,    Proxy Authentication Required)        \
  XX(408, RequestTimeout,                 Request Timeout)                      \
  XX(409, CONFLICT,                       Conflict)                             \
  XX(410, GONE,                           Gone)                                 \
  XX(411, LengthRequired,                 Length Required)                      \
  XX(412, PreconditionFailed,             Precondition Failed)                  \
  XX(413, PayloadTooLarge,                Payload Too Large)                    \
  XX(414, UriTooLong,                     URI Too Long)                         \
  XX(415, UnsupportedMediaddress_type,    Unsupported Media Type)               \
  XX(416, RangeNotSatisfiable,            Range Not Satisfiable)                \
  XX(417, ExpectationFailed,              Expectation Failed)                   \
  XX(421, MisdirectedRequest,             Misdirected Request)                  \
  XX(422, UnprocessableEntity,            Unprocessable Entity)                 \
  XX(423, LOCKED,                         Locked)                               \
  XX(424, FailedDependency,               Failed Dependency)                    \
  XX(426, UpgradeRequired,                Upgrade Required)                     \
  XX(428, PreconditionRequired,           Precondition Required)                \
  XX(429, TooManyRequests,                Too Many Requests)                    \
  XX(431, RequestHeaderFieldsTooLarge,    Request Header Fields Too Large)      \
  XX(451, UnavailableForLegalReasons,     Unavailable For Legal Reasons)        \
  XX(500, InternalServerError,            Internal Server Error)                \
  XX(501, NotImplemented,                 Not Implemented)                      \
  XX(502, BadGateway,                     Bad Gateway)                          \
  XX(503, ServiceUnavailable,             Service Unavailable)                  \
  XX(504, GatewayTimeout,                 Gateway Timeout)                      \
  XX(505, HttpVersionNotSupported,        HTTP Version Not Supported)           \
  XX(506, VariantAlsoNegotiates,          Variant Also Negotiates)              \
  XX(507, InsufficientStorage,            Insufficient Storage)                 \
  XX(508, LoopDetected,                   Loop Detected)                        \
  XX(510, NotExtended,                    Not Extended)                         \
  XX(511, NetworkAuthenticationRequired, Network Authentication Required)       \

// HTTP_STATUS_##name
enum http_status {
#define XX(num, name, string) kHttpStatus##name = (num),
    HTTP_STATUS_MAP(XX)
#undef XX
    kHttpCustomStatus
};

#define HTTP_STATUS_IS_REDIRECT(status)             \
    (                                               \
    (status) == kHttpStatusMovedPermanently   ||    \
    (status) == kHttpStatusFound              ||    \
    (status) == kHttpStatusSeeOther           ||    \
    (status) == kHttpStatusTemporaryRedirect  ||    \
    (status) == kHttpStatusPermanentRedirect        \
	)

// http_mehtod
// XX(num, name, string)
#define HTTP_METHOD_MAP(XX)         \
  XX(0,  Delete,      DELETE )      \
  XX(1,  Get,         GET)          \
  XX(2,  Head,        HEAD)         \
  XX(3,  Post,        POST)         \
  XX(4,  Put,         PUT)          \
  /* pathological */                \
  XX(5,  Connect,     CONNECT)      \
  XX(6,  Options,     OPTIONS)      \
  XX(7,  Trace,       TRACE)        \
  /* WebDAV */                      \
  XX(8,  Copy,        COPY)         \
  XX(9,  Lock,        LOCK)         \
  XX(10, Mkcol,       MKCOL)        \
  XX(11, Move,        MOVE)         \
  XX(12, Propfind,    PROPFIND)     \
  XX(13, Proppatch,   PROPPATCH)    \
  XX(14, Search,      SEARCH)       \
  XX(15, Unlock,      UNLOCK)       \
  XX(16, Bind,        BIND)         \
  XX(17, Rebind,      REBIND)       \
  XX(18, Unbind,      UNBIND)       \
  XX(19, Acl,         ACL)          \
  /* subversion */                  \
  XX(20, Report,      REPORT)       \
  XX(21, Mkactivity,  MKACTIVITY)   \
  XX(22, Checkout,    CHECKOUT)     \
  XX(23, Merge,       MERGE)        \
  /* upnp */                        \
  XX(24, Msearch,     M-SEARCH)     \
  XX(25, Notify,      NOTIFY)       \
  XX(26, Subscribe,   SUBSCRIBE)    \
  XX(27, Unsubscribe, UNSUBSCRIBE)  \
  /* RFC-5789 */                    \
  XX(28, Patch,       PATCH)        \
  XX(29, Purge,       PURGE)        \
  /* CalDAV */                      \
  XX(30, Mkcalendar,  MKCALENDAR)   \
  /* RFC-2068, section 19.6.1.2 */  \
  XX(31, Link,        LINK)         \
  XX(32, Unlink,      UNLINK)       \
  /* icecast */                     \
  XX(33, Source,      SOURCE)       \

// HTTP_##name
enum http_method {
#define XX(num, name, string) kHttp##name = (num),
    HTTP_METHOD_MAP(XX)
#undef XX
    kHttpCustomMethod
};

// MIME: https://www.iana.org/assignments/media-types/media-types.xhtml
// XX(name, mime, suffix)
#define MIME_TYPE_TEXT_MAP(XX) \
    XX(TextPlain,              text/plain,               txt)          \
    XX(TextHtml,               text/html,                html)         \
    XX(TextCss,                text/css,                 css)          \
    XX(TextCsv,                text/csv,                 csv)          \
    XX(TextMarkdown,           text/markdown,            md)           \
    XX(TextEventStream,       text/event-stream,         sse)          \

#define MIME_TYPE_APPLICATION_MAP(XX) \
    XX(ApplicationJavascript,  application/javascript,             js)     \
    XX(ApplicationJson,        application/json,                   json)   \
    XX(ApplicationXml,         application/xml,                    xml)    \
    XX(ApplicationUrlencoded,  application/x-www-form-urlencoded,  kv)     \
    XX(ApplicationOctetStream,application/octet-stream,            bin)    \
    XX(ApplicationZip,         application/zip,                    zip)    \
    XX(ApplicationGzip,        application/gzip,                   gzip)   \
    XX(Application_7Z,          application/x-7z-compressed,        7z)    \
    XX(ApplicationRar,         application/x-rar-compressed,       rar)    \
    XX(ApplicationPdf,         application/pdf,                    pdf)    \
    XX(ApplicationRtf,         application/rtf,                    rtf)    \
    XX(ApplicationGrpc,        application/grpc,                   grpc)   \
    XX(ApplicationWasm,        application/wasm,                   wasm)   \
    XX(ApplicationJar,         application/java-archive,           jar)    \
    XX(ApplicationXhtml,       application/xhtml+xml,              xhtml)  \
    XX(ApplicationAtom,        application/atom+xml,               atom)   \
    XX(ApplicationRss,         application/rss+xml,                rss)    \
    XX(ApplicationWord,        application/msword,                 doc)    \
    XX(ApplicationExcel,       application/vnd.ms-excel,           xls)    \
    XX(ApplicationPpt,         application/vnd.ms-powerpoint,      ppt)    \
    XX(ApplicationEot,         application/vnd.ms-fontobject,      eot)    \
    XX(ApplicationM3U8,        application/vnd.apple.mpegurl,      m3u8)   \
    XX(ApplicationDocx,        application/vnd.openxmlformats-officedocument.wordprocessingml.document,    docx) \
    XX(ApplicationXlsx,        application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,          xlsx) \
    XX(ApplicationPptx,        application/vnd.openxmlformats-officedocument.presentationml.presentation,  pptx) \

#define MIME_TYPE_MULTIPART_MAP(XX) \
    XX(MultipartFormData,     multipart/form-data,                mp) \

#define MIME_TYPE_IMAGE_MAP(XX) \
    XX(ImageJpeg,              image/jpeg,               jpg)          \
    XX(ImagePng,               image/png,                png)          \
    XX(ImageGif,               image/gif,                gif)          \
    XX(ImageIco,               image/x-icon,             ico)          \
    XX(ImageBmp,               image/x-ms-bmp,           bmp)          \
    XX(ImageSvg,               image/svg+xml,            svg)          \
    XX(ImageTiff,              image/tiff,               tiff)         \
    XX(ImageWebp,              image/webp,               webp)         \

#define MIME_TYPE_VIDEO_MAP(XX) \
    XX(VideoMp4,               video/mp4,                mp4)          \
    XX(VideoFlv,               video/x-flv,              flv)          \
    XX(VideoM4V,               video/x-m4v,              m4v)          \
    XX(VideoMng,               video/x-mng,              mng)          \
    XX(VideoTs,                video/mp2t,               ts)           \
    XX(VideoMpeg,              video/mpeg,               mpeg)         \
    XX(VideoWebm,              video/webm,               webm)         \
    XX(VideoMov,               video/quicktime,          mov)          \
    XX(Video_3Gpp,              video/3gpp,              3gpp)         \
    XX(VideoAvi,               video/x-msvideo,          avi)          \
    XX(VideoWmv,               video/x-ms-wmv,           wmv)          \
    XX(VideoAsf,               video/x-ms-asf,           asf)          \

#define MIME_TYPE_AUDIO_MAP(XX) \
    XX(AudioMp3,               audio/mpeg,               mp3)          \
    XX(AudioOgg,               audio/ogg,                ogg)          \
    XX(AudioM4A,               audio/x-m4a,              m4a)          \
    XX(AudioAac,               audio/aac,                aac)          \
    XX(AudioPcma,              audio/PCMA,               pcma)         \
    XX(AudioOpus,              audio/opus,               opus)         \

#define MIME_TYPE_FONT_MAP(XX) \
    XX(FontTtf,                font/ttf,                 ttf)          \
    XX(FontOtf,                font/otf,                 otf)          \
    XX(FontWoff,               font/woff,                woff)         \
    XX(FontWoff2,              font/woff2,               woff2)        \

#define HTTP_CONTENT_TYPE_MAP(XX)   \
    MIME_TYPE_TEXT_MAP(XX)          \
    MIME_TYPE_APPLICATION_MAP(XX)   \
    MIME_TYPE_MULTIPART_MAP(XX)     \
    MIME_TYPE_IMAGE_MAP(XX)         \
    MIME_TYPE_VIDEO_MAP(XX)         \
    MIME_TYPE_AUDIO_MAP(XX)         \
    MIME_TYPE_FONT_MAP(XX)          \

#define X_WWW_FORM_URLENCODED   APPLICATION_URLENCODED // for compatibility

enum http_content_type {
#define XX(name, string, suffix)   k##name,
    kContentTypeNone           = 0,

    kContentTypeText           = 100,
    MIME_TYPE_TEXT_MAP(XX)

    kContentTypeApplication    = 200,
    MIME_TYPE_APPLICATION_MAP(XX)

    kContentTypeMultipart      = 300,
    MIME_TYPE_MULTIPART_MAP(XX)

    kContentTypeImage          = 400,
    MIME_TYPE_IMAGE_MAP(XX)

    kContentTypeVideo          = 500,
    MIME_TYPE_VIDEO_MAP(XX)

    kContentTypeAudio          = 600,
    MIME_TYPE_AUDIO_MAP(XX)

    kContentTypeFont           = 700,
    MIME_TYPE_FONT_MAP(XX)

    kContentTypeUndefined      = 1000
#undef XX
};



const char*             httpStatusStr(enum http_status status);
const char*             httpMethodStr(enum http_method method);
const char*             httpContentTypeStr(enum http_content_type type);
enum http_status        httpStatusEnum(const char* str);
enum http_method        httpMethodEnum(const char* str);
enum http_content_type  httpContentTypeEnum(const char* str);
const char*             httpContentTypeSuffix(enum http_content_type type);
const char*             httpContentTypeStrBySuffix(const char* str);
enum http_content_type  httpContentTypeEnumBySuffix(const char* str);

