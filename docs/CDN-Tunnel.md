<div dir="rtl">

# مقدمه

یکی از اهداف اصلی شروع این پروژه رسیدن به تونل معکوس با کلود فلیر بود ؛ هرچند تنها راه این تونل واتروال نیست و ابزار زیاد هست براش اما من سعی کردم یه ورژن بهینه و تست شده رو درست کنم که انعطاف پذیر هم باشه و بشه مثلا اگه ایده ای اومد روی همین تونل اضافه اش کرد .


تونل معکوس با کلود فلیر یکی از امن ترین روش های تونل حساب میشه و مناسبه برای کسایی که میترسند سرور ایرانشون اکسس بشه یا مشکلات دیگه ؛ چون کلود فلیر قانونی ترین و تمیز ترین ایپی هایی هست که 
بیشتر اینترنت روش هست ؛ حتی خودش دولت هم سرور های ایرانش رو بعضا پشت کلود فلیر میبره و کلا هر سایتی چه بزرگ و چه کوچک عموما پشت کلود قرار میدن همه که از سایر مزایا کلود فلیر مثل
محافظت در برابر دیداس و غیره بهره مند بشن؛ چه ایرانی و چه خارجی.


اولین بار که این تونل رو انجام دادم با پروژه RTCF بود که اونجا با وبسوکت کانکشن رو ایجاد می کردیم ؛ متاسفانه پایداریش جالب نبود و کرش و مشکلات دیگه داشت ؛ این بار با grpc کانکشن
رو برقرار میکنیم که طی مدت کوتاهی که تست کردم قابل قبول بوده کیفیت اش.

---

برای این روش ما نیاز به دامنه شخصی داریم ؛ من شخصا ir رو بهترین گزینه میدونم ولی دامنه های دیگه هم باید اوکی باشن ؛ درمورد ir بودن دامنه هم جای نگرانی نیست چون اتصال تحت tls هست 
و مشکلی ایجاد نمیشه ؛ کما اینکه مدت ها من و سایر دوستان استفاده کردیم ؛ حتی خودتون هم حتما دیدین فروشنده هایی هستن که کانفیگ مستقیم با دامنه ir میفروشن و برای اون ها هم تا جایی که من میدونم مشکلی ایجاد نشد حتی بعد فیلتر شدن دامنه هاشون ؛ پس از نظر من جای نگرانی در این مورد نیست که دامنه چی باشه.

برای دامنه باید سرتیفکیت گرفته بشه تا tls فعال بشه ؛ معمولا با certbot این رو انجام میدن و علاوه بر این شما می توانید سرتفیکیت از خود کلود فلیر هم دریافت کنید.

سرتیفیکیت رو اگه کلود فلیر دریافت میکنید ؛ فرقی که با سرتفیکیت certbot داره اینه که فقط کلود فلیر به اون سرتفیکیت اعتماد میکنه ؛ نمی توانید با اون سرتفیکیت از جای دیگه ای به سرور متصل بشید
مثلا اگه یه کانفیگ مستقیم با اون سرتفیکیت درست کنید ؛ گوشی وصل نمیشه  مگه اینکه allowinsecure فعلا بشه.

درکل این ها جزیاته ؛ ما سرتیفکیت رو چون برای تانل کلود فیلر میخوایم استفاده کنیم پس هر ۲ راه جوابه

نکته دوم ساب دامنه هست ؛‌ اگه از certbot برای سرتفیکیت استفاده میکنید ؛ سرتیفیکیتی که بهتون میده فقط و فقط برای سابی که درخواست داید کار میکنه مگر اینکه به روش Wildcard درخواست بدید 
اونوقت برای تمام ساب دامنه ها معتبر هست ؛ اموزش تو اینترنت و یوتیوب به زبان فارسی در این خصوص زیاده و کار پیچیده ای نیست به اون صورت


اگه از کلود فیلر سرتیفیکت میگیرید ؛ اون به شما به صورت پیش فرض سرتفیکیت wildcard میده که می توانید برای هر سابی استفاده کنید


اگه از سرتفیکیت کلود استفاده میکنید نکته مهم دیگه ای که وجود داره اینه که ساب هاتون فقط یک مرحله ای باشه ؛ سرتفیکیت کلود برای ساب ۲ بخشی و بیشتر کار نمیکنه 

مثلا این ساب اوکیه

</div>

> sub1.mydomain.com

<div dir="rtl">


ولی این ساب با سرتیفکیت کلودفلیر اوکی نیست 

</div>

> sub2.sub1.mydomain.com

<div dir="rtl">

اگه میخواهید از کلود فلیر سرتیفکیت بگیرید ؛ قبلا یه آموزش با عکس دادم که کمکتون میکنه 

[لینک](https://github.com/radkesvat/RTCF/blob/main/docs/private_domain.md)


خوب درمورد ساب من دیگه نکته ای نمیگم


--- 


مرحله بعدی اینه که داخل پنل کلود فلیر grpc رو فعال کنید ؛ داخل بخش نتورک می توانید انجام بدید


و همچنین حتما چک کنید bot fight mode فعال نباشه؛ این پیشفرض فعال نیست ولی دیدم خیلیا فعال کرده بودن و ساعت ها دیباگ کردیم تا متوجه شدیم مشکل از این بوده

کلا پیشناهاد میکنم فیچر خاص و امنتیی الکی فعال نکنید که مشکل بخوریم 


سپس در تنظیمات tls هم حتما حداقل ورژن را برابر 1.2 قرار بدین 

و همچنین گزینه SSL/TLS encryption mode را برابر Full تنظیم کنید

---

خوب نکته آخر اینکه ؛ کلود فلیر فقط باید به پورت ۴۴۳ سرور ایران وصل بشه ؛ حتی پورت های دیگه مثل ۲۰۸۳ هم نمیشه ؛ این جزو قوانین کلود فلیر هست که انتقال دیتا grpc فقط روی این پورت باشه
اما ؛ همونطور که توی روش های قبلی هم نشون دادم ؛ واتروال سیستم پکت فیلترینگ داخلی داره و ما هم چنان می توانیم از پورت ۴۴۳ به صورت دوگانه استفاده کنیم ؛‌ حتی اگه با مالتی پورت ترکیب شده باشه

--- 

چند نوع مثال از این نوع تانل رو اینجا می ببینیم

عموما شما در کانفیگ فایل سرور ایران تغییر خاصی نمیدید ؛ توی سرور ایران به فایل های سرتیفکیت نیاز هست که باید کنار فایل اجرایی waterwall قرار بدین


خوب اول یه مثال ساده بزنم ؛ کانفیگ زیر reverse tls grpc هست که تک پورته

و فقط پورت ۴۴۳ رو تونل میکنه

یعنی کاربر به ۴۴۳ ایران وصل میشه و در نهایت به ۴۴۳ خارج وصل خواهد شد ؛ که خوب این رو می توانید پورت دلخواه قرار بدین 


## سرور خارج

فرضیات: پورت کانفیگ روی همین سرور و پورت ۴۴۳

دامنه که تیک پروکسی کلود هم روشنه : sub.mydomain.com

دقت کنید دامنه ۳ جا در کانفیگ سرور خارج تکرار شده که هر ۳ تارو دقیقا یکی و برابر با دامنه خودتون قرار بدین


</div>

```json
{
    "name": "config_reverse_tls_grpc_singleport_kharej",
    "nodes": [
        {
            "name": "core_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": 443
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "core_outbound"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            },
            "next": "reverse_client"
        },
        {
            "name": "reverse_client",
            "type": "ReverseClient",
            "settings": {
            },
            "next": "grpc_client"
        },
        {
            "name": "grpc_client",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "sub.mydomain.com",
                "port": 443,
                "path": "/service",
                "content-type": "application/grpc"
            },
            "next": "sslclient"
        },
        {
            "name": "sslclient",
            "type": "OpenSSLClient",
            "settings": {
                "sni": "sub.mydomain.com",
                "verify": true,
                "alpn": "h2"
            },
            "next": "iran_outbound"
        },
        {
            "name": "iran_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "sub.mydomain.com",
                "port": 443
            }
        }
    ]
}

```

<div dir="rtl">

##  سرور ایران

فرضیات : کاربر به پورت ۴۴۳ وصل میشه

کلود فلیر هم به پورت ۴۴۳ وصل میشه

</div>

```json
{
    "name": "config_reverse_tls_grpc_singleport_iran",
    "nodes": [
        {
            "name": "inbound_users",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true
            },
            "next": "bridge2"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            }
        },
        {
            "name": "reverse_server",
            "type": "ReverseServer",
            "settings": {},
            "next": "bridge1"
        },
        {
            "name": "grpc_server",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "reverse_server"
        },
        {
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "grpc_server"
        },
        {
            "name": "sslserver",
            "type": "OpenSSLServer",
            "settings": {
                "cert-file": "fullchain.pem",
                "key-file": "privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ],
                "fallbackintencedelay": 0
            },
            "next": "h2server"
        },
        {
            "name": "inbound_cloudflare",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true,
                "whitelist": [
                    "173.245.48.0/20",
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                    "103.31.4.0/22",
                    "141.101.64.0/18",
                    "108.162.192.0/18",
                    "190.93.240.0/20",
                    "188.114.96.0/20",
                    "197.234.240.0/22",
                    "198.41.128.0/17",
                    "162.158.0.0/15",
                    "104.16.0.0/13",
                    "104.24.0.0/14",
                    "172.64.0.0/13",
                    "131.0.72.0/22",
                    "2400:cb00::/32",
                    "2606:4700::/32",
                    "2803:f800::/32",
                    "2405:b500::/32",
                    "2405:8100::/32",
                    "2a06:98c0::/29",
                    "2c0f:f248::/32"
                ]
            },
            "next": "sslserver"
        }
    ]
}

```

<div dir="rtl">

---

# مالتی پورت


همین کارو می توانیم با مالتی پورت هم انجام بدیم و کاربر به هر پورتی که به سرور ایران وصل شد ؛ به همون پورت  سرور خارج وصل خواهد شد


## سرور خارج

</div>

```json
{
    "name": "config_reverse_tls_grpc_multiport_kharej",
    "nodes": [
        {
            "name": "core_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": "dest_context->port"
            }
        },
        {
            "name": "port_header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "core_outbound"
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "port_header"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            },
            "next": "reverse_client"
        },
        {
            "name": "reverse_client",
            "type": "ReverseClient",
            "settings": {
            },
            "next": "grpc_client"
        },
        {
            "name": "grpc_client",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "sub.mydomain.com",
                "port": 443,
                "path": "/service",
                "content-type": "application/grpc"
            },
            "next": "sslclient"
        },
        {
            "name": "sslclient",
            "type": "OpenSSLClient",
            "settings": {
                "sni": "sub.mydomain.com",
                "verify": true,
                "alpn": "h2"
            },
            "next": "iran_outbound"
        },
        {
            "name": "iran_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "sub.mydomain.com",
                "port": 443
            }
        }
    ]
}
```
<div dir="rtl">

## سرور ایران

</div>

```json


{
    "name": "config_reverse_tls_grpc_multiport_iran",
    "nodes": [
        {
            "name": "inbound_users",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [23,65535],
                "nodelay": true
            },
            "next": "port_header"
        },
        {
            "name": "port_header",
            "type": "HeaderClient",
            "settings": {
                "data": "src_context->port"
            },
            "next": "bridge2"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            }
        },
        {
            "name": "reverse_server",
            "type": "ReverseServer",
            "settings": {},
            "next": "bridge1"
        },
        {
            "name": "grpc_server",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "reverse_server"
        },
        {
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "grpc_server"
        },
        {
            "name": "sslserver",
            "type": "OpenSSLServer",
            "settings": {
                "cert-file": "fullchain.pem",
                "key-file": "privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ],
                "fallbackintencedelay": 0
            },
            "next": "h2server"
        },
        {
            "name": "inbound_cloudflare",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true,
                "whitelist": [
                    "173.245.48.0/20",
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                    "103.31.4.0/22",
                    "141.101.64.0/18",
                    "108.162.192.0/18",
                    "190.93.240.0/20",
                    "188.114.96.0/20",
                    "197.234.240.0/22",
                    "198.41.128.0/17",
                    "162.158.0.0/15",
                    "104.16.0.0/13",
                    "104.24.0.0/14",
                    "172.64.0.0/13",
                    "131.0.72.0/22",
                    "2400:cb00::/32",
                    "2606:4700::/32",
                    "2803:f800::/32",
                    "2405:b500::/32",
                    "2405:8100::/32",
                    "2a06:98c0::/29",
                    "2c0f:f248::/32"
                ]
            },
            "next": "sslserver"
        }
    ]
}
```

<div dir="rtl">


# ترکیب با halfduplex

من با روش های بالا تست کردم مشکل پینگ یا نوسان ندیدم و همه چی اوکی بود ولی بازم خیلی خوبه اگه این ترکیب انجام بشه

## سرور خارج

</div>

```json
{
    "name": "config_reverse_tls_grpc_multiport_hd_kharej",
    "nodes": [
        {
            "name": "core_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": 443
            }
        },
        {
            "name": "port_header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "core_outbound"
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "port_header"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            },
            "next": "reverse_client"
        },
        {
            "name": "reverse_client",
            "type": "ReverseClient",
            "settings": {
            },
            "next": "halfc"
        },
        {
            "name": "halfc",
            "type": "HalfDuplexClient",
            "settings": {},
            "next": "grpc_client"
        },
        {
            "name": "grpc_client",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "sub.mydomain.com",
                "port": 443,
                "path": "/service",
                "content-type": "application/grpc"
            },
            "next": "sslclient"
        },
        {
            "name": "sslclient",
            "type": "OpenSSLClient",
            "settings": {
                "sni": "sub.mydomain.com",
                "verify": true,
                "alpn": "h2"
            },
            "next": "iran_outbound"
        },
        {
            "name": "iran_outbound",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "sub.mydomain.com",
                "port": 443
            }
        }
    ]
}

```

<div dir="rtl">


## سرور ایران


</div>

```json
{
    "name": "config_reverse_tls_grpc_multiport_hd_iran",
    "nodes": [
        {
            "name": "inbound_users",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [23,65535],
                "nodelay": true
            },
            "next": "port_header"
        },
        {
            "name": "port_header",
            "type": "HeaderClient",
            "settings": {
                "data": "src_context->port"
            },
            "next": "bridge2"
        },
        {
            "name": "bridge2",
            "type": "Bridge",
            "settings": {
                "pair": "bridge1"
            }
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            }
        },
        {
            "name": "reverse_server",
            "type": "ReverseServer",
            "settings": {},
            "next": "bridge1"
        },
        {
            "name": "halfs",
            "type": "HalfDuplexServer",
            "settings": {},
            "next": "reverse_server"
        },
        {
            "name": "grpc_server",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "halfs"
        },
        {
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "grpc_server"
        },
        {
            "name": "sslserver",
            "type": "OpenSSLServer",
            "settings": {
                "cert-file": "fullchain.pem",
                "key-file": "privkey.pem",
                "alpns": [
                    {
                        "value": "h2",
                        "next": "node->next"
                    },
                    {
                        "value": "http/1.1",
                        "next": "node->next"
                    }
                ],
                "fallbackintencedelay": 0
            },
            "next": "h2server"
        },
        {
            "name": "inbound_cloudflare",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true,
                "whitelist": [
                    "173.245.48.0/20",
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                    "103.31.4.0/22",
                    "141.101.64.0/18",
                    "108.162.192.0/18",
                    "190.93.240.0/20",
                    "188.114.96.0/20",
                    "197.234.240.0/22",
                    "198.41.128.0/17",
                    "162.158.0.0/15",
                    "104.16.0.0/13",
                    "104.24.0.0/14",
                    "172.64.0.0/13",
                    "131.0.72.0/22",
                    "2400:cb00::/32",
                    "2606:4700::/32",
                    "2803:f800::/32",
                    "2405:b500::/32",
                    "2405:8100::/32",
                    "2a06:98c0::/29",
                    "2c0f:f248::/32"
                ]
            },
            "next": "sslserver"
        }
    ]
}

```

<div dir="rtl">



ترکییب این روش با halfduplex شاید مشکل داشته باشه دقیق نمیدونم بیشتر این روی برای ریورس عادی تست کردم

ولی در آپدیت هایی بعدی مشکلات این روش برطرف خواهند شد









</div>
