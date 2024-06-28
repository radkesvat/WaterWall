# HalfDuplex

<div dir="rtl">

قابلیت halfduplex به این معنی است که ما هر کانکشن  تبدیل کنیم به ۲ کانکشن 

یکی اش برای ارسال فقط استفاده بشه و یکی اش برای دریافت

و البته هرکودم در هنگام شروع یه هندشیک tls حالا با هر دامنه ام داشته باشن 


انجام این عمل باعث میشه که

- دست فایروال کاملا بسته میشه برای تحلیل ترافیک چون دیتا روی هر کانکشن یه طرفه میشه کاملا 

- و حتی روی مستقیم هم قابل انجام هست و محدود به تانل نیست و میتونه باعث فیلتر نشدن کانفیگ مستقیم بشه

کانکشنی که دیتا روش رفت و برگشتی باشه (که یعنی تمام کانکشن های mux) عموملا به معنی تانل هست

مثلا تو کانکشن های عادی http2 ؛ دیتایی که به یه سایت زده میشه معمولا اول چندتا پکت اپلود هست و بعدش دیگه اپلود خیلی کم روی اون کانکشن رخ میده

ولی کانشن های vpn مدام اپلود دارن روی کانکشن mux شده


به تجربه کاملا اثبات شده که این برای تانل معکوس نیازه تا افت کیفیت پیدا نکنه

اما خوب این روش شاید حتی تانل عادی پورت به پورت رو هم در برابر فیلتر شدن مقاوم کنه؛ من اینو تست نکردم هنوز چون کانفیگی که هدفم بود بهش برسم ریورس ریلیتی با  h2 هست 

که اینجا فایل کاملشو قرار خواهم داد

# اجرای ساده مالتی پورت

بهتره قبل اینکه کانفیگ نهایی ریورس رو بدم ؛ اینجا نحوه اعمال halfduplex رو در حالت مالتی پورت ساده بزارم جهت یادگیری

# سرور ایران

حالت مالتی پورت

ادرس سرور خارج 1.1.1.1

</div>

```json
{
    "name": "simple_multiport_hd_client",
    "nodes": [
        {
            "name": "input",
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
            "next": "halfc"
        }, 
        {
            "name": "halfc",
            "type": "HalfDuplexClient",
            "next": "output"
        },
        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "1.1.1.1",
                "port": 443
            }
        }
    ]
}
```
<div dir="rtl">


# سرور خارج

</div>

```json
{
    "name": "simple_multiport_hd_server",
    "nodes": [
        {
            "name": "input",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true
            },
            "next": "halfs"
        },
        {
            "name": "halfs",
            "type": "HalfDuplexServer",
            "settings": {},
            "next": "port_header"
        },
        {
            "name":"port_header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "output"

        },

        {
            "name": "output",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address":"127.0.0.1",
                "port":"dest_context->port"
            }
        }
    ]
}
```
<div dir="rtl">

---


خوب بریم سراغ کانفیگ ریورس ریلیتی با ماکس که در حال حاضر خودم از همین برای کاربرهام استفاده می کنم

# سرور ایران

فرضیات 

fake sni: sahab.ir

ip kharej: 2.2.2.2

password: passwd

</div>


```json

{
    "name": "reverse_reality_grpc_hd_multiport_server",
    "nodes": [
        {
            "name": "users_inbound",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": [23,65535],
                "nodelay": true
            },
            "next": "header"
        },
        {
            "name": "header",
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
            "name": "pbserver",
            "type": "ProtoBufServer",
            "settings": {},
            "next": "reverse_server"
        },
        {
            "name": "h2server",
            "type": "Http2Server",
            "settings": {},
            "next": "pbserver"
        },
        {
            "name": "halfs",
            "type": "HalfDuplexServer",
            "settings": {},
            "next": "h2server"
        },
        {
            "name": "reality_server",
            "type": "RealityServer",
            "settings": {
                "destination": "reality_dest",
                "password": "passwd"
            },
            "next": "halfs"
        },
        {
            "name": "kharej_inbound",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": 443,
                "nodelay": true,
                "whitelist": [
                    "2.2.2.2/32"
                ]
            },
            "next": "reality_server"
        },
        {
            "name": "reality_dest",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "sahab.ir",
                "port": 443
            }
        }
    ]
}

```

<div dir="rtl">


# سرور خارج

فرضیات:

ایپی سرور ایران: 1.1.1.1

fake sni: sahab.ir

password: passwd

</div>

```json

{
    "name": "reverse_reality_grpc_client_hd_multiport_client",
    "nodes": [
        {
            "name": "outbound_to_core",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "127.0.0.1",
                "port": "dest_context->port"
            }
        },
        {
            "name": "header",
            "type": "HeaderServer",
            "settings": {
                "override": "dest_context->port"
            },
            "next": "outbound_to_core"
        },
        {
            "name": "bridge1",
            "type": "Bridge",
            "settings": {
                "pair": "bridge2"
            },
            "next": "header"
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
                "minimum-unused": 16
            },
            "next": "pbclient"
        },
        {
            "name": "pbclient",
            "type": "ProtoBufClient",
            "settings": {},
            "next": "h2client"
        },
        {
            "name": "h2client",
            "type": "Http2Client",
            "settings": {
                "host": "sahab.ir",
                "port": 443,
                "path": "/",
                "content-type": "application/grpc",
                "concurrency": 64
            },
            "next": "halfc"
        },
        {
            "name": "halfc",
            "type": "HalfDuplexClient",
            "next": "reality_client"
        },
        
        {
            "name": "reality_client",
            "type": "RealityClient",
            "settings": {
                "sni": "sahab.ir",
                "password": "passwd"
            },
            "next": "outbound_to_iran"
        },
        {
            "name": "outbound_to_iran",
            "type": "TcpConnector",
            "settings": {
                "nodelay": true,
                "address": "1.1.1.1",
                "port": 443
            }
        }
    ]
}

```

<div dir="rtl">

# نکته

یه کار قشنگی که میشه انجام داد روی این روش که من همیشه انجام میدم ؛ اینکه که صرف نظر از اینکه سرور ایران یا خارج چند هسته دارن 

در سرور خارج تعداد ورکر هارو همیشه 4 برابر تعداد ورکر های سرور ایران قرار میدم ؛ عددشو دستی وارد میکنم 

اینکه تعداد ورکر ها به این نسبت بیشتر باشه ؛ سرعت رو هم خیلی بهتر میکنه حتی ۸ برابر هم بزارید مشکلی نداره 

و بازم میگم اگه سرورتون یک هسته هم هست ؛ بهتره این کار انجام بشه و مشکلی ایجاد نمیشه

دلیل این هم اصلا ربطی به مصرف cpu نداره ؛ به خاطر اینه که هر ورکر برای خودش یه کانکشن مجزا ایجاد میکنه و همه کاربرا رو یه کانکشن Mux بسته نمیشن

این نکته هم فقط برای ریورس ریلیتی با ماکس هست ؛ رو تمام روش های دیگه بهترین حالت اینه که ورکر همون صفر باشه


# مستقیم

این قابلیت روی مستقیم هم قابل اعماله ولی خوب همونطور که در json مشخصه سمت کلاینت هم باید تغییر داده بشه

پس کلاینت خود واتروال فقط میتونه وصل بشه که الان برای دسکتاپ موجوده فقط و شاید هیچوقت برای موبایل قرار نخواهد گرفت

البته اندروید میشه خروجی اش رو در termux ران کرد ولی اینا چیزی نیست که همه بتونن استفاده کنن



</div>

[Homepage](.) | [Prev Page](Direct-Trojan) | [Next Page](Load-Balancing)