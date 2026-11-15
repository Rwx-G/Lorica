# Active health checks

## TCP check templates and the limits of a custom check

<!-- BEGIN health-check-templates: rendered by lorica-api/tests/health_check_template_fixture.rs, never edit by hand -->
| Template | Sends | Expects, any of | What it proves |
|---|---|---|---|
| `redis_ping` | `PING\r\n` (hex `50494e470d0a`) | prefix `+PONG`, prefix `-NOAUTH` | Redis: PING answered by +PONG, or by -NOAUTH from a server that requires authentication (it is up and speaking its protocol) |
| `smtp_banner` | nothing | prefix `220` | SMTP: the server's greeting starts with 220 |
| `postgresql_ssl_request` | `\x00\x00\x00\x08\x04\xd2\x16/` (hex `0000000804d2162f`) | prefix `S`, prefix `N` | PostgreSQL: an SSLRequest answered by S (TLS offered) or N (TLS declined) |

| Limit | Meaning | Value |
|---|---|---|
| `SEND_MAX_BYTES` | most bytes a custom `send` carries, decoded | 1024 |
| `EXPECT_MAX_ALTERNATIVES` | most alternatives a custom `expect` lists | 8 |
| `EXPECT_MAX_BYTES` | most bytes one expected alternative carries, decoded | 256 |
| `PROBE_READ_MAX_BYTES` | most bytes one probe reads, whatever the check says | 4096 |
| `PROBE_TIMEOUT_MS_MIN` | shortest `timeout_ms` a check may set | 100 |
| `PROBE_TIMEOUT_MS_MAX` | longest `timeout_ms` a check may set | 10000 |
| `PROBE_TIMEOUT_MS_DEFAULT` | `timeout_ms` of a check that sets none | 5000 |

<!-- END health-check-templates -->
