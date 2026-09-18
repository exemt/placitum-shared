# Placitum shared

English · [Русский](README.ru.md)

Go packages shared by Placitum processes: inspectors, services and agents. A package lands here
only when it means the same thing to every process and has one owner. Anything a component does
its own way stays in that component.

## Packages

| Package | What it does |
| --- | --- |
| `pulse` | presence frame on `WAF_STATUS`: who is running, where and for how long. It is neither a verdict nor a health check. `Frame` is embedded in the frame of any process, `Message` is the inspector frame |
| `host` | machine snapshot for the frame: cores, memory, load |
| `flow` | I/O counters: how much was received and sent within a window |
| `loglevel` | nginx log levels (`debug` … `alert`), their parsing and the starting threshold from a process environment variable |
| `logkit` | service log: lines go to `waf.log` in `kind=log` batches, the live threshold follows the `policy/log-levels` document |
| `dataset` | writes to active datasets through keeper: synchronously in HTTP processes, in the background in inspectors |
| `netinfo` | network directory client: announcements, AS composition, cache and negative cache |
| `geopb` | generated gRPC client of the network directory; `geo.proto` is a copy of the contract owned by the network directory |

## Usage

```go
import "github.com/exemt/placitum-shared/pulse"
```

```sh
go get github.com/exemt/placitum-shared@vX.Y.Z
```

A component pins the version in its `go.mod` and moves it when it needs to.

Every process has its own presence frame: the address inspector adds live datasets, captcha adds
verdict counters, keeper adds datasets, the Redis agent adds a store snapshot. The shared part does
not grow because of that. A process embeds `pulse.Frame` (service) or `pulse.Message` (inspector)
in its own struct and sends it with `pulse.PublishFrame`; the fields end up in one JSON object.

## What is not here

Inspector decisions: profiles, conditions, verdicts, thresholds and policy. That is what a component
is for.

## Versions

Semantic versioning. A major version does not break for convenience: more than a dozen components
cannot be rewritten at once. Bus contract changes go the other way round: every reader first, then
the writers.

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
