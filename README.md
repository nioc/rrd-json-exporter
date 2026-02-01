# RRD JSON Exporter

[![license: AGPLv3](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub release](https://img.shields.io/github/release/nioc/rrd-json-exporter.svg)](https://github.com/nioc/rrd-json-exporter/releases/latest)
[![GitHub Docker workflow status](https://img.shields.io/github/actions/workflow/status/nioc/rrd-json-exporter/docker.yml?label=github%20build)](https://github.com/nioc/rrd-json-exporter/actions/workflows/docker.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/nioc/rrd-json-exporter)](https://hub.docker.com/r/nioc/rrd-json-exporter/tags)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/nioc/rrd-json-exporter?sort=date)](https://hub.docker.com/r/nioc/rrd-json-exporter/tags)

Lightweight HTTP service written in Go that exposes data from `.rrd` (Round Robin Database) files as JSON.  
It is designed to integrate seamlessly with Grafana (via the [Infinity datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/)), monitoring stacks, or any system that needs to consume RRD metrics (such as those produced by [Munin](https://munin-monitoring.org/)) over HTTP.

## Key features

- Lightweight (uses less than 20 MB of RAM)
- RRD parsing via `rrdtool fetch`
- JSON API endpoints
- File‑level or bulk RRD export
- Built‑in caching
- Secured with basic authentication

## Installation

This can be used as docker container:

- as standalone service:

  ```bash
  docker run -it -p 9090:808080 --rm \
  -v $(pwd)/rrd:/app/rrd:ro \
  -e LOG_LEVEL=debug \
  -e CACHE_TTL=60 \
  --name rrd-json-exporter nioc/rrd-json-exporter:latest
  ```

- in a `docker-compose.yml` file:
  ```yml
  services:
    rrd-json-exporter:
      image: nioc/rrd-json-exporter:latest
      container_name: rrd-json-exporter
      environment:
        LOG_LEVEL: debug
        # CACHE_TTL: 60
        # PORT: 8080
        # AUTH_USER: myuser
        # AUTH_PASS: mypassword
      volumes:
        - ./rrd:/app/rrd:ro
      ports:
        - 9090:8080
      restart: unless-stopped
  ```

Environment Variables

| Variable    | Default | Description                                   |
| ----------- | ------- | --------------------------------------------- |
| `LOG_LEVEL` | `info`  | Logging verbosity (`error`, `info`, `debug`)  |
| `CACHE_TTL` | `60`    | Cache duration in seconds                     |
| `PORT`      | `8080`  | Port the exporter listens on in the container |
| `AUTH_USER` |         | User (basic authentication)                   |
| `AUTH_PASS` |         | Password (basic authentication)               |

NB: Basic authentication is only enabled if both the `AUTH_USER` and `AUTH_PASS` environment variables are provided.

## Usage

### API Endpoints

#### List RRD files

Request the list of available RRD metric files

```http
GET /list
```

This returns a JSON array containing the available RRD metric files:

```json
[
  "server-docker_cpu-proxy-g.rrd",
  "server-docker_cpu-nginx-g.rrd",
  "server-docker_memory-proxy-g.rrd",
  "server-docker_memory-nginx-g.rrd"
]
```

#### Get all RRD metrics

Request all available RRD metrics

```http
GET /metrics
```

This returns a JSON array containing all metrics:

```json
[
  {
    "n": "server-docker_cpu-proxy-g",
    "t": 1769878800,
    "v": 1.9536137042
  },
  {
    "n": "server-docker_cpu-proxy-g",
    "t": 1769879100,
    "v": 2.1562561502
  },
  {
    "n": "server-docker_cpu-proxy-g",
    "t": 1769879400,
    "v": 1.2935769699
  }
]
```

With the following attributes:

- `n`: the **name** of the metric
- `t`: the **Unix timestamp** in seconds
- `v`: the **value** of the metric at that time

#### Get specific RRD metrics

Request a specific RRD metric by its filename

```http
GET /metrics?rrd=filename.rrd
```

Request several specific RRD metrics by their file name

```http
GET /metrics?rrd={filename1.rrd,filename2.rrd}
```

This returns a JSON object containing the requested metrics.

#### Error messages

In case of an error, the message has the following structure with proper HTTP status codes:

```json
{
  "status": "error",
  "message": "RRD file not found",
  "details": "server-docker_cpu.rrd"
}
```

### Grafana integration

Use the Infinity Datasource plugin.

#### Declare source

- Home > Connections > Data sources > **Add new data source**
- Select `Infinity` type
- Choose a name
- In _URL, Headers & Params_ set Base URL to `http://rrd-json-exporter:8080/` (according to the name of your container)

#### Use in dashboard

- Add a variable: Settings > Variables > **New variable**
  - Type: `Query`
  - Name: `rrdfile`
  - Data source: select the Infinity source created before
  - Type: `JSON`
  - Parser: `JQ`
  - Source: `URL`
  - Method: `GET`
  - URL: `list`
  - Multi-value: ✅

- Add a **visualization** with:
  - Data source: select the Infinity source created before
  - Type: `JSON`
  - Parser: `JSONata`
  - Source: `URL`
  - Format: `Time Series`
  - Method: `GET`
  - URL: `metrics?rrd=${rrdfile}`
  - In _Parsing options & Result fields_
    - add 3 colmuns:
      - selector: `t`, format as `Time (UNIX s)`
      - selector: `v`, format as `Number`
      - selector: `n`, format as `String`

## Credits

- **[Nioc](https://github.com/nioc/)** - _Initial work_

See also the list of [contributors](https://github.com/nioc/rrd-json-exporter/contributors) to this project.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details
