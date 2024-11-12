---
next: false
prev:
  text: 'Watch Usage'
  link: './watch'
---

# Use Stat Command to Analyze Traffic

The `watch` command provides a granular view of request-response pairs, which is useful for analyzing issues at a low level. However, some scenarios require a broader analysis, such as:

- If my HTTP requests are slow or timeout, is every server slow, or just a specific one?
- If someone is sending `GET` requests (which value is big) to my Redis instance, causing bandwidth saturation, which client IP is responsible?

The `stat` command is designed to address the need to analyze a large number of request-response pairs to derive conclusions.

## How to Use the Stat Command

Using the `stat` command is straightforward; you just need to determine **what metric you care about**.

For example, to solve the question: "If my HTTP requests are slow or timeout, is every server slow, or just a specific one?" so **the metric you care about** is the **response time** of  **remote servers(remote-ip)**.

then you can use the following command:
```bash
./kyanos stat --metric total-time --group-by remote-ip
```
Here, the `--metric` option is set to `total-time`, indicating that we want to analyze the total time of the request-responses. The `--group-by` option is set to `remote-ip`, meaning we want to observe the response times grouped by each `remote-ip`. Kyanos will aggregate all request-responses with the same `remote-ip` and provide the relevant metrics for total time.

A shorter version of the command would be:
```bash
./kyanos stat -m t -g remote-ip
```
Here, `-m` is a shorthand for `metric`, `t` for `total-time`, and `-g` for `group-by`.

> [!TIP]
> **How to Filter Traffic?**  
> The `stat` command supports all the filtering options available in the `watch` command.

## Analyzing the Results of the Stat Command

After entering the above `stat` command, you will see a table like this:
![kyanos stat result](/stat-result.jpg)

Like the `watch` table, you can sort the columns by pressing the corresponding number key. You can also navigate up and down using the `"↑"` `"↓"` or `"k"` `"j"` keys to select records in the table.

However, unlike the `watch` table, the records in the `stat` command are aggregated based on the `--group-by` option. Therefore, the second column is labeled `remote-ip`, with subsequent columns such as `max`, `avg`, `p50`, etc., representing the specified metric (in this case, `total-time`), showing the maximum, average, and 50th percentile values.

Pressing `enter` allows you to dive into the specific request-responses for that `remote-ip`. This view mirrors the results from the `watch` command, so you can examine individual request-responses, their timings, and their content in the same manner.


## Currently Supported Metrics

Kyanos currently supports the following metrics that can be specified with `--metric`:

| Metric               | Short Flag | Long Flag       |
| :------------------- | :--------- | :-------------- |
| Total Time           | `t`        | `total-time`    |
| Response Size        | `p`        | `respsize`      |
| Request Size         | `q`        | `reqsize`       |
| Network Time         | `n`        | `network-time`  |
| Internal Time        | `i`        | `internal-time` |
| Socket Read Time     | `s`        | `socket-time`   |

## Currently Supported Grouping Methods

Kyanos supports the following grouping dimensions that can be specified with `--group-by`:

| Grouping Dimension   | Value       |
| :------------------- | :---------- |
| Group by Connection   | `conn`     |
| Remote IP            | `remote-ip` |
| Remote Port          | `remote-port` |
| Local Port           | `local-port` |
| L7 Protocol          | `protocol`  |
| HTTP Path            | `http-path` |
| Redis Command        | `redis-command` |
| Aggregate All        | `none`      |

## What if You Can’t Remember These Options?

If you find it difficult to remember all these options, the `stat` command offers three quick options for analysis:

- `slow`: Analyze slow requests.
- `bigreq`: Analyze large requests.
- `bigresp`: Analyze large responses.

You can also use the --time option to specify the data collection period. For example, --time 10 will have the stat command collect traffic for 10 seconds.

![kyanos stat fast](/qs-stat-slow.jpg)

Once the collection is complete or if you press `ctrl+c` to stop early, you’ll see a table like this:

![kyanos stat quick result](/stat-quick-result.jpg)

From there, the operation proceeds in the same way as before.

### Analyzing Slow Requests

To quickly identify which `remote-ip` has the slowest HTTP requests, use:
```bash
./kyanos stat http --slow
```

### Analyzing Large Requests and Responses

To find which `remote-ip` has the largest requests, run:
```bash
./kyanos stat http --bigreq
```

To identify which `remote-ip` has the largest responses, use:
```bash
./kyanos stat http --bigresp
```
