# Splunk configs

Configs used on the Splunk server to normalize Windows logs.

## Files
- `props.conf` – source/sourcetype handling + transforms mapping
- `transforms.conf` – transforms used by props (rename Sysmon sourcetype + set `EventCode` from `<EventID>`)

## Expected result
After reload/restart, searches like:
- `index=windows EventCode=4688`
- `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1`

should work.


## Design decisions

- CommandLine, NewProcessName and ParentProcessName are **not extracted at index time**
- Detection logic relies on `_raw` searches
- This avoids:
  - field explosion
  - fragile regex-based ingest parsing
  - performance issues on large Windows event volumes

Field extraction is intentionally done **at search time** inside detections.

