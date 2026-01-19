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
