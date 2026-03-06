# pattern_key_v1 Contract

`pattern_key_v1` must be constructed consistently by OpenResty and Java.

## Shape

`method | route_key | content_type | surface | field_selector | detector | signature_token`

## Rules

- `method`: uppercase (example: `POST`)
- `route_key`: normalized route key
- `content_type`: normalized major content type (example: `application/json`)
- `surface`:
  - one of `query`, `form`, `json`, `header`, `multipart_filename`, `multipart_text`
- `field_selector`:
  - for `json` surface, use `json_path`
  - for other surfaces, use `field_name`
  - if missing, use `-`
- `signature_token`:
  - parser hit fingerprint if available
  - else `-`

## Example

`POST|/api/search|application/json|json|$.keyword|libinjection_sqli|sqli_fingerprint_xxx`

## Notes

- Use the exact delimiter `|`.
- Do not include extra spaces.
- If value contains `|`, percent-encode it before joining.
