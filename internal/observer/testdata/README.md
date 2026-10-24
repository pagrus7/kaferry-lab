# Fixed observer wire fixtures

These files contain complete big-endian Fetch-v11 response frames, including the four-byte response length, correlation ID 1, topic `a`, and partition 0. They were specified from the Kafka Fetch-v11 and magic-2 record-batch layouts without using a Kafka client encoder. Integer and ZigZag-varint fields were assembled independently; batch CRC32C uses the Castagnoli polynomial over attributes through records. Hex files are immutable test inputs; tests do not regenerate expected bytes from implementation functions.

- `valid-negative-binary`: batch offset 5, -2 ms, null key, present-empty value, ordered duplicate binary header key `ff00` with null then present-empty values.
- `valid-multibatch`: two records A/B at offsets 0/1 in one batch, then C at offset 2.
- `valid-gzip-multibatch`: the same input with a standard gzip first batch (mtime zero), followed by an uncompressed batch.
- `valid-sparse-empty`: A/C at offsets 0/2, a declared batch end of 4, then an empty batch whose validated declared span is [4,6). Sparse offsets are not missing-record counts. Qualification still needs its independent ledger and justified availability/gap rules.
- `valid-transaction-reuse`: producer 7 aborts offset 0, abort marker offset 1, then a required record at offset 2 and commit marker at offset 3. The response lists the first aborted transaction. This catches incorrectly filtering every record from the reused producer ID.
- `malformed-successful-prefix`: a CRC-valid batch declares two records and last delta 1, contains a complete record at offset 0 and a truncated second record, then a complete batch at offset 2. The pinned client's permissive decoder returns offsets 0/2; strict admission must reject the entire frame.
- `malformed-record-length`: a second record's declared byte length disagrees with its fields, while the batch CRC is valid.
- `malformed-later-crc`, `malformed-later-truncated`, `malformed-trailing-recordset`, `malformed-trailing-payload`: successful-prefix failures must not be accepted because an earlier batch/record was valid.
- `malformed-control-count`, `malformed-control-key`: transaction control metadata must not invent progress.
- `unsupported-compression`: a CRC-valid batch uses unsupported compression code 5 and must fail explicitly.

Literal malformed fixtures have valid CRC32C except the fixture explicitly named for CRC corruption and physically truncated batch. Independent expected records and decisions are asserted in tests, rather than inferred from the client's returned records.
