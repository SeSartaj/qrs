# Embed schema inline: maps integer keys (as strings) -> field names
import cbor2

schema = {
    "0": "name",
    "1": "age",
    "2": "skills"
}

# Inverse mapping: field name -> integer key
name_to_key = {v: int(k) for k, v in schema.items()}

data = {
    "name": "Ahmad",
    "age": 20,
    "skills": ["C", "Arduino"]
}

# Build compact map using integer keys where schema defines them
compact = {}
for field, val in data.items():
    if field in name_to_key:
        compact[name_to_key[field]] = val
    else:
        compact[field] = val

# Encode to CBOR (with integer keys)
encoded = cbor2.dumps(compact)

print(encoded)

# Save to file
with open("data.cbor", "wb") as f:
    f.write(encoded)

# Read back
with open("data.cbor", "rb") as f:
    decoded = cbor2.loads(f.read())

print(decoded)

# Expand integer keys back to human-readable names using schema
expanded = {}
for k, v in decoded.items():
    if isinstance(k, int) and str(k) in schema:
        expanded[schema[str(k)]] = v
    else:
        expanded[k] = v

print(expanded)