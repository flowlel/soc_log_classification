# incident_classification

The goal of this exercice is to parse each sentence from sentences.txt into a json like object:

```json
{
"Incident": {
"Type": "<incident_type>",
"Source": {
"IP": "<ip_address>",
"Location": "<location>"
},
"Target": {
"System": "<system>",
"User": "<user>"
},
"Time": "<time>"
}
}
```

In each JSON object:

- incident_type represents the type of cybersecurity incident. The possible values are
phishing, malware, DoS, DDoS, data leak, insider attack, and ransomware.

- ip_address is the IP address of the source of the incident. It consists of four numbers
separated by periods.

- location is the location of the source IP. It's given in the format "City, Country".

- system is an identifier of the targeted system. It may consist of letters, numbers, and
dashes.

- user is the username of the targeted user. It consists of alphanumeric characters and may
include underscores.

- time is the timestamp of when the incident occurred, given in the ISO 8601 format

# Usage

```python
result=Sentences("sentences.txt", "output.json")
result.parse()
result.write()
```