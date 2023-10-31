import pandas as pd
import matplotlib.pyplot as plt
import openai
from stix2 import FileSystemSource, TAXIICollectionSource, Filter, Indicator, parse
from taxii2client import Server, Collection
import os
import git

# Initialize a STIX FileSystemSource to work with ATT&CK data
source = FileSystemSource("/Users/admin/Desktop/log_data")

# Load ATT&CK data from your STIX/TAXII feed
# Replace 'YOUR_STIX_TAXII_URL' with your actual feed URL
collection_source = TAXIICollectionSource("https://otx.alienvault.com/taxii/collections/9fe35b0b-5a9e-4c08-a6d0-251f0cf5318b")
source.load_from(collection_source)

# Load network logs into a pandas DataFrame
# Replace 'network_logs.csv' with the path to your network logs file
with open('/var/log/appfirewall.log', 'r') as file:
    log_data = []
    for line in file:
        parts = line.split()  # Split the log entry by whitespace
        if len(parts) >= 3:
            timestamp = parts[0]
            log_level = parts[1]
            message = ' '.join(parts[2:])
            log_data.append({'Timestamp': timestamp, 'Log_Level': log_level, 'Message': message})

# Create a Pandas DataFrame
network_logs = pd.DataFrame(log_data)

# Configure your OpenAI API key
openai.api_key = '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'

# Function to create a STIX Indicator
def create_stix_indicator():
    indicator = Indicator(
        name="File hash for malware variant",
        indicator_types=["malicious-activity"],
        pattern_type="stix",
        pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']"
    )
    return indicator

# Function to parse a STIX JSON string into a Python STIX object
def parse_stix_json(stix_json):
    indicator = parse(stix_json)
    return indicator

# Function to detect suspicious network activity
def detect_network_threats():
    # Define a list of suspicious network activity patterns (you can expand this)
    suspicious_patterns = [
        'Unauthorized access attempt',
        'Unusual data exfiltration',
        # Add more patterns here
    ]

    threats_found = []

    for pattern in suspicious_patterns:
        matching_logs = network_logs[network_logs['Message'].str.contains(pattern, case=False, na=False)]

        if not matching_logs.empty:
            threats_found.append(pattern)

    return threats_found

# Function to map detected threats to MITRE ATT&CK techniques
def map_threats_to_attck(threats_found):
    mapped_techniques = set()

    for threat in threats_found:
        # You can define mappings between threats and specific ATT&CK techniques here
        if threat == 'Unauthorized access attempt':
            mapped_techniques.add('T1078')  # Initial Access - Valid Accounts
        elif threat == 'Unusual data exfiltration':
            mapped_techniques.add('T1020')  # Exfiltration Over C2 Channel

    return list(mapped_techniques)

# Function to find associated threat actors using ATT&CK data
def find_threat_actors(technique_id):
    actors_found = set()

    # Query ATT&CK data to find threat actors using the specified technique
    filter_str = f"relationship-type:uses AND target_ref.technique_id = '{technique_id}'"
    relationships = source.query(Filter(filter_str))

    for relationship in relationships:
        threat_actor = relationship.source_ref
        actors_found.add(threat_actor.name)

    return list(actors_found)

# Function to display graphical representations of detected threats
def visualize_threats(threats_found):
    if threats_found:
        # Count the occurrences of each threat pattern
        threat_counts = {threat: threats_found.count(threat) for threat in threats_found}

        # Plot the threats as a bar chart
        plt.bar(threat_counts.keys(), threat_counts.values())
        plt.xlabel('Threat Patterns')
        plt.ylabel('Occurrences')
        plt.title('Detected Threats')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()
    else:
        print("No threats detected.")

# Example usage
if __name__ == "__main__":
    # Create a STIX Indicator
    stix_indicator = create_stix_indicator()
    print(stix_indicator)

    # Parse a STIX JSON string into a Python STIX object
    stix_json = """
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--dbcbd659-c927-4f9a-994f-0a2632274394",
        "created": "2017-09-26T23:33:39.829Z",
        "modified": "2017-09-26T23:33:39.829Z",
        "name": "File hash for malware variant",
        "indicator_types": [
            "malicious-activity"
        ],
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "pattern": "[file:hashes.md5 ='d41d8cd98f00b204e9800998ecf8427e']",
        "valid_from": "2017-09-26T23:33:39.829952Z"
    }
    """
    parsed_indicator = parse_stix_json(stix_json)
    print(parsed_indicator.serialize(pretty=True))

    # Continue with your existing code
    threats_found = detect_network_threats()
    if threats_found:
        print("Detected threats:")
        for threat in threats_found:
            print(threat)
        mapped_techniques = map_threats_to_attck(threats_found)
        if mapped_techniques:
            print("\nMapped MITRE ATT&CK techniques:")
            for technique in mapped_techniques:
                print(technique)
                threat_actors = find_threat_actors(technique)
                if threat_actors:
                    print("Associated threat actors:")
                    for actor in threat_actors:
                        print(actor)