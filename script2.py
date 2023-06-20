import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import matplotlib.pyplot as plt
from datetime import datetime
# Initialize Firebase
cred = credentials.Certificate('fbdatabase.json')
firebase_admin.initialize_app(cred)

# Initialize Firestore
db = firestore.client()

# Get the references to the Logs collection
logs_collection = db.collection('Logs')

# Get the references to the documents (e.g. Application, Security) within the Logs collection
log_documents = logs_collection.stream()

# Process the data
# I am using the 'TimeGenerated' and 'RecordNumber' fields for this example.
# You can adjust the fields and plotting method according to the structure and type of data you are dealing with.
time_generated_values = []
record_numbers = []

for log_document in log_documents:
    # Get the document name (e.g. "Application", "Security")
    document_name = log_document.id
    
    # Get the entries within this document
    entries = logs_collection.document(document_name).collection('Entries').stream()
    
    # Iterate through the entries
    for entry in entries:
        entry_data = entry.to_dict()
        
        # Convert TimeGenerated to a datetime object for plotting
        time_generated = datetime.strptime(entry_data['TimeGenerated'], "%a %b %d %H:%M:%S %Y")
        time_generated_values.append(time_generated)
        record_numbers.append(entry_data['RecordNumber'])

# Visualize the data
# For this example, I am just plotting the record numbers against the time they were generated.
# This is just an example, please adjust it according to the specific visualization you need.
plt.plot(time_generated_values, record_numbers, marker='o')
plt.xlabel('Time Generated')
plt.ylabel('Record Number')
plt.title('Your Data Visualization')
plt.xticks(rotation=45)
plt.grid(True)
plt.show()